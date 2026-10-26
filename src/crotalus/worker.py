"""Run the detection rules on pending releases forever, one at a time.

Run with: python -m crotalus.worker

For each release, in one transaction that holds a row lock on it the whole time:

    1. claim the oldest pending release        queries.claim_next_pending_release
    2. gather its metadata, history and code   analysis_context.build_analysis_context
    3. run every rule on it                    rules.RULES
    4. score the findings into a verdict       scoring.score / scoring.rules_verdict
    5. store the findings and mark it 'done'   queries.replace_findings / mark_analyzed

- Another worker skips locked rows (SKIP LOCKED), so no release is analyzed twice.
- If the worker dies mid-analysis, Postgres rolls back and the release is 'pending'
  again for the next worker. Only database changes are rolled back.
- Any earlier LLM triage of the release is deleted: it judged the old findings. If
  the new verdict is still flagged, the triager looks at it again.
- If the analysis raises, the release is marked 'failed' so it isn't retried forever.
  Except when PyPI is unreachable: that isn't the release's fault, so it rolls back
  to 'pending' and the worker waits before trying again.

Because the claim is never committed on its own, other connections never see a
release in 'analyzing'. That status is unused for now.

Database errors are not caught: the worker stops so the problem gets looked at.
"""

from __future__ import annotations

import psycopg

from crotalus import queries, scoring
from crotalus.analysis_context import build_analysis_context
from crotalus.db import Connection
from crotalus.loop import run_forever
from crotalus.models import AnalysisContext, Finding, Release, Verdict
from crotalus.pypi import PyPIUnavailable
from crotalus.rules import RULES

IDLE_SLEEP_SECONDS = 5
PYPI_BACKOFF_SECONDS = 30


def run_rules(context: AnalysisContext) -> list[Finding]:
    """Every rule's findings for one release."""
    return [finding for rule in RULES for finding in rule(context)]


def analyze_next_release(conn: Connection) -> bool:
    """Claim, analyze and store one pending release. False if none is pending."""
    with conn.transaction():
        release: Release | None = queries.claim_next_pending_release(conn)
        if release is None:
            return False
        queries.delete_triage(conn, release.id)  # stale once the findings are redone

        try:
            context: AnalysisContext = build_analysis_context(conn, release)
            findings: list[Finding] = run_rules(context)
        except PyPIUnavailable:
            raise  # not this release's fault: roll back to 'pending', run_forever waits
        except psycopg.Error:
            raise  # database problems stop the worker, like everywhere else
        except Exception as exc:  # a problem with this release, or a bug in a rule
            print(f"Analysis failed for {release.name} {release.version}: {exc!r}")
            queries.mark_failed(conn, release.id)
            return True

        score: int = scoring.score(findings)
        rules_verdict: Verdict = scoring.rules_verdict(findings)
        queries.replace_findings(conn, release.id, findings)
        queries.mark_analyzed(conn, release.id, score, rules_verdict)
        print(f"{release.name} {release.version}: {rules_verdict} (score {score})")
    return True


def main() -> None:
    run_forever(
        "Worker",
        analyze_next_release,
        sleep_after_work=0,  # straight on to the next pending release
        sleep_when_idle=IDLE_SLEEP_SECONDS,
        # Marking releases failed while PyPI is down would fail the whole queue.
        retry_later_on=(PyPIUnavailable,),
        sleep_before_retry=PYPI_BACKOFF_SECONDS,
    )


if __name__ == "__main__":
    main()
