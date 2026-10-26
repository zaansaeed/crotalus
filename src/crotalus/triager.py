"""Ask the LLM about flagged releases forever, one at a time, and set their final verdict.

Run with: python -m crotalus.triager   (needs GEMINI_API_KEY in .env)

Works like the worker, on releases the worker finished with a 'suspicious' or
'likely_malicious' rules verdict that this model and prompt version haven't triaged
yet. For each one, in one transaction that holds a row lock on the release:

    1. claim the oldest flagged release        queries.claim_next_flagged_release
    2. gather its code again, load findings    build_analysis_context / queries.load_findings
    3. ask the LLM                             triage.triage_release
    4. store its opinion                       queries.store_triage_result
    5. combine the two verdicts                scoring.final_verdict / queries.record_llm_verdict

- A bad answer from the LLM, or a release that can't be rebuilt (e.g. deleted from
  PyPI, which malware often is), is stored as a 'failed' triage row so it isn't
  retried forever. Its llm_verdict stays NULL and its final verdict stays the rules'.
- Gemini or PyPI being unreachable or rate-limiting isn't the release's fault: it
  rolls back, stays untriaged, and the triager waits before trying again.
- No API key, a rejected key, or an unknown model stops the triager: every release
  would fail the same way.

It runs separately from the worker so that a slow, rate-limited LLM never holds up
analysis, and so a new prompt can be tried on old releases without re-analyzing them.
"""

from __future__ import annotations

import os

import psycopg
from dotenv import load_dotenv

from crotalus import queries, scoring, triage
from crotalus.analysis_context import build_analysis_context
from crotalus.db import Connection
from crotalus.loop import run_forever
from crotalus.models import AnalysisContext, Finding, FlaggedRelease, TriageResult, Verdict
from crotalus.pypi import PyPIUnavailable

IDLE_SLEEP_SECONDS = 30  # flagged releases are rare
# Between LLM calls, to stay under the free tier's requests-per-minute limit.
CALL_INTERVAL_SECONDS = 6
BACKOFF_SECONDS = 60  # when Gemini or PyPI is unavailable or rate-limiting us


def triage_next_flagged_release(conn: Connection, model: str) -> bool:
    """Claim one flagged release, ask the LLM, store its opinion and the final verdict.
    False if no release is waiting."""
    prompt_version = triage.PROMPT_VERSION
    with conn.transaction():
        flagged: FlaggedRelease | None = queries.claim_next_flagged_release(
            conn, model, prompt_version
        )
        if flagged is None:
            return False
        release = flagged.release

        try:
            context: AnalysisContext = build_analysis_context(conn, release)
            findings: list[Finding] = queries.load_findings(conn, release.id)
            result: TriageResult = triage.triage_release(context, findings, model) #send in the context of the package + all the findings for it
        except (PyPIUnavailable, triage.LLMUnavailable):
            raise  # not this release's fault: roll back, run_forever waits and retries
        except psycopg.Error:
            raise  # database problems stop the triager, like everywhere else
        except triage.BadAnswer as exc:
            print(f"Bad LLM answer for {release.name} {release.version}: {exc}")
            queries.store_triage_failure(conn, release.id, model, prompt_version, str(exc))
            return True
        except triage.TriageError:
            raise  # no API key, bad key, unknown model: stop
        except Exception as exc:  # the release can't be rebuilt, or a bug
            print(f"Triage failed for {release.name} {release.version}: {exc!r}")
            queries.store_triage_failure(conn, release.id, model, prompt_version, repr(exc))
            return True

        final_verdict: Verdict = scoring.final_verdict(
            flagged.rules_verdict, result.verdict, result.confidence
        )
        queries.store_triage_result(conn, release.id, result)
        queries.record_llm_verdict(conn, release.id, result.verdict, final_verdict)
        print(
            f"{release.name} {release.version}: rules say {flagged.rules_verdict},"
            f" LLM says {result.verdict} ({result.confidence:.2f}) -> {final_verdict}."
            f" {result.reasoning}"
        )
    return True


def main() -> None:
    load_dotenv()
    if not os.environ.get("GEMINI_API_KEY"):
        print("GEMINI_API_KEY is not set (add it to .env).")
        return
    model = triage.configured_model()
    print(f"Using {model}, prompt {triage.PROMPT_VERSION}.")
    try:
        run_forever(
            "Triager",
            lambda conn: triage_next_flagged_release(conn, model),
            sleep_after_work=CALL_INTERVAL_SECONDS,
            sleep_when_idle=IDLE_SLEEP_SECONDS,
            retry_later_on=(PyPIUnavailable, triage.LLMUnavailable),
            sleep_before_retry=BACKOFF_SECONDS,
        )
    except triage.TriageError as exc:
        print(f"Triager stopped: {exc}")


if __name__ == "__main__":
    main()
