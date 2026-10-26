"""Get the LLM's second opinion on flagged releases, forever, one at a time.

Run with: python -m crotalus.triager   (needs GEMINI_API_KEY in .env)

Works like the worker (see worker.py), but only on releases the worker finished
with a 'suspicious' or 'likely_malicious' verdict and that have no triage yet from
this model and prompt version. Each one is claimed and triaged inside one
transaction, holding a row lock on the release:

- The release's code is downloaded again and its findings loaded, then both go
  to the LLM (see triage.py). The answer is stored as a 'done' triage row.
- A bad answer from the LLM, or a release that can't be rebuilt (e.g. deleted from
  PyPI, which malware often is), is stored as a 'failed' row, so it isn't retried
  forever. Delete the row to retry.
- Gemini or PyPI being unreachable or over a rate limit isn't the release's fault:
  it rolls back, stays untriaged, and the triager waits before trying again.

The rules' verdict on the release is never changed here.

It runs separately from the worker so that a slow, rate-limited LLM never holds up
analysis, and so a new prompt can be tried on old releases without re-analyzing them.
"""

from __future__ import annotations

import os
import time

import psycopg
from psycopg.rows import TupleRow

from crotalus import triage
from crotalus.db import connect
from crotalus.models import Finding, Release, TriageResult
from crotalus.pypi import PyPIUnavailable
from crotalus.worker import build_context

IDLE_SLEEP_SECONDS = 30  # flagged releases are rare
# Between LLM calls, to stay under the free tier's requests-per-minute limit.
CALL_INTERVAL_SECONDS = 6
BACKOFF_SECONDS = 60  # when Gemini or PyPI is unavailable or rate-limiting us


def claim_flagged_release(conn: psycopg.Connection[TupleRow], model: str) -> Release | None:
    """Lock the oldest flagged release not yet triaged by `model` with this prompt.

    Must run inside a transaction: the lock is held until it ends.
    """
    row = conn.execute(
        """
        SELECT r.id, p.name, r.version
        FROM releases r JOIN packages p ON p.id = r.package_id
        WHERE r.status = 'done'
          AND r.verdict IN ('suspicious', 'likely_malicious')
          AND NOT EXISTS (
              SELECT 1 FROM triage t
              WHERE t.release_id = r.id AND t.model = %s AND t.prompt_version = %s
          )
        ORDER BY r.first_seen_at, r.id
        LIMIT 1
        FOR UPDATE OF r SKIP LOCKED
        """,
        (model, triage.PROMPT_VERSION),
    ).fetchone()
    if row is None:
        return None
    return Release(id=row[0], name=row[1], version=row[2])


def load_findings(conn: psycopg.Connection[TupleRow], release_id: int) -> list[Finding]:
    """The findings the worker stored for a release."""
    rows = conn.execute(
        "SELECT rule_id, severity, message, evidence FROM findings"
        " WHERE release_id = %s ORDER BY id",
        (release_id,),
    ).fetchall()
    # evidence is jsonb, which psycopg returns as a dict.
    return [
        Finding(rule_id=rule_id, severity=severity, message=message, evidence=evidence)
        for rule_id, severity, message, evidence in rows
    ]


def store_done(
    conn: psycopg.Connection[TupleRow], release_id: int, result: TriageResult
) -> None:
    conn.execute(
        "INSERT INTO triage (release_id, model, prompt_version, status, verdict,"
        " confidence, reasoning, false_positive_rules)"
        " VALUES (%s, %s, %s, 'done', %s, %s, %s, %s)",
        (
            release_id,
            result.model,
            result.prompt_version,
            result.verdict,
            result.confidence,
            result.reasoning,
            list(result.false_positive_rules),  # a list becomes a Postgres text[]
        ),
    )


def store_failed(
    conn: psycopg.Connection[TupleRow], release_id: int, model: str, error: str
) -> None:
    conn.execute(
        "INSERT INTO triage (release_id, model, prompt_version, status, error)"
        " VALUES (%s, %s, %s, 'failed', %s)",
        (release_id, model, triage.PROMPT_VERSION, error),
    )


def triage_one(conn: psycopg.Connection[TupleRow], model: str) -> bool:
    """Claim, triage and store one flagged release. Returns False if none is waiting."""
    with conn.transaction():
        release = claim_flagged_release(conn, model)
        if release is None:
            return False

        try:
            context = build_context(conn, release)
            findings = load_findings(conn, release.id)
            result = triage.triage(context, findings, model) #do triage check
        except (PyPIUnavailable, triage.LLMUnavailable):
            raise  # not this release's fault: roll back, main() waits and retries
        except psycopg.Error:
            raise  # database problems stop the triager, like everywhere else
        except triage.BadAnswer as exc:
            print(f"Bad LLM answer for {release.name} {release.version}: {exc}")
            store_failed(conn, release.id, model, str(exc))
        except triage.TriageError:
            raise  # no API key, bad key, unknown model: every release would fail
        except Exception as exc:  # this release can't be rebuilt, or a bug
            print(f"Triage failed for {release.name} {release.version}: {exc!r}")
            store_failed(conn, release.id, model, repr(exc))
        else:
            store_done(conn, release.id, result)
            print(
                f"{release.name} {release.version}: LLM says {result.verdict}"
                f" ({result.confidence:.2f}): {result.reasoning}"
            )
    return True


def main() -> None:
    print("Triager started. Ctrl+C to stop.")
    try:
        with connect() as conn:  # connect() also loads .env
            if not os.environ.get("GEMINI_API_KEY"):
                print("GEMINI_API_KEY is not set (add it to .env).")
                return
            model = triage.model_name()
            print(f"Using {model}, prompt {triage.PROMPT_VERSION}.")
            conn.autocommit = True  # each triage_one() is its own transaction
            while True:
                try:
                    if triage_one(conn, model):
                        time.sleep(CALL_INTERVAL_SECONDS)
                    else:
                        time.sleep(IDLE_SLEEP_SECONDS)
                except (PyPIUnavailable, triage.LLMUnavailable) as exc:
                    print(f"Unavailable ({exc}); retrying in {BACKOFF_SECONDS}s")
                    time.sleep(BACKOFF_SECONDS)
    except triage.TriageError as exc:
        print(f"Stopping: {exc}")
    except KeyboardInterrupt:
        # Ctrl+C mid-triage rolls back, so that release is simply untriaged again.
        print("Stopped.")


if __name__ == "__main__":
    main()
