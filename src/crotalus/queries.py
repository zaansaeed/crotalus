"""Every SQL query crotalus runs, grouped by the stage that runs it.

    poller   store_new_releases, record_poll, record_failed_poll
    worker   claim_next_pending_release, cached_first_upload, cache_first_upload,
             replace_findings, delete_triage, mark_analyzed, mark_failed
    triager  claim_next_flagged_release, load_findings, store_triage_result,
             store_triage_failure, record_llm_verdict

None of these commit or open a transaction: the caller decides what has to succeed
or fail together (see poller.poll_once, worker.analyze_next_release and
triager.triage_next_flagged_release).

The claim_* queries lock the row they return with FOR UPDATE ... SKIP LOCKED: the
lock lasts until the caller's transaction ends, and other workers skip locked rows
instead of waiting, so no release is handled twice at once. That's what lets
Postgres act as the job queue.
"""

from __future__ import annotations

from datetime import datetime

from psycopg.types.json import Jsonb

from crotalus.db import Connection
from crotalus.models import (
    FeedEntry,
    Finding,
    FlaggedRelease,
    LLMVerdict,
    Release,
    TriageResult,
    Verdict,
)

# --- Poller ------------------------------------------------------------------------


def store_new_releases(conn: Connection, entries: list[FeedEntry]) -> int:
    """Insert the feed's releases as 'pending', skipping ones already stored.

    Returns how many were new.
    """
    new_releases = 0
    for entry in entries:
        conn.execute(
            "INSERT INTO packages (name) VALUES (%s) ON CONFLICT (name) DO NOTHING",
            (entry.name,),
        )
        # Look up package_id in the same statement: RETURNING on the package insert
        # gives nothing when the package already existed.
        inserted = conn.execute(
            """
            INSERT INTO releases (package_id, version, published_at, source)
            SELECT id, %s, %s, %s FROM packages WHERE name = %s
            ON CONFLICT (package_id, version) DO NOTHING
            RETURNING id
            """,
            (entry.version, entry.published_at, entry.source, entry.name),
        ).fetchone()  # a row if inserted, None if it was already there
        if inserted is not None:
            new_releases += 1
    return new_releases


def record_poll(conn: Connection, started_at: datetime, entries: int, new_releases: int) -> None:
    conn.execute(
        "INSERT INTO ingest_runs (started_at, entries, new_releases) VALUES (%s, %s, %s)",
        (started_at, entries, new_releases),
    )


def record_failed_poll(conn: Connection, started_at: datetime, error: str) -> None:
    conn.execute(
        "INSERT INTO ingest_runs (started_at, error) VALUES (%s, %s)", (started_at, error)
    )


# --- Worker ------------------------------------------------------------------------


def claim_next_pending_release(conn: Connection) -> Release | None:
    """Lock the oldest release waiting for analysis, or None if there isn't one."""
    # FOR UPDATE OF r: lock only the releases row, not the joined packages row.
    row = conn.execute(
        """
        SELECT r.id, p.name, r.version
        FROM releases r JOIN packages p ON p.id = r.package_id
        WHERE r.status = 'pending'
        ORDER BY r.first_seen_at, r.id
        LIMIT 1
        FOR UPDATE OF r SKIP LOCKED
        """
    ).fetchone()
    if row is None:
        return None
    return Release(id=row[0], name=row[1], version=row[2])


def cached_first_upload(conn: Connection, package_name: str) -> datetime | None:
    """When the package first appeared on PyPI, if we've looked it up before."""
    row = conn.execute(
        "SELECT first_uploaded_at FROM packages WHERE name = %s", (package_name,)
    ).fetchone()
    return row[0] if row else None


def cache_first_upload(conn: Connection, package_name: str, first_uploaded_at: datetime) -> None:
    conn.execute(
        "UPDATE packages SET first_uploaded_at = %s WHERE name = %s",
        (first_uploaded_at, package_name),
    )


def replace_findings(conn: Connection, release_id: int, findings: list[Finding]) -> None:
    """Delete the release's old findings (from an earlier analysis) and store these."""
    conn.execute("DELETE FROM findings WHERE release_id = %s", (release_id,))
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO findings (release_id, rule_id, severity, message, evidence)"
            " VALUES (%s, %s, %s, %s, %s)",
            [
                (release_id, finding.rule_id, finding.severity, finding.message,
                 Jsonb(finding.evidence))  # Jsonb: the dict is stored as jsonb
                for finding in findings
            ],
        )


def delete_triage(conn: Connection, release_id: int) -> None:
    """Forget the LLM's opinions of a release, e.g. because its findings changed."""
    conn.execute("DELETE FROM triage WHERE release_id = %s", (release_id,))


def mark_analyzed(conn: Connection, release_id: int, score: int, rules_verdict: Verdict) -> None:
    """'done', with the rules' score and verdict. No LLM verdict yet, so the final
    verdict starts out as the rules' verdict; the triager may change both later."""
    conn.execute(
        "UPDATE releases SET status = 'done', score = %s, rules_verdict = %s,"
        " llm_verdict = NULL, final_verdict = %s WHERE id = %s",
        (score, rules_verdict, rules_verdict, release_id),
    )


def mark_failed(conn: Connection, release_id: int) -> None:
    """'failed', so it isn't retried forever. Any verdict from an earlier analysis is
    cleared: only 'done' releases may have one (releases_verdicts_iff_done)."""
    conn.execute(
        "UPDATE releases SET status = 'failed', score = NULL, rules_verdict = NULL,"
        " llm_verdict = NULL, final_verdict = NULL WHERE id = %s",
        (release_id,),
    )


# --- Triager -----------------------------------------------------------------------


def claim_next_flagged_release(
    conn: Connection, model: str, prompt_version: str
) -> FlaggedRelease | None:
    """Lock the oldest flagged release this model and prompt haven't triaged yet.

    "Not triaged yet" is checked against the triage table, not `llm_verdict IS NULL`:
    - A failed triage (a bad answer, or the release is gone from PyPI) leaves
      llm_verdict NULL. Its 'failed' triage row is what stops the triager from
      claiming it again forever, spending its rate limit on the same failure.
    - It's per model and prompt version: bumping triage.PROMPT_VERSION, or switching
      model, makes every flagged release eligible again, so the new prompt or model
      can be compared with the old one on the same releases.
    llm_verdict is for reading the current opinion; this check is for picking work.
    """
    row = conn.execute(
        """
        SELECT r.id, p.name, r.version, r.rules_verdict
        FROM releases r JOIN packages p ON p.id = r.package_id
        WHERE r.status = 'done'
          AND r.rules_verdict IN ('suspicious', 'likely_malicious')
          AND NOT EXISTS (
              SELECT 1 FROM triage t
              WHERE t.release_id = r.id AND t.model = %s AND t.prompt_version = %s
          )
        ORDER BY r.first_seen_at, r.id
        LIMIT 1
        FOR UPDATE OF r SKIP LOCKED
        """,
        (model, prompt_version),
    ).fetchone()
    if row is None:
        return None
    return FlaggedRelease(
        release=Release(id=row[0], name=row[1], version=row[2]), rules_verdict=row[3]
    )


def load_findings(conn: Connection, release_id: int) -> list[Finding]:
    """The findings the worker stored for a release, in the order it stored them."""
    rows = conn.execute(
        "SELECT rule_id, severity, message, evidence FROM findings"
        " WHERE release_id = %s ORDER BY id",
        (release_id,),
    ).fetchall()
    # evidence is jsonb, which psycopg turns back into a dict.
    return [
        Finding(rule_id=rule_id, severity=severity, message=message, evidence=evidence)
        for rule_id, severity, message, evidence in rows
    ]


def store_triage_result(conn: Connection, release_id: int, result: TriageResult) -> None:
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


def store_triage_failure(
    conn: Connection, release_id: int, model: str, prompt_version: str, error: str
) -> None:
    """A 'failed' triage row, so the triager doesn't retry it. Delete the row to retry."""
    conn.execute(
        "INSERT INTO triage (release_id, model, prompt_version, status, error)"
        " VALUES (%s, %s, %s, 'failed', %s)",
        (release_id, model, prompt_version, error),
    )


def record_llm_verdict(
    conn: Connection, release_id: int, llm_verdict: LLMVerdict, final_verdict: Verdict
) -> None:
    """The LLM's verdict, and the final verdict it led to (see scoring.final_verdict)."""
    conn.execute(
        "UPDATE releases SET llm_verdict = %s, final_verdict = %s WHERE id = %s",
        (llm_verdict, final_verdict, release_id),
    )
