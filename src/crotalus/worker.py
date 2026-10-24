"""Analyze pending releases forever, one at a time.

Run with: python -m crotalus.worker

Each pending release is claimed and analyzed inside one transaction, which holds a row lock
on it the whole time:
- Another worker skips locked rows (SKIP LOCKED), so no release is analyzed twice.
- If the worker dies mid-analysis, Postgres rolls back and the release goes back to
  'pending' for the next worker. Database changes only are rolled back.
- Success stores the findings, a score and a verdict (see scoring.py) and marks it 'done'.
- If the analysis raises, the release is marked 'failed' so it isn't retried forever.
  Except when PyPI is unreachable: that isn't the release's fault, so it rolls back
  to 'pending' and the worker waits before trying again.

Because the claim is never committed on its own, other connections never see a
release in 'analyzing'. That status is unused for now.

Database errors are not caught: the worker stops so the problem gets looked at.
"""

from __future__ import annotations

import time

import psycopg
from psycopg.rows import TupleRow
from psycopg.types.json import Jsonb

from crotalus import scoring
from crotalus.db import connect
from crotalus.models import AnalysisContext, Finding, PackageInfo, Release
from crotalus.pypi import PyPIUnavailable, fetch_first_upload, fetch_metadata
from crotalus.rules import RULES

IDLE_SLEEP_SECONDS = 5
PYPI_BACKOFF_SECONDS = 30


def claim_release(conn: psycopg.Connection[TupleRow]) -> Release | None:
    """Lock the oldest pending release and return it, or None if there is none.

    Must run inside a transaction: the lock is held until it ends.
    """
    # FOR UPDATE OF r: lock only the releases row (we'll update its status),
    # not the joined packages row.
    # SKIP LOCKED: rows another worker holds are skipped instead of waited on.
    row = conn.execute(
        """
        SELECT r.id, p.name, r.version
        FROM releases r JOIN packages p ON p.id = r.package_id
        WHERE r.status = 'pending'
        ORDER BY r.first_seen_at, r.id
        LIMIT 1
        FOR UPDATE OF r SKIP LOCKED
        """
    ).fetchone()  # only the one row, if it does exist
    if row is None:
        return None
    return Release(id=row[0], name=row[1], version=row[2])


def build_context(conn: psycopg.Connection[TupleRow], release: Release) -> AnalysisContext:
    """Gather everything the rules look at: the release's PyPI metadata, plus package
    history (the time this package was created)."""
    # The release first: if it's gone from PyPI, don't bother with the package history.
    metadata = fetch_metadata(release.name, release.version)

    # Package history comes from the database if we have it. Otherwise it's fetched once
    # and stored: the project JSON can be large, so this happens once per package.
    row = conn.execute(
        "SELECT first_uploaded_at FROM packages WHERE name = %s", (release.name,)
    ).fetchone()
    first_uploaded_at = row[0] if row else None
    if first_uploaded_at is None:
        first_uploaded_at = fetch_first_upload(release.name)
        conn.execute(
            "UPDATE packages SET first_uploaded_at = %s WHERE name = %s",
            (first_uploaded_at, release.name),
        )

    return AnalysisContext(
        release=release,
        metadata=metadata,
        package=PackageInfo(first_uploaded_at=first_uploaded_at),
    )


def store_findings(
    conn: psycopg.Connection[TupleRow], release_id: int, findings: list[Finding]
) -> None:
    """Replace a release's findings with `findings`.
    Findings is a list of Finding classes, where each Finding is a rule that this release
    has broken.
    """
    # Delete first so re-analyzing a release doesn't duplicate its findings.
    conn.execute("DELETE FROM findings WHERE release_id = %s", (release_id,))
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO findings (release_id, rule_id, severity, message, evidence)"
            " VALUES (%s, %s, %s, %s, %s)",
            [
                (release_id, f.rule_id, f.severity, f.message, Jsonb(f.evidence))
                for f in findings
            ],
        )


def process_one(conn: psycopg.Connection[TupleRow]) -> bool:
    """Claim, analyze and finish one release. Returns False if nothing was pending.
    Sets that release's status to done if successful, otherwise, it failed."""
    with conn.transaction():
        release = claim_release(conn)
        if release is None:
            return False

        try:
            context = build_context(conn, release)
            findings = [finding for rule in RULES for finding in rule(context)]
        except PyPIUnavailable:
            # Not this release's fault. Roll back so it stays pending; main() waits and retries.
            raise
        except psycopg.Error:
            raise  # database problems stop the worker, like everywhere else
        except Exception as exc:  # problems with this release or a bug in a rule
            print(f"Analysis failed for {release.name} {release.version}: {exc!r}")
            # Clear any verdict from an earlier analysis: only 'done' releases may have one.
            conn.execute(
                "UPDATE releases SET status = 'failed', score = NULL, verdict = NULL"
                " WHERE id = %s",
                (release.id,),
            )
        else:  # everything is good in this branch. We can give a verdict, given the findings
            score = scoring.score(findings)
            verdict = scoring.verdict(findings)
            store_findings(conn, release.id, findings)
            conn.execute(
                "UPDATE releases SET status = 'done', score = %s, verdict = %s WHERE id = %s",
                (score, verdict, release.id),
            )
            print(f"{release.name} {release.version}: {verdict} (score {score})")
    return True


def main() -> None:
    print("Worker started. Ctrl+C to stop.")
    try:
        # One connection for the worker's lifetime: it loops much faster than the poller.
        with connect() as conn:
            # each transaction within this one connection is its own transaction,
            # not a part of one larger one.
            conn.autocommit = True
            while True:
                try:
                    if not process_one(conn):
                        time.sleep(IDLE_SLEEP_SECONDS)
                except PyPIUnavailable as exc:
                    # Marking releases failed while PyPI is down would fail the whole queue.
                    print(f"PyPI unavailable ({exc}); retrying in {PYPI_BACKOFF_SECONDS}s")
                    time.sleep(PYPI_BACKOFF_SECONDS)
    except KeyboardInterrupt:
        # Ctrl+C mid-analysis rolls back, so that release is simply pending again.
        print("Stopped.")


if __name__ == "__main__":
    main()
