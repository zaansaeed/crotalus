"""Analyze pending releases forever, one at a time.

Run with: python -m crotalus.analyze.worker

Each release is claimed and analyzed inside one transaction, which holds a row lock
on it the whole time:
- Another worker skips locked rows (SKIP LOCKED), so no release is analyzed twice.
- If the worker dies mid-analysis, Postgres rolls back and the release goes back to
  'pending' for the next worker. Database changes only are rolled back.
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

from crotalus.models import AnalysisContext, Finding, PackageInfo, Release
from crotalus.analyze.rules import RULES
from crotalus.database.connect_db import connect
from crotalus.pypi.client import PyPIUnavailable, fetch_first_upload, fetch_metadata

IDLE_SLEEP_SECONDS = 5
PYPI_BACKOFF_SECONDS = 30


def claim_release(conn: psycopg.Connection[TupleRow]) -> Release | None:
    """Lock the oldest pending release and return it, or None if there is none.

    Must run inside a transaction: the lock is held until it ends.
    """
    # FOR UPDATE OF r: lock only the releases row, not the joined packages row. We will update this (the status)
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
    ).fetchone() #only the one row, if it does exist
    if row is None:
        return None
    return Release(id=row[0], name=row[1], version=row[2])


def get_package_info(conn: psycopg.Connection[TupleRow], name: str) -> PackageInfo:
    """The package's history, from the database if we have it, else from PyPI (once)."""
    row = conn.execute(
        "SELECT first_uploaded_at FROM packages WHERE name = %s", (name,)
    ).fetchone()
    first_uploaded_at = row[0] if row else None

    if first_uploaded_at is None:
        # Not looked up yet. The project JSON can be large, so this happens once per package.
        first_uploaded_at = fetch_first_upload(name)
        conn.execute(
            "UPDATE packages SET first_uploaded_at = %s WHERE name = %s",
            (first_uploaded_at, name),
        )
    return PackageInfo(first_uploaded_at=first_uploaded_at)


def build_context(conn: psycopg.Connection[TupleRow], release: Release) -> AnalysisContext:
    """Gather everything the rules look at: PyPI metadata, with release name and version, plus package history 
    (the time this package was created)."""
    # The release first: if it's gone from PyPI, don't bother with the package history.
    metadata = fetch_metadata(release.name, release.version)
    package = get_package_info(conn, release.name)
    return AnalysisContext(release=release, metadata=metadata, package=package)


def analyze(context: AnalysisContext) -> list[Finding]:
    """Run every detection rule on a release."""
    return [finding for rule in RULES for finding in rule(context)]


def store_findings(
    conn: psycopg.Connection[TupleRow], release_id: int, findings: list[Finding]
) -> None:
    """Replace a release's findings with `findings`.
        Findings is a list of Finding classes, where each Finding is a rule that this release has broken.
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


def set_status(conn: psycopg.Connection[TupleRow], release_id: int, status: str) -> None:
    conn.execute("UPDATE releases SET status = %s WHERE id = %s", (status, release_id))


def process_one(conn: psycopg.Connection[TupleRow]) -> bool:
    """Claim, analyze and finish one release. Returns False if nothing was pending."""
    with conn.transaction():
        release = claim_release(conn)
        if release is None:
            return False

        try:
            findings = analyze(build_context(conn, release))
        except PyPIUnavailable:
            # Not this release's fault. Roll back so it stays pending; main() waits and retries.
            raise
        except psycopg.Error:
            raise  # database problems stop the worker, like everywhere else
        except Exception as exc:  # problems with this release or a bug in a rule
            print(f"Analysis failed for {release.name} {release.version}: {exc!r}")
            set_status(conn, release.id, "failed")
        else:
            store_findings(conn, release.id, findings)
            set_status(conn, release.id, "done")
            print(f"{release.name} {release.version}: {len(findings)} findings")
    return True


def main() -> None:
    print("Worker started. Ctrl+C to stop.")
    try:
        # One connection for the worker's lifetime: it loops much faster than the poller.
        with connect() as conn:
            conn.autocommit = True # each transaction within this one connection is its own transaction, not apart of one larger one.
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
