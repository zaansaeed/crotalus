"""Poll PyPI's RSS feed forever and store new releases.
Fetches the feed's entries, stores the new ones as 'pending' releases for the worker,
and repeats this every 60s. Each poll is recorded in ingest_runs.

Run with: python -m crotalus.poller

Feed problems (PyPI down, malformed XML) skip that poll and try again next time.
Database errors are not caught: the poller stops so the problem gets looked at.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import psycopg
from psycopg.rows import TupleRow

from crotalus.db import connect
from crotalus.models import FeedEntry
from crotalus.pypi import RSS_URL, PyPIError, fetch_feed

POLL_INTERVAL_SECONDS = 60


def store_entries(conn: psycopg.Connection[TupleRow], entries: list[FeedEntry]) -> int:
    """Insert entries, skipping releases already stored. Returns how many releases were new.

    Runs in one transaction: either every entry is stored or none are.
    """
    new_releases = 0
    with conn.transaction():
        for entry in entries:
            conn.execute(
                "INSERT INTO packages (name) VALUES (%s) ON CONFLICT (name) DO NOTHING",
                (entry.name,),
            )
            # Look up package_id in the same statement: RETURNING on the package insert
            # gives nothing when the package already existed.
            cur = conn.execute(
                """
                INSERT INTO releases (package_id, version, published_at, source)
                SELECT id, %s, %s, %s FROM packages WHERE name = %s
                ON CONFLICT (package_id, version) DO NOTHING
                RETURNING id
                """,
                (entry.version, entry.published_at, entry.source, entry.name),
            )
            # One row back if inserted, none if it was already there.
            if cur.fetchone() is not None:
                new_releases += 1
    return new_releases


def poll_once() -> None:
    """Run one poll: fetch entries, store new releases, record the run in ingest_runs."""
    started_at = datetime.now(timezone.utc)

    try:
        entries = fetch_feed()
    except PyPIError as exc:
        # Skip this poll, but record why.
        with connect() as conn:
            conn.execute(
                "INSERT INTO ingest_runs (started_at, error) VALUES (%s, %s)",
                (started_at, str(exc)),
            )
        print(f"{time.strftime('%H:%M:%S')}  skipped: {exc}")
        return

    # A fresh connection each poll. The releases and the run record commit together
    # when the `with` ends, so the counts always match what was stored.
    with connect() as conn:
        new = store_entries(conn, entries)
        conn.execute(
            "INSERT INTO ingest_runs (started_at, entries, new_releases) VALUES (%s, %s, %s)",
            (started_at, len(entries), new),
        )

    print(f"{time.strftime('%H:%M:%S')}  {len(entries)} entries, {new} new")


def main() -> None:
    print(f"Polling {RSS_URL} every {POLL_INTERVAL_SECONDS}s. Ctrl+C to stop.")
    try:
        while True:
            poll_once()
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    main()
