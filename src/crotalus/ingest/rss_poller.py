"""Poll PyPI's RSS feed forever and store new releases. Uses functions from rss_inegstor (fetch_entries).
Fetches these entries, stories them, and repeats this every 60s.

Run with: python -m crotalus.ingest.rss_poller

Feed problems (PyPI down, malformed XML) skip that poll and try again next time.
Database errors are not caught: the poller stops so the problem gets looked at.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from crotalus.database.connect_db import connect
from crotalus.ingest.ingest_storer import store_entries
from crotalus.ingest.rss_ingestor import RSS_URL, FeedError, fetch_entries

POLL_INTERVAL_SECONDS = 60


def poll_once() -> None:
    """Run one poll: fetch entries, store new releases, record the run in ingest_runs."""
    started_at = datetime.now(timezone.utc)

    try:
        entries = fetch_entries()
    except FeedError as exc:
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
