"""Poll PyPI's RSS feed forever and store new releases. Uses functions from rss_inegstor (fetch_entries).
Fetches these entries, stories them, and repeats this every 60s.

Run with: python -m crotalus.ingest.rss_poller

Feed problems (PyPI down, malformed XML) skip that poll and try again next time.
Database errors are not caught: the poller stops so the problem gets looked at.
"""

from __future__ import annotations

import time

from crotalus.database.connect_db import connect
from crotalus.ingest.ingest_storer import store_entries
from crotalus.ingest.rss_ingestor import RSS_URL, fetch_entries

POLL_INTERVAL_SECONDS = 60


def poll_once() -> None:
    """Run one poll: fetch entries, store new releases, report."""
    entries = fetch_entries()
    if entries is None:
        print("Skipping this poll.")
        return

    # A fresh connection each poll
    with connect() as conn:
        new = store_entries(conn, entries)

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
