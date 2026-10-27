"""Poll PyPI's RSS feed forever and store new releases for the worker.

Run with: python -m crotalus.poller

Every 15s: fetch the feed (the latest ~100 uploads), store the releases not seen
before as 'pending', and record the poll in ingest_runs.

Most of a release's time to a verdict is waiting for the next poll, so the interval
sets how fast crotalus is. PyPI's feed changes every 10-20s, and 100 entries cover
several minutes of uploads, so polling faster than this would add load, not speed.

Feed problems (PyPI down, malformed XML) skip that poll, recorded with the reason,
and the next poll tries again. Database errors stop the poller.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

from crotalus import queries
from crotalus.db import Connection
from crotalus.loop import run_forever
from crotalus.models import FeedEntry
from crotalus.pypi import RSS_URL, PyPIError, fetch_feed

POLL_INTERVAL_SECONDS = 15


def poll_once(conn: Connection) -> bool:
    """Fetch the feed and store its new releases. Always True: a poll always happens."""
    started_at = datetime.now(UTC)
    try:
        entries: list[FeedEntry] = fetch_feed()
    except PyPIError as exc:
        queries.record_failed_poll(conn, started_at, str(exc))
        print(f"{time.strftime('%H:%M:%S')}  skipped: {exc}")
        return True

    # One transaction, so the poll's record always matches what was stored.
    with conn.transaction():
        new_releases = queries.store_new_releases(conn, entries)
        queries.record_poll(conn, started_at, len(entries), new_releases)
    print(f"{time.strftime('%H:%M:%S')}  {len(entries)} entries, {new_releases} new")
    return True


def main() -> None:
    print(f"Polling {RSS_URL} every {POLL_INTERVAL_SECONDS}s.")
    run_forever(
        "Poller",
        poll_once,
        sleep_after_work=POLL_INTERVAL_SECONDS,
        sleep_when_idle=POLL_INTERVAL_SECONDS,
    )


if __name__ == "__main__":
    main()
