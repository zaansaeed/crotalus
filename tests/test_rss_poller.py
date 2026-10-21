from datetime import datetime, timezone

import psycopg
import pytest
from psycopg.rows import TupleRow

from crotalus.ingest import rss_poller
from crotalus.ingest.rss_ingestor import FeedEntry, FeedError

Conn = psycopg.Connection[TupleRow]

WHEN = datetime(2026, 10, 17, 4, 33, 56, tzinfo=timezone.utc)
ENTRIES = [
    FeedEntry(name="requests", version="2.31.0", published_at=WHEN, source="rss"),
    FeedEntry(name="numpy", version="2.1.0", published_at=WHEN, source="rss"),
]


def runs(db: Conn) -> list[tuple[object, ...]]:
    return db.execute("SELECT entries, new_releases, error FROM ingest_runs ORDER BY id").fetchall()


def test_successful_poll_records_run(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rss_poller, "fetch_entries", lambda: ENTRIES)
    rss_poller.poll_once()
    rss_poller.poll_once()
    # Second poll sees the same two entries, none new.
    assert runs(db) == [(2, 2, None), (2, 0, None)]


def test_skipped_poll_records_error(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> list[FeedEntry]:
        raise FeedError("malformed feed: mismatched tag")

    monkeypatch.setattr(rss_poller, "fetch_entries", broken)
    rss_poller.poll_once()
    assert runs(db) == [(None, None, "malformed feed: mismatched tag")]
