from datetime import UTC, datetime

import psycopg
import pytest

from crotalus import poller
from crotalus.db import Connection
from crotalus.models import FeedEntry
from crotalus.pypi import PyPIError
from crotalus.queries import store_new_releases

WHEN = datetime(2026, 10, 17, 4, 33, 56, tzinfo=UTC)
ENTRIES = [
    FeedEntry(name="requests", version="2.31.0", published_at=WHEN, source="rss"),
    FeedEntry(name="requests", version="2.32.0", published_at=WHEN, source="rss"),
    FeedEntry(name="numpy", version="2.1.0", published_at=WHEN, source="rss"),
]


def count(db: Connection, table: str) -> int:
    row = db.execute(f"SELECT count(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])


def runs(db: Connection) -> list[tuple[object, ...]]:
    return db.execute("SELECT entries, new_releases, error FROM ingest_runs ORDER BY id").fetchall()


# store_new_releases


def test_stores_new_entries(db: Connection) -> None:
    assert store_new_releases(db, ENTRIES) == 3
    assert count(db, "releases") == 3


def test_same_package_stored_once(db: Connection) -> None:
    store_new_releases(db, ENTRIES)
    assert count(db, "packages") == 2


def test_storing_again_adds_nothing(db: Connection) -> None:
    store_new_releases(db, ENTRIES)
    assert store_new_releases(db, ENTRIES) == 0
    assert count(db, "releases") == 3


def test_stores_fields(db: Connection) -> None:
    store_new_releases(db, ENTRIES[:1])
    row = db.execute(
        "SELECT p.name, r.version, r.published_at, r.source, r.status"
        " FROM releases r JOIN packages p ON p.id = r.package_id"
    ).fetchone()
    assert row == ("requests", "2.31.0", WHEN, "rss", "pending")


# poll_once


def test_successful_poll_records_run(db: Connection, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(poller, "fetch_feed", lambda: ENTRIES)
    assert poller.poll_once(db) is True
    poller.poll_once(db)
    # Second poll sees the same three entries, none new.
    assert runs(db) == [(3, 3, None), (3, 0, None)]


def test_skipped_poll_records_error(db: Connection, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> list[FeedEntry]:
        raise PyPIError("malformed feed: mismatched tag")

    monkeypatch.setattr(poller, "fetch_feed", broken)
    poller.poll_once(db)
    assert runs(db) == [(None, None, "malformed feed: mismatched tag")]


def test_bad_entry_stores_nothing(db: Connection, monkeypatch: pytest.MonkeyPatch) -> None:
    bad = FeedEntry(name="Foo_Bar", version="1.0", published_at=WHEN, source="rss")
    monkeypatch.setattr(poller, "fetch_feed", lambda: [ENTRIES[0], bad])
    with pytest.raises(psycopg.errors.CheckViolation):
        poller.poll_once(db)
    # One transaction: the valid entry before the bad one, and the run, rolled back too.
    assert count(db, "releases") == 0
    assert runs(db) == []
