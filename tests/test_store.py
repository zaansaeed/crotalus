from datetime import datetime, timezone

import psycopg
import pytest
from psycopg.rows import TupleRow

from crotalus.ingest.ingest_storer import store_entries
from crotalus.ingest.rss_ingestor import FeedEntry

Conn = psycopg.Connection[TupleRow]

WHEN = datetime(2026, 10, 17, 4, 33, 56, tzinfo=timezone.utc)
ENTRIES = [
    FeedEntry(name="requests", version="2.31.0", published_at=WHEN, source="rss"),
    FeedEntry(name="requests", version="2.32.0", published_at=WHEN, source="rss"),
    FeedEntry(name="numpy", version="2.1.0", published_at=WHEN, source="rss"),
]


def count(db: Conn, table: str) -> int:
    row = db.execute(f"SELECT count(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])


def test_stores_new_entries(db: Conn) -> None:
    assert store_entries(db, ENTRIES) == 3
    assert count(db, "releases") == 3


def test_same_package_stored_once(db: Conn) -> None:
    store_entries(db, ENTRIES)
    assert count(db, "packages") == 2


def test_storing_again_adds_nothing(db: Conn) -> None:
    store_entries(db, ENTRIES)
    assert store_entries(db, ENTRIES) == 0
    assert count(db, "releases") == 3


def test_stores_fields(db: Conn) -> None:
    store_entries(db, ENTRIES[:1])
    row = db.execute(
        "SELECT p.name, r.version, r.published_at, r.source, r.status"
        " FROM releases r JOIN packages p ON p.id = r.package_id"
    ).fetchone()
    assert row == ("requests", "2.31.0", WHEN, "rss", "pending")


def test_bad_entry_stores_nothing(db: Conn) -> None:
    bad = FeedEntry(name="Foo_Bar", version="1.0", published_at=WHEN, source="rss")
    with pytest.raises(psycopg.errors.CheckViolation):
        store_entries(db, [ENTRIES[0], bad])
    # One transaction: the valid entry before the bad one was rolled back too.
    assert count(db, "releases") == 0
