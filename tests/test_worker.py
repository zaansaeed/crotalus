from datetime import datetime, timezone

import psycopg
import pytest
from psycopg.rows import TupleRow

from crotalus.analyze import worker
from crotalus.analyze.models import Finding, Release
from crotalus.analyze.worker import claim_release, process_one
from crotalus.database.connect_db import connect
from crotalus.ingest.ingest_storer import store_entries
from crotalus.ingest.rss_ingestor import FeedEntry

Conn = psycopg.Connection[TupleRow]

WHEN = datetime(2026, 10, 17, 4, 33, 56, tzinfo=timezone.utc)
FINDING = Finding(
    rule_id="typosquat",
    severity="high",
    message="name is 1 edit away from 'requests'",
    evidence={"similar_to": "requests", "distance": 1},
)


@pytest.fixture(autouse=True)
def no_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the worker's plumbing, not the real rules (they have their own tests)."""
    monkeypatch.setattr(worker, "RULES", [])


def add_release(db: Conn, name: str, version: str = "1.0") -> None:
    # Its own transaction, so each release gets a later first_seen_at than the last.
    store_entries(db, [FeedEntry(name=name, version=version, published_at=WHEN, source="rss")])


def status_of(db: Conn, name: str) -> str:
    row = db.execute(
        "SELECT r.status FROM releases r JOIN packages p ON p.id = r.package_id"
        " WHERE p.name = %s",
        (name,),
    ).fetchone()
    assert row is not None
    return str(row[0])


def test_nothing_pending_returns_false(db: Conn) -> None:
    assert process_one(db) is False


def test_marks_release_done(db: Conn) -> None:
    add_release(db, "requests")
    assert process_one(db) is True
    assert status_of(db, "requests") == "done"
    assert process_one(db) is False  # nothing left


def test_oldest_release_first(db: Conn) -> None:
    add_release(db, "older")
    add_release(db, "newer")
    with db.transaction():
        release = claim_release(db)
    assert release is not None
    assert release.name == "older"


def test_stores_findings(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "analyze", lambda release: [FINDING])
    add_release(db, "reqeusts")
    process_one(db)
    row = db.execute("SELECT rule_id, severity, message, evidence FROM findings").fetchone()
    assert row == (FINDING.rule_id, FINDING.severity, FINDING.message, FINDING.evidence)


def test_reanalysis_replaces_findings(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "analyze", lambda release: [FINDING])
    add_release(db, "reqeusts")
    process_one(db)
    db.execute("UPDATE releases SET status = 'pending'")
    process_one(db)
    row = db.execute("SELECT count(*) FROM findings").fetchone()
    assert row == (1,)


def test_analysis_error_marks_failed(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(release: Release) -> list[Finding]:
        raise ValueError("bad archive")

    monkeypatch.setattr(worker, "analyze", broken)
    add_release(db, "requests")
    assert process_one(db) is True
    assert status_of(db, "requests") == "failed"


def test_locked_release_is_skipped(db: Conn) -> None:
    add_release(db, "requests")
    with db.transaction():
        assert claim_release(db) is not None  # db now holds the lock
        # A second worker, on its own connection, must not get the same release.
        with connect() as other:
            assert claim_release(other) is None
    # Lock released without marking it done: still pending for the next worker.
    assert status_of(db, "requests") == "pending"
