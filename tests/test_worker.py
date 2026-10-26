from datetime import datetime, timezone

import psycopg
import pytest
from psycopg.rows import TupleRow

from crotalus import worker
from crotalus.db import connect
from crotalus.models import AnalysisContext, FeedEntry, Finding, ReleaseMetadata
from crotalus.poller import store_entries
from crotalus.pypi import PyPIUnavailable, ReleaseNotFound
from crotalus.worker import claim_release, process_one

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
    """Test the worker's plumbing, not the real rules or PyPI (they have their own tests)."""
    monkeypatch.setattr(worker, "RULES", [])
    def fetch_metadata(name: str, version: str) -> ReleaseMetadata:
        return ReleaseMetadata(name=name, version=version)

    monkeypatch.setattr(worker, "fetch_metadata", fetch_metadata)
    monkeypatch.setattr(worker, "fetch_first_upload", lambda name: WHEN)


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


def verdict_of(db: Conn, name: str) -> tuple[int | None, str | None]:
    row = db.execute(
        "SELECT r.score, r.verdict FROM releases r JOIN packages p ON p.id = r.package_id"
        " WHERE p.name = %s",
        (name,),
    ).fetchone()
    assert row is not None
    return row[0], row[1]


def test_nothing_pending_returns_false(db: Conn) -> None:
    assert process_one(db) is False


def test_marks_release_done(db: Conn) -> None:
    add_release(db, "requests")
    assert process_one(db) is True
    assert status_of(db, "requests") == "done"
    assert verdict_of(db, "requests") == (0, "clean")  # no rules, no findings
    assert process_one(db) is False  # nothing left


def test_oldest_release_first(db: Conn) -> None:
    add_release(db, "older")
    add_release(db, "newer")
    with db.transaction():
        release = claim_release(db)
    assert release is not None
    assert release.name == "older"


def test_stores_findings(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "RULES", [lambda context: [FINDING]])
    add_release(db, "reqeusts")
    process_one(db)
    row = db.execute("SELECT rule_id, severity, message, evidence FROM findings").fetchone()
    assert row == (FINDING.rule_id, FINDING.severity, FINDING.message, FINDING.evidence)
    assert verdict_of(db, "reqeusts") == (6, "suspicious")  # one high finding


def test_reanalysis_replaces_findings(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "RULES", [lambda context: [FINDING]])
    add_release(db, "reqeusts")
    process_one(db)
    # Re-queue it. A pending release can't keep its old verdict (releases_verdict_iff_done).
    db.execute("UPDATE releases SET status = 'pending', score = NULL, verdict = NULL")
    process_one(db)
    row = db.execute("SELECT count(*) FROM findings").fetchone()
    assert row == (1,)


def test_reanalysis_deletes_old_triage(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "RULES", [lambda context: [FINDING]])
    add_release(db, "reqeusts")
    process_one(db)
    db.execute(
        "INSERT INTO triage (release_id, model, prompt_version, status, verdict,"
        " confidence, reasoning) VALUES (1, 'm', 'v1', 'done', 'benign', 0.9, 'fine')"
    )
    db.execute("UPDATE releases SET status = 'pending', score = NULL, verdict = NULL")
    process_one(db)
    assert db.execute("SELECT count(*) FROM triage").fetchone() == (0,)


def test_analysis_error_marks_failed(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(context: AnalysisContext) -> list[Finding]:
        raise ValueError("bad archive")  # e.g. a bug in a rule

    monkeypatch.setattr(worker, "RULES", [broken])
    add_release(db, "requests")
    assert process_one(db) is True
    assert status_of(db, "requests") == "failed"
    assert verdict_of(db, "requests") == (None, None)


def test_failed_reanalysis_clears_verdict(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    add_release(db, "requests")
    process_one(db)
    assert verdict_of(db, "requests") == (0, "clean")

    def broken(context: AnalysisContext) -> list[Finding]:
        raise ValueError("bad archive")  # e.g. a bug in a rule

    monkeypatch.setattr(worker, "RULES", [broken])
    db.execute("UPDATE releases SET status = 'pending', score = NULL, verdict = NULL")
    process_one(db)
    assert status_of(db, "requests") == "failed"
    assert verdict_of(db, "requests") == (None, None)


def test_locked_release_is_skipped(db: Conn) -> None:
    add_release(db, "requests")
    with db.transaction():
        assert claim_release(db) is not None  # db now holds the lock
        # A second worker, on its own connection, must not get the same release.
        with connect() as other:
            assert claim_release(other) is None
    # Lock released without marking it done: still pending for the next worker.
    assert status_of(db, "requests") == "pending"


def test_release_not_on_pypi_marks_failed(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    def not_found(name: str, version: str) -> ReleaseMetadata:
        raise ReleaseNotFound(f"{name} is not on PyPI")

    monkeypatch.setattr(worker, "fetch_metadata", not_found)
    add_release(db, "requests")
    assert process_one(db) is True
    assert status_of(db, "requests") == "failed"
    assert verdict_of(db, "requests") == (None, None)


def test_pypi_down_leaves_release_pending(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(name: str, version: str) -> ReleaseMetadata:
        raise PyPIUnavailable("PyPI returned 503")

    monkeypatch.setattr(worker, "fetch_metadata", unavailable)
    add_release(db, "requests")
    with pytest.raises(PyPIUnavailable):
        process_one(db)
    assert status_of(db, "requests") == "pending"  # rolled back, will be retried


def test_package_history_fetched_once(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fetch_first_upload(name: str) -> datetime:
        calls.append(name)
        return WHEN

    monkeypatch.setattr(worker, "fetch_first_upload", fetch_first_upload)
    add_release(db, "requests", "1.0")
    add_release(db, "requests", "2.0")
    process_one(db)
    process_one(db)
    assert calls == ["requests"]  # the second release used the stored value
    row = db.execute("SELECT first_uploaded_at FROM packages WHERE name = 'requests'").fetchone()
    assert row == (WHEN,)


def test_rules_see_package_history(db: Conn, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[datetime | None] = []
    monkeypatch.setattr(
        worker, "RULES", [lambda context: seen.append(context.package.first_uploaded_at) or []]
    )
    add_release(db, "requests")
    process_one(db)
    assert seen == [WHEN]

