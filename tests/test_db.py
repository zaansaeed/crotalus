from datetime import datetime, timezone

import psycopg
import pytest
from psycopg.rows import TupleRow

from crotalus.db import applied_migrations, migrate, migration_files

Conn = psycopg.Connection[TupleRow]

# db fixture in conftest


def add_package(db: Conn, name: str) -> int:
    row = db.execute("INSERT INTO packages (name) VALUES (%s) RETURNING id", (name,)).fetchone()
    assert row is not None
    return int(row[0])


def add_release(db: Conn, package_id: int, version: str) -> None:
    db.execute(
        "INSERT INTO releases (package_id, version, published_at, source)"
        " VALUES (%s, %s, %s, 'rss')",
        (package_id, version, datetime(2026, 10, 17, tzinfo=timezone.utc)),
    )


def test_connects_to_test_database(db: Conn) -> None:
    row = db.execute("SELECT current_database()").fetchone()
    assert row == ("crotalus_test",)


def test_migrations_applied(db: Conn) -> None:
    assert applied_migrations(db) == {p.stem for p in migration_files()}


def test_rerunning_migrations_applies_nothing(db: Conn, capsys: pytest.CaptureFixture[str]) -> None:
    migrate()
    assert "Applied migration" not in capsys.readouterr().out


def test_insert_package_and_release(db: Conn) -> None:
    add_release(db, add_package(db, "requests"), "2.31.0")
    row = db.execute("SELECT version, status FROM releases").fetchone()
    assert row == ("2.31.0", "pending")


def test_rejects_unnormalized_name(db: Conn) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        add_package(db, "Foo_Bar")


def test_rejects_duplicate_release(db: Conn) -> None:
    package_id = add_package(db, "requests")
    add_release(db, package_id, "2.31.0")
    with pytest.raises(psycopg.errors.UniqueViolation):
        add_release(db, package_id, "2.31.0")


def test_done_requires_verdict(db: Conn) -> None:
    add_release(db, add_package(db, "requests"), "2.31.0")
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute("UPDATE releases SET status = 'done'")


def test_verdict_requires_done(db: Conn) -> None:
    add_release(db, add_package(db, "requests"), "2.31.0")
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute("UPDATE releases SET score = 0, verdict = 'clean'")  # still pending


def test_rejects_unknown_verdict(db: Conn) -> None:
    add_release(db, add_package(db, "requests"), "2.31.0")
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute("UPDATE releases SET status = 'done', score = 0, verdict = 'probably_fine'")



def add_triage(db: Conn, status: str, verdict: str | None, error: str | None = None) -> None:
    add_release(db, add_package(db, "requests"), "2.31.0")
    db.execute(
        "INSERT INTO triage (release_id, model, prompt_version, status, verdict, confidence,"
        " reasoning, error) VALUES (1, 'm', 'v1', %s, %s, %s, %s, %s)",
        (status, verdict, 0.9 if verdict else None, "why" if verdict else None, error),
    )


def test_triage_done_and_failed(db: Conn) -> None:
    add_triage(db, "done", "benign")
    db.execute(
        "INSERT INTO triage (release_id, model, prompt_version, status, error)"
        " VALUES (1, 'm', 'v2', 'failed', 'answer is not JSON')"
    )
    rows = db.execute("SELECT prompt_version, status FROM triage ORDER BY id").fetchall()
    assert rows == [("v1", "done"), ("v2", "failed")]


@pytest.mark.parametrize(
    ("status", "verdict", "error"),
    [
        ("done", None, None),  # done without an answer
        ("failed", None, None),  # failed without an error
        ("done", "benign", "oops"),  # done with an error
        ("done", "safe", None),  # unknown verdict
    ],
)
def test_triage_rejects_inconsistent_rows(
    db: Conn, status: str, verdict: str | None, error: str | None
) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        add_triage(db, status, verdict, error)


def test_triage_once_per_model_and_prompt(db: Conn) -> None:
    add_triage(db, "done", "benign")
    with pytest.raises(psycopg.errors.UniqueViolation):
        db.execute(
            "INSERT INTO triage (release_id, model, prompt_version, status, verdict,"
            " confidence, reasoning) VALUES (1, 'm', 'v1', 'done', 'malicious', 1, 'x')"
        )
