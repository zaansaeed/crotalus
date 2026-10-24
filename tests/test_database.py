from datetime import datetime, timezone

import psycopg
import pytest
from psycopg.rows import TupleRow

from crotalus.database import migration_runner

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
    assert migration_runner.get_applied(db) == {p.stem for p in migration_runner.find_migrations()}


def test_rerunning_migrations_applies_nothing(db: Conn, capsys: pytest.CaptureFixture[str]) -> None:
    migration_runner.main()
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

