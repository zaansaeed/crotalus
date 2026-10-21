from __future__ import annotations

from pathlib import Path

import psycopg
from psycopg.rows import TupleRow

from crotalus.database.connect_db import connect

# This file is src/crotalus/database/migration_runner.py, so parents[3] is the repo root.
MIGRATIONS_DIR = Path(__file__).resolve().parents[3] / "migrations"


def create_tracking_table(connection: psycopg.Connection[TupleRow]) -> None:
    """
    Create the table to track which migrations have been applied to the DB
    if it has not been created yet.
    """
    connection.execute("""
    CREATE TABLE IF NOT EXISTS applied_schema_migrations ( 
        name TEXT PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now() 
    )
    """)


def get_applied(connection: psycopg.Connection[TupleRow]) -> set[str]:
    """
    Get migration names that have been applied to the database thus far.
    """

    res = connection.execute("""
        SELECT name FROM applied_schema_migrations
    """)
    return {name[0] for name in res}


def find_migrations() -> list[Path]:
    """
    Get the migration files in the migrations folder, in the order they must run.
    """
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def apply_migration(connection: psycopg.Connection[TupleRow], path: Path) -> None:
    """
    Apply one single migration to the database, and update the tracking table.
    """

    # Explicit UTF-8: the default is platform-dependent (cp1252 on Windows).
    sql_text = path.read_text(encoding="utf-8")

    # One transaction: the migration and its record succeed or fail together.
    with connection.transaction():
        # run the migration
        connection.execute(sql_text)

        # record the migration, by name (e.g. "001_packages_releases")
        connection.execute(
            "INSERT INTO applied_schema_migrations (name) VALUES (%s)",
            (path.stem,),
        )


def main() -> None:
    with connect() as connection:
        connection.autocommit = (
            True  # each transaction with this one is its own seperate transaction
        )
        create_tracking_table(connection)
        applied_migrations = get_applied(connection)

        for path in find_migrations():
            if path.stem not in applied_migrations:
                apply_migration(connection, path)
                print(f"Applied migration: {path.stem}")


if __name__ == "__main__":
    main()
