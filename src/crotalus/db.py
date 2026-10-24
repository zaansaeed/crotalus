"""The crotalus Postgres database: opening connections and applying migrations.

The connection string comes from the `DATABASE_URL` environment variable. For
local development it can be set in a `.env` file at the repo root; on other
platforms (CI, AWS) the platform sets it.

Apply pending migrations with: python -m crotalus.db

Migrations are the numbered .sql files in migrations/, run in order. Each one runs
in a transaction together with its row in applied_schema_migrations, so it either
fully applies and is recorded, or neither happens. Applied ones are skipped.
"""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv
from psycopg.rows import TupleRow

# This file is src/crotalus/db.py, so parents[2] is the repo root.
MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"


def connect() -> psycopg.Connection[TupleRow]:
    """Return a new connection to the database named by `DATABASE_URL`.
    Rows are tuples.
    """
    # Loads .env if present. Never overrides variables that are already set,
    # so values from the shell, CI or AWS take priority.
    load_dotenv()

    # Read at call time, not import time, so tests can point it elsewhere.
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. For local development, check .env, "
            "e.g. DATABASE_URL=postgresql://crotalus:crotalus@localhost:5432/crotalus"
        )
    return psycopg.connect(url)


def migration_files() -> list[Path]:
    """The migration files in the migrations folder, in the order they must run."""
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def applied_migrations(conn: psycopg.Connection[TupleRow]) -> set[str]:
    """Names of the migrations already applied, e.g. {"001_packages_releases"}."""
    return {row[0] for row in conn.execute("SELECT name FROM applied_schema_migrations")}


def migrate() -> None:
    """Apply every migration that hasn't been applied yet."""
    with connect() as conn:
        conn.autocommit = True  # each migration below gets its own transaction
        conn.execute("""
            CREATE TABLE IF NOT EXISTS applied_schema_migrations (
                name TEXT PRIMARY KEY,
                applied_at timestamptz NOT NULL DEFAULT now()
            )
        """)
        applied = applied_migrations(conn)

        for path in migration_files():
            if path.stem in applied:
                continue
            # Explicit UTF-8: the default is platform-dependent (cp1252 on Windows).
            sql_text = path.read_text(encoding="utf-8")

            # One transaction: the migration and its record succeed or fail together.
            with conn.transaction():
                conn.execute(sql_text)
                conn.execute(
                    "INSERT INTO applied_schema_migrations (name) VALUES (%s)", (path.stem,)
                )
            print(f"Applied migration: {path.stem}")


if __name__ == "__main__":
    migrate()
