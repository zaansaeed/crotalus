"""Shared pytest fixtures. pytest loads this file automatically.

Database tests use a separate `crotalus_test` database on the same server as
`DATABASE_URL`, rebuilt from the migrations at the start of each test run.
They are skipped when Postgres isn't reachable.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import psycopg
import pytest
from dotenv import load_dotenv
from psycopg.conninfo import make_conninfo
from psycopg.rows import TupleRow

from crotalus.database import migration_runner
from crotalus.database.connect_db import connect

TEST_DB_NAME = "crotalus_test"


@pytest.fixture(scope="session") #only ran once. tests use the same instance
def test_database_url() -> Iterator[str]:
    """Create a fresh, migrated crotalus_test database once per test session."""
    load_dotenv()
    dev_url = os.environ.get("DATABASE_URL")
    if not dev_url:
        pytest.skip("DATABASE_URL is not set")

    # Same server and credentials as dev, different database.
    test_url = make_conninfo(dev_url, dbname=TEST_DB_NAME)

    try:
        # autocommit: CREATE DATABASE can't run inside a transaction.
        admin = psycopg.connect(dev_url, autocommit=True)
    except psycopg.OperationalError:
        pytest.skip("Postgres is not running")

    with admin:
        admin.execute(f"DROP DATABASE IF EXISTS {TEST_DB_NAME} WITH (FORCE)")
        admin.execute(f"CREATE DATABASE {TEST_DB_NAME}")

    # Session-scoped fixtures can't use the `monkeypatch` fixture, so use its context manager.
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("DATABASE_URL", test_url)
        migration_runner.main()

    yield test_url


@pytest.fixture
def db(
    test_database_url: str, monkeypatch: pytest.MonkeyPatch #fixture above is test_database_url
) -> Iterator[psycopg.Connection[TupleRow]]:
    """A connection to crotalus_test. Tables are emptied after each test."""
    monkeypatch.setenv("DATABASE_URL", test_database_url)
    with connect() as conn:
        conn.autocommit = True
        yield conn
        conn.execute("TRUNCATE packages, releases RESTART IDENTITY")
