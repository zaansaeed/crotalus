"""Shared pytest fixtures. pytest loads this file automatically.

Database tests use a separate `crotalus_test` database on the same server as
`DATABASE_URL`, rebuilt from the migrations at the start of each test run.
They are skipped when Postgres isn't reachable.

No test reaches the network: the shared HTTP client is replaced for every test.
A test that needs PyPI to answer uses the `fake_pypi` fixture to say how.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import httpx
import psycopg
import pytest
from dotenv import load_dotenv
from psycopg.conninfo import make_conninfo

from crotalus import db as crotalus_db
from crotalus import http_client
from crotalus.db import Connection

# Answers one request, in place of PyPI.
Handler = Callable[[httpx.Request], httpx.Response]

TEST_DB_NAME = "crotalus_test"


@pytest.fixture(scope="session")  # only ran once. tests use the same instance
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
        crotalus_db.migrate()

    yield test_url


@pytest.fixture
def db(
    test_database_url: str,
    monkeypatch: pytest.MonkeyPatch,  # fixture above is test_database_url
) -> Iterator[Connection]:
    """A connection to crotalus_test. Tables are emptied after each test."""
    monkeypatch.setenv("DATABASE_URL", test_database_url)
    with crotalus_db.connect() as conn:
        conn.autocommit = True
        yield conn
        conn.execute("TRUNCATE packages, releases, ingest_runs, findings, triage RESTART IDENTITY")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test: any request to PyPI fails the test instead of going out."""

    def refuse(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"test tried to reach the network: {request.url}")

    fake = http_client.make_client(httpx.MockTransport(refuse))
    monkeypatch.setattr(http_client, "client", fake)


@pytest.fixture
def fake_pypi(monkeypatch: pytest.MonkeyPatch) -> Callable[[Handler], None]:
    """Make PyPI answer with `handler`, e.g. fake_pypi(lambda request: httpx.Response(404))."""

    def install(handler: Handler) -> None:
        fake = http_client.make_client(httpx.MockTransport(handler))
        monkeypatch.setattr(http_client, "client", fake)

    return install
