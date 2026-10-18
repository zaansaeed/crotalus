"""Open connections to the crotalus Postgres database.

The connection string comes from the `DATABASE_URL` environment variable. For
local development it can be set in a `.env` file at the repo root; on other
platforms (CI, AWS) the platform sets it.
"""

from __future__ import annotations

import os

import psycopg
from dotenv import load_dotenv
from psycopg.rows import TupleRow

# we must connect to our database to do anything to it programmatically via python. 
# this will run after the docker compose runs, so we can talk to that postgres server in the docker container.
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
