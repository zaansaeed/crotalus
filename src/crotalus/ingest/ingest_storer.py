"""Store parsed feed entries in the packages and releases tables."""

from __future__ import annotations

import psycopg
from psycopg.rows import TupleRow

from crotalus.ingest.rss_ingestor import FeedEntry


def store_entries(conn: psycopg.Connection[TupleRow], entries: list[FeedEntry]) -> int:
    """Insert entries, skipping releases already stored. Returns how many releases were new.

    Runs in one transaction: either every entry is stored or none are.
    """
    new_releases = 0
    with conn.transaction():
        for entry in entries:
            conn.execute(
                "INSERT INTO packages (name) VALUES (%s) ON CONFLICT (name) DO NOTHING",
                (entry.name,),
            )
            # Look up package_id in the same statement: RETURNING on the package insert
            # gives nothing when the package already existed.
            cur = conn.execute(
                """
                INSERT INTO releases (package_id, version, published_at, source)
                SELECT id, %s, %s, %s FROM packages WHERE name = %s
                ON CONFLICT (package_id, version) DO NOTHING
                RETURNING id
                """,
                (entry.version, entry.published_at, entry.source, entry.name),
            )
            # One row back if inserted, none if it was already there.
            if cur.fetchone() is not None:
                new_releases += 1
    return new_releases
