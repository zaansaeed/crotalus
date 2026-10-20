"""Ingest new PyPI releases from the RSS feed.

PyPI publishes its most recent uploads at `https://pypi.org/rss/updates.xml`.
This module fetches that feed (`poll`) and turns each item into a `FeedEntry`
(`parse_feed`) with a PEP 503 normalized name, version, and UTC publish time.
Malformed items are skipped rather than failing the whole batch.

It is the first stage of crotalus: the feed is polled frequently so newly
published releases can be queued for analysis within minutes of upload.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

import feedparser

if TYPE_CHECKING:
    from feedparser import FeedParserDict


RSS_URL = "https://pypi.org/rss/updates.xml"

_NAME_SEPARATORS = re.compile(r"[-_.]+")

# How crotalus found a release; matches the CHECK on releases.source.
Source = Literal["rss", "on_demand"]


def normalize_name(name: str) -> str:
    """PEP 503: runs of '-', '_', '.' become a single '-', then lowercase."""
    # compiled_regex_pattern.sub(replacement, name)
    return _NAME_SEPARATORS.sub("-", name).lower()


@dataclass(frozen=True)
class FeedEntry:
    name: str  # PEP 503 normalized,
    version: str  # e.g. "0.5.20"
    published_at: datetime  # timezone-aware, UTC
    source: Source  # "rss" or "on_demand"


def poll(rss_url: str) -> FeedParserDict | None:
    feed = feedparser.parse(rss_url)

    # Check if feedparser encountered an issue (malformed XML, bad encoding, etc.)
    if feed.get("bozo") == 1:
        print(f"Warning: Issue parsing feed - {feed.bozo_exception}")
        return None

    return feed


def parse_feed(feed: FeedParserDict) -> list[FeedEntry]:
    """Parse PyPI's updates.xml into entries. Skip malformed items.
    title -> "<name> <version>" only
    timestamp -> entry parsed timedate
    """
    parsed_entries = []

    for entry in feed.entries:
        try:
            # Split the title safely (e.g., "requests 2.31.0")
            parts = entry.title.split()
            if len(parts) != 2:
                continue  # Skip if title doesn't have both name and version

            name, version = parts[0], parts[1]

            # published_parsed is a UTC with no tzinfo; attach UTC explicitly via tzinfo.
            # otherwise, without UTC, changes to current location tz.
            if entry.get("published_parsed"):
                timestamp = datetime(*entry.published_parsed[:6]).replace(tzinfo=timezone.utc)
            else:
                continue

            parsed_entries.append(
                FeedEntry(
                    name=normalize_name(name),
                    version=version,
                    published_at=timestamp,
                    source="rss",
                )
            )

        except (ValueError, AttributeError):
            # Skip any item that fails to unpack or lacks required attributes
            continue

    return parsed_entries


if __name__ == "__main__":
    pass
