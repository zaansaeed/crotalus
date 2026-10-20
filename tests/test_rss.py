from datetime import datetime, timezone
from pathlib import Path

import feedparser
import pytest

from crotalus.ingest.rss_ingestor import FeedEntry, normalize_name, parse_feed

FIXTURE = Path(__file__).parent / "fixtures" / "updates.xml"


@pytest.fixture
def feed() -> feedparser.FeedParserDict:
    # Pass bytes, not the path: feedparser.parse also treats strings as URLs.
    return feedparser.parse(FIXTURE.read_bytes())


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("X5Browser", "x5browser"),
        ("Foo_Bar", "foo-bar"),
        ("foo.bar", "foo-bar"),
        ("foo__bar", "foo-bar"),
        ("foo-_.-bar", "foo-bar"),
        ("already-normal", "already-normal"),
    ],
)
def test_normalize_name(raw: str, expected: str) -> None:
    assert normalize_name(raw) == expected


def test_parses_valid_entries(feed: feedparser.FeedParserDict) -> None:
    assert parse_feed(feed) == [
        FeedEntry(
            name="requests",
            version="2.31.0",
            published_at=datetime(2026, 10, 17, 4, 33, 56, tzinfo=timezone.utc),
            source="rss",
        ),
        FeedEntry(
            name="x5-browser-tools",
            version="1.6.0",
            published_at=datetime(2026, 10, 17, 4, 33, 8, tzinfo=timezone.utc),
            source="rss",
        ),
    ]


def test_skips_malformed_entries(feed: feedparser.FeedParserDict) -> None:
    names = {e.name for e in parse_feed(feed)}
    assert names.isdisjoint({"nodate", "noversion", "extra", "notitle"})


def test_published_at_is_utc_aware(feed: feedparser.FeedParserDict) -> None:
    for entry in parse_feed(feed):
        assert entry.published_at.utcoffset() == timezone.utc.utcoffset(None)


def test_empty_feed_returns_empty_list() -> None:
    assert parse_feed(feedparser.parse(b"<rss><channel></channel></rss>")) == []
