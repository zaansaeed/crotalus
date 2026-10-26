"""Tests for crotalus.pypi. PyPI is faked with `fake_pypi` (see conftest.py)."""

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from crotalus.models import FeedEntry, ReleaseFile
from crotalus.pypi import (
    PyPIError,
    PyPIUnavailable,
    ReleaseNotFound,
    download,
    fetch_feed,
    fetch_first_upload,
    fetch_metadata,
    normalize_name,
)

FIXTURES = Path(__file__).parent / "fixtures"
FEED_XML = (FIXTURES / "updates.xml").read_bytes()

FakePyPI = Callable[[Callable[[httpx.Request], httpx.Response]], None]


def answer_json(data: Any) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(200, json=data)


@pytest.fixture
def release_json() -> Any:
    return json.loads((FIXTURES / "pypi_release.json").read_text(encoding="utf-8"))


# normalize_name


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


# fetch_feed


def test_feed_entries(fake_pypi: FakePyPI) -> None:
    fake_pypi(lambda request: httpx.Response(200, content=FEED_XML))
    assert fetch_feed() == [
        FeedEntry(
            name="requests",
            version="2.31.0",
            published_at=datetime(2026, 10, 17, 4, 33, 56, tzinfo=UTC),
            source="rss",
        ),
        FeedEntry(
            name="x5-browser-tools",
            version="1.6.0",
            published_at=datetime(2026, 10, 17, 4, 33, 8, tzinfo=UTC),
            source="rss",
        ),
    ]  # the fixture's malformed items (no date, no version, extra words, no title) skipped


def test_empty_feed(fake_pypi: FakePyPI) -> None:
    fake_pypi(lambda request: httpx.Response(200, content=b"<rss><channel></channel></rss>"))
    assert fetch_feed() == []


def test_malformed_feed(fake_pypi: FakePyPI) -> None:
    fake_pypi(lambda request: httpx.Response(200, content=b"<rss><channel>"))
    with pytest.raises(PyPIError):
        fetch_feed()


# fetch_metadata


def test_parses_release(fake_pypi: FakePyPI, release_json: Any) -> None:
    fake_pypi(answer_json(release_json))
    meta = fetch_metadata("examplepkg", "1.0")
    assert meta.name == "ExamplePkg"
    assert meta.version == "1.0"
    assert [f.filename for f in meta.files] == [
        "examplepkg-1.0-py3-none-any.whl",
        "examplepkg-1.0.tar.gz",
    ]
    assert meta.files[1].packagetype == "sdist"
    assert meta.files[1].sha256 == "11" * 32
    # The sdist (12:00) was uploaded before the wheel (12:05).
    assert meta.uploaded_at == datetime(2024, 6, 1, 12, 0, tzinfo=UTC)


def test_empty_strings_become_none(fake_pypi: FakePyPI, release_json: Any) -> None:
    fake_pypi(answer_json(release_json))
    meta = fetch_metadata("examplepkg", "1.0")
    assert meta.summary is None
    assert meta.author == "dev@example.com"  # author is empty, falls back to the email


def test_homepage_joins_project_urls(fake_pypi: FakePyPI, release_json: Any) -> None:
    fake_pypi(answer_json(release_json))
    assert fetch_metadata("examplepkg", "1.0").project_urls == {
        "Source": "https://github.com/example/examplepkg",
        "Homepage": "https://example.com",
    }


def test_release_without_files(fake_pypi: FakePyPI, release_json: Any) -> None:
    release_json["urls"] = []
    fake_pypi(answer_json(release_json))
    meta = fetch_metadata("examplepkg", "1.0")
    assert meta.files == ()
    assert meta.uploaded_at is None


def test_metadata_request(fake_pypi: FakePyPI, release_json: Any) -> None:
    seen: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=release_json)

    fake_pypi(answer)
    fetch_metadata("examplepkg", "1.0+local")
    # "+" must be escaped, or it's read as a space.
    assert str(seen[0].url) == "https://pypi.org/pypi/examplepkg/1.0%2Blocal/json"
    assert seen[0].headers["User-Agent"].startswith("crotalus/")


@pytest.mark.parametrize(
    "body",
    [
        {"info": {}, "urls": []},  # missing fields
        {"info": {"name": "x", "version": "1"}, "urls": [{"filename": "only-this"}]},
        ["not", "an", "object"],
    ],
)
def test_unexpected_shape(fake_pypi: FakePyPI, body: Any) -> None:
    fake_pypi(answer_json(body))
    with pytest.raises(PyPIError):
        fetch_metadata("examplepkg", "1.0")


def test_invalid_json(fake_pypi: FakePyPI) -> None:
    fake_pypi(lambda request: httpx.Response(200, content=b"<html>oops</html>"))
    with pytest.raises(PyPIError):
        fetch_metadata("examplepkg", "1.0")


# errors, shared by every fetch


@pytest.mark.parametrize(
    ("code", "error"),
    [
        (404, ReleaseNotFound),
        (429, PyPIUnavailable),
        (503, PyPIUnavailable),
        (400, PyPIError),
    ],
)
def test_http_errors(fake_pypi: FakePyPI, code: int, error: type[Exception]) -> None:
    fake_pypi(lambda request: httpx.Response(code))
    with pytest.raises(error):
        fetch_metadata("examplepkg", "1.0")


@pytest.mark.parametrize(
    "exception", [httpx.ConnectError("connection refused"), httpx.ReadTimeout("timed out")]
)
def test_network_errors(fake_pypi: FakePyPI, exception: httpx.TransportError) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise exception

    fake_pypi(fail)
    with pytest.raises(PyPIUnavailable):
        fetch_feed()


# fetch_first_upload


def test_first_upload_across_versions(fake_pypi: FakePyPI) -> None:
    seen: list[httpx.Request] = []
    project = {
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2024-06-01T12:00:00.000000Z"}],
            "0.9": [
                {"upload_time_iso_8601": "2024-01-01T10:05:00.000000Z"},
                {"upload_time_iso_8601": "2024-01-01T10:00:00.000000Z"},
            ],
            "2.0": [],  # a version with no files
        }
    }

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=project)

    fake_pypi(answer)
    assert fetch_first_upload("examplepkg") == datetime(2024, 1, 1, 10, 0, tzinfo=UTC)
    assert str(seen[0].url) == "https://pypi.org/pypi/examplepkg/json"


def test_first_upload_without_files(fake_pypi: FakePyPI) -> None:
    fake_pypi(answer_json({"releases": {}}))
    assert fetch_first_upload("examplepkg") is None


def test_first_upload_unexpected_shape(fake_pypi: FakePyPI) -> None:
    fake_pypi(answer_json({"releases": {"1.0": [{}]}}))
    with pytest.raises(PyPIError):
        fetch_first_upload("examplepkg")


# download


def file_for(data: bytes) -> ReleaseFile:
    return ReleaseFile(
        filename="pkg-1.0.tar.gz",
        url="https://files.pythonhosted.org/packages/pkg-1.0.tar.gz",
        packagetype="sdist",
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        uploaded_at=datetime(2026, 10, 17, tzinfo=UTC),
    )


def test_download(fake_pypi: FakePyPI) -> None:
    fake_pypi(lambda request: httpx.Response(200, content=b"archive bytes"))
    assert download(file_for(b"archive bytes"), max_bytes=1000) == b"archive bytes"


def test_download_hash_mismatch(fake_pypi: FakePyPI) -> None:
    fake_pypi(lambda request: httpx.Response(200, content=b"tampered bytes"))
    with pytest.raises(PyPIError, match="sha256"):
        download(file_for(b"archive bytes"), max_bytes=1000)


def test_download_stops_past_the_limit(fake_pypi: FakePyPI) -> None:
    # The size PyPI listed doesn't matter: the limit is enforced on what arrives.
    fake_pypi(lambda request: httpx.Response(200, content=b"x" * 2000))
    with pytest.raises(PyPIError, match="larger than"):
        download(file_for(b"small"), max_bytes=1000)


@pytest.mark.parametrize(("code", "error"), [(404, ReleaseNotFound), (503, PyPIUnavailable)])
def test_download_http_errors(fake_pypi: FakePyPI, code: int, error: type[Exception]) -> None:
    fake_pypi(lambda request: httpx.Response(code))
    with pytest.raises(error):
        download(file_for(b"x"), max_bytes=1000)
