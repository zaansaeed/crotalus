import io
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from crotalus.pypi.client import (
    PyPIError,
    PyPIUnavailable,
    ReleaseNotFound,
    fetch_first_upload,
    fetch_release_json,
    parse_first_upload,
    parse_metadata,
)

FIXTURE = Path(__file__).parent / "fixtures" / "pypi_release.json"


@pytest.fixture
def release_json() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return data


def test_parses_release(release_json: dict[str, Any]) -> None:
    meta = parse_metadata(release_json)
    assert meta.name == "ExamplePkg"
    assert meta.version == "1.0"
    assert [f.filename for f in meta.files] == [
        "examplepkg-1.0-py3-none-any.whl",
        "examplepkg-1.0.tar.gz",
    ]
    assert meta.files[1].packagetype == "sdist"
    assert meta.files[1].sha256 == "11" * 32


def test_uploaded_at_is_earliest_file(release_json: dict[str, Any]) -> None:
    # The sdist (12:00) was uploaded before the wheel (12:05).
    assert parse_metadata(release_json).uploaded_at == datetime(
        2024, 6, 1, 12, 0, tzinfo=timezone.utc
    )


def test_release_without_files(release_json: dict[str, Any]) -> None:
    release_json["urls"] = []
    meta = parse_metadata(release_json)
    assert meta.files == ()
    assert meta.uploaded_at is None


def test_empty_strings_become_none(release_json: dict[str, Any]) -> None:
    meta = parse_metadata(release_json)
    assert meta.summary is None
    assert meta.author == "dev@example.com"  # author is empty, falls back to the email


def test_homepage_joins_project_urls(release_json: dict[str, Any]) -> None:
    assert parse_metadata(release_json).project_urls == {
        "Source": "https://github.com/example/examplepkg",
        "Homepage": "https://example.com",
    }


def test_unexpected_shape(release_json: dict[str, Any]) -> None:
    release_json["urls"] = [{"filename": "missing-everything-else"}]
    with pytest.raises(PyPIError):
        parse_metadata(release_json)


def raise_http(code: int) -> Any:
    def fake_urlopen(request: urllib.request.Request, timeout: float) -> Any:
        raise urllib.error.HTTPError(request.full_url, code, "error", Message(), None)

    return fake_urlopen


@pytest.mark.parametrize(
    ("code", "error"),
    [
        (404, ReleaseNotFound),
        (429, PyPIUnavailable),
        (503, PyPIUnavailable),
        (400, PyPIError),
    ],
)
def test_http_errors(monkeypatch: pytest.MonkeyPatch, code: int, error: type[Exception]) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", raise_http(code))
    with pytest.raises(error):
        fetch_release_json("examplepkg", "1.0")


def test_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: urllib.request.Request, timeout: float) -> Any:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(PyPIUnavailable):
        fetch_release_json("examplepkg", "1.0")


def test_fetch_request(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[urllib.request.Request] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> Any:
        seen.append(request)
        return io.BytesIO(FIXTURE.read_bytes())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert fetch_release_json("examplepkg", "1.0+local")["info"]["name"] == "ExamplePkg"
    # "+" must be escaped, or it's read as a space.
    assert seen[0].full_url == "https://pypi.org/pypi/examplepkg/1.0%2Blocal/json"
    assert str(seen[0].get_header("User-agent")).startswith("crotalus/")


def test_first_upload_across_versions() -> None:
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
    assert parse_first_upload(project) == datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc)


def test_first_upload_without_files() -> None:
    assert parse_first_upload({"releases": {}}) is None


def test_first_upload_unexpected_shape() -> None:
    with pytest.raises(PyPIError):
        parse_first_upload({"releases": {"1.0": [{}]}})


def test_fetch_project_url(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[urllib.request.Request] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> Any:
        seen.append(request)
        return io.BytesIO(b'{"releases": {}}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert fetch_first_upload("examplepkg") is None
    assert seen[0].full_url == "https://pypi.org/pypi/examplepkg/json"
