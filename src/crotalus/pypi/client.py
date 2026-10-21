"""Fetch one release's metadata from PyPI's JSON API.

`https://pypi.org/pypi/<name>/<version>/json` describes a single version: its own
`info` (summary, author, links, ...) and `urls`, the files uploaded for it.
`fetch_release_json` downloads that, `parse_metadata` picks out what the detection
rules need, and `fetch_metadata` does both.

This is release-specific only. Package history (age, earlier versions) would need
the much larger project endpoint, `/pypi/<name>/json`, and isn't fetched yet.

Errors:
- ReleaseNotFound: the project or version isn't on PyPI. Either it was removed
  (common for malware once reported) or PyPI's CDN hasn't caught up yet.
- PyPIUnavailable: network problems, timeouts, 429 or 5xx. Worth retrying later.
- PyPIError: anything else, e.g. a response that isn't the JSON we expect.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any

from crotalus import __version__
from crotalus.models import ReleaseFile, ReleaseMetadata

RELEASE_URL = "https://pypi.org/pypi/{name}/{version}/json"
# PyPI asks API clients to identify themselves.
USER_AGENT = f"crotalus/{__version__} (+https://github.com/zaansaeed/crotalus)"
TIMEOUT_SECONDS = 10


class PyPIError(Exception):
    pass


class ReleaseNotFound(PyPIError):
    pass


class PyPIUnavailable(PyPIError):
    pass


def fetch_release_json(name: str, version: str) -> dict[str, Any]:
    """Download one release's JSON. Raises ReleaseNotFound, PyPIUnavailable or PyPIError."""
    # Versions can contain characters that aren't URL-safe, e.g. "1.0+local".
    url = RELEASE_URL.format(name=name, version=urllib.parse.quote(version, safe=""))
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    label = f"{name} {version}"
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            data: dict[str, Any] = json.load(response)
            return data
    # error handling
    except urllib.error.HTTPError as exc:  # must come before URLError, its parent class
        if exc.code == 404:
            raise ReleaseNotFound(f"{label} is not on PyPI") from exc
        if exc.code == 429 or exc.code >= 500:
            raise PyPIUnavailable(f"PyPI returned {exc.code} for {label}") from exc
        raise PyPIError(f"PyPI returned {exc.code} for {label}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise PyPIUnavailable(f"could not reach PyPI for {label}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PyPIError(f"PyPI sent invalid JSON for {label}") from exc


def _parse_time(value: str) -> datetime:
    # e.g. "2023-05-22T15:12:42.123456Z". fromisoformat only accepts "Z" from 3.11 on.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_file(raw: dict[str, Any]) -> ReleaseFile:
    """One entry of `urls` -> ReleaseFile."""
    return ReleaseFile(
        filename=raw["filename"],
        url=raw["url"],
        packagetype=raw["packagetype"],
        size=raw["size"],
        sha256=raw["digests"]["sha256"],
        uploaded_at=_parse_time(raw["upload_time_iso_8601"]),
    )


def parse_metadata(release_json: dict[str, Any]) -> ReleaseMetadata:
    """Pick out what the rules need from one release's JSON."""
    try:
        info = release_json["info"]
        files: tuple[ReleaseFile] = tuple(_parse_file(raw) for raw in release_json["urls"])

        project_urls = dict(info.get("project_urls") or {})
        if info.get("home_page"):
            project_urls.setdefault("Homepage", info["home_page"])

        return ReleaseMetadata(
            name=info["name"],
            version=info["version"],
            summary=info.get("summary") or None,  # PyPI uses "" for missing
            author=info.get("author") or info.get("author_email") or None,
            project_urls=project_urls,
            files=files,
            uploaded_at=min((f.uploaded_at for f in files), default=None),
        )
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise PyPIError(f"unexpected JSON shape from PyPI: {exc!r}") from exc


def fetch_metadata(name: str, version: str) -> ReleaseMetadata:
    return parse_metadata(fetch_release_json(name, version))
