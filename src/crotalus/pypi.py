"""Everything crotalus fetches from PyPI.

- fetch_feed():                the RSS feed of the latest ~100 uploads (the poller)
- fetch_metadata(name, ver):   one release's info and files (the worker, every release)
- fetch_first_upload(name):    when the project first appeared (the worker, once per package)
- download(file, max_bytes):   one of a release's files, as bytes (the worker)

All requests go through the shared client in crotalus.http_client.

Errors:
- ReleaseNotFound: the project or version isn't on PyPI. Either it was removed
  (common for malware once reported) or PyPI's CDN hasn't caught up yet.
- PyPIUnavailable: network problems, timeouts, 429 or 5xx. Worth retrying later.
- PyPIError: anything else, e.g. a response that isn't what we expect.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from urllib.parse import quote

import feedparser
import httpx

from crotalus import http_client
from crotalus.models import FeedEntry, ReleaseFile, ReleaseMetadata

RSS_URL = "https://pypi.org/rss/updates.xml"
RELEASE_URL = "https://pypi.org/pypi/{name}/{version}/json"  # one version, small
PROJECT_URL = "https://pypi.org/pypi/{name}/json"  # every version, can be several MB


class PyPIError(Exception):
    pass


class ReleaseNotFound(PyPIError):
    pass


class PyPIUnavailable(PyPIError):
    pass


_NAME_SEPARATORS = re.compile(r"[-_.]+")


def normalize_name(name: str) -> str:
    """PEP 503: runs of '-', '_', '.' become a single '-', then lowercase."""
    # compiled_regex_pattern.sub(replacement, name)
    return _NAME_SEPARATORS.sub("-", name).lower()


def _check_status(response: httpx.Response, label: str) -> None:
    """Raise our error for anything but 200. `label` is for error messages."""
    status = response.status_code
    if status == 404:
        raise ReleaseNotFound(f"{label} is not on PyPI")
    if status == 429 or status >= 500:
        raise PyPIUnavailable(f"PyPI returned {status} for {label}")
    if status != 200:
        raise PyPIError(f"PyPI returned {status} for {label}")


def _get(url: str, label: str) -> httpx.Response:
    """GET from PyPI, turning failures into our errors. `label` is for error messages."""
    try:
        response = http_client.client.get(url)
    # error handling
    except httpx.TransportError as exc:  # timeouts, connection failures, ...
        raise PyPIUnavailable(f"could not reach PyPI for {label}: {exc!r}") from exc
    except httpx.HTTPError as exc:  # anything else httpx raises, e.g. too many redirects
        raise PyPIError(f"request to PyPI failed for {label}: {exc!r}") from exc
    _check_status(response, label)
    return response


def _parse_time(value: str) -> datetime:
    # e.g. "2023-05-22T15:12:42.123456Z". fromisoformat only accepts "Z" from 3.11 on.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def fetch_feed() -> list[FeedEntry]:
    """The releases in PyPI's RSS feed, newest first. Malformed items are skipped.

    Each item's title is "<name> <version>"; its date is when it was published.
    """
    # Parse the bytes we downloaded. Given a string, feedparser would fetch the URL itself.
    feed = feedparser.parse(_get(RSS_URL, "RSS feed").content)

    # Check if feedparser encountered an issue (malformed XML, bad encoding, etc.)
    if feed.get("bozo") == 1:
        raise PyPIError(f"malformed feed: {feed.bozo_exception}")

    entries = []
    for item in feed.entries:
        try:
            # Split the title safely (e.g., "requests 2.31.0")
            parts = item.title.split()
            if len(parts) != 2:
                continue  # Skip if title doesn't have both name and version
            if not item.get("published_parsed"):
                continue

            # published_parsed is a UTC with no tzinfo; attach UTC explicitly via tzinfo.
            # otherwise, without UTC, changes to current location tz.
            published_at = datetime(*item.published_parsed[:6]).replace(tzinfo=timezone.utc)
            entries.append(
                FeedEntry(
                    name=normalize_name(parts[0]),
                    version=parts[1],
                    published_at=published_at,
                    source="rss",
                )
            )
        except (ValueError, AttributeError):
            # Skip any item that fails to unpack or lacks required attributes
            continue
    return entries


def fetch_metadata(name: str, version: str) -> ReleaseMetadata:
    """One release's metadata, as of that version: its `info` and its files (`urls`)."""
    # Versions can contain characters that aren't URL-safe, e.g. "1.0+local".
    url = RELEASE_URL.format(name=name, version=quote(version, safe=""))
    response = _get(url, f"{name} {version}")
    try:
        data = response.json()
        info = data["info"]
        files = tuple(
            ReleaseFile(
                filename=raw["filename"],
                url=raw["url"],
                packagetype=raw["packagetype"],
                size=raw["size"],
                sha256=raw["digests"]["sha256"],
                uploaded_at=_parse_time(raw["upload_time_iso_8601"]),
            )
            for raw in data["urls"]
        )

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
    # ValueError also covers invalid JSON (json.JSONDecodeError is a ValueError).
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise PyPIError(f"unexpected response from PyPI for {name} {version}: {exc!r}") from exc


def fetch_first_upload(name: str) -> datetime | None:
    """
    Fetches entire project json, finds first upload time of every file, and then returns the
    oldest one. Gives one date for the first file in the project, ever. None if it has no files.
    """
    response = _get(PROJECT_URL.format(name=name), name)
    try:
        return min(
            (
                _parse_time(raw["upload_time_iso_8601"])
                for files in response.json()["releases"].values()
                for raw in files
            ),
            default=None,
        )
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise PyPIError(f"unexpected response from PyPI for {name}: {exc!r}") from exc


def download(file: ReleaseFile, max_bytes: int) -> bytes:
    """Download one of a release's files into memory and check it against its sha256.

    Called once per file the worker inspects: up to twice per release (the sdist
    and one wheel).

    The file comes from whoever published the release, so trust nothing about it:
    the size is enforced while reading (stop past `max_bytes`, whatever PyPI said it
    was), and the bytes must hash to what PyPI listed.
    """
    label = file.filename
    chunks: list[bytes] = []
    received = 0
    digest = hashlib.sha256()
    try:
        with http_client.client.stream("GET", file.url) as response:
            _check_status(response, label)
            for chunk in response.iter_bytes():
                received += len(chunk)
                if received > max_bytes:
                    raise PyPIError(f"{label} is larger than {max_bytes} bytes")
                digest.update(chunk)
                chunks.append(chunk)
    except httpx.TransportError as exc:
        raise PyPIUnavailable(f"could not download {label}: {exc!r}") from exc
    except httpx.HTTPError as exc:
        raise PyPIError(f"download failed for {label}: {exc!r}") from exc

    if digest.hexdigest() != file.sha256:
        raise PyPIError(f"{label} does not match its sha256")
    return b"".join(chunks)  # join all chunks of the binary data
