"""Data passed between the poller, the worker, PyPI fetching and the detection rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

# How crotalus found a release; matches the CHECK on releases.source.
Source = Literal["rss", "on_demand"]

# Matches the CHECK on findings.severity.
Severity = Literal["low", "medium", "high", "critical"]

# Matches the CHECK on releases.verdict.
Verdict = Literal["clean", "suspicious", "likely_malicious"]


# One item of PyPI's RSS feed: a release the poller should store.
@dataclass(frozen=True)
class FeedEntry:
    name: str  # PEP 503 normalized,
    version: str  # e.g. "0.5.20"
    published_at: datetime  # timezone-aware, UTC
    source: Source  # "rss" or "on_demand"


# One release from database.
@dataclass(frozen=True)
class Release:
    id: int
    name: str  # PEP 503 normalized
    version: str


# One file uploaded for a release (an sdist or a wheel), as PyPI describes it.
@dataclass(frozen=True)
class ReleaseFile:
    filename: str
    url: str
    packagetype: str  # "sdist" or "bdist_wheel"
    size: int  # bytes
    sha256: str
    uploaded_at: datetime  # UTC


# PyPI's metadata for one release.
@dataclass(frozen=True)
class ReleaseMetadata:
    """What PyPI says about one version, as of that version."""

    name: str  # as the author wrote it, not normalized
    version: str
    summary: str | None = None
    author: str | None = None
    project_urls: dict[str, str] = field(default_factory=dict)  # label -> URL, incl. homepage
    files: tuple[ReleaseFile, ...] = ()
    uploaded_at: datetime | None = None  # earliest of its files; None if it has none


# What we know about the package as a whole, across all its versions.
@dataclass(frozen=True)
class PackageInfo:
    first_uploaded_at: datetime | None = None  # the package's first file on PyPI; its age


# The source files read out of one downloaded archive (an sdist or a wheel).
@dataclass(frozen=True)
class ArchiveContents:
    filename: str  # e.g. "pkg-1.0.tar.gz"
    # Path inside the archive -> text, for the files rules read (.py, .pth,
    # pyproject.toml). An sdist's top folder ("pkg-1.0/") is dropped, so its
    # setup.py is just "setup.py". Paths are as the archive gives them: a hostile
    # one like "../../evil.py" is kept as-is (and never written anywhere).
    files: dict[str, str] = field(default_factory=dict)


# Everything the rules get to look at for one release. Grows as rules need more
# (the previous version's diff, ...). will be helpful for agents
@dataclass(frozen=True)
class AnalysisContext:
    release: Release
    metadata: ReleaseMetadata
    package: PackageInfo
    # None when the release has no such file, or it was too big to download.
    sdist: ArchiveContents | None = None
    wheel: ArchiveContents | None = None


# Finding for one release.
@dataclass(frozen=True)
class Finding:
    rule_id: str  # snake_case, e.g. "typosquat"
    severity: Severity
    message: str  # one line for humans
    evidence: dict[str, Any] = field(default_factory=dict)  # stored as jsonb
