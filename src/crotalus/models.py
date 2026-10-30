"""The data passed between crotalus's parts: the poller, worker, triager, PyPI and the rules.

Only plain data lives here, no behaviour, so any module can import it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

# How crotalus found a release; matches the CHECK on releases.source.
Source = Literal["rss", "on_demand"]

# Matches the CHECK on findings.severity.
Severity = Literal["low", "medium", "high", "critical"]

# A release's verdict. Matches the CHECKs on releases.rules_verdict (from the rules'
# findings, see scoring.py) and releases.final_verdict (the rules' verdict adjusted
# by the LLM's opinion).
Verdict = Literal["clean", "suspicious", "likely_malicious"]

# The LLM's opinion of a flagged release (see triage.py). Matches the CHECKs on
# triage.verdict and releases.llm_verdict.
LLMVerdict = Literal["benign", "suspicious", "malicious"]


# One item of PyPI's RSS feed: a release the poller should store.
@dataclass(frozen=True)
class FeedEntry:
    name: str  # PEP 503 normalized,
    version: str  # e.g. "0.5.20"
    published_at: datetime  # timezone-aware, UTC
    source: Source  # "rss" or "on_demand"


# One release, as stored in the releases table.
@dataclass(frozen=True)
class Release:
    id: int
    name: str  # PEP 503 normalized
    version: str


# A release the rules flagged, waiting for the LLM's opinion (see triager.py).
@dataclass(frozen=True)
class FlaggedRelease:
    release: Release
    rules_verdict: Verdict  # "suspicious" or "likely_malicious"


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
class PackageHistory:
    first_uploaded_at: datetime | None = None  # the package's first file on PyPI; its age


# The source files read out of one downloaded archive (an sdist or a wheel).
@dataclass(frozen=True)
class DistributionContents:
    filename: str  # e.g. "pkg-1.0.tar.gz"

    # Path inside the archive -> the file's text, for the files rules read. An
    # sdist's top folder ("pkg-1.0/") is dropped, so its setup.py is just "setup.py".
    # Paths are as the archive gives them: a hostile one like "../../evil.py" is
    # kept as-is (and never written anywhere). Built by distribution.distribution_contents.
    python_files: dict[str, str] = field(default_factory=dict)  # every .py
    pth_files: dict[str, str] = field(default_factory=dict)  # every .pth


# One Python file from an archive, parsed, with what its names mean. Made by
# rules/helpers/static_code_analysis.read for the code rules.
@dataclass(frozen=True)
class PyFile:
    file_contents: str
    tree: ast.Module
    aliases: dict[str, str]  # local name -> full name: "b" -> "base64", "e" -> "exec"
    origins: dict[str, set[str]]  # variable -> decoder/network calls its value came from


# Everything the rules (and the LLM) get to look at for one release. Built by
# analysis_context.build_analysis_context. Grows as rules need more (the previous
# version's diff, ...).
@dataclass(frozen=True)
class AnalysisContext:
    release: Release
    metadata: ReleaseMetadata
    package_history: PackageHistory
    # None when the release has no such file, or it was too big to download.
    sdist: DistributionContents | None = None
    wheel: DistributionContents | None = None


# One thing a rule found wrong with a release. Stored in the findings table.
@dataclass(frozen=True)
class Finding:
    rule_id: str  # snake_case, e.g. "typosquat"
    severity: Severity
    message: str  # one line for humans
    evidence: dict[str, Any] = field(default_factory=dict)  # stored as jsonb


# The LLM's opinion of a release the rules flagged. Stored in the triage table, next
# to the rules' verdict rather than in place of it, so the two can be compared.
@dataclass(frozen=True)
class TriageResult:
    verdict: LLMVerdict
    confidence: float  # 0 to 1
    reasoning: str  # a few sentences for humans
    false_positive_rules: tuple[str, ...]  # rule_ids the LLM thinks are honest code
    model: str  # e.g. "gemini-flash-lite-latest"
    prompt_version: str  # which prompt produced this; bump it when the prompt changes
