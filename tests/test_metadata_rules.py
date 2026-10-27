"""Tests for the rules that only look at a release's PyPI metadata."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import ModuleType
from typing import Any

import pytest

from crotalus.models import (
    AnalysisContext,
    Finding,
    PackageHistory,
    Release,
    ReleaseFile,
    ReleaseMetadata,
)
from crotalus.rules.metadata import (
    late_file_upload,
    missing_metadata,
    no_project_links,
    sdist_only,
    suspicious_links,
)

T0 = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)


def file(filename: str, packagetype: str, uploaded_at: datetime = T0) -> ReleaseFile:
    return ReleaseFile(
        filename=filename,
        url=f"https://files.pythonhosted.org/{filename}",
        packagetype=packagetype,
        size=1000,
        sha256="00" * 32,
        uploaded_at=uploaded_at,
    )


SDIST = file("pkg-1.0.tar.gz", "sdist")
WHEEL = file("pkg-1.0-py3-none-any.whl", "bdist_wheel")


# A well-behaved release: no rule here should flag it.
GOOD = ReleaseMetadata(
    name="pkg",
    version="1.0",
    summary="A package",
    author="Someone",
    project_urls={"Source": "https://github.com/someone/pkg"},
    files=(SDIST, WHEEL),
    uploaded_at=T0,
)


def context(**changes: Any) -> AnalysisContext:
    """GOOD with some fields changed, e.g. context(summary=None)."""
    return AnalysisContext(
        release=Release(id=1, name="pkg", version="1.0"),
        metadata=replace(GOOD, **changes),  # a copy of the frozen dataclass with `changes`
        package_history=PackageHistory(),
    )


def rule_ids(findings: list[Finding]) -> list[str]:
    return [f.rule_id for f in findings]


ALL_RULES = [sdist_only, no_project_links, missing_metadata, late_file_upload, suspicious_links]


@pytest.mark.parametrize("rule", ALL_RULES)
def test_well_behaved_release_is_not_flagged(rule: ModuleType) -> None:
    assert rule.check(context()) == []


# sdist_only


def test_sdist_only() -> None:
    findings = sdist_only.check(context(files=(SDIST,)))
    assert rule_ids(findings) == ["sdist_only"]
    assert findings[0].evidence == {"files": ["pkg-1.0.tar.gz"]}


def test_wheel_only_is_fine() -> None:
    assert sdist_only.check(context(files=(WHEEL,))) == []


def test_no_files_is_not_sdist_only() -> None:
    assert sdist_only.check(context(files=(), uploaded_at=None)) == []


# no_project_links


def test_no_project_links() -> None:
    assert rule_ids(no_project_links.check(context(project_urls={}))) == ["no_project_links"]


# missing_metadata


def test_missing_summary_and_author() -> None:
    findings = missing_metadata.check(context(summary=None, author=None))
    assert rule_ids(findings) == ["missing_metadata"]


def test_missing_only_one_is_fine() -> None:
    assert missing_metadata.check(context(summary=None)) == []
    assert missing_metadata.check(context(author=None)) == []


# late_file_upload


def test_file_added_days_later() -> None:
    late_wheel = file("pkg-1.0-py3-none-any.whl", "bdist_wheel", T0 + timedelta(days=3))
    findings = late_file_upload.check(context(files=(SDIST, late_wheel)))
    assert rule_ids(findings) == ["late_file_upload"]
    assert [f["filename"] for f in findings[0].evidence["late_files"]] == [late_wheel.filename]


def test_wheels_built_hours_later_are_fine() -> None:
    ci_wheel = file("pkg-1.0-cp312-win_amd64.whl", "bdist_wheel", T0 + timedelta(hours=5))
    assert late_file_upload.check(context(files=(SDIST, ci_wheel))) == []


# suspicious_links


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://github.com/someone/pkg", None),
        ("https://pkg.readthedocs.io", None),
        ("http://203.0.113.7/pkg", "raw IP address"),
        ("https://bit.ly/3abc", "URL shortener"),
        ("https://discord.gg/abcdef", "chat invite"),
        ("https://cdn.discord.com/x", "chat invite"),  # subdomains count
        ("https://notdiscord.com", None),  # but not lookalike names
        ("https://pastebin.com/raw/abc", "paste site"),
        ("ftp://example.com/pkg", "unusual scheme 'ftp'"),
        ("not a url", "unusual scheme ''"),
    ],
)
def test_link_problem(url: str, reason: str | None) -> None:
    assert suspicious_links.link_problem(url) == reason


def test_suspicious_links_finding() -> None:
    findings = suspicious_links.check(
        context(
            project_urls={
                "Source": "https://github.com/someone/pkg",
                "Chat": "https://discord.gg/abcdef",
            }
        )
    )
    assert rule_ids(findings) == ["suspicious_links"]
    assert findings[0].evidence == {
        "links": [{"label": "Chat", "url": "https://discord.gg/abcdef", "reason": "chat invite"}]
    }
