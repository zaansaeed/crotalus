from datetime import datetime, timedelta, timezone

import pytest

from crotalus.analyze.rules.new_package import check
from crotalus.models import AnalysisContext, Finding, PackageInfo, Release, ReleaseMetadata

UPLOADED = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)


def context(age: timedelta | None, uploaded_at: datetime | None = UPLOADED) -> AnalysisContext:
    """A release uploaded at `uploaded_at`, whose package first appeared `age` earlier."""
    first = None if age is None or uploaded_at is None else uploaded_at - age
    return AnalysisContext(
        release=Release(id=1, name="pkg", version="1.0"),
        metadata=ReleaseMetadata(name="pkg", version="1.0", uploaded_at=uploaded_at),
        package=PackageInfo(first_uploaded_at=first),
    )


def test_first_release_of_new_package() -> None:
    assert check(context(timedelta(0))) == [
        Finding(
            rule_id="new_package",
            severity="medium",
            message="first release of a brand-new package",
            evidence={"first_uploaded_at": UPLOADED.isoformat(), "age_hours": 0.0},
        )
    ]


def test_created_hours_before() -> None:
    [finding] = check(context(timedelta(hours=5)))
    assert finding.severity == "medium"
    assert finding.message == "package was created 5 hours before this release"


def test_created_days_before() -> None:
    [finding] = check(context(timedelta(days=3)))
    assert finding.severity == "low"
    assert finding.message == "package was created 3 days before this release"


@pytest.mark.parametrize("age", [timedelta(days=7), timedelta(days=4000)])
def test_established_package(age: timedelta) -> None:
    assert check(context(age)) == []


def test_unknown_history() -> None:
    assert check(context(None)) == []  # first upload never looked up / no files
    assert check(context(timedelta(0), uploaded_at=None)) == []  # release has no files
