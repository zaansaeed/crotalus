"""A package that's brand new: created days, hours, or seconds before this release.

Most malicious packages are created, uploaded and removed within days. New
packages are also everyday on PyPI, so this mostly matters next to other findings
(e.g. new + typosquat + no links).

Age is measured at this release's upload time, not now, so re-analyzing an old
release gives the same answer it would have when it came out.
"""

from __future__ import annotations

from datetime import timedelta

from crotalus.models import AnalysisContext, Finding

NEW_WITHIN = timedelta(days=7)
VERY_NEW_WITHIN = timedelta(days=1)


def check(context: AnalysisContext) -> list[Finding]:
    first_upload = context.package_history.first_uploaded_at
    this_upload = context.metadata.uploaded_at
    if first_upload is None or this_upload is None:
        return []

    age = this_upload - first_upload
    if age >= NEW_WITHIN:
        return []

    if age == timedelta(0):
        message = "first release of a brand-new package"
    elif age < VERY_NEW_WITHIN:
        message = f"package was created {age.total_seconds() / 3600:.0f} hours before this release"
    else:
        message = f"package was created {age.days} days before this release"

    return [
        Finding(
            rule_id="new_package",
            severity="medium" if age < VERY_NEW_WITHIN else "low",
            message=message,
            evidence={
                "first_uploaded_at": first_upload.isoformat(),
                "age_hours": round(age.total_seconds() / 3600, 1),
            },
        )
    ]
