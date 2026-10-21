"""Files added to a release long after its first one.

A compromised account can slip a malicious file into an existing release instead
of publishing a new version, where people would notice. CI pipelines that build
wheels for many platforms can take hours, so only a gap of a day or more counts.

Only fires when a release is analyzed after the late file arrived. A release
analyzed minutes after upload has no late files yet.
"""

from __future__ import annotations

from datetime import timedelta

from crotalus.models import AnalysisContext, Finding

LATE_AFTER = timedelta(days=1)


def check(context: AnalysisContext) -> list[Finding]:
    first = context.metadata.uploaded_at  # earliest file of the release
    if first is None:
        return []

    late = [f for f in context.metadata.files if f.uploaded_at - first >= LATE_AFTER]
    if not late:
        return []

    return [
        Finding(
            rule_id="late_file_upload",
            severity="medium",
            message=f"{len(late)} file(s) added a day or more after the release was published",
            evidence={
                "release_uploaded_at": first.isoformat(),
                "late_files": [
                    {"filename": f.filename, "uploaded_at": f.uploaded_at.isoformat()}
                    for f in late
                ],
            },
        )
    ]
