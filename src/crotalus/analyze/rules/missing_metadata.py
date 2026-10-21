"""No summary and no author: the marks of a low-effort, throwaway upload."""

from __future__ import annotations

from crotalus.models import AnalysisContext, Finding


def check(context: AnalysisContext) -> list[Finding]:
    metadata = context.metadata
    if metadata.summary is not None or metadata.author is not None:
        return []

    return [
        Finding(
            rule_id="missing_metadata",
            severity="low",
            message="no summary and no author",
        )
    ]
