"""No homepage or repository links.

Real projects usually point to their source; throwaway malware rarely bothers.
"""

from __future__ import annotations

from crotalus.models import AnalysisContext, Finding


def check(context: AnalysisContext) -> list[Finding]:
    if context.metadata.project_urls:
        return []

    return [
        Finding(
            rule_id="no_project_links",
            severity="low",
            message="no homepage or repository links",
        )
    ]
