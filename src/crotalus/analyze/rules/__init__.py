"""Detection rules. Each rule looks at one release's context and returns what it found.

To add a rule: write a module with a `check` function matching `Rule`,
then add it to RULES.
"""

from __future__ import annotations

from collections.abc import Callable

from crotalus.analyze.rules import (
    late_file_upload,
    missing_metadata,
    new_package,
    no_project_links,
    sdist_only,
    suspicious_links,
    typosquat,
)
from crotalus.models import AnalysisContext, Finding

Rule = Callable[[AnalysisContext], list[Finding]]

RULES: list[Rule] = [
    typosquat.check,
    sdist_only.check,
    no_project_links.check,
    missing_metadata.check,
    late_file_upload.check,
    suspicious_links.check,
    new_package.check,
]
