"""Detection rules. Each rule looks at one release's context and returns what it found.

To add a rule: write a module with a `check` function matching `Rule`,
then add it to RULES.
"""

from __future__ import annotations

from collections.abc import Callable

from crotalus.models import AnalysisContext, Finding
from crotalus.rules import (
    hidden_code_exec,
    late_file_upload,
    missing_metadata,
    new_package,
    no_project_links,
    pth_import_running_code,
    sdist_only,
    suspicious_links,
    typosquat,
)

Rule = Callable[[AnalysisContext], list[Finding]]

RULES: list[Rule] = [
    typosquat.check,
    sdist_only.check,
    no_project_links.check,
    missing_metadata.check,
    late_file_upload.check,
    suspicious_links.check,
    new_package.check,
    # Code rules: read the sdist's and wheel's source (see static_code_analysis_helpers.py).
    hidden_code_exec.check,
    pth_import_running_code.check,
]
