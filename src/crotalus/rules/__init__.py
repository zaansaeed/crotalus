"""Detection rules. Each rule looks at one release's context and returns what it found.

To add a rule: write a module with a `check` function matching `Rule`,
then add it to RULES.
"""

from __future__ import annotations

from collections.abc import Callable

from crotalus.models import AnalysisContext, Finding
from crotalus.rules import (
    hidden_code_exec,
    import_time_code,
    late_file_upload,
    missing_metadata,
    new_package,
    no_project_links,
    pth_import_running_code,
    sdist_only,
    setup_py_install_time,
    suspicious_links,
    typosquat,
    unimported_script_code,
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
    # Code rules: read the sdist's and wheel's source (see rules/helpers/).
    hidden_code_exec.check,
    pth_import_running_code.check,
    setup_py_install_time.check,
    import_time_code.check,
    unimported_script_code.check,
]
