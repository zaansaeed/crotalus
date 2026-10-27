"""Detection rules. Each rule looks at one release's context and returns what it found.

    metadata/              PyPI's information about the release, never its code
    hidden_code/           code that runs from somewhere a reader wouldn't look
    process_and_network/   programs and network calls, by when they run
    helpers/               reading code, and the import graph, for the code rules

To add a rule: write a module with a `check` function matching `Rule` in the
folder it fits, then add it to RULES.
"""

from __future__ import annotations

from collections.abc import Callable

from crotalus.models import AnalysisContext, Finding
from crotalus.rules.hidden_code import hidden_code_exec, pth_import_running_code
from crotalus.rules.metadata import (
    late_file_upload,
    missing_metadata,
    new_package,
    no_project_links,
    sdist_only,
    suspicious_links,
    typosquat,
)
from crotalus.rules.process_and_network import (
    import_time_code,
    setup_py_install_time,
    unimported_script_code,
)

Rule = Callable[[AnalysisContext], list[Finding]]

RULES: list[Rule] = [
    # metadata/
    typosquat.check,
    sdist_only.check,
    no_project_links.check,
    missing_metadata.check,
    late_file_upload.check,
    suspicious_links.check,
    new_package.check,
    # hidden_code/
    hidden_code_exec.check,
    pth_import_running_code.check,
    # process_and_network/
    setup_py_install_time.check,
    import_time_code.check,
    unimported_script_code.check,
]
