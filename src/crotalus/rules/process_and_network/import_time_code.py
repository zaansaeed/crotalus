"""Package code that starts programs or uses the network as soon as it's imported.

The way into a real, trusted package once its account or build is compromised:
add a few lines to its __init__.py, and they run on every `import pkg`, on every
machine that installed the new version, before any of its functions are called:

    # pkg/__init__.py
    import subprocess, base64
    subprocess.Popen([sys.executable, "-c", base64.b64decode("aW1wb3J0IG9z...")])

Checks the modules `import pkg` actually loads (modules_run_on_import: each
package's __init__.py and what it imports, followed through the import graph), and
in them, the code that runs on import (import_time_calls):

- process calls, or network requests                           -> high
- both, or a process started with decoded or downloaded data   -> critical

Higher than setup_py_install_time's medium for the same calls: setup.py files
often run build tools, but honest libraries almost never start programs or make
requests just because they were imported. And a compromised library has nothing
else wrong with it (an old project, real links), so this finding has to be
suspicious on its own.

Modules nothing imports (a Streamlit app, a launcher script) only run when someone
runs them: unimported_script_code's job. Not followed: imports by a computed name
(importlib.import_module(name)) and calls into functions of other files.
"""

from __future__ import annotations

from crotalus.models import AnalysisContext, Finding, Severity
from crotalus.rules.helpers.import_graph import (
    import_time_calls,
    installed_package_code,
    modules_run_on_import,
)
from crotalus.rules.helpers.static_code_analysis import (
    calls_evidence,
    describe_calls,
    process_and_network_calls,
)


def check(context: AnalysisContext) -> list[Finding]:
    package_code = installed_package_code(context)
    if package_code is None:
        return []
    archive_name, files = package_code

    run_on_import = modules_run_on_import(files)
    found = process_and_network_calls(
        {path: source for path, source in files.items() if path in run_on_import},
        import_time_calls,
    )
    if not found.calls:
        return []
    critical = found.runs_hidden_data or (found.process_calls and found.network_calls)
    severity: Severity = "critical" if critical else "high"
    return [
        Finding(
            rule_id="import_time_code",
            severity=severity,
            message=f"importing the package {describe_calls(found)} ({', '.join(found.files[:3])})",
            evidence=calls_evidence(found, archive_name),
        )
    ]
