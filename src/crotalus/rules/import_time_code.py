"""Package code that starts programs or uses the network as soon as it's imported.

The way into a real, trusted package once its account or build is compromised:
add a few lines to its __init__.py, and they run on every `import pkg`, on every
machine that installed the new version, before any of its functions are called:

    # pkg/__init__.py
    import subprocess, base64
    subprocess.Popen([sys.executable, "-c", base64.b64decode("aW1wb3J0IG9z...")])

The same check as setup_py_install_time, for every module of the package, but only
for code that runs on import (static_code_analysis_helpers.import_time_calls):

- process calls, or network requests                           -> medium
- both                                                         -> high
- a process started with decoded or downloaded data            -> critical

Network requests means calls that connect somewhere (NETWORK_REQUESTS), not all of
a network module: API clients routinely build settings like httpx.Timeout(...) at
import time, which sends nothing.

Not checked: setup.py (setup_py_install_time's job), tests, docs, examples, project
templates and __main__.py, which aren't imported when the package is used. The wheel is checked
when there is one, since that's what gets installed; otherwise the sdist.
"""

from __future__ import annotations

from typing import Any

from crotalus.models import AnalysisContext, Finding
from crotalus.rules.static_code_analysis_helpers import (
    NETWORK_REQUESTS,
    code_severity,
    import_time_calls,
    is_process,
    read,
    runs_decoded_or_downloaded_data,
    snippet,
)

# Folders whose files aren't imported when the package is used. Template folders
# hold files for generating new projects (e.g. cookiecutter hooks), not package code.
NOT_IMPORTED_FOLDERS = {"tests", "test", "testing", "docs", "doc", "examples", "scripts"}
NOT_IMPORTED_FILES = {"setup.py", "conftest.py", "__main__.py"}


def check(context: AnalysisContext) -> list[Finding]:
    archive_name, archive = ("wheel", context.wheel) if context.wheel else ("sdist", context.sdist)
    if archive is None:
        return []

    process_calls: set[str] = set()
    network_calls: set[str] = set()
    runs_hidden_data = False  # a process started with decoded or downloaded data
    call_locations: list[dict[str, Any]] = []  # where each call is, for the evidence
    for path, source in sorted(archive.files.items()):
        py_file = read(source) if _loaded_by_import(path) else None
        if py_file is None:
            continue
        for call_name, call_node in import_time_calls(py_file):
            if call_name in NETWORK_REQUESTS:
                network_calls.add(call_name)
            elif call_name and is_process(call_name):
                process_calls.add(call_name)
                runs_hidden_data |= runs_decoded_or_downloaded_data(call_node, py_file)
            else:
                continue
            call_locations.append(
                {
                    "file": path,
                    "call": call_name,
                    "line": call_node.lineno,
                    "snippet": snippet(py_file, call_node),
                }
            )
    if not call_locations:
        return []

    behaviours = []
    if process_calls:
        behaviours.append("starts programs")
    if network_calls:
        behaviours.append("uses the network")
    files = sorted({location["file"] for location in call_locations})
    return [
        Finding(
            rule_id="import_time_code",
            severity=code_severity(bool(process_calls), bool(network_calls), runs_hidden_data),
            message=f"importing the package {' and '.join(behaviours)} ({', '.join(files[:3])})",
            evidence={
                "archive": archive_name,
                "files": files,
                "process_calls": sorted(process_calls),
                "network_calls": sorted(network_calls),
                "runs_decoded_or_downloaded_data": runs_hidden_data,
                "calls": call_locations[:10],  # the first few is enough to see what it does
            },
        )
    ]


def _loaded_by_import(path: str) -> bool:
    """Whether a .py file is part of what `import pkg` can load."""
    if not path.endswith(".py"):
        return False
    *folders, filename = path.split("/")
    if filename in NOT_IMPORTED_FILES or filename.startswith("test_"):
        return False
    return not any(folder in NOT_IMPORTED_FOLDERS or "template" in folder for folder in folders)
