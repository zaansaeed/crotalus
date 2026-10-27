"""Package code that starts programs or uses the network as soon as it's imported.

The way into a real, trusted package once its account or build is compromised:
add a few lines to its __init__.py, and they run on every `import pkg`, on every
machine that installed the new version, before any of its functions are called:

    # pkg/__init__.py
    import subprocess, base64
    subprocess.Popen([sys.executable, "-c", base64.b64decode("aW1wb3J0IG9z...")])

The same check as setup_py_install_time, for every module of the package, but only
for code that runs on import (static_code_analysis_helpers.import_time_calls):

- process calls, or network requests                           -> high
- both, or a process started with decoded or downloaded data   -> critical

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
    import_time_calls,
    is_process,
    origins,
    read,
    snippet,
)

# Folders whose files aren't imported when the package is used. Template folders
# hold files for generating new projects (e.g. cookiecutter hooks), not package code.
NOT_IMPORTED_FOLDERS = {"tests", "test", "testing", "docs", "doc", "examples", "scripts"}
NOT_IMPORTED_FILES = {"setup.py", "conftest.py", "__main__.py"}


def check(context: AnalysisContext) -> list[Finding]:
    archive_name, contents = ("wheel", context.wheel) if context.wheel else ("sdist", context.sdist)
    if contents is None:
        return []

    process_calls: set[str] = set()
    network_calls: set[str] = set()
    runs_hidden_data = False  # a process started with decoded or downloaded data
    examples: list[dict[str, Any]] = []  # where each call is, for the evidence
    for path, source in sorted(contents.files.items()):
        if not _imported(path):
            continue
        py_file = read(source)
        if py_file is None:
            continue
        for call_name, call_node in import_time_calls(py_file):
            if call_name is None:
                continue
            if is_process(call_name):
                process_calls.add(call_name)
                arguments = [*call_node.args, *(kw.value for kw in call_node.keywords)]
                if any(origins(argument, py_file) for argument in arguments):
                    runs_hidden_data = True
            elif call_name in NETWORK_REQUESTS:
                network_calls.add(call_name)
            else:
                continue
            examples.append(
                {
                    "file": path,
                    "call": call_name,
                    "line": call_node.lineno,
                    "snippet": snippet(py_file, call_node),
                }
            )
    if not examples:
        return []

    kinds = []
    if process_calls:
        kinds.append("starts programs")
    if network_calls:
        kinds.append("uses the network")
    files = sorted({example["file"] for example in examples})
    critical = runs_hidden_data or (process_calls and network_calls)
    return [
        Finding(
            rule_id="import_time_code",
            severity="critical" if critical else "high",
            message=f"importing the package {' and '.join(kinds)} ({', '.join(files[:3])})",
            evidence={
                "archive": archive_name,
                "files": files,
                "process_calls": sorted(process_calls),
                "network_calls": sorted(network_calls),
                "runs_decoded_or_downloaded_data": runs_hidden_data,
                "calls": examples[:10],  # the first few is enough to see what it does
            },
        )
    ]


def _imported(path: str) -> bool:
    """Whether a .py file is part of what `import pkg` can load."""
    if not path.endswith(".py"):
        return False
    *folders, filename = path.split("/")
    if filename in NOT_IMPORTED_FILES or filename.startswith("test_"):
        return False
    return not any(folder in NOT_IMPORTED_FOLDERS or "template" in folder for folder in folders)
