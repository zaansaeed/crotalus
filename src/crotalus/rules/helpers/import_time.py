"""What runs when a package is imported: within one file, and across the package.

Importing a package runs its __init__.py, top to bottom, then every module it
imports, and so on. Function bodies don't run until they're called. So:

    import_time_nodes(py_file)     the code in one file that runs on import: its top
                                   level and class bodies, plus same-file functions
                                   that code calls (or starts as a thread)
    modules_run_on_import(files)   which files run on import: from each package's
                                   __init__.py (and each top-level module), follow
                                   the imports, as a graph
    top_level_calls(py_files)      the process calls and network requests in those
                                   files' top-level code, with evidence

Used by import_time_code (the files that run on import) and unimported_script_code
(the package's other files, which only run when someone runs them).
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from crotalus.models import AnalysisContext, PyFile
from crotalus.rules.helpers.static_code_analysis import (
    NETWORK_REQUESTS,
    full_name,
    is_process,
    read,
    runs_decoded_or_downloaded_data,
    snippet,
)

# --- Within one file ---------------------------------------------------------------


def import_time_calls(py_file: PyFile) -> Iterator[tuple[str | None, ast.Call]]:
    """(full name, call node) for the calls that run when the module is imported."""
    for node in import_time_nodes(py_file):
        if isinstance(node, ast.Call):
            yield full_name(node.func, py_file.aliases), node


def import_time_nodes(py_file: PyFile) -> Iterator[ast.AST]:
    """Every node of the file that runs when the module is imported.

    That's code at the top level of the file and in class bodies, but not inside
    functions, which only run when called. Except: a function of this file that the
    top level calls, or starts as a thread (`Thread(target=f)`), runs on import too,
    so its body counts as well. Code under `if __name__ == "__main__":` only runs
    when the file is executed directly, so it's skipped.
    """
    top_level_functions = {
        node.name: node
        for node in py_file.tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    nodes_to_visit: list[ast.AST] = list(py_file.tree.body)
    followed_functions: set[str] = set()  # functions whose body is already queued
    while nodes_to_visit:
        node = nodes_to_visit.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue  # defined here, not run here
        if _is_main_guard(node):
            continue
        yield node
        if isinstance(node, ast.Call):
            # f() or Thread(target=f): f's body runs now too. Each function once.
            functions_run_by_call = [
                node.func,
                *(kw.value for kw in node.keywords if kw.arg == "target"),
            ]
            for function in functions_run_by_call:
                if isinstance(function, ast.Name) and function.id in top_level_functions:
                    if function.id not in followed_functions:
                        followed_functions.add(function.id)
                        nodes_to_visit.extend(top_level_functions[function.id].body)
        nodes_to_visit.extend(ast.iter_child_nodes(node))


def _is_main_guard(node: ast.AST) -> bool:
    """`if __name__ == "__main__":`"""
    return (
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
        and len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == "__main__"
    )


# --- Across the package: the import graph ---------------------------------------


def modules_run_on_import(files: dict[str, str]) -> dict[str, PyFile]:
    """The .py files that run when the package, or any part of it, is imported: path -> PyFile.

    Python runs a package's __init__.py when the package is imported, and a top-level
    module (`six.py`) when it is. Those are the roots. Each file that runs then runs
    the modules it imports, and so on: a graph, walked from the roots. A file nothing
    imports, like a Streamlit app or a launcher script, never runs on import.
    """
    path_of_module = {_module_name(path): path for path in files if path.endswith(".py")}
    paths_to_visit = [  # the roots: packages and top-level modules
        path
        for module, path in path_of_module.items()
        if path.endswith("__init__.py") or "." not in module
    ]
    run_on_import: dict[str, PyFile] = {}
    while paths_to_visit:
        path = paths_to_visit.pop()
        if path in run_on_import:
            continue
        py_file = read(files[path])
        if py_file is None:
            continue
        run_on_import[path] = py_file
        for module in imported_modules(py_file, _module_name(path), path.endswith("__init__.py")):
            if module in path_of_module:
                paths_to_visit.append(path_of_module[module])
    return run_on_import


def imported_modules(py_file: PyFile, module: str, is_package: bool) -> set[str]:
    """The modules a file imports when it's imported itself, as full dotted names.

    Includes every name that could be a module: `from pkg import x` might import
    the submodule pkg.x, and importing pkg.sub also runs pkg. Names that aren't
    modules of this package (functions, `os`) simply don't match a file.
    """
    names: set[str] = set()
    for node in import_time_nodes(py_file):
        if isinstance(node, ast.Import):  # import pkg.sub
            for alias in node.names:
                names |= _with_parents(alias.name)
        elif isinstance(node, ast.ImportFrom):  # from .sub import x
            imported_from = _absolute_module(node, module, is_package)
            if imported_from:
                names |= _with_parents(imported_from)
                names |= {f"{imported_from}.{alias.name}" for alias in node.names}
    return names


def _absolute_module(node: ast.ImportFrom, module: str, is_package: bool) -> str | None:
    """The full name of what `from X import ...` imports from, inside `module`.

    `from .sub import x` in pkg/__init__.py -> "pkg.sub"; `from .. import y` in
    pkg/a/b.py -> "pkg". None if it climbs above the top package.
    """
    if node.level == 0:
        return node.module
    package = module if is_package else module.rpartition(".")[0]
    parts = package.split(".")
    if node.level - 1 >= len(parts):
        return None
    parts = parts[: len(parts) - (node.level - 1)]
    return ".".join([*parts, node.module] if node.module else parts)


def _module_name(path: str) -> str:
    """The module a file is: "pkg/sub/__init__.py" -> "pkg.sub", "src/pkg/a.py" -> "pkg.a"."""
    path = path.removeprefix("src/").removesuffix(".py").removesuffix("/__init__")
    return path.replace("/", ".")


def _with_parents(module: str) -> set[str]:
    """a.b.c -> {a, a.b, a.b.c}: importing a module runs its parent packages too."""
    parts = module.split(".")
    return {".".join(parts[:end]) for end in range(1, len(parts) + 1)}


# --- The package's code and its top-level calls ----------------------------------


# Folders and files that aren't the package's own code. Template folders hold files
# for generating new projects (e.g. cookiecutter hooks).
NOT_PACKAGE_CODE_FOLDERS = {"tests", "test", "testing", "docs", "doc", "examples", "scripts"}
NOT_PACKAGE_CODE_FILES = {"setup.py", "conftest.py", "__main__.py"}


def installed_package_code(context: AnalysisContext) -> tuple[str, dict[str, str]] | None:
    """("wheel" or "sdist", path -> source) of the package's own .py files.

    From the wheel if there is one, since that's what gets installed; otherwise the
    sdist. Tests, docs, examples, templates, setup.py and __main__.py are left out.
    """
    archive_name, contents = ("wheel", context.wheel) if context.wheel else ("sdist", context.sdist)
    if contents is None:
        return None
    return archive_name, {
        path: source for path, source in contents.files.items() if _package_code(path)
    }


def _package_code(path: str) -> bool:
    if not path.endswith(".py"):
        return False
    *folders, filename = path.split("/")
    if filename in NOT_PACKAGE_CODE_FILES or filename.startswith("test_"):
        return False
    return not any(f in NOT_PACKAGE_CODE_FOLDERS or "template" in f for f in folders)


@dataclass
class TopLevelCalls:
    """The process calls and network requests in some files' top-level code."""

    process_calls: set[str] = field(default_factory=set)
    network_calls: set[str] = field(default_factory=set)
    runs_hidden_data: bool = False  # a process started with decoded or downloaded data
    locations: list[dict[str, Any]] = field(default_factory=list)  # file, call, line, snippet

    def files(self) -> list[str]:
        return sorted({location["file"] for location in self.locations})

    def description(self) -> str:
        """What the calls do, e.g. "starts programs and uses the network"."""
        behaviours = []
        if self.process_calls:
            behaviours.append("starts programs")
        if self.network_calls:
            behaviours.append("uses the network")
        return " and ".join(behaviours)

    def evidence(self, archive_name: str) -> dict[str, Any]:
        return {
            "archive": archive_name,
            "files": self.files(),
            "process_calls": sorted(self.process_calls),
            "network_calls": sorted(self.network_calls),
            "runs_decoded_or_downloaded_data": self.runs_hidden_data,
            "calls": self.locations[:10],  # the first few is enough to see what it does
        }


def top_level_calls(py_files: dict[str, PyFile]) -> TopLevelCalls:
    """The process calls and network requests in the files' top-level code.

    Network requests means calls that connect somewhere (NETWORK_REQUESTS), not all
    of a network module: API clients build settings like httpx.Timeout(...) at the
    top level, which sends nothing.
    """
    found = TopLevelCalls()
    for path, py_file in sorted(py_files.items()):
        for call_name, call_node in import_time_calls(py_file):
            if call_name in NETWORK_REQUESTS:
                found.network_calls.add(call_name)
            elif call_name and is_process(call_name):
                found.process_calls.add(call_name)
                found.runs_hidden_data |= runs_decoded_or_downloaded_data(call_node, py_file)
            else:
                continue
            found.locations.append(
                {
                    "file": path,
                    "call": call_name,
                    "line": call_node.lineno,
                    "snippet": snippet(py_file, call_node),
                }
            )
    return found
