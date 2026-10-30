"""Which files run when a package is installed or imported: the import graph.

Importing a package runs its __init__.py, top to bottom, then every module it
imports, and so on (within one file, static_code_analysis.import_time_nodes says
which code runs). So:

    modules_run_on_import(files)   which files run on import: from each package's
                                   __init__.py (and each top-level module), follow
                                   the imports, as a graph
    modules_run_on_install(files)  which sdist files run on install: the same graph,
                                   from setup.py
    installed_package_code(ctx)    the package's own .py files, from what gets
                                   installed

Used by process_and_network/process_and_network_code.
"""

from __future__ import annotations

import ast

from crotalus.models import AnalysisContext, PyFile
from crotalus.rules.helpers.static_code_analysis import import_time_nodes, read

# --- The import graph -------------------------------------------------------------


def modules_run_on_import(files: dict[str, str]) -> set[str]:
    """The paths of the .py files that run when the package, or any part of it, is imported.

    Python runs a package's __init__.py when the package is imported, and a top-level
    module (`six.py`) when it is. Those are the roots. A file nothing imports, like a
    Streamlit app or a launcher script, never runs on import.
    """
    roots = [
        path for path in files if path.endswith("__init__.py") or "." not in _module_name(path)
    ]
    return modules_run_from(roots, files)


def modules_run_on_install(sdist_files: dict[str, str]) -> set[str]:
    """The paths of the sdist's .py files that run when pip installs it: setup.py,
    and the modules it imports (`from mypkg import __version__` runs mypkg/__init__.py).
    """
    return modules_run_from(["setup.py"], sdist_files) if "setup.py" in sdist_files else set()


def modules_run_from(roots: list[str], files: dict[str, str]) -> set[str]:
    """The roots, every file they import, every file those import, and so on.

    Each file is parsed only to read its imports, and its tree is let go before the
    next one: parse trees are many times the size of the source, so a big package
    with every tree in memory at once could need gigabytes.
    """
    path_of_module = {_module_name(path): path for path in files}
    paths_to_visit = list(roots)
    run: set[str] = set()
    while paths_to_visit:
        path = paths_to_visit.pop()
        if path in run:
            continue
        py_file = read(files[path])
        if py_file is None:
            continue
        run.add(path)
        for module in imported_modules(py_file, _module_name(path), path.endswith("__init__.py")):
            if module in path_of_module:
                paths_to_visit.append(path_of_module[module])
    return run


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


# --- The package's own code -------------------------------------------------------


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
        path: source for path, source in contents.python_files.items() if _package_code(path)
    }


def _package_code(path: str) -> bool:
    *folders, filename = path.split("/")
    if filename in NOT_PACKAGE_CODE_FILES or filename.startswith("test_"):
        return False
    return not any(f in NOT_PACKAGE_CODE_FOLDERS or "template" in f for f in folders)
