"""Reading a release's Python code: what its names mean, and where values come from.

Malware rarely calls things by their plain names. `exec(base64.b64decode(x))` can
also be written `import base64 as b; exec(b.b64decode(x))`, `builtins.exec(...)`,
`e = exec; e(...)` or `__import__("base64").b64decode(x)`. `full_name` resolves all
of those to the same names ("exec", "base64.b64decode"), so a rule only has to check
those names against the groups below.

`read` also tracks where values come from: after `data = zlib.decompress(blob)`,
`data` is known to hold decoded data, so `exec(data)` is caught too.

The flow, for `import base64 as b; data = b.b64decode(x); exec(data)`:

    python_files(context)                → each .py file: ("wheel", "pkg/setup.py", source)
    read(source)                         → PyFile (None if it isn't valid Python 3):
        .tree                            →   the parsed code
        .aliases                         →   {"b": "base64"}
        .origins                         →   {"data": {"base64.b64decode"}}
    calls(py_file)                       → every call with its full name; keep exec/eval/compile
    origins(call_node.args[0], py_file)  → {"base64.b64decode"} → a decoder → critical finding
        get the origin (or the full value) of what this exec/eval calls.
        is it a decoder or network call? -> critical finding
    snippet(py_file, call_node)          → "exec(data)" for the evidence

Each file is read once; the other helpers take the PyFile.

Aliases and origins both come from assignments; the difference is the function
itself vs what it returns (`f` vs `f()`):

    e = exec               # names a function -> alias:  e is exec
    data = b.b64decode(x)  # calls a function -> origin: data holds what b64decode returned

Imports make aliases too (`import base64 as b`: b is base64). Aliases name the
function being called, so `e(...)` is recognised as exec; origins say what's passed
into it, so `exec(data)` is known to run decoded data.

This is static analysis: names built at runtime (`getattr(builtins, "ex" + "ec")`)
can't be resolved, and come back as None.
"""

from __future__ import annotations

import ast
import warnings
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from crotalus.models import AnalysisContext, ProcessAndNetworkCalls, PyFile

# --- Groups of dangerous names, as full_name resolves them -------------------------

# Run a string or bytes as Python code.
RUN_CODE = {"exec", "eval", "compile"}

# Turn hidden (encoded or compressed) data back into its original form.
DECODERS = {
    "base64.b64decode",
    "base64.b32decode",
    "base64.b85decode",
    "base64.a85decode",
    "base64.urlsafe_b64decode",
    "base64.decodebytes",
    "binascii.a2b_base64",
    "binascii.unhexlify",
    "bytes.fromhex",
    "codecs.decode",
    "zlib.decompress",
    "gzip.decompress",
    "lzma.decompress",
    "bz2.decompress",
    "marshal.loads",
}

# Start other programs: these names, plus anything in the subprocess module.
PROCESS = {
    "os.system",
    "os.popen",
    "os.startfile",
    "os.execv",
    "os.execve",
    "os.execl",
    "os.execlp",
    "os.execvp",
    "os.spawnl",
    "os.spawnv",
    "os.posix_spawn",
    "pty.spawn",
}

# Talk to the network: anything in these modules.
NETWORK_MODULES = {
    "socket",
    "urllib.request",
    "http.client",
    "ftplib",
    "smtplib",
    "telnetlib",
    "requests",
    "httpx",
    "urllib3",
    "aiohttp",
}


# Calls that actually connect somewhere, as opposed to everything else in a network
# module (settings objects like httpx.Timeout, urllib3.disable_warnings, ...).
NETWORK_REQUESTS = {
    *(
        f"{module}.{method}"
        for module in ("requests", "httpx")
        for method in ("get", "post", "put", "patch", "delete", "head", "options", "request")
    ),
    "httpx.stream",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urllib3.request",
    "aiohttp.request",
    "socket.socket",
    "socket.create_connection",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "ftplib.FTP",
    "smtplib.SMTP",
    "smtplib.SMTP_SSL",
    "telnetlib.Telnet",
}


def is_network(name: str) -> bool:
    """Whether `name` is in a network module: "requests.get" is in "requests"."""
    return any(name == m or name.startswith(m + ".") for m in NETWORK_MODULES)


def is_process(name: str) -> bool:
    return name in PROCESS or name == "subprocess" or name.startswith("subprocess.")


# --- Reading code ------------------------------------------------------------------


def read(source: str) -> PyFile | None:
    """Parse a file and work out what its names mean.

    None if it isn't valid Python 3 (e.g. an old Python 2 setup.py): code that
    can't be parsed can't run on Python 3 either.
    """
    try:
        with warnings.catch_warnings():
            # Package code is full of e.g. invalid escape sequences; not our problem.
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):  # ValueError: null bytes in source
        return None

    # One pass, filling in both maps as names are defined. ast.walk visits the top of
    # the file first and a function's statements in order, so imports are normally
    # known by the time an assignment like `data = b.b64decode(x)` uses them.
    py_file = PyFile(source=source, tree=tree, aliases={}, origins={})
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):  # import base64 as b
            for imported in node.names:
                if imported.asname:
                    py_file.aliases[imported.asname] = imported.name
                else:  # `import urllib.request` makes the name `urllib` available
                    top_level = imported.name.split(".")[0]
                    py_file.aliases[top_level] = top_level

        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for imported in node.names:  # from zlib import decompress as d
                local_name = imported.asname or imported.name
                py_file.aliases[local_name] = f"{node.module}.{imported.name}"

        elif isinstance(node, ast.Assign):
            # `e = exec`: the right side is a plain reference, so `e` now IS exec.
            if (
                len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, (ast.Name, ast.Attribute))
            ):
                resolved = full_name(node.value, py_file.aliases)  # full name of what the value is
                if resolved:
                    py_file.aliases[node.targets[0].id] = resolved

            # `data = b.b64decode(x)` (or `b = data`): the variable now holds decoded or
            # downloaded data. Checked for every assignment, so it carries through copies.
            value_origins = origins(node.value, py_file)
            if value_origins:
                for assign_target in node.targets:
                    for variable in _assigned_names(assign_target):
                        py_file.origins.setdefault(variable, set()).update(value_origins)
    return py_file


def _assigned_names(target: ast.expr) -> Iterator[str]:
    """The variables an assignment sets: `x = ...` and `a, *b = ...`.

    Not the names inside `self.x = ...` or `d[k] = ...`: those change an attribute
    or item, and tainting all of `self` would flag every later use of it.
    """
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _assigned_names(element)
    elif isinstance(target, ast.Starred):
        yield from _assigned_names(target.value)


def full_name(func: ast.expr, aliases: dict[str, str]) -> str | None:
    """What `func` really refers to: `b.b64decode` -> "base64.b64decode"."""
    attributes: list[str] = []
    while isinstance(func, ast.Attribute):  # b.b64decode -> ["b64decode"], then b
        attributes.insert(0, func.attr)
        func = func.value

    if isinstance(func, ast.Name):
        base = aliases.get(func.id, func.id)  # "b" -> "base64", unknown names stay as they are
    elif (  # __import__("subprocess").run -> subprocess.run
        isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == "__import__"
        and func.args
        and isinstance(func.args[0], ast.Constant)
        and isinstance(func.args[0].value, str)
    ):
        base = func.args[0].value
    else:
        return None  # e.g. getattr(...)(...): only known at runtime

    resolved = ".".join([base, *attributes])
    # builtins.exec / __builtins__.exec are just exec
    for prefix in ("builtins.", "__builtins__."):
        resolved = resolved.removeprefix(prefix)
    return resolved


def calls(py_file: PyFile) -> Iterator[tuple[str | None, ast.Call]]:
    """(full name, call node) for every call in the file."""
    for node in ast.walk(py_file.tree):
        if isinstance(node, ast.Call):
            yield full_name(node.func, py_file.aliases), node


# --- Where values come from --------------------------------------------------------


def origins(expr: ast.expr, py_file: PyFile) -> set[str]:
    """The decoder and network calls an expression's value comes from.

    Looks inside the whole expression, so nesting doesn't hide anything:
    `zlib.decompress(base64.b64decode(x))` gives both names, and a variable
    brings along the origins of the value it was assigned.
    """
    value_origins: set[str] = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            call_name = full_name(node.func, py_file.aliases)
            if call_name and (call_name in DECODERS or is_network(call_name)):
                value_origins.add(call_name)
        elif isinstance(node, ast.Name):
            value_origins |= py_file.origins.get(node.id, set())
    return value_origins


def runs_decoded_or_downloaded_data(call_node: ast.Call, py_file: PyFile) -> bool:
    """Whether any argument of a call holds decoded or downloaded data."""
    arguments = [*call_node.args, *(kw.value for kw in call_node.keywords)]
    return any(origins(argument, py_file) for argument in arguments)


# --- For evidence and rules --------------------------------------------------------


def snippet(py_file: PyFile, node: ast.AST, limit: int = 200) -> str:
    """The source text of `node`, shortened for evidence."""
    text = ast.get_source_segment(py_file.source, node) or ""
    return text if len(text) <= limit else text[:limit] + "..."


def python_files(context: AnalysisContext) -> Iterator[tuple[str, str, str]]:
    """(archive, path, source) for every .py file in the sdist and wheel."""
    for archive, contents in (("sdist", context.sdist), ("wheel", context.wheel)):
        if contents is None:
            continue
        for path, source in contents.files.items():
            if path.endswith(".py"):
                yield archive, path, source


# --- Calls that start programs or use the network ----------------------------------
# For setup_py_install_time, import_time_code and unimported_script_code.

FindCalls = Callable[[PyFile], Iterable[tuple[str | None, ast.Call]]]


def process_and_network_calls(
    py_files: dict[str, PyFile], find_calls: FindCalls
) -> ProcessAndNetworkCalls:
    """The calls in the files that start programs or connect to the network.

    `find_calls` picks which calls count: `calls` (all of them) or `import_time_calls`
    (the code that runs on import).

    Network means calls that connect somewhere (NETWORK_REQUESTS), not all of a
    network module: code builds settings like httpx.Timeout(...), which sends nothing.
    """
    process_calls: set[str] = set()
    network_calls: set[str] = set()
    runs_hidden_data = False
    calls_found: list[dict[str, Any]] = []
    for path, py_file in sorted(py_files.items()):
        for call_name, call_node in sorted(find_calls(py_file), key=lambda call: call[1].lineno):
            if call_name in NETWORK_REQUESTS:
                network_calls.add(call_name)
            elif call_name and is_process(call_name):
                process_calls.add(call_name)
                runs_hidden_data |= runs_decoded_or_downloaded_data(call_node, py_file)
            else:
                continue
            calls_found.append(
                {
                    "file": path,
                    "call": call_name,
                    "line": call_node.lineno,
                    "snippet": snippet(py_file, call_node),
                }
            )
    return ProcessAndNetworkCalls(
        files=sorted({call["file"] for call in calls_found}),
        process_calls=process_calls,
        network_calls=network_calls,
        runs_hidden_data=runs_hidden_data,
        calls=calls_found,
    )


def describe_calls(found: ProcessAndNetworkCalls) -> str:
    """What the calls do, for a finding's message: "starts programs and uses the network"."""
    behaviours = []
    if found.process_calls:
        behaviours.append("starts programs")
    if found.network_calls:
        behaviours.append("uses the network")
    return " and ".join(behaviours)


def calls_evidence(found: ProcessAndNetworkCalls, archive_name: str) -> dict[str, Any]:
    """The calls as a finding's evidence."""
    return {
        "archive": archive_name,
        "files": found.files,
        "process_calls": sorted(found.process_calls),
        "network_calls": sorted(found.network_calls),
        "runs_decoded_or_downloaded_data": found.runs_hidden_data,
        "calls": found.calls[:10],  # the first few is enough to see what it does
    }
