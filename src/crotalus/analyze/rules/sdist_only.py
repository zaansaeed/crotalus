"""Only an sdist, no wheel: installing it always runs the package's setup.py.

Most install-time malware lives in setup.py, so attackers skip wheels on purpose.
Plenty of honest packages are sdist-only too, so on its own this is weak.
"""

from __future__ import annotations

from crotalus.models import AnalysisContext, Finding


def check(context: AnalysisContext) -> list[Finding]:
    files = context.metadata.files
    types = {f.packagetype for f in files}
    if "sdist" not in types or "bdist_wheel" in types:
        return []

    return [
        Finding(
            rule_id="sdist_only",
            severity="low",
            message="only an sdist was uploaded, so installing it always runs setup.py",
            evidence={"files": [f.filename for f in files]},
        )
    ]
