"""Detection rules. Each rule looks at one release and returns what it found.

To add a rule: write a module with a `check` function matching `Rule`,
then add it to RULES.
"""

from __future__ import annotations

from collections.abc import Callable

from crotalus.analyze.models import Finding, Release
from crotalus.analyze.rules import typosquat

Rule = Callable[[Release], list[Finding]]

RULES: list[Rule] = [typosquat.check]
