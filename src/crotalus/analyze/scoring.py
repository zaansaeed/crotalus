"""Turn a release's findings into a score and a verdict.

Each rule counts once, at its most severe finding: a rule firing on exec() in five
files is one problem, not five. The score is the sum of those weights, and the
verdict is where the score lands. One critical finding is enough on its own.

  score 0-4   -> clean
  score 5-9   -> suspicious        (later: sent to the LLM)
  score 10+   -> likely_malicious  (or any critical finding)

The weights and thresholds are starting guesses, to be tuned against the eval set.
Findings are stored, so releases can be re-scored without re-analyzing them.
"""

from __future__ import annotations

from crotalus.models import Finding, Severity, Verdict

SEVERITY_WEIGHTS: dict[Severity, int] = {
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 10,
}

SUSPICIOUS_AT = 5
LIKELY_MALICIOUS_AT = 10


def score(findings: list[Finding]) -> int:
    """Sum of each rule's highest weight."""
    worst: dict[str, int] = {}  # rule_id -> its highest weight
    for finding in findings:
        weight = SEVERITY_WEIGHTS[finding.severity]
        worst[finding.rule_id] = max(worst.get(finding.rule_id, 0), weight) # sum the worst severity of a broken rule once.
    return sum(worst.values())


def verdict(findings: list[Finding]) -> Verdict:
    if any(f.severity == "critical" for f in findings):
        return "likely_malicious"

    total = score(findings)
    if total >= LIKELY_MALICIOUS_AT:
        return "likely_malicious"
    if total >= SUSPICIOUS_AT:
        return "suspicious"
    return "clean"
