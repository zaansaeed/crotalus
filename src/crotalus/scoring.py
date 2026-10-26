"""Turn a release's findings into a verdict, and combine it with the LLM's opinion.

1. The rules' verdict (the worker, for every release):
   Each rule counts once, at its most severe finding: a rule firing on exec() in five
   files is one problem, not five. The score is the sum of those weights, and the
   verdict is where the score lands. One critical finding is enough on its own.

     score 0-4   -> clean
     score 5-9   -> suspicious        (sent to the LLM)
     score 10+   -> likely_malicious  (or any critical finding; also sent to the LLM)

2. The final verdict (the triager, for flagged releases): see final_verdict().

The weights and thresholds are starting guesses, to be tuned against the eval set.
Findings are stored, so releases can be re-scored without re-analyzing them.
"""

from __future__ import annotations

from crotalus.models import Finding, LLMVerdict, Severity, Verdict

SEVERITY_WEIGHTS: dict[Severity, int] = {
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 10,
}

SUSPICIOUS_AT = 5
LIKELY_MALICIOUS_AT = 10

# How sure the LLM must say it is before its "benign" clears a suspicious release.
# The model reports this itself and isn't calibrated, so it's a bar against
# half-hearted answers, not a probability. A starting guess, like the weights.
CLEAR_AT_CONFIDENCE = 0.8


def score(findings: list[Finding]) -> int:
    """Sum of each rule's highest weight."""
    highest_weight_by_rule: dict[str, int] = {}  # rule_id -> its highest weight
    for finding in findings:
        weight = SEVERITY_WEIGHTS[finding.severity]
        # Keep each rule's worst severity, so a rule counts once in the sum.
        highest_weight_by_rule[finding.rule_id] = max(
            highest_weight_by_rule.get(finding.rule_id, 0), weight
        )
    return sum(highest_weight_by_rule.values())


def rules_verdict(findings: list[Finding]) -> Verdict:
    """What the findings add up to, before the LLM has a say."""
    if any(finding.severity == "critical" for finding in findings):
        return "likely_malicious"

    total = score(findings)
    if total >= LIKELY_MALICIOUS_AT:
        return "likely_malicious"
    if total >= SUSPICIOUS_AT:
        return "suspicious"
    return "clean"


def final_verdict(rules: Verdict, llm: LLMVerdict | None, confidence: float | None) -> Verdict:
    """The verdict to act on: the rules' verdict, changed by the LLM only where allowed.

    - No LLM opinion (not flagged, not triaged yet, or triage failed): the rules' verdict.
    - "suspicious" means the rules aren't sure, so the LLM decides:
      benign -> clean, but only at confidence >= CLEAR_AT_CONFIDENCE (else it stays
      suspicious); malicious -> likely_malicious; suspicious -> suspicious.
      Only clearing needs the confidence: wrongly clearing hides malware, while wrongly
      escalating just flags a release for a closer look.
    - "likely_malicious" stays, whatever the LLM says. The LLM reads code written by
      the attacker, who can try to talk it into "benign" (prompt injection). Limiting
      it to "suspicious" releases means a fooled LLM can at worst clear a release the
      rules weren't sure about, never one they were.
    """
    if llm is None or rules != "suspicious":
        return rules
    if llm == "benign":
        if confidence is not None and confidence >= CLEAR_AT_CONFIDENCE:
            return "clean"
        return "suspicious"
    if llm == "malicious":
        return "likely_malicious"
    return "suspicious"
