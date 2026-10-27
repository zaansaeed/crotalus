import pytest

from crotalus.models import Finding, LLMVerdict, Severity, Verdict
from crotalus.scoring import CLEAR_AT_CONFIDENCE, final_verdict, rules_verdict, score


def finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(rule_id=rule_id, severity=severity, message="")


def test_no_findings() -> None:
    assert score([]) == 0
    assert rules_verdict([]) == "clean"


def test_weights_add_up() -> None:
    findings = [finding("a", "low"), finding("b", "medium"), finding("c", "high")]
    assert score(findings) == 1 + 3 + 6


def test_rule_counts_once_at_its_worst() -> None:
    # e.g. exec() in three files: one problem, scored at its most severe.
    findings = [finding("exec", "low"), finding("exec", "high"), finding("exec", "medium")]
    assert score(findings) == 6


@pytest.mark.parametrize(
    ("severities", "expected"),
    [
        (["low", "low", "low"], "clean"),  # 3
        (["low", "medium"], "clean"),  # 4
        (["low", "low", "medium"], "suspicious"),  # 5: the threshold itself
        (["high"], "suspicious"),  # 6
        (["high", "medium"], "suspicious"),  # 9
        (["high", "medium", "low"], "likely_malicious"),  # 10: the threshold itself
    ],
)
def test_verdict_thresholds(severities: list[Severity], expected: str) -> None:
    # A different rule per finding, so every weight counts.
    findings = [finding(f"rule_{i}", s) for i, s in enumerate(severities)]
    assert rules_verdict(findings) == expected


def test_typosquat_on_new_package() -> None:
    # The textbook malicious upload: each signal is weak, together they're not.
    findings = [
        finding("typosquat", "high"),
        finding("new_package", "medium"),
        finding("no_project_links", "low"),
        finding("sdist_only", "low"),
    ]
    assert score(findings) == 11
    assert rules_verdict(findings) == "likely_malicious"


# final_verdict: what the LLM's opinion may change


@pytest.mark.parametrize(
    ("rules", "llm", "confidence", "expected"),
    [
        ("suspicious", "benign", 0.95, "clean"),  # the LLM decides unsure cases
        ("suspicious", "benign", CLEAR_AT_CONFIDENCE, "clean"),  # the bar itself is enough
        ("suspicious", "benign", 0.5, "suspicious"),  # but must be sure to clear
        ("suspicious", "suspicious", 0.95, "suspicious"),
        ("suspicious", "malicious", 0.5, "likely_malicious"),  # escalating needs no bar
        ("likely_malicious", "benign", 0.99, "suspicious"),  # only lowered, never cleared
        ("likely_malicious", "benign", 0.5, "likely_malicious"),  # and only when sure
        ("likely_malicious", "malicious", 0.95, "likely_malicious"),
        ("suspicious", None, None, "suspicious"),  # no opinion yet, or triage failed
        ("clean", None, None, "clean"),  # never triaged
    ],
)
def test_final_verdict(
    rules: Verdict, llm: LLMVerdict | None, confidence: float | None, expected: Verdict
) -> None:
    assert final_verdict(rules, llm, confidence) == expected
