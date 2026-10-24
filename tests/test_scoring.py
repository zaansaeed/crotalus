import pytest

from crotalus.models import Finding, Severity
from crotalus.scoring import score, verdict


def finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(rule_id=rule_id, severity=severity, message="")


def test_no_findings() -> None:
    assert score([]) == 0
    assert verdict([]) == "clean"


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
        (["low", "low", "medium"], "suspicious"), # 5: the threshold itself
        (["high"], "suspicious"),  # 6
        (["high", "medium"], "suspicious"),  # 9
        (["high", "medium", "low"], "likely_malicious"),  # 10: the threshold itself
    ],
)
def test_verdict_thresholds(severities: list[Severity], expected: str) -> None:
    # A different rule per finding, so every weight counts.
    findings = [finding(f"rule_{i}", s) for i, s in enumerate(severities)]
    assert verdict(findings) == expected


def test_typosquat_on_new_package() -> None:
    # The textbook malicious upload: each signal is weak, together they're not.
    findings = [
        finding("typosquat", "high"),
        finding("new_package", "medium"),
        finding("no_project_links", "low"),
        finding("sdist_only", "low"),
    ]
    assert score(findings) == 11
    assert verdict(findings) == "likely_malicious"
