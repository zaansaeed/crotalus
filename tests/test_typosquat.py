import pytest

from crotalus.analyze.models import AnalysisContext, Finding, Release, ReleaseMetadata
from crotalus.analyze.rules import typosquat
from crotalus.analyze.rules.typosquat import check, find_lookalike, levenshtein

# Most popular first, like data/top_packages.txt.
TOP = ("requests", "numpy", "pandas", "six", "panda")


def context(name: str) -> AnalysisContext:
    return AnalysisContext(
        release=Release(id=1, name=name, version="1.0"),
        metadata=ReleaseMetadata(name=name, version="1.0"),
    )


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("", "", 0),
        ("abc", "", 3),
        ("", "abc", 3),
        ("requests", "requests", 0),
        ("requests", "reqests", 1),  # delete
        ("requests", "requestss", 1),  # insert
        ("requests", "requezts", 1),  # substitute
        ("requests", "reqeusts", 2),  # swapped letters count as 2
        ("kitten", "sitting", 3),
    ],
)
def test_levenshtein(a: str, b: str, expected: int) -> None:
    assert levenshtein(a, b) == expected
    assert levenshtein(b, a) == expected  # symmetric


def test_flags_one_typo() -> None:
    assert find_lookalike("reqests", TOP) == ("requests", 1)


def test_flags_two_typos() -> None:
    assert find_lookalike("reqeusts", TOP) == ("requests", 2)


def test_ignores_three_typos() -> None:
    assert find_lookalike("reqxxxts", TOP) is None


def test_ignores_popular_package_itself() -> None:
    # "panda" is 1 edit from "pandas", but it's popular in its own right.
    assert find_lookalike("panda", TOP) is None


def test_ignores_short_names() -> None:
    assert find_lookalike("sax", TOP) is None  # 1 edit from "six", but too short


def test_prefers_closest_match() -> None:
    # 2 edits from "pandas" (more popular) but 1 from "panda": closer wins.
    assert find_lookalike("panxa", TOP) == ("panda", 1)


def test_tie_goes_to_more_popular() -> None:
    # 1 edit from both "pandas" and "panda"; "pandas" is listed first.
    assert find_lookalike("pandae", TOP) == ("pandas", 1)


def test_typosquat_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquat, "load_top_packages", lambda: TOP)
    assert check(context("nunpy")) == [
        Finding(
            rule_id="typosquat",
            severity="high",
            message="name is 1 edit away from popular package 'numpy'",
            evidence={"similar_to": "numpy", "distance": 1},
        )
    ]

def test_short_names_allow_one_typo_only() -> None:
    assert find_lookalike("nmupi", TOP) is None  # 2 edits from "numpy", but only 5 chars

def test_typosquat_nothing_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquat, "load_top_packages", lambda: TOP)
    assert check(context("totally-unrelated")) == []
