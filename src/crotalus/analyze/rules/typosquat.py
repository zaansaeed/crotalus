"""Typosquatting: a new package named one or two typos away from a popular one.

Attackers publish e.g. `reqeusts` hoping someone mistypes `pip install requests`.
The popular names come from data/top_packages.txt, ordered most downloaded first
(regenerate it with scripts/update_top_packages.py).
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import cache
from pathlib import Path

from crotalus.analyze.models import Finding, Release

TOP_PACKAGES_FILE = Path(__file__).resolve().parents[1] / "data" / "top_packages.txt"
# TOP 5000 most common pypi packages in the last 30 days

# Shorter names are too often a typo away from something popular by chance (six -> sax).
MIN_NAME_LENGTH = 5
MAX_DISTANCE = 2
SHORT_NAME_LENGTH = 8  # below this, only 1 edit counts: 2 edits make it a different word


def levenshtein(a: str, b: str) -> int:
    """Fewest single-character inserts, deletes or substitutions turning a into b."""
    # dp[i][j] = distance between a[:i] and b[:j]
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        dp[i][0] = i  # delete all of a[:i]
    for j in range(len(b) + 1):
        dp[0][j] = j  # insert all of b[:j]

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            substitution = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,  # delete a[i-1]
                dp[i][j - 1] + 1,  # insert b[j-1]
                dp[i - 1][j - 1] + substitution,
            )
    return dp[len(a)][len(b)]


@cache  # read the file once per process, not once per release
def load_top_packages() -> tuple[str, ...]:
    """Popular package names, most downloaded first. Lines starting with '#' are comments."""
    lines = TOP_PACKAGES_FILE.read_text(encoding="utf-8").splitlines()
    return tuple(line.strip() for line in lines if line.strip() and not line.startswith("#"))


def find_lookalike(name: str, top_packages: Sequence[str]) -> tuple[str, int] | None:
    """Return the popular package `name` imitates and their distance, or None.

    Ties go to the more popular package, since that's the likelier target.
    """
    if len(name) < MIN_NAME_LENGTH or name in top_packages:
        return None

    
    max_distance = 1 if len(name) < SHORT_NAME_LENGTH else MAX_DISTANCE

    best_match: tuple[str, int] | None = None
    for target in top_packages:
        if abs(len(target) - len(name)) > max_distance:
            continue
        distance = levenshtein(name, target)
        if distance <= max_distance and (best_match is None or distance < best_match[1]):
            best_match = (target, distance)
            if distance == 1:
                break  # can't do better, and later targets are less popular
    return best_match


def check(release: Release) -> list[Finding]:
    """Flag the release if its name looks like a typo of a popular package."""
    match = find_lookalike(release.name, load_top_packages())
    if match is None:
        return []

    target, distance = match
    edits = "edit" if distance == 1 else "edits"
    return [
        Finding(
            rule_id="typosquat",
            severity="high" if distance == 1 else "medium",
            message=f"name is {distance} {edits} away from popular package '{target}'",
            evidence={"similar_to": target, "distance": distance},
        )
    ]
