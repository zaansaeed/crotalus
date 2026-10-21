"""Data passed between the worker and the detection rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# Matches the CHECK on findings.severity.
Severity = Literal["low", "medium", "high", "critical"]


# One release from database.
@dataclass(frozen=True)
class Release:
    id: int
    name: str  # PEP 503 normalized
    version: str


# Finding for one release.
@dataclass(frozen=True)
class Finding:
    rule_id: str  # snake_case, e.g. "typosquat"
    severity: Severity
    message: str  # one line for humans
    evidence: dict[str, Any] = field(default_factory=dict)  # stored as jsonb
