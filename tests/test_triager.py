"""Tests for the triager loop. The LLM and PyPI are faked; triage.py has its own tests."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from crotalus import queries, triage, triager
from crotalus.db import Connection
from crotalus.models import (
    AnalysisContext,
    FeedEntry,
    Finding,
    PackageHistory,
    Release,
    ReleaseMetadata,
    TriageResult,
    Verdict,
)
from crotalus.pypi import PyPIUnavailable, ReleaseNotFound

MODEL = "test-model"
FINDING = Finding(
    rule_id="setup_py_install_time",
    severity="high",
    message="setup.py starts programs at install time",
    evidence={"archive": "sdist", "file": "setup.py", "calls": []},
)
RESULT = TriageResult(
    verdict="benign",
    confidence=0.8,
    reasoning="It runs a README converter.",
    false_positive_rules=("setup_py_install_time",),
    model=MODEL,
    prompt_version=triage.PROMPT_VERSION,
)

# What the fake LLM was asked about: (release name, findings).
Asked = list[tuple[str, list[Finding]]]


@pytest.fixture
def asked(monkeypatch: pytest.MonkeyPatch) -> Asked:
    """Fake PyPI (build_analysis_context) and the LLM. The LLM answers RESULT (benign)."""
    calls: Asked = []

    def build_analysis_context(conn: Connection, release: Release) -> AnalysisContext:
        return AnalysisContext(
            release=release,
            metadata=ReleaseMetadata(name=release.name, version=release.version),
            package_history=PackageHistory(),
        )

    def fake_triage(
        context: AnalysisContext, findings: list[Finding], model: str | None = None
    ) -> TriageResult:
        calls.append((context.release.name, findings))
        # Like the real one: the answer records the model and prompt that made it.
        return replace(RESULT, model=model or MODEL, prompt_version=triage.PROMPT_VERSION)

    monkeypatch.setattr(triager, "build_analysis_context", build_analysis_context)
    monkeypatch.setattr(triage, "triage_release", fake_triage)
    return calls


def add_analyzed_release(db: Connection, name: str, rules_verdict: Verdict, score: int = 6) -> int:
    """A release the worker has finished, with FINDING stored. Returns its id."""
    when = datetime(2026, 10, 26, tzinfo=UTC)
    entry = FeedEntry(name=name, version="1.0", published_at=when, source="rss")
    queries.store_new_releases(db, [entry])
    release = queries.claim_next_pending_release(db)
    assert release is not None
    queries.replace_findings(db, release.id, [FINDING])
    queries.mark_analyzed(db, release.id, score, rules_verdict)
    return release.id


def verdicts(db: Connection) -> tuple[str, str | None, str]:
    """(rules_verdict, llm_verdict, final_verdict) of the only release."""
    row = db.execute("SELECT rules_verdict, llm_verdict, final_verdict FROM releases").fetchone()
    assert row is not None
    return row[0], row[1], row[2]


def triage_rows(db: Connection) -> list[tuple[object, ...]]:
    return db.execute(
        "SELECT release_id, model, status, verdict, false_positive_rules, error"
        " FROM triage ORDER BY id"
    ).fetchall()


def test_waiting_release_has_no_llm_verdict(db: Connection, asked: Asked) -> None:
    add_analyzed_release(db, "pkg", "suspicious")
    assert verdicts(db) == ("suspicious", None, "suspicious")


def test_nothing_flagged_returns_false(db: Connection, asked: Asked) -> None:
    add_analyzed_release(db, "fine", "clean", score=0)
    assert triager.triage_next_flagged_release(db, MODEL) is False
    assert asked == []


def test_stores_llm_answer(db: Connection, asked: Asked) -> None:
    release_id = add_analyzed_release(db, "pkg", "suspicious")
    assert triager.triage_next_flagged_release(db, MODEL) is True

    assert triage_rows(db) == [
        (release_id, MODEL, "done", "benign", ["setup_py_install_time"], None)
    ]
    # The rules' verdict is kept; the final verdict follows the LLM (suspicious -> clean).
    assert verdicts(db) == ("suspicious", "benign", "clean")


def test_llm_cannot_clear_likely_malicious(db: Connection, asked: Asked) -> None:
    add_analyzed_release(db, "pkg", "likely_malicious", score=10)
    triager.triage_next_flagged_release(db, MODEL)  # the fake LLM says benign
    assert verdicts(db) == ("likely_malicious", "benign", "likely_malicious")


def test_llm_sees_stored_findings(db: Connection, asked: Asked) -> None:
    add_analyzed_release(db, "pkg", "likely_malicious", score=10)
    triager.triage_next_flagged_release(db, MODEL)
    assert asked == [("pkg", [FINDING])]  # evidence comes back from jsonb as a dict


def test_each_release_triaged_once(db: Connection, asked: Asked) -> None:
    add_analyzed_release(db, "pkg", "suspicious")
    assert triager.triage_next_flagged_release(db, MODEL) is True
    assert triager.triage_next_flagged_release(db, MODEL) is False


def test_new_prompt_or_model_triages_again(
    db: Connection, asked: Asked, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_analyzed_release(db, "pkg", "suspicious")
    triager.triage_next_flagged_release(db, MODEL)
    assert triager.triage_next_flagged_release(db, "other-model") is True

    monkeypatch.setattr(triage, "PROMPT_VERSION", "v-next")
    assert triager.triage_next_flagged_release(db, MODEL) is True


def test_bad_answer_stored_as_failed(
    db: Connection, asked: Asked, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad_answer(*args: object) -> TriageResult:
        raise triage.BadAnswer("answer isn't JSON")

    monkeypatch.setattr(triage, "triage_release", bad_answer)
    release_id = add_analyzed_release(db, "pkg", "suspicious")
    assert triager.triage_next_flagged_release(db, MODEL) is True

    assert triage_rows(db) == [(release_id, MODEL, "failed", None, [], "answer isn't JSON")]
    assert verdicts(db) == ("suspicious", None, "suspicious")  # no opinion: the rules' verdict
    assert triager.triage_next_flagged_release(db, MODEL) is False  # not retried


def test_release_gone_from_pypi_stored_as_failed(
    db: Connection, asked: Asked, monkeypatch: pytest.MonkeyPatch
) -> None:
    def gone(conn: Connection, release: Release) -> AnalysisContext:
        raise ReleaseNotFound("pkg 1.0 is not on PyPI")

    monkeypatch.setattr(triager, "build_analysis_context", gone)
    add_analyzed_release(db, "pkg", "likely_malicious", score=10)
    triager.triage_next_flagged_release(db, MODEL)

    [row] = triage_rows(db)
    assert row[2] == "failed" and "not on PyPI" in str(row[5])


@pytest.mark.parametrize(
    "error", [triage.LLMUnavailable("429"), PyPIUnavailable("PyPI returned 503")]
)
def test_unavailable_leaves_release_untriaged(
    db: Connection, asked: Asked, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def unavailable(*args: object) -> TriageResult:
        raise error

    monkeypatch.setattr(triage, "triage_release", unavailable)
    add_analyzed_release(db, "pkg", "suspicious")
    with pytest.raises(type(error)):
        triager.triage_next_flagged_release(db, MODEL)
    assert triage_rows(db) == []  # rolled back: tried again later


def test_setup_problem_stops_triager(
    db: Connection, asked: Asked, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad_key(*args: object) -> TriageResult:
        raise triage.TriageError("Gemini returned 403")

    monkeypatch.setattr(triage, "triage_release", bad_key)
    add_analyzed_release(db, "pkg", "suspicious")
    with pytest.raises(triage.TriageError):
        triager.triage_next_flagged_release(db, MODEL)
    assert triage_rows(db) == []
