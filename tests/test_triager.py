"""Tests for the triager loop. The LLM and PyPI are faked; triage.py has its own tests."""

from dataclasses import replace
from datetime import UTC, datetime

import psycopg
import pytest
from psycopg.rows import TupleRow

from crotalus import triage, triager
from crotalus.models import (
    AnalysisContext,
    FeedEntry,
    Finding,
    PackageInfo,
    Release,
    ReleaseMetadata,
    TriageResult,
)
from crotalus.poller import store_entries
from crotalus.pypi import PyPIUnavailable, ReleaseNotFound
from crotalus.worker import store_findings

Conn = psycopg.Connection[TupleRow]

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
    """Fake PyPI (build_context) and the LLM. The LLM answers RESULT."""
    calls: Asked = []

    def build_context(conn: Conn, release: Release) -> AnalysisContext:
        return AnalysisContext(
            release=release,
            metadata=ReleaseMetadata(name=release.name, version=release.version),
            package=PackageInfo(),
        )

    def fake_triage(
        context: AnalysisContext, findings: list[Finding], model: str | None = None
    ) -> TriageResult:
        calls.append((context.release.name, findings))
        # Like the real one: the answer records the model and prompt that made it.
        return replace(RESULT, model=model or MODEL, prompt_version=triage.PROMPT_VERSION)

    monkeypatch.setattr(triager, "build_context", build_context)
    monkeypatch.setattr(triage, "triage", fake_triage)
    return calls


def add_analyzed_release(db: Conn, name: str, verdict: str, score: int = 6) -> int:
    """A release the worker has finished, with FINDING stored."""
    when = datetime(2026, 10, 26, tzinfo=UTC)
    store_entries(db, [FeedEntry(name=name, version="1.0", published_at=when, source="rss")])
    row = db.execute(
        "UPDATE releases SET status = 'done', score = %s, verdict = %s"
        " WHERE package_id = (SELECT id FROM packages WHERE name = %s) RETURNING id",
        (score, verdict, name),
    ).fetchone()
    assert row is not None
    store_findings(db, row[0], [FINDING])
    return int(row[0])


def triage_rows(db: Conn) -> list[tuple[object, ...]]:
    return db.execute(
        "SELECT release_id, model, status, verdict, false_positive_rules, error"
        " FROM triage ORDER BY id"
    ).fetchall()


def test_nothing_flagged_returns_false(db: Conn, asked: Asked) -> None:
    add_analyzed_release(db, "fine", "clean", score=0)
    assert triager.triage_one(db, MODEL) is False
    assert asked == []


def test_stores_llm_answer(db: Conn, asked: Asked) -> None:
    release_id = add_analyzed_release(db, "pkg", "suspicious")
    assert triager.triage_one(db, MODEL) is True

    assert triage_rows(db) == [
        (release_id, MODEL, "done", "benign", ["setup_py_install_time"], None)
    ]
    # The rules' verdict is left alone.
    assert db.execute("SELECT verdict FROM releases").fetchone() == ("suspicious",)


def test_llm_sees_stored_findings(db: Conn, asked: Asked) -> None:
    add_analyzed_release(db, "pkg", "likely_malicious", score=10)
    triager.triage_one(db, MODEL)
    assert asked == [("pkg", [FINDING])]  # evidence comes back from jsonb as a dict


def test_each_release_triaged_once(db: Conn, asked: Asked) -> None:
    add_analyzed_release(db, "pkg", "suspicious")
    assert triager.triage_one(db, MODEL) is True
    assert triager.triage_one(db, MODEL) is False


def test_new_prompt_or_model_triages_again(
    db: Conn, asked: Asked, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_analyzed_release(db, "pkg", "suspicious")
    triager.triage_one(db, MODEL)
    assert triager.triage_one(db, "other-model") is True

    monkeypatch.setattr(triage, "PROMPT_VERSION", "v-next")
    assert triager.triage_one(db, MODEL) is True


def test_bad_answer_stored_as_failed(
    db: Conn, asked: Asked, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad_answer(*args: object) -> TriageResult:
        raise triage.BadAnswer("answer isn't JSON")

    monkeypatch.setattr(triage, "triage", bad_answer)
    release_id = add_analyzed_release(db, "pkg", "suspicious")
    assert triager.triage_one(db, MODEL) is True

    assert triage_rows(db) == [(release_id, MODEL, "failed", None, [], "answer isn't JSON")]
    assert triager.triage_one(db, MODEL) is False  # not retried


def test_release_gone_from_pypi_stored_as_failed(
    db: Conn, asked: Asked, monkeypatch: pytest.MonkeyPatch
) -> None:
    def gone(conn: Conn, release: Release) -> AnalysisContext:
        raise ReleaseNotFound("pkg 1.0 is not on PyPI")

    monkeypatch.setattr(triager, "build_context", gone)
    add_analyzed_release(db, "pkg", "likely_malicious", score=10)
    triager.triage_one(db, MODEL)

    [row] = triage_rows(db)
    assert row[2] == "failed" and "not on PyPI" in str(row[5])


@pytest.mark.parametrize(
    "error", [triage.LLMUnavailable("429"), PyPIUnavailable("PyPI returned 503")]
)
def test_unavailable_leaves_release_untriaged(
    db: Conn, asked: Asked, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def unavailable(*args: object) -> TriageResult:
        raise error

    monkeypatch.setattr(triage, "triage", unavailable)
    add_analyzed_release(db, "pkg", "suspicious")
    with pytest.raises(type(error)):
        triager.triage_one(db, MODEL)
    assert triage_rows(db) == []  # rolled back: tried again later


def test_setup_problem_stops_triager(
    db: Conn, asked: Asked, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad_key(*args: object) -> TriageResult:
        raise triage.TriageError("Gemini returned 403")

    monkeypatch.setattr(triage, "triage", bad_key)
    add_analyzed_release(db, "pkg", "suspicious")
    with pytest.raises(triage.TriageError):
        triager.triage_one(db, MODEL)
    assert triage_rows(db) == []
