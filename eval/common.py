"""What the malicious and benign evals share: analyzing one release, and the report.

Both build an AnalysisContext their own way (from a dataset zip, or from PyPI), then
hand it to analyze(), which runs the same rules, scoring and (optionally) LLM
triage the pipeline does.
"""

from __future__ import annotations

import argparse
import csv
import time
from collections import Counter
from dataclasses import dataclass, replace

from crotalus import scoring, triage
from crotalus.models import AnalysisContext, Finding, LLMVerdict, Verdict
from crotalus.worker import run_rules

TRIAGE_SLEEP_SECONDS = 6  # the same pace as the triager, for Gemini's rate limit


@dataclass(frozen=True)
class Result:
    source: str  # where it came from, e.g. "malicious_intent/pydefender/..." or "top_packages"
    name: str
    version: str
    findings: list[Finding]
    score: int
    rules_verdict: Verdict
    notes: str = ""  # caveats about this sample, e.g. "wheel, no package_info"
    llm_verdict: LLMVerdict | None = None  # only with --triage, and only for flagged ones
    llm_confidence: float | None = None
    final_verdict: Verdict | None = None


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--seed", type=int, default=0, help="which random samples (default 0)")
    parser.add_argument("--triage", action="store_true", help="also ask the LLM (uses quota)")
    parser.add_argument("--out", help="write one row per sample to this CSV file")


def analyze(context: AnalysisContext, source: str, use_llm: bool, notes: str = "") -> Result:
    """The rules' verdict for one release, plus the LLM's if asked and it's flagged."""
    findings: list[Finding] = run_rules(context)
    rules_verdict: Verdict = scoring.rules_verdict(findings)
    result = Result(
        source=source,
        name=context.release.name,
        version=context.release.version,
        findings=findings,
        score=scoring.score(findings),
        rules_verdict=rules_verdict,
        notes=notes,
    )
    if not use_llm or rules_verdict == "clean":  # the triager only sees flagged releases
        return result

    answer = triage.triage_release(context, findings)
    time.sleep(TRIAGE_SLEEP_SECONDS)
    return replace(
        result,
        llm_verdict=answer.verdict,
        llm_confidence=answer.confidence,
        final_verdict=scoring.final_verdict(rules_verdict, answer.verdict, answer.confidence),
    )


def print_progress(i: int, total: int, result: Result) -> None:
    llm = f", LLM {result.llm_verdict} -> {result.final_verdict}" if result.llm_verdict else ""
    print(
        f"[{i}/{total}] {result.name} {result.version}: {result.rules_verdict}"
        f" (score {result.score}){llm}"
    )


def print_summary(results: list[Result], failed: int, use_llm: bool, flagged_means: str) -> None:
    """Verdict counts, rules + LLM if used, and how often each rule fired.

    `flagged_means` is what a non-clean verdict is in this eval: "caught" for
    malware, "false positives" for benign packages.
    """
    total = len(results)
    print(f"\n{total} analyzed, {failed} skipped\n")
    if not total:
        return

    def show(label: str, verdicts: list[Verdict]) -> None:
        counts = Counter(verdicts)
        flagged = total - counts["clean"]
        print(f"{label}:")
        for verdict in ("clean", "suspicious", "likely_malicious"):
            print(f"  {verdict:<17} {counts[verdict]:>5}  {counts[verdict] / total:>6.1%}")
        print(f"  {flagged_means + ' (not clean)':<17} {flagged:>5}  {flagged / total:>6.1%}\n")

    show("Rules", [r.rules_verdict for r in results])
    if use_llm:
        # Clean ones never reach the LLM, so their final verdict is the rules' one.
        show("Rules + LLM (final)", [r.final_verdict or r.rules_verdict for r in results])

    print("Rules that fired (share of samples):")
    fired = Counter(rule for r in results for rule in {f.rule_id for f in r.findings})
    for rule, count in fired.most_common():
        print(f"  {rule:<28} {count:>5}  {count / total:>6.1%}")

    notes = Counter(r.notes for r in results if r.notes)
    if notes:
        print("\nCaveats:")
        for note, count in notes.most_common():
            print(f"  {note:<28} {count:>5}")


def write_csv(path: str, results: list[Result]) -> None:
    columns = [
        "source", "name", "version", "score", "rules_verdict", "llm_verdict",
        "llm_confidence", "final_verdict", "rules_fired", "notes",
    ]  # fmt: skip
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(columns)
        for r in results:
            writer.writerow(
                [
                    r.source,
                    r.name,
                    r.version,
                    r.score,
                    r.rules_verdict,
                    r.llm_verdict or "",
                    "" if r.llm_confidence is None else r.llm_confidence,
                    r.final_verdict or "",
                    " ".join(sorted({f.rule_id for f in r.findings})),
                    r.notes,
                ]
            )
    print(f"Wrote {path}")
