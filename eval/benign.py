"""Measure crotalus's false positives: how often it flags packages that aren't malware.

Run with: docker compose run --rm eval eval/benign.py [--limit 100] [--triage]
                                                  [--out eval/results/benign.csv]
          docker compose run --rm eval eval/benign.py --packages psutil fused

For each package, the latest release is analyzed exactly as the worker would:

    1. fetch its metadata, history and code from PyPI    build_context
    2. rules, score, and optionally the LLM              common.analyze
    3. print how many were flagged, and by which rules; write a CSV if --out

Every package here is assumed benign, so anything flagged is a false positive.

Which packages:
- By default, a random sample of the most downloaded packages on PyPI
  (crotalus/data/top_packages.txt, the list typosquat uses). They're popular and
  long-lived, so very likely clean. But they're also unlike what the pipeline
  mostly sees: mature, with full metadata, links and years of history, so this is
  the easy case. A low false-positive rate here is necessary, not sufficient.
- --packages: specific ones, e.g. known false positives (psutil, fused), as a
  regression check after changing a rule or a weight.
"""

from __future__ import annotations

import argparse
import random
import sys

import common

from crotalus import archive, pypi, triage
from crotalus.models import (
    AnalysisContext,
    ArchiveContents,
    PackageHistory,
    Release,
    ReleaseFile,
    ReleaseMetadata,
)
from crotalus.rules.typosquat import load_top_packages


def build_context(name: str) -> AnalysisContext:
    """Everything the rules see for `name`'s latest release, fetched from PyPI.

    The same steps as analysis_context.build_analysis_context, minus the database:
    the project JSON gives the latest version and the first upload in one request.
    """
    project = pypi.fetch_project(name)
    version: str = project["info"]["version"]
    history = PackageHistory(first_uploaded_at=pypi.first_upload_in(project))

    metadata: ReleaseMetadata = pypi.fetch_metadata(name, version)
    sdist_file: ReleaseFile | None
    wheel_file: ReleaseFile | None
    sdist_file, wheel_file = archive.choose_files_to_inspect(metadata.files)
    sdist: ArchiveContents | None = archive.download_and_read(sdist_file)
    wheel: ArchiveContents | None = archive.download_and_read(wheel_file)

    return AnalysisContext(
        release=Release(id=0, name=pypi.normalize_name(name), version=version),
        metadata=metadata,
        package_history=history,
        sdist=sdist,
        wheel=wheel,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--limit", type=int, default=100, help="top packages to sample")
    parser.add_argument("--packages", nargs="+", help="these packages instead of a sample")
    common.add_common_arguments(parser)
    args = parser.parse_args()

    if args.packages:
        names: list[str] = args.packages
        source = "chosen"
    else:
        top = list(load_top_packages())
        # The same seed picks the same packages every run.
        names = random.Random(args.seed).sample(top, min(args.limit, len(top)))
        source = "top_packages"

    results: list[common.Result] = []
    failed = 0
    for i, name in enumerate(names, 1):
        try:
            result = common.analyze(build_context(name), source, args.triage)
        except (pypi.PyPIError, archive.ArchiveError, triage.BadAnswer, KeyError) as exc:
            failed += 1
            print(f"[{i}/{len(names)}] skipped {name}: {exc}", file=sys.stderr)
            continue
        results.append(result)
        common.print_progress(i, len(names), result)

    common.print_summary(results, failed, args.triage, flagged_means="false positives")
    if args.out:
        common.write_csv(args.out, results)


if __name__ == "__main__":
    main()
