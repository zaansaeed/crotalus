"""Measure crotalus on known malware: Datadog's malicious-software-packages-dataset.

Run with: docker compose run --rm eval eval/malicious.py [--limit 100] [--triage]
                                                     [--out eval/results/malicious.csv]
(or python eval/malicious.py with crotalus installed, but see "Safety" below)

For each sample, picked at random from the dataset:

    1. download the sample's zip into memory          from GitHub, never to disk
    2. build an AnalysisContext from it               read_sample
    3. rules, score, and optionally the LLM            common.analyze
    4. print how many were caught, and by which rules; write a CSV if --out

Every sample is malware, so this measures recall: how much of it gets flagged. It
says nothing about false positives: that's eval/benign.py.

The dataset (https://github.com/DataDog/malicious-software-packages-dataset):
- samples/pypi/malicious_intent/: packages published to be malicious.
  samples/pypi/compromised_lib/: real packages with some versions hijacked.
- Each sample is a zip encrypted with the password "infected", holding the files
  of one sdist or wheel, already extracted (not the original .tar.gz or .whl),
  under a folder whose name varies. Most also hold "package_info-*.json": PyPI's
  JSON for the release, saved when it was found, which is what fetch_metadata
  would have returned.
- Without package_info, the metadata comes from the archive's PKG-INFO or
  METADATA instead, and has no file list: sdist_only, late_file_upload and
  new_package can't fire on those samples.
- package_info may only list this one version, which makes every package look
  brand new to new_package. Most of these packages were, but not all.
- The samples were mostly found by Datadog's own scanner (GuardDog), so they lean
  towards what its rules catch.

Safety: these are real malware. Nothing is written to disk, extracted, installed or
run: zips are decrypted and read in memory, exactly like archive.py reads PyPI's
files. Running it in a container (the compose service) keeps it off your machine
entirely.
"""

from __future__ import annotations

import argparse
import io
import json
import random
import sys
import zipfile
from dataclasses import dataclass
from email.parser import Parser
from typing import Any

import common

from crotalus import archive, http_client, pypi, triage
from crotalus.models import (
    AnalysisContext,
    ArchiveContents,
    PackageHistory,
    Release,
    ReleaseMetadata,
)

REPO = "DataDog/malicious-software-packages-dataset"
TREE_URL = "https://api.github.com/repos/" + REPO + "/git/trees/{sha}?recursive=1"
CONTENTS_URL = "https://api.github.com/repos/" + REPO + "/contents/samples/pypi"
RAW_URL = "https://raw.githubusercontent.com/" + REPO + "/main/samples/pypi/{path}"
PASSWORD = b"infected"
KINDS = ("malicious_intent", "compromised_lib")


class SampleError(Exception):
    """The sample's zip can't be read, or isn't laid out like an sdist or wheel."""


@dataclass(frozen=True)
class Sample:
    kind: str  # "malicious_intent" or "compromised_lib"
    path: str  # under samples/pypi/<kind>/, e.g. "pydefender/1.0.0/2023-...-v1.0.0.zip"
    size: int  # bytes of the zip


# --- Finding samples ---------------------------------------------------------------


def list_samples(kind: str) -> list[Sample]:
    """Every PyPI sample of one kind in the dataset, from GitHub's API (two requests)."""
    folders = _get_json(CONTENTS_URL)  # samples/pypi: the kind folders and the manifest
    sha = next(entry["sha"] for entry in folders if entry["name"] == kind)
    tree = _get_json(TREE_URL.format(sha=sha))
    if tree.get("truncated"):
        raise SystemExit(f"GitHub truncated the listing of {kind}: too many samples")
    return [
        Sample(kind=kind, path=entry["path"], size=entry["size"])
        for entry in tree["tree"]
        if entry["type"] == "blob" and entry["path"].endswith(".zip")
    ]


def download(sample: Sample) -> bytes:
    response = http_client.client.get(RAW_URL.format(path=f"{sample.kind}/{sample.path}"))
    response.raise_for_status()
    return response.content


def _get_json(url: str) -> Any:
    response = http_client.client.get(url)
    response.raise_for_status()  # 403 here usually means GitHub's limit: 60 requests/hour
    return response.json()


# --- Reading a sample --------------------------------------------------------------


def read_sample(sample: Sample, data: bytes) -> tuple[AnalysisContext, str, bool]:
    """(context, "sdist" or "wheel", whether it had package_info) for one sample's zip."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        paths: list[str] = [info.filename for info in zf.infolist() if not info.is_dir()]
        if len(paths) > archive.MAX_MEMBERS:
            raise SampleError(f"more than {archive.MAX_MEMBERS} files")

        archive_type, root = _find_archive_root(paths)
        files: dict[str, str] = _read_files(zf, paths, root)

        package_info = next((p for p in paths if "/package_info-" in p), None)
        if package_info is not None:
            data_json = _json(zf, package_info)
            metadata: ReleaseMetadata = pypi.parse_release_json(data_json)
            history = PackageHistory(first_uploaded_at=pypi.first_upload_in(data_json))
        else:
            metadata = _metadata_from_archive(zf, paths, root, archive_type)
            history = PackageHistory()  # unknown: new_package doesn't fire
    except (zipfile.BadZipFile, KeyError, TypeError, ValueError, AttributeError) as exc:
        raise SampleError(f"{sample.path}: {exc!r}") from exc

    # The original file's name isn't in the sample; this is only for the LLM prompt.
    suffix = ".tar.gz" if archive_type == "sdist" else "-py3-none-any.whl"
    contents = ArchiveContents(filename=f"{metadata.name}-{metadata.version}{suffix}", files=files)
    context = AnalysisContext(
        release=Release(id=0, name=pypi.normalize_name(metadata.name), version=metadata.version),
        metadata=metadata,
        package_history=history,
        sdist=contents if archive_type == "sdist" else None,
        wheel=contents if archive_type == "wheel" else None,
    )
    return context, archive_type, package_info is not None


def _find_archive_root(paths: list[str]) -> tuple[str, str]:
    """("sdist" or "wheel", the folder the archive's files are under, ending in "/").

    The folder above it varies between samples ("2023-03-20-pkg-v1.0/", "tmp/tmpab12/pkg/"),
    so it's found from what's inside: a wheel has "<name>.dist-info/WHEEL", an sdist
    has PKG-INFO (or at least setup.py or pyproject.toml) at its top.
    """
    for path in paths:
        folder, _, filename = path.rpartition("/")
        if filename == "WHEEL" and folder.endswith(".dist-info"):
            return "wheel", folder.rpartition("/")[0] + "/"
    for wanted in ("PKG-INFO", "setup.py", "pyproject.toml"):
        # The shallowest one: egg-info folders have a PKG-INFO of their own.
        candidates = [p for p in paths if p.rpartition("/")[2] == wanted and ".egg-info/" not in p]
        if candidates:
            top = min(candidates, key=lambda p: p.count("/"))
            return "sdist", top.rpartition("/")[0] + "/"
    raise SampleError("no WHEEL, PKG-INFO, setup.py or pyproject.toml")


def _read_files(zf: zipfile.ZipFile, paths: list[str], root: str) -> dict[str, str]:
    """Path under `root` -> text, for the files rules read. The same limits as archive.py."""
    files: dict[str, str] = {}
    total = 0
    for path in paths:
        if not path.startswith(root) or not archive.wanted_by_rules(path):
            continue
        if zf.getinfo(path).file_size > archive.MAX_FILE_BYTES:
            continue
        with zf.open(path, pwd=PASSWORD) as handle:  # decrypted in memory
            content: bytes = handle.read(archive.MAX_FILE_BYTES + 1)
        if len(content) > archive.MAX_FILE_BYTES:
            continue
        total += len(content)
        if total > archive.MAX_TOTAL_BYTES:
            raise SampleError(f"more than {archive.MAX_TOTAL_BYTES} bytes of source")
        files[path.removeprefix(root)] = content.decode("utf-8", errors="replace")
    return files


def _json(zf: zipfile.ZipFile, path: str) -> Any:
    return json.loads(zf.read(path, pwd=PASSWORD))


def _metadata_from_archive(
    zf: zipfile.ZipFile, paths: list[str], root: str, archive_type: str
) -> ReleaseMetadata:
    """Metadata from the archive's own PKG-INFO (sdist) or METADATA (wheel).

    The same fields PyPI's JSON is built from, minus the file list and upload times.
    """
    if archive_type == "sdist":
        path = root + "PKG-INFO"
    else:
        path = next(p for p in paths if p.startswith(root) and p.endswith(".dist-info/METADATA"))
    if path not in paths:
        raise SampleError("no package_info, and no PKG-INFO to take metadata from")
    # Core metadata is email-header format: "Name: pkg", "Project-URL: Source, https://...".
    headers = Parser().parsestr(zf.read(path, pwd=PASSWORD).decode("utf-8", errors="replace"))

    project_urls: dict[str, str] = {}
    for value in headers.get_all("Project-URL") or []:
        label, _, url = value.partition(",")
        project_urls[label.strip()] = url.strip()
    home_page = headers.get("Home-page")
    if home_page and home_page != "UNKNOWN":
        project_urls.setdefault("Homepage", home_page)

    def field(name: str) -> str | None:
        value = headers.get(name)
        return value if value and value != "UNKNOWN" else None  # old setuptools wrote UNKNOWN

    return ReleaseMetadata(
        name=headers["Name"],
        version=headers["Version"],
        summary=field("Summary"),
        author=field("Author") or field("Author-email"),
        project_urls=project_urls,
    )


# --- Running it --------------------------------------------------------------------


def evaluate(sample: Sample, use_llm: bool) -> common.Result:
    context, archive_type, has_package_info = read_sample(sample, download(sample))
    notes = archive_type + ("" if has_package_info else ", no package_info")
    return common.analyze(context, f"{sample.kind}/{sample.path}", use_llm, notes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--limit", type=int, default=100, help="samples per kind (default 100)")
    parser.add_argument("--kind", choices=[*KINDS, "all"], default="all")
    common.add_common_arguments(parser)
    args = parser.parse_args()

    rng = random.Random(args.seed)  # the same seed picks the same samples every run
    samples: list[Sample] = []
    for kind in KINDS if args.kind == "all" else (args.kind,):
        # Bigger ones aren't worth the download: the worker skips them too.
        available = [s for s in list_samples(kind) if s.size <= archive.MAX_DOWNLOAD_BYTES]
        samples += rng.sample(available, min(args.limit, len(available)))

    results: list[common.Result] = []
    failed = 0
    for i, sample in enumerate(samples, 1):
        try:
            result = evaluate(sample, args.triage)
        except (SampleError, archive.ArchiveError, triage.BadAnswer) as exc:
            failed += 1
            print(f"[{i}/{len(samples)}] skipped {sample.path}: {exc}", file=sys.stderr)
            continue
        results.append(result)
        common.print_progress(i, len(samples), result)

    common.print_summary(results, failed, args.triage, flagged_means="caught")
    if args.out:
        common.write_csv(args.out, results)


if __name__ == "__main__":
    main()
