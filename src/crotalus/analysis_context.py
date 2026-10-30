"""Gather everything known about one release: what the rules and the LLM look at.

    metadata         PyPI's info for this version: summary, links, files
    package_history  when the package first appeared (cached in the packages table)
    sdist, wheel     the source code of the two files inspected (see distribution.py)

Used by the worker (before running the rules) and the triager (before asking the
LLM). The triager downloads the code again rather than storing it: only flagged
releases get that far, and nothing hostile is ever kept on disk.
"""

from __future__ import annotations

from datetime import datetime

from crotalus import distribution, queries
from crotalus.db import Connection
from crotalus.models import (
    AnalysisContext,
    DistributionContents,
    PackageHistory,
    Release,
    ReleaseFile,
    ReleaseMetadata,
)
from crotalus.pypi import fetch_first_upload, fetch_metadata


def build_analysis_context(conn: Connection, release: Release) -> AnalysisContext:
    """Fetch the release's metadata, package history and code.

    Raises pypi.ReleaseNotFound if it's gone from PyPI, pypi.PyPIUnavailable if PyPI
    can't be reached, and distribution.DistributionError if its files can't be read.
    """
    # The release first: if it's gone from PyPI, don't bother with the package history.
    metadata: ReleaseMetadata = fetch_metadata(release.name, release.version)
    package_history = PackageHistory(first_uploaded_at=first_upload(conn, release.name))

    # Each is None if the release has no such file, or it's too big.
    sdist_file: ReleaseFile | None
    wheel_file: ReleaseFile | None
    sdist_file, wheel_file = distribution.choose_files_to_inspect(metadata.files)
    sdist: DistributionContents | None = distribution.download_and_read(sdist_file)
    wheel: DistributionContents | None = distribution.download_and_read(wheel_file)

    return AnalysisContext(
        release=release,
        metadata=metadata,
        package_history=package_history,
        sdist=sdist,
        wheel=wheel,
    )


def first_upload(conn: Connection, package_name: str) -> datetime | None:
    """When the package first appeared on PyPI. None if it has no files.

    Fetched once per package and cached: the project JSON it comes from lists every
    version, and can be several MB.
    """
    first_uploaded_at = queries.cached_first_upload(conn, package_name)
    if first_uploaded_at is None:
        first_uploaded_at = fetch_first_upload(package_name)
        if first_uploaded_at is not None:
            queries.cache_first_upload(conn, package_name, first_uploaded_at)
    return first_uploaded_at
