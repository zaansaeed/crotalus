"""Pick which of a release's files to inspect, and read their source code.

Of everything a release uploaded, two files are inspected:
- the sdist, because installing it runs its setup.py / build backend
- one wheel, because it's what actually gets installed: a pure-Python ("any") wheel
  if there is one, otherwise Linux, then Windows, then macOS; x86-64 before ARM,
  newest CPython first

Archives come from whoever published the release, so they're treated as hostile:
- Nothing is extracted to disk. Files are read straight out of the archive bytes
  in memory, so a path like "../../.bashrc" or a symlink can't touch anything:
  it's just a name in a dict.
- Only regular files are read; links, devices and other special entries are skipped.
- Limits on file count, bytes per file and total bytes read stop archive bombs
  (a few KB that decompress to many GB).

Only the files rules care about are read: .py, .pth and pyproject.toml.
"""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from typing import IO

from packaging.tags import Tag
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from crotalus import pypi
from crotalus.models import ArchiveContents, ReleaseFile

MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # bigger files aren't downloaded at all
MAX_MEMBERS = 20_000  # entries in one archive
MAX_FILE_BYTES = 2 * 1024 * 1024  # bigger source files are skipped
MAX_TOTAL_BYTES = 100 * 1024 * 1024  # decompressed bytes read from one archive


class ArchiveError(Exception):
    """The archive is corrupt, or breaks one of the limits above."""


def _wheel_rank(tags: frozenset[Tag]) -> tuple[int, int, int]:
    """Sort key for wheels, lower is preferred: (platform, architecture, -Python version)."""
    platforms = {tag.platform for tag in tags}
    if "any" in platforms:
        rank = 0
    elif any(p.startswith(("manylinux", "musllinux", "linux")) for p in platforms):
        rank = 1
    elif any(p.startswith("win") for p in platforms):
        rank = 2
    elif any(p.startswith("macosx") for p in platforms):
        rank = 3
    else:
        rank = 4
    # x86-64 is what most CI and servers run; ARM builds (aarch64, arm64) come after.
    arch = 0 if any(p.endswith(("x86_64", "amd64")) for p in platforms) else 1
    # "cp313" -> 313, so newer Pythons sort first.
    versions = [int(t.interpreter[2:]) for t in tags if t.interpreter[2:].isdigit()]
    # Compared left to right: platform (any > linux > windows > mac) first,
    # then x86-64 before ARM, then the newest Python.
    return rank, arch, -max(versions, default=0)


def choose_files_to_inspect(
    files: tuple[ReleaseFile, ...],
) -> tuple[ReleaseFile | None, ReleaseFile | None]:
    """The (sdist, wheel) to inspect. Either is None if there's none small enough."""
    small: list[ReleaseFile] = [f for f in files if f.size <= MAX_DOWNLOAD_BYTES]

    # The first sdist, or None. PyPI allows only one per release.
    sdist: ReleaseFile | None = next((f for f in small if f.packagetype == "sdist"), None)

    wheels: list[tuple[tuple[int, int, int], ReleaseFile]] = []  # (rank, file)
    for f in small:
        if f.packagetype != "bdist_wheel":
            continue
        try:
            # (name, version, build, tags); each tag has interpreter, abi, platform.
            _, _, _, tags = parse_wheel_filename(f.filename)
        except InvalidWheelFilename:
            continue  # can't tell what it's for; pip wouldn't install it either
        wheels.append((_wheel_rank(tags), f))

    # Only the best-ranked wheel; [1] takes the file out of its (rank, file) pair.
    wheel: ReleaseFile | None = min(wheels, key=lambda pair: pair[0])[1] if wheels else None

    return sdist, wheel


def wanted_by_rules(path: str) -> bool:
    """Whether rules want to read this file: .py, .pth and pyproject.toml.

    .pth files matter because Python reads every one in site-packages each time the
    interpreter starts, and runs any line starting with 'import'. They only take
    effect when installed, so in practice that means the wheel. pyproject.toml and
    setup.py matter in the sdist, where they control the build at install time.
    """
    name = path.rsplit("/", 1)[-1].lower()
    return name.endswith((".py", ".pth")) or name == "pyproject.toml"


def _members(filename: str, data: bytes) -> Iterator[tuple[str, int, IO[bytes]]]:
    """(path, declared size, handle) for every regular file in the archive.

    Call .read() on the handle to get that file's contents. Called once per archive
    (sdist and/or wheel); folders, links and other special entries are skipped.
    """
    if filename.endswith((".whl", ".zip")):  # wheels, and the odd old .zip sdist
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()  # info for each file/folder in the zip
            if len(infos) > MAX_MEMBERS:
                raise ArchiveError(f"{filename} has more than {MAX_MEMBERS} entries")
            for info in infos:
                mode = info.external_attr >> 16  # Unix permission bits, if any
                if info.is_dir() or stat.S_ISLNK(mode):  # we only want real files
                    continue
                with zf.open(info) as handle:
                    yield info.filename, info.file_size, handle
    else:  # sdists: .tar.gz, and the odd .tar.bz2 / .tgz
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            count = 0
            for member in tf:
                count += 1
                if count > MAX_MEMBERS:
                    raise ArchiveError(f"{filename} has more than {MAX_MEMBERS} entries")
                if not member.isfile():  # skips links, devices, FIFOs, directories
                    continue
                extracted = tf.extractfile(member)  # reads from memory, writes nothing
                if extracted is not None:
                    yield member.name, member.size, extracted


def _strip_top_folder(files: dict[str, str], all_paths: list[str]) -> dict[str, str]:
    """Sdists wrap everything in one folder ("pkg-1.0/setup.py"). Drop it if so.

    Only for sdists: a wheel's paths are where its files get installed, so they're
    kept exactly as they are.
    """
    tops = {p.split("/", 1)[0] for p in all_paths}
    if len(tops) != 1 or not all("/" in p for p in all_paths):
        return files
    return {path.split("/", 1)[1]: text for path, text in files.items()}


def read_members(filename: str, data: bytes) -> dict[str, str]:
    """Path -> text for the .py, .pth and pyproject.toml files in an archive.

    Raises ArchiveError if the archive is corrupt or too big once decompressed.
    """
    files: dict[str, str] = {}
    all_paths: list[str] = []
    total = 0
    try:
        for path, declared_size, handle in _members(filename, data):
            path = path.replace("\\", "/")
            all_paths.append(path)
            if not wanted_by_rules(path) or declared_size > MAX_FILE_BYTES:
                continue
            # Read at most one byte past the limit: the declared size could be a lie.
            content: bytes = handle.read(MAX_FILE_BYTES + 1)  # actual content in bytes
            if len(content) > MAX_FILE_BYTES:  # we got that extra byte: too big
                continue
            total += len(content)
            if total > MAX_TOTAL_BYTES:
                raise ArchiveError(
                    f"{filename} has more than {MAX_TOTAL_BYTES} bytes of source"
                )
            # Python source is UTF-8. Anything else is kept readable rather than dropped,
            # since odd encodings are a way to hide code.
            files[path] = content.decode("utf-8", errors="replace")
    except (tarfile.TarError, zipfile.BadZipFile, zlib.error, EOFError, OSError) as exc:
        raise ArchiveError(f"could not read {filename}: {exc!r}") from exc
    if filename.endswith(".whl"):
        return files
    # sdist: drop its top folder.
    return _strip_top_folder(files, all_paths)


def download_and_read(file: ReleaseFile | None) -> ArchiveContents | None:
    """Download `file` and read its source files. None if there's no file.

    Called by analysis_context.build_analysis_context, for the sdist and the wheel.
    """
    if file is None:
        return None
    data: bytes = pypi.download(file, MAX_DOWNLOAD_BYTES)
    return ArchiveContents(filename=file.filename, files=read_members(file.filename, data))
