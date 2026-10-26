"""Tests for crotalus.archive.

Hostile archives are built inside the tests, so no malicious file is ever stored
in the repo, and nothing here writes to disk.
"""

import hashlib
import io
import stat
import tarfile
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime

import httpx
import pytest

from crotalus import archive
from crotalus.archive import ArchiveError, choose_files_to_inspect, download_and_read, read_members
from crotalus.models import ReleaseFile

T0 = datetime(2026, 10, 17, tzinfo=UTC)
MB = 1024 * 1024

FakePyPI = Callable[[Callable[[httpx.Request], httpx.Response]], None]


def release_file(filename: str, size: int = 1000, data: bytes = b"") -> ReleaseFile:
    packagetype = "bdist_wheel" if filename.endswith(".whl") else "sdist"
    return ReleaseFile(
        filename=filename,
        url=f"https://files.pythonhosted.org/packages/{filename}",
        packagetype=packagetype,
        size=size,
        sha256=hashlib.sha256(data).hexdigest(),
        uploaded_at=T0,
    )


def make_tar(files: dict[str, bytes], extra: list[tarfile.TarInfo] | None = None) -> bytes:
    """A .tar.gz with `files` (path -> content) plus any special `extra` entries."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for path, content in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        for info in extra or []:
            tf.addfile(info)
    return buffer.getvalue()


def make_zip(files: dict[str, bytes], symlinks: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in files.items():
            zf.writestr(path, content)
        for path, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(path)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return buffer.getvalue()


# choose_files_to_inspect


SDIST = release_file("pkg-1.0.tar.gz")
ANY = release_file("pkg-1.0-py3-none-any.whl")
LINUX = release_file("pkg-1.0-cp313-cp313-manylinux_2_17_x86_64.whl")
LINUX_OLD = release_file("pkg-1.0-cp310-cp310-manylinux_2_17_x86_64.whl")
LINUX_ARM = release_file("pkg-1.0-cp313-cp313-manylinux_2_17_aarch64.whl")
WINDOWS = release_file("pkg-1.0-cp313-cp313-win_amd64.whl")
MAC = release_file("pkg-1.0-cp313-cp313-macosx_11_0_arm64.whl")


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ((SDIST, ANY), (SDIST, ANY)),
        ((MAC, WINDOWS, LINUX, ANY), (None, ANY)),  # pure-Python wins
        ((MAC, WINDOWS, LINUX), (None, LINUX)),  # then Linux
        ((MAC, WINDOWS), (None, WINDOWS)),  # then Windows
        ((MAC,), (None, MAC)),
        ((LINUX_OLD, LINUX), (None, LINUX)),  # newest CPython first
        ((LINUX_ARM, LINUX_OLD), (None, LINUX_OLD)),  # x86-64 before ARM, even if older
        ((SDIST,), (SDIST, None)),
        ((), (None, None)),
    ],
)
def test_choose_files_to_inspect(
    files: tuple[ReleaseFile, ...], expected: tuple[ReleaseFile | None, ReleaseFile | None]
) -> None:
    assert choose_files_to_inspect(files) == expected


def test_too_big_files_are_skipped() -> None:
    huge = release_file("pkg-1.0.tar.gz", size=archive.MAX_DOWNLOAD_BYTES + 1)
    assert choose_files_to_inspect((huge, ANY)) == (None, ANY)


def test_invalid_wheel_name_is_skipped() -> None:
    assert choose_files_to_inspect((release_file("not-a-real-wheel.whl"),)) == (None, None)


# read_members: what gets read


def test_reads_sdist_sources() -> None:
    data = make_tar(
        {
            "pkg-1.0/setup.py": b"from setuptools import setup\nsetup()\n",
            "pkg-1.0/pyproject.toml": b"[build-system]\n",
            "pkg-1.0/pkg/__init__.py": b"VERSION = '1.0'\n",
            "pkg-1.0/README.md": b"# pkg\n",  # not source: skipped
            "pkg-1.0/PKG-INFO": b"Name: pkg\n",
        }
    )
    assert read_members("pkg-1.0.tar.gz", data) == {
        "setup.py": "from setuptools import setup\nsetup()\n",  # top folder dropped
        "pyproject.toml": "[build-system]\n",
        "pkg/__init__.py": "VERSION = '1.0'\n",
    }


def test_reads_wheel_sources() -> None:
    data = make_zip(
        {
            "pkg/__init__.py": b"x = 1\n",
            "pkg_hook.pth": b"import os\n",  # runs on every Python startup
            "pkg-1.0.dist-info/METADATA": b"Name: pkg\n",
        }
    )
    assert read_members("pkg-1.0-py3-none-any.whl", data) == {
        "pkg/__init__.py": "x = 1\n",
        "pkg_hook.pth": "import os\n",
    }


def test_non_utf8_is_kept_readable() -> None:
    data = make_zip({"pkg/__init__.py": b"x = '\xff\xfe'\n"})
    assert read_members("pkg-1.0-py3-none-any.whl", data)["pkg/__init__.py"].startswith("x = '")


def test_oversized_source_file_is_skipped() -> None:
    data = make_zip({"pkg/big.py": b"#" * (archive.MAX_FILE_BYTES + 1), "pkg/ok.py": b"ok\n"})
    assert read_members("pkg-1.0-py3-none-any.whl", data) == {"pkg/ok.py": "ok\n"}


# read_members: hostile archives


def test_path_traversal_is_just_a_name() -> None:
    # Extracting this naively would write outside the target folder. We never extract.
    data = make_tar({"../../evil.py": b"import os\n", "/etc/cron.py": b"x\n"})
    assert read_members("pkg-1.0.tar.gz", data) == {
        "../../evil.py": "import os\n",
        "/etc/cron.py": "x\n",
    }


def test_tar_links_and_devices_are_skipped() -> None:
    symlink = tarfile.TarInfo("pkg-1.0/link.py")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "/etc/passwd"
    hardlink = tarfile.TarInfo("pkg-1.0/hard.py")
    hardlink.type = tarfile.LNKTYPE
    hardlink.linkname = "pkg-1.0/setup.py"
    device = tarfile.TarInfo("pkg-1.0/dev.py")
    device.type = tarfile.CHRTYPE
    data = make_tar({"pkg-1.0/setup.py": b"setup()\n"}, extra=[symlink, hardlink, device])
    assert read_members("pkg-1.0.tar.gz", data) == {"setup.py": "setup()\n"}


def test_zip_symlinks_are_skipped() -> None:
    data = make_zip({"pkg/__init__.py": b"x\n"}, symlinks={"pkg/evil.py": "/etc/passwd"})
    assert read_members("pkg-1.0-py3-none-any.whl", data) == {"pkg/__init__.py": "x\n"}


def test_too_many_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "MAX_MEMBERS", 3)
    data = make_zip({f"pkg/m{i}.py": b"x\n" for i in range(4)})
    with pytest.raises(ArchiveError):
        read_members("pkg-1.0-py3-none-any.whl", data)


def test_archive_bomb(monkeypatch: pytest.MonkeyPatch) -> None:
    # 3 files of 1 MB of zeros: a few KB compressed, much more once read.
    monkeypatch.setattr(archive, "MAX_TOTAL_BYTES", 2 * MB)
    data = make_zip({f"pkg/zeros{i}.py": b"\0" * MB for i in range(3)})
    assert len(data) < 50_000
    with pytest.raises(ArchiveError):
        read_members("pkg-1.0-py3-none-any.whl", data)


@pytest.mark.parametrize("filename", ["pkg-1.0.tar.gz", "pkg-1.0-py3-none-any.whl"])
def test_corrupt_archive(filename: str) -> None:
    with pytest.raises(ArchiveError):
        read_members(filename, b"this is not an archive")


# download_and_read


def test_download_and_read(fake_pypi: FakePyPI) -> None:
    data = make_zip({"pkg/__init__.py": b"x = 1\n"})
    file = release_file("pkg-1.0-py3-none-any.whl", data=data)
    fake_pypi(lambda request: httpx.Response(200, content=data))
    contents = download_and_read(file)
    assert contents is not None
    assert contents.filename == file.filename
    assert contents.files == {"pkg/__init__.py": "x = 1\n"}


def test_load_nothing() -> None:
    assert download_and_read(None) is None
