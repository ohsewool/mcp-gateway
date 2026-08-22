"""The gateway is supposed to run without agent-safety-core. Nobody had checked.

The README says the policy and integrity layers work on their own and the
approval tests skip when the core is absent. Every local run had the core
installed, and CI installs it deliberately, so the claim had never been
exercised - the same shape as the audit log the gateway was not writing to and
the two verifiers that could not read each other's logs.

Running it found one test out of five reaching for the core without a guard: it
decided whether to skip by checking for a directory at an absolute path on one
machine. Elsewhere the directory is missing and it skips silently; on that
machine with the package uninstalled the directory is there, the import fails
anyway, and it errors.
"""

import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_no_test_decides_to_skip_by_looking_for_a_filesystem_path():
    """Availability is "does it import", not "is there a directory".

    A path check answers a question about one machine's layout, and gets the
    answer wrong in both directions.
    """
    # 예전 패턴은 `Path("/...형제이름` 하나만 봤다. 좁게 잡은 이유는 기록돼 있었고
    # 맞는 걱정이었다 — 첫 판이 `Path(__file__)`과 이 파일의 산문까지 잡았다.
    #
    # 그런데 좁힌 결과가 **한 가지 철자만** 잡는 상태였다. 2026-08-22에 재봤더니
    # 이 셋이 전부 통과했다:
    #
    #     os.path.exists("/home/jovyan/work/agent-safety-core")
    #     SIBLING = "/home/jovyan/work/agent-safety-core"
    #     from pathlib import Path as P; P("/home/jovyan/work/agent-safety-core")
    #
    # 셋 다 이 검사가 막으려는 바로 그 실수다. 이제 **주석과 독스트링을 걷어낸 뒤**
    # 기계 고유 경로가 문자열 리터럴로 들어 있는지 본다 — 걷어내기가 `Path(__file__)`
    # 오탐과 산문 인용을 함께 없애므로, 넓히면서 정밀도를 잃지 않는다.
    #
    # 인용과 사용을 구분하는 이 방식은 이 저장소들이 이미 여러 번 쓴 것이다.
    without_strings_of_prose = re.compile(r'("""|\'\'\')(?:.|\n)*?\1')
    pattern = re.compile(r'["\'][^"\']*/home/[^"\']*agent-safety-core')
    offenders = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        text = without_strings_of_prose.sub('""', path.read_text(encoding="utf-8"))
        text = "\n".join(re.sub(r"#.*$", "", line) for line in text.splitlines())
        if pattern.search(text):
            offenders.append(path.name)
    assert not offenders, f"hardcoded sibling paths in {offenders}"


# Deliberately no test that every core import uses `importorskip`. A first
# version had one, and it failed on test_live_server.py - which guards the
# import perfectly well with try/except ImportError feeding a skipif. The check
# was asserting a spelling rather than a property, and the property is what the
# subprocess test below measures: with the core absent, the suite skips instead
# of erroring. Testing the effect covers every correct idiom, including ones
# nobody has written yet.


@pytest.mark.integration
def test_the_suite_survives_the_core_being_absent():
    """Run the suite in a subprocess with `core` genuinely unimportable.

    ModuleNotFoundError rather than a bare ImportError, because that is what
    Python raises for a missing module and it is what importorskip is written
    to catch. A first attempt at this harness raised plain ImportError, which
    importorskip did not intercept - so it reported collection errors that were
    an artefact of the harness rather than a fault in the suite.
    """
    script = textwrap.dedent('''
        import sys
        from importlib.abc import MetaPathFinder

        class Absent(MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                if name == "core" or name.startswith("core."):
                    raise ModuleNotFoundError(f"No module named {name!r}", name=name)
                return None

        sys.meta_path.insert(0, Absent())
        import pytest
        sys.exit(pytest.main(["tests/", "-q", "-p", "no:cacheprovider",
                              "-m", "not integration"]))
    ''')
    finished = subprocess.run([sys.executable, "-c", script], cwd=ROOT,
                              capture_output=True, text=True, timeout=900)
    assert finished.returncode == 0, finished.stdout[-2000:]
    assert "skipped" in finished.stdout, "nothing skipped; the core was still reachable"
