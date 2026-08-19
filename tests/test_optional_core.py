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
    # Precise on purpose. A first version flagged any file mentioning the
    # sibling alongside any absolute path, which caught Path(__file__) and this
    # file's own docstring - a check that fires on everything is as useless as
    # one that fires on nothing.
    pattern = re.compile(r'Path\(\s*"/[^"]*agent-safety-core')
    offenders = [path.name for path in sorted((ROOT / "tests").glob("*.py"))
                 if pattern.search(path.read_text(encoding="utf-8"))]
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
