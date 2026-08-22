"""선언한 의존성이 실제로 쓰는 것과 맞는가.

**이 파일은 나흘 동안 비어 있었다.** 2026-08-19에 "코어 없이도 도는가"를 확인하는
커밋이 두 파일을 만들었는데, `test_optional_core.py`에는 내용이 들어갔고 여기에는
들어가지 않았다. 0바이트로 커밋됐고 그대로 있었다.

**아무 검사도 그것을 말하지 않았다.** 테스트 개수 대조는 0을 더해도 0이니 눈치채지
못하고, 공허 테스트 검사기는 **테스트가 있어야** 그것이 공허한지 볼 수 있다. 파일을
하나씩 따로 돌려보다가 `no tests ran`(종료 코드 5)으로 드러났다.

이름이 약속한 검사를 이제 쓴다. `pyproject.toml`은 이렇게 말한다:

    dependencies = []

**의존성이 없다는 것은 이 저장소의 주장이다.** MCP 서버 앞에 끼어드는 프록시가
설치할 것을 요구하지 않는다는 것은 배포 결정을 바꾸는 사실이고, 그 주장은 소스가
표준 라이브러리 밖의 것을 import하지 않을 때만 참이다.

예외가 하나 있다. `audit.py`가 `core.checkpoint`를 **함수 안에서** import한다 —
형제 저장소 `agent-safety-core`의 서명을 앵커링에 쓴다. 그것이 함수 안에 있는 이유가
정확히 이 주장이다: 모듈 수준으로 올리면 코어가 없는 곳에서 **import만으로 게이트웨이
전체가 죽는다.** `test_optional_core.py`가 그 상태를 하위 프로세스로 만들어 확인하고,
여기서는 **그 import가 함수 안에 남아 있는지**를 지킨다.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "mcp_gateway"

# 함수 안에서만 허용되는 최상위 이름. 늘리려면 이유가 있어야 한다 —
# 이 목록이 길어지는 것은 "의존성 없음"이 흐려지고 있다는 뜻이다.
LAZY_ONLY = {"core"}


def modules() -> list[Path]:
    return sorted(path for path in PACKAGE.rglob("*.py") if "__pycache__" not in path.parts)


def imports(tree: ast.AST) -> list[tuple[str, bool]]:
    """(최상위 이름, 모듈 수준인가). 함수·메서드 안의 import는 지연 import다."""
    inside_a_function = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in ast.walk(node):
                inside_a_function.add(id(inner))

    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((alias.name.split(".")[0], id(node) not in inside_a_function))
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.append((node.module.split(".")[0], id(node) not in inside_a_function))
    return found


def outside_the_standard_library() -> dict[str, set[str]]:
    stdlib = set(sys.stdlib_module_names)
    found: dict[str, set[str]] = {}
    for path in modules():
        for name, at_module_level in imports(ast.parse(path.read_text(encoding="utf-8"))):
            if name in stdlib or name == "mcp_gateway":
                continue
            found.setdefault(name, set()).add(f"{path.name}{'' if at_module_level else ' (지연)'}")
    return found


class TestTheDeclarationMatchesTheSource:
    def test_the_project_declares_no_runtime_dependencies(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        assert data["project"]["dependencies"] == []

    def test_nothing_outside_the_standard_library_is_imported_at_module_level(self):
        """모듈 수준 import는 **설치 요구사항**이다. 함수 안의 것과 달리, 없으면
        `import mcp_gateway` 자체가 실패한다."""
        stdlib = set(sys.stdlib_module_names)
        offenders: dict[str, set[str]] = {}
        for path in modules():
            for name, at_module_level in imports(ast.parse(path.read_text(encoding="utf-8"))):
                if name in stdlib or name == "mcp_gateway" or not at_module_level:
                    continue
                offenders.setdefault(name, set()).add(path.name)
        assert offenders == {}, (
            f"모듈 수준에서 밖을 부른다: {offenders}. "
            "`pyproject.toml`의 `dependencies = []`가 더 이상 참이 아니다."
        )

    def test_the_only_outside_name_is_the_sibling_and_it_is_lazy(self):
        outside = outside_the_standard_library()
        assert set(outside) == LAZY_ONLY, f"밖의 이름: {sorted(outside)}"
        for name, where in outside.items():
            assert all("(지연)" in place for place in where), f"{name}: {sorted(where)}"

    def test_the_test_requirements_stay_test_only(self):
        """`requirements.txt`는 검사에 필요한 것만 담는다. 런타임 의존성이 여기로
        들어오면 `dependencies = []`와 갈린다 — 한 사실을 두 곳에 적는 셈이다."""
        declared = [line.strip() for line
                    in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
        assert declared == ["pytest>=8"], declared


class TestTheScanIsNotVacuous:
    def test_it_read_the_package(self):
        assert len(modules()) >= 5
        assert any(path.name == "audit.py" for path in modules())

    def test_it_can_tell_module_level_from_lazy(self):
        tree = ast.parse(
            "import json\n"
            "def f():\n"
            "    import cryptography\n"
        )
        found = dict(imports(tree))
        assert found["json"] is True
        assert found["cryptography"] is False

    def test_it_would_notice_a_new_outside_import(self):
        stdlib = set(sys.stdlib_module_names)
        tree = ast.parse("import requests\n")
        assert [name for name, _ in imports(tree) if name not in stdlib] == ["requests"]

    def test_this_file_is_not_empty_again(self):
        """**이 파일이 나흘 동안 0바이트였다.** 그 상태를 스스로 알아채는 검사는 이
        파일 안에 있을 수 없다 — 파일이 비면 이 검사도 함께 사라진다. 그래서 프로필
        저장소의 `find_vacuous_tests.py`가 다섯 저장소를 훑어 **테스트가 하나도 없는
        테스트 파일**을 잡게 했다. 여기서는 그 사실을 기록으로만 남긴다."""
        assert Path(__file__).stat().st_size > 1000
