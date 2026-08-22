"""지시 파일이 이미 끝난 일을 금지하고 있지 않은가.

`AGENTS.md`는 README와 다르다. README는 읽는 사람에게 설명하고, **`AGENTS.md`는 다음
작업이 무엇을 해도 되는지 정한다.** 틀리면 오해로 끝나지 않고 다음 변경을 잘못된
방향으로 밀어낸다.

실제로 그랬다. `rag-profile-selector`의 것은 "MVP는 HotpotQA만 쓴다"고 몇 달간
지시하고 있었다 — 그 코퍼스는 한 번도 내려받은 적이 없다. `document-intelligence`의
것은 "현재 승인된 작업은 조사·계획·문서화로 한정되며 **애플리케이션 구현을 승인하지
않는다**"고 되어 있었다. 그 저장소에는 구현과 테스트가 있다.

착수 단계의 게이트는 소진되면 소진됐다고 적어야 한다. 지우지는 않는다 — 무엇을
의도적으로 미뤘는지가 사라지기 때문이다. 그래서 게이트 문장 아래에 **소진 표시**를
달고, 이 검사는 그 표시가 붙어 있는지를 본다.

**안전 제약은 이 검사의 대상이 아니다.** 실서비스·실크리덴셜 금지 같은 것은 단계와
무관하게 계속 유효하고, 소진되지 않는다.
"""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTRUCTIONS = ROOT / "AGENTS.md"

# 착수 단계에서만 참이었던 문장들. 지금 이 저장소는 구현돼 있다.
PHASE_GATES = (
    "does not authorize application implementation",
    "AUTO_READY` is limited to repository inspection",
    "Work only on items listed under `AUTO_READY`",
    "Work only on `AUTO_READY` tasks",
)
SPENT = "착수 단계 게이트는 소진됐다"


def instructions_text() -> str:
    return INSTRUCTIONS.read_text(encoding="utf-8")


@pytest.mark.skipif(not INSTRUCTIONS.exists(), reason="AGENTS.md가 없다")
def test_a_spent_phase_gate_is_marked_as_spent():
    text = instructions_text()
    present = [gate for gate in PHASE_GATES if gate in text]
    if not present:
        pytest.skip("이 저장소의 지시 파일에는 단계 게이트 문장이 없다")
    assert SPENT in text, (
        f"단계 게이트 {present}가 소진 표시 없이 남아 있다. "
        f"다음 작업이 이미 끝난 단계로 되돌아간다."
    )


@pytest.mark.skipif(not INSTRUCTIONS.exists(), reason="AGENTS.md가 없다")
def test_the_instructions_point_at_something_that_exists():
    """지시 파일이 가리키는 문서가 없으면 읽으라는 지시가 공회전한다."""
    referenced = re.findall(r"`(docs/[A-Za-z0-9_./-]+\.md)`", instructions_text())
    missing = [name for name in dict.fromkeys(referenced) if not (ROOT / name).exists()]
    assert not missing, f"지시 파일이 없는 문서를 읽으라고 한다: {missing}"


def test_the_instruction_file_does_not_carry_a_stale_test_count():
    """지시 파일이 "지금 이 저장소에는 … 테스트 N개가 돈다"고 말한다.

    2026-08-22에 재보니 세 저장소 모두 낡아 있었다 — `mcp-gateway` 239 대 320,
    `rag-profile-selector` 243 대 317, `document-intelligence` 153 대 189.
    **세 저장소 모두 이 파일을 읽는 검사가 이미 있었고**, 소진 표시와 문서 경로와
    안전 제약을 봤지 **숫자는 아무도 보지 않았다.**

    그 숫자는 "착수 단계는 끝났다"는 근거로 쓰인다. 근거로 쓰이는 숫자가 낡으면
    읽는 사람은 저장소를 실제보다 작게 본다.

    README의 값과 비교한다. README는 CI가 `--collect-only`로 재서 대조하므로,
    여기를 README에 묶으면 세 곳이 한 값을 가리킨다 — **한 사실을 여러 곳에 적으면
    전부 검사해야 한다**가 지난 회차의 결론이었다.
    """
    claimed = re.search(r"테스트 (\d+)개가 돈다", instructions_text())
    assert claimed, "지시 파일에서 테스트 개수를 찾지 못했다. 문장이 바뀌었으면 여기도 고쳐라."
    readme = re.search(r"# (\d+) tests", (ROOT / "README.md").read_text(encoding="utf-8"))
    assert readme, "README에서 테스트 개수를 찾지 못했다"
    assert int(claimed.group(1)) == int(readme.group(1)), (
        f"AGENTS.md는 {claimed.group(1)}개, README는 {readme.group(1)}개라고 한다."
    )


class TestTheCheckIsNotVacuous:
    @pytest.mark.skipif(not INSTRUCTIONS.exists(), reason="AGENTS.md가 없다")
    def test_the_instruction_file_was_actually_read(self):
        assert len(instructions_text()) > 500

    @pytest.mark.skipif(not INSTRUCTIONS.exists(), reason="AGENTS.md가 없다")
    def test_it_still_carries_the_safety_constraints(self):
        """단계 게이트를 소진 처리하면서 안전 제약까지 지우지 않았는지.
        이쪽은 단계와 무관하게 계속 유효하다."""
        text = instructions_text().lower()
        assert any(phrase in text for phrase in
                   ("real service", "real secret", "실서비스", "실크리덴셜",
                    "production", "do not break", "never claim"))

    def test_the_gate_list_is_not_empty(self):
        """`PHASE_GATES = ()`는 모든 저장소를 통과시키면서 검사처럼 보인다."""
        assert len(PHASE_GATES) >= 3

    def test_it_would_notice_an_unmarked_gate(self, tmp_path):
        doc = tmp_path / "AGENTS.md"
        doc.write_text("- Work only on `AUTO_READY` tasks unless approved.\n", encoding="utf-8")
        text = doc.read_text(encoding="utf-8")
        assert any(gate in text for gate in PHASE_GATES)
        assert SPENT not in text
