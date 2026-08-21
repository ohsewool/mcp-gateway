"""차단된 클라이언트가 무엇을 알게 되는가.

`modelmate`에서 "거절이 필요 이상을 말하는가"를 훑다가 여기로 들고 왔다. 거기서는
로그인 응답 시간이 계정 존재를 알려주고 있었다(280ms 대 10ms).

여기서 재보니, 차단된 `tools/call` 응답은 이유 코드와 **`rule_id`를 함께** 준다:

    delete_file    → explicit_deny,  rule_id "deny-delete-secret"
    no_such_tool   → unknown_tool,   rule_id null
    (규칙 없는 도구) → default_deny,   rule_id null

도구 이름을 훑는 클라이언트는 이것으로 **정책을 지도로 그릴 수 있다** — 어떤 도구가
존재하고, 어떤 것이 명시적으로 금지됐고, 규칙 이름이 무엇을 뜻하는지까지. 규칙
이름은 의도를 담는다.

**그런데 바꾸지 않는다.** 정찰은 `docs/PROJECT_SPEC.md` §3의 승인된 위협 집합에
없고, `AGENTS.md`는 그 밖의 위협을 추가하려면 `NEEDS_APPROVAL`에 적고 승인을 받으라고
한다. 적어뒀다. 그리고 이유 코드는 정당한 클라이언트가 다음 행동을 정하는 근거이자
운영자가 정책을 디버깅하는 근거다 — 지우면 그 둘을 함께 잃는다.

이 파일이 하는 일은 **지금 모양을 고정**하는 것이다. 바뀌는 날 이 테스트가 실패하고,
그때 위 결정을 다시 하게 된다. 그냥 흘러가서 바뀌는 것과 정해서 바꾸는 것은 다르다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_gateway.policy import DeterministicPolicy, PolicyRule
from mcp_gateway.registry import RegisteredServer
from mcp_gateway.transport import GatewayInterceptor

SERVER = "srv"


def interceptor():
    policy = DeterministicPolicy(
        {SERVER: ["read_file", "delete_file", "unruled_tool"]},
        [PolicyRule("allow-read", "allow", SERVER, "read_file"),
         PolicyRule("deny-delete-secret", "deny", SERVER, "delete_file")])
    return GatewayInterceptor(
        policy, SERVER,
        baseline_servers=[RegisteredServer(identifier=SERVER, metadata={})])


def call(tool):
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}}


def reply_for(tool):
    return interceptor().inspect_request(call(tool)).reply


class TestWhatABlockedClientLearns:
    @pytest.mark.parametrize("tool,reason", [
        ("delete_file", "explicit_deny"),
        ("no_such_tool", "unknown_tool"),
        ("unruled_tool", "default_deny"),
    ])
    def test_the_reason_code_is_returned(self, tool, reason):
        assert reason in reply_for(tool)["error"]["message"]

    def test_the_rule_id_is_returned_for_an_explicit_deny(self):
        """규칙 이름이 나간다. 지금 상태를 못박아 두는 것이 이 파일의 요점이다."""
        assert reply_for("delete_file")["error"]["data"]["rule_id"] == "deny-delete-secret"

    def test_no_rule_id_when_no_rule_matched(self):
        for tool in ("no_such_tool", "unruled_tool"):
            assert reply_for(tool)["error"]["data"]["rule_id"] is None

    def test_the_three_cases_are_distinguishable(self):
        """구별되기 때문에 지도가 그려진다. 구별을 없애는 것이 이 결정의 반대편이다."""
        reasons = {reply_for(tool)["error"]["message"]
                   for tool in ("delete_file", "no_such_tool", "unruled_tool")}
        assert len(reasons) == 3


class TestThisIsRecordedAsADecisionNotAnOversight:
    def test_reconnaissance_is_absent_from_the_spec(self):
        spec = (Path(__file__).resolve().parents[1] / "docs" / "PROJECT_SPEC.md").read_text(
            encoding="utf-8")
        section = spec[spec.index("## 3. Approved threat"):]
        section = section[:section.index("## 4.")]
        assert "reconnaissance" not in section.lower()

    def test_it_is_filed_under_needs_approval(self):
        tasks = (Path(__file__).resolve().parents[1] / "docs" / "TASKS.md").read_text(
            encoding="utf-8")
        assert "policy reconnaissance" in tasks.lower()


class TestTheAuditKeepsMoreThanTheClientSees:
    """운영자와 클라이언트가 같은 것을 볼 필요는 없다. 지금은 같지만, 그 사실도
    적어둔다 — 나중에 갈라놓는다면 그것이 위 결정을 실행하는 방법이다."""

    def test_the_record_carries_the_rule_id(self):
        instance = interceptor()
        instance.inspect_request(call("delete_file"))
        record = instance.records[-1]
        assert record.rule_id == "deny-delete-secret"
        assert record.action == "blocked"


class TestTheChecksAreNotVacuous:
    def test_an_allowed_call_is_not_blocked(self):
        """전부 차단하는 인터셉터로도 위 검사 대부분이 통과한다."""
        assert reply_for("read_file") is None

    def test_the_reply_shape_is_what_the_tests_assume(self):
        reply = reply_for("delete_file")
        assert set(reply) >= {"error"}
        assert set(reply["error"]) >= {"code", "message", "data"}
