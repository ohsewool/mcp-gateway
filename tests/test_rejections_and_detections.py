"""거부와 탐지가 실제로 동작하는가 — 이 저장소에서는 그게 곧 제품이다.

커버리지로 훑었더니 `metadata_integrity.py`와 `registry.py`가 89%·88%였고,
**실행되지 않는 줄이 거의 전부 거부 아니면 탐지**였다. 게이트웨이는 막기 위해
존재하는데, 막는 코드가 한 번도 실행된 적이 없었다.

두 종류가 섞여 있었다.

**거부** — 잘못된 메타데이터를 레지스트리에 들이지 않는 검사 18개. 위조된
`integrity_id`, 비유한수, 객체가 아닌 스키마, 중복 `required`, 미등록 서버의 도구.
전부 쏴봤고 전부 동작한다.

**탐지** — `compare_metadata`가 서버가 **추가되거나 제거된** 것을 잡는 경로.
rug-pull 탐지의 일부인데 실행된 적이 없었다. 도구가 바뀌는 경우는 테스트가 있었고
서버 단위는 없었다. 이것도 동작한다.

결함은 없었다. 그래서 이 파일은 고치는 것이 아니라 **다음에 조건이 뒤집혔을 때
알아차리게** 하는 것이다. 자매 저장소 `agent-safety-core`에서 같은 방법으로 훑었을
때는 하나가 나왔다 — 경로 traversal 검사가 발동할 수 없는 상태였다.

**프로브가 틀려서 헛것을 봤던 기록.** 처음에 `RegisteredTool`을 잘못된 인자로
불렀고, 생성자가 낸 `TypeError`를 "거부가 동작한다"로 읽었다. 일곱 개가 그렇게
초록불이었다. 검사하려던 거부는 하나도 실행되지 않았다. 그래서 아래 헬퍼는 실제
서명으로 한 벌을 만들고 필요한 것만 바꾼다 — 인자를 매번 손으로 쓰면 같은 실수가
반복된다.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.metadata_integrity import (  # noqa: E402
    MetadataIntegrityError,
    MetadataSnapshot,
    ServerMetadataSnapshot,
    ToolMetadataSnapshot,
    compare_metadata,
)
from mcp_gateway.registry import (  # noqa: E402
    RegisteredServer,
    RegisteredTool,
    RegistryError,
    RegistryValidationError,
    ServerToolRegistry,
)


def server(identifier: str = "fs", **over) -> RegisteredServer:
    return RegisteredServer(**{"identifier": identifier, "metadata": {}, **over})


def registered_tool(**over) -> RegisteredTool:
    """실제 서명으로 만든 한 벌. 필요한 것만 바꾼다.

    인자를 매번 손으로 쓰다가 존재하지 않는 이름을 넘겼고, 생성자의 `TypeError`를
    거부로 착각했다. 한 곳에서 만들면 그 실수가 이 파일 전체에서 한 번에 드러난다.
    """
    return RegisteredTool(**{"server_identifier": "fs", "identifier": "read",
                             "input_schema": {"type": "object"}, "metadata": {}, **over})


class TestTheRegistryRefusesForgedIntegrity:
    """`integrity_id`는 내용에서 계산된다. 공급된 값이 다르면 내용이 바뀐 것이다."""

    def test_a_forged_server_integrity_id_is_refused(self):
        with pytest.raises(RegistryValidationError, match="server integrity_id"):
            server(integrity_id="deadbeef")

    def test_a_forged_tool_integrity_id_is_refused(self):
        with pytest.raises(RegistryValidationError, match="tool integrity_id"):
            registered_tool(integrity_id="deadbeef")

    def test_a_matching_integrity_id_is_accepted(self):
        """거부만 확인하면 전부 거부하는 구현도 통과한다."""
        calculated = server().integrity_id
        assert server(integrity_id=calculated).integrity_id == calculated


class TestTheRegistryRefusesMalformedMetadata:
    def test_a_non_finite_number_is_refused(self):
        with pytest.raises(RegistryValidationError, match="finite JSON"):
            server(metadata={"a": float("nan")})

    def test_metadata_that_is_not_an_object_is_refused(self):
        with pytest.raises(RegistryValidationError, match="must be a JSON object"):
            server(metadata=[1, 2])

    def test_schema_properties_must_be_an_object(self):
        with pytest.raises(RegistryValidationError, match="properties must be an object"):
            registered_tool(input_schema={"type": "object", "properties": [1, 2]})

    def test_schema_required_must_be_a_list(self):
        with pytest.raises(RegistryValidationError, match="required must be a list"):
            registered_tool(input_schema={"type": "object", "required": "path"})

    def test_schema_required_must_not_repeat(self):
        with pytest.raises(RegistryValidationError, match="must not contain duplicates"):
            registered_tool(input_schema={"type": "object", "required": ["a", "a"]})


class TestTheRegistryRefusesWrongShapes:
    def test_registering_something_that_is_not_a_server(self):
        with pytest.raises(RegistryValidationError, match="must be a RegisteredServer"):
            ServerToolRegistry().register_server("fs")

    def test_registering_something_that_is_not_a_tool(self):
        registry = ServerToolRegistry()
        registry.register_server(server())
        with pytest.raises(RegistryValidationError, match="must be a RegisteredTool"):
            registry.register_tool("read")

    def test_a_tool_for_an_unregistered_server_is_refused(self):
        """서버를 모르면 그 도구를 허용할 근거가 없다."""
        registry = ServerToolRegistry()
        registry.register_server(server())
        with pytest.raises(RegistryError, match="is not registered"):
            registry.register_tool(registered_tool(server_identifier="nope"))

    def test_an_ordinary_registration_still_works(self):
        registry = ServerToolRegistry()
        registry.register_server(server())
        registry.register_tool(registered_tool())
        assert len(registry.registered_tools()) == 1


class TestSnapshotsRefuseWhatTheyCannotRecord:
    def test_a_server_snapshot_needs_a_registered_server(self):
        with pytest.raises(MetadataIntegrityError, match="requires a RegisteredServer"):
            ServerMetadataSnapshot.from_registered("fs")

    def test_a_tool_snapshot_needs_a_registered_tool(self):
        with pytest.raises(MetadataIntegrityError, match="requires a RegisteredTool"):
            ToolMetadataSnapshot.from_registered("read")

    def test_a_snapshot_needs_a_registry(self):
        with pytest.raises(MetadataIntegrityError, match="requires a ServerToolRegistry"):
            MetadataSnapshot.from_registry({})

    def test_duplicate_server_identifiers_are_refused(self):
        with pytest.raises(MetadataIntegrityError, match="conflicting server identifiers"):
            MetadataSnapshot.from_registered([server(), server()], [])

    def test_duplicate_tool_identifiers_are_refused(self):
        with pytest.raises(MetadataIntegrityError, match="conflicting tool identifiers"):
            MetadataSnapshot.from_registered([server()], [registered_tool(), registered_tool()])

    def test_a_tool_without_its_server_is_refused(self):
        """서버가 없는 도구 기록은 무엇에 대한 무결성인지 말할 수 없다."""
        with pytest.raises(MetadataIntegrityError, match="unregistered server"):
            MetadataSnapshot.from_registered([server()],
                                             [registered_tool(server_identifier="other")])

    def test_comparing_things_that_are_not_snapshots_is_refused(self):
        with pytest.raises(MetadataIntegrityError, match="require MetadataSnapshot"):
            compare_metadata("before", "after")


class TestWholeServersAppearingOrVanishingIsDetected:
    """rug-pull 탐지에서 실행된 적 없던 부분.

    도구가 바뀌는 경우는 테스트가 있었고 **서버 단위는 없었다.** 서버가 통째로
    나타나거나 사라지는 것은 도구 하나가 바뀌는 것보다 큰 사건인데, 그 경로가
    한 번도 돌지 않았다.
    """

    def _snapshot(self, servers, tools):
        return MetadataSnapshot.from_registered(servers, tools)

    def test_a_new_server_is_reported(self):
        before = self._snapshot([server("fs")], [registered_tool()])
        after = self._snapshot([server("fs"), server("net")], [registered_tool()])
        changes = compare_metadata(before, after)
        assert [(c.subject, c.server_identifier, c.reason) for c in changes] == [
            ("server", "net", "server_added")]

    def test_a_vanished_server_is_reported_with_its_tools(self):
        """서버가 사라지면 그 도구도 사라진다. 둘 다 보고돼야 무엇이 없어졌는지
        읽을 수 있다."""
        before = self._snapshot([server("fs")], [registered_tool()])
        changes = compare_metadata(before, self._snapshot([], []))
        assert {c.reason for c in changes} == {"server_removed", "tool_removed"}

    def test_a_new_tool_is_reported(self):
        before = self._snapshot([server("fs")], [registered_tool()])
        after = self._snapshot([server("fs")],
                               [registered_tool(), registered_tool(identifier="write")])
        assert [c.reason for c in compare_metadata(before, after)] == ["tool_added"]

    def test_a_changed_schema_is_reported(self):
        before = self._snapshot([server("fs")], [registered_tool()])
        after = self._snapshot([server("fs")], [registered_tool(
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}})])
        assert [c.reason for c in compare_metadata(before, after)] == ["tool_schema_changed"]

    def test_an_unchanged_snapshot_reports_nothing(self):
        """모든 것을 변화로 보고하는 비교기는 아무것도 보고하지 않는 것과 같다 —
        읽는 사람이 끄게 된다."""
        snapshot = self._snapshot([server("fs")], [registered_tool()])
        assert not compare_metadata(snapshot, snapshot)
