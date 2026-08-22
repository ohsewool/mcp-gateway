"""거부 아홉 개가 한 번도 발동한 적이 없었다.

2026-08-22에 형제 저장소 `document-intelligence`·`agent-safety-core`에서 한 감사를
여기로 가져왔다. 문자열 메시지를 가진 `raise` **34개를 하나씩 `pass`로 바꾸고** 매번
스위트를 돌렸다.

    잡힘        25건
    안 잡힘      9건

**그중 하나는 테스트가 있는데도 안 잡혔다.** `test_an_empty_body_is_refused`는 빈
응답에 `pytest.raises(TransportError)`만 걸었다. 빈 본문 검사를 지우면 그 다음
`decode_frame("")`이 **같은 타입의** `TransportError("frame is not valid JSON")`를 내고
테스트는 그대로 통과한다. 바로 위 줄의 테스트는 `"500" in str(error.value)`로 메시지를
고정하고 있다 — **한 파일 안에서 규칙이 갈렸다.**

이 프로젝트에서 같은 모양을 이걸로 세 번째 본다. `document-intelligence`의
`test_rejects_duplicate_regions`가 유일성 검사를 지워도 통과했고, 그쪽 옆 파일이 그
이유를 이미 적어두고 있었다. **거부 타입만 보는 단언은 "무언가 거부됐다"만 말한다.**

나머지 여덟은 안 써본 입력이다 — 퇴화한 숫자와 문자열 아닌 키, JSON이 될 수 없는
메타데이터, 깨진 프레임, 그리고 **프로세스가 없는 상태로 stdio를 쓰는 경우 셋**.
마지막 셋이 눈에 띈다: 게이트웨이가 서버 없이 살아 있는 상태를 스위트가 한 번도
만들어본 적이 없다는 뜻이고, 그 상태에서 조용히 성공하면 **차단이 일어나지 않은 채
통과처럼 보인다.**
"""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.guard import canonical_digest  # noqa: E402
from mcp_gateway.metadata_integrity import (  # noqa: E402
    MetadataIntegrityError,
    MetadataSnapshot,
)
from mcp_gateway.policy import DeterministicPolicy, PolicyRule  # noqa: E402
from mcp_gateway.registry import RegisteredServer, RegistryValidationError  # noqa: E402
from mcp_gateway.transport import (  # noqa: E402
    GatewayInterceptor,
    StdioProxy,
    TransportError,
    decode_frame,
)

SERVER_ID = "server-under-test"


def interceptor():
    policy = DeterministicPolicy(
        {SERVER_ID: ["read_file"]},
        [PolicyRule("allow-read", "allow", SERVER_ID, "read_file")],
    )
    server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "local"})
    return GatewayInterceptor(policy, SERVER_ID, baseline_servers=[server])


class TestArgumentsThatCannotBeCanonicalised:
    """승인은 인자 digest에 묶인다. 정규화할 수 없는 값이 통과하면 **승인한 것과
    실행한 것이 다르다는 것을 증명할 수 없게 된다** — 이 저장소의 중심 주장이
    거기에 걸려 있다."""

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_a_non_finite_number_is_refused(self, value):
        with pytest.raises(ValueError, match="non-finite numbers are not permitted"):
            canonical_digest({"amount": value})

    def test_a_non_string_key_is_refused(self):
        """정수 키는 JSON에서 문자열이 된다. 정규 순서가 없으므로 두 구현이 다른
        digest를 낼 수 있고, 그러면 결속이 결속이 아니다."""
        with pytest.raises(ValueError, match="argument keys must be strings"):
            canonical_digest({1: "one"})

    def test_a_plain_payload_still_digests(self):
        """거부만 확인하면 전부 거부하는 구현도 통과한다."""
        assert canonical_digest({"amount": 1000, "tags": ["a", "b"]})


class TestMetadataThatCannotBeSnapshotted:
    def test_the_registry_refuses_it_first_so_the_snapshot_never_sees_it(self):
        """`metadata_integrity.py`의 "snapshot content must be finite JSON data"는
        **도달할 수 없다.** 같은 검사를 `registry.py`가 먼저 하기 때문이다 —
        `RegisteredServer`를 만드는 순간 `RegistryValidationError`가 난다.

        지우지 않는다. 두 겹이 같은 것을 막는 것은 여기서는 의도된 것이고, 등록을
        거치지 않고 스냅숏을 만드는 호출자가 생기면 그때 안쪽이 일한다. 대신
        **바깥쪽이 실제로 먼저 막는지**를 여기서 고정한다 — 바깥이 사라지면 이
        테스트가 실패하고, 그러면 안쪽이 도달 가능해졌다는 뜻이다.

        이것이 이 감사에서 유일하게 "테스트를 쓰지 않기로" 판단한 자리다. 억지로
        도달하려면 `object.__setattr__`로 검증을 우회해야 하는데, 그것은 타입이
        존재할 수 없다고 말하는 상태를 만들어놓고 검사하는 일이다.
        """
        with pytest.raises(RegistryValidationError, match="finite JSON values"):
            RegisteredServer(identifier=SERVER_ID, metadata={"ratio": float("nan")})

    def test_something_that_is_not_a_registry_record_is_refused(self):
        """`servers`가 순회 불가면 `TypeError`가 나고, 그것을 잡아 무엇이 잘못됐는지
        말하는 자리가 있다. 그 자리가 비어 있으면 호출자는 `TypeError`를 그대로
        받는다 — 게이트웨이의 오류가 아니라 파이썬의 오류처럼 보인다."""
        with pytest.raises(MetadataIntegrityError, match="invalid registered metadata"):
            MetadataSnapshot.from_registered(None, [])

    def test_a_real_registration_snapshots(self):
        server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "local"})
        assert MetadataSnapshot.from_registered([server], []).servers


class TestFramesThatAreNotFrames:
    def test_a_frame_that_is_not_json_is_refused(self):
        with pytest.raises(TransportError, match="frame is not valid JSON"):
            decode_frame("{not json")

    def test_a_real_frame_decodes(self):
        assert decode_frame(json.dumps({"jsonrpc": "2.0", "id": 1}))["id"] == 1


class TestUsingStdioWithoutAServer:
    """게이트웨이 객체는 서버 프로세스 없이도 만들어진다. 그 상태에서 읽고 쓰는 것을
    막지 않으면 **차단이 일어나지 않은 채 통과처럼 보인다** — 스위트는 이 상태를 한
    번도 만들어본 적이 없었다."""

    def test_writing_without_a_process_is_refused(self):
        proxy = StdioProxy(interceptor(), ["true"])
        with pytest.raises(TransportError, match="server process is not running"):
            proxy._write({"jsonrpc": "2.0", "id": 1})

    def test_reading_without_a_process_is_refused(self):
        proxy = StdioProxy(interceptor(), ["true"])
        with pytest.raises(TransportError, match="server process is not running"):
            proxy._read(timeout=0.1)

    def test_a_closed_pipe_is_reported_as_a_closed_connection(self):
        """읽을 것이 없는 것과 **상대가 사라진 것**은 다르다. 구분하지 않으면
        서버가 죽은 뒤의 호출이 타임아웃으로 보이고, 타임아웃은 UNKNOWN이 아니라
        재시도로 읽힌다."""
        read_fd, write_fd = os.pipe()
        os.close(write_fd)                      # 상대가 사라졌다
        proxy = StdioProxy(interceptor(), ["true"])

        class DeadProcess:
            stdout = os.fdopen(read_fd, "rb")
            stdin = None

        proxy._process = DeadProcess()
        try:
            with pytest.raises(TransportError, match="server closed the connection"):
                proxy._read(timeout=1.0)
        finally:
            DeadProcess.stdout.close()
