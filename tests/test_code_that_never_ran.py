"""스위트가 한 번도 실행하지 않던 줄들.

거부 감사(`test_rejections_that_were_never_fired.py`)는 `raise`만 봤다. 2026-08-22에
질문을 넓혔다 — **스위트가 한 번도 실행하지 않는 줄이 무엇인가.** 네 저장소에서 81줄이
나왔고, 여기가 44줄로 가장 많았다.

두 덩어리가 컸다.

**`HttpProxy._post`의 실제 네트워크 경로 전체**(19줄 중 19줄). 모든 테스트가 `opener`
스텁을 넘기므로 `urllib`을 쓰는 진짜 경로가 한 번도 돌지 않았다. 거기에는 이 저장소가
README에서 약속한 것이 들어 있다 — HTTP 오류와 타임아웃을 파이프와 같은 원칙으로
구분해 옮기는 세 줄. **약속을 지키는 코드가 한 번도 실행되지 않았다.**

**`python3 -m mcp_gateway.audit verify` CLI 전체.** README 19줄이 안내하는 명령이다.
문서가 시키는 것을 아무도 돌려본 적이 없었다.

CLI는 먼저 손으로 돌려봤다. 온전한 로그는 `OK`, 내용 변조는 `content was modified`,
중간 줄 삭제는 `chain is broken` + `sequence jumped`, 없는 파일은 `log does not exist`.
**결함은 없었다. 없던 것은 검사다.**

그 확인 중에 내 대조가 한 번 헛돌았다. 기록은 정규 JSON(`"request_id":1`, 공백 없음)
인데 `"request_id": 1`로 치환해서 **아무것도 바꾸지 않은 채 "OK"를 받았다.** 하마터면
"감사 로그가 변조를 못 잡는다"고 적을 뻔했다 — 대조가 실제로 무언가를 바꿨는지 보는
것이 대조의 절반이다.

여기서 쓰는 HTTP 서버는 **127.0.0.1의 이 프로세스가 띄우는 것**이다. 바깥으로 나가지
않는다.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp_gateway.audit import AuditLog, AuditReport, main as audit_main  # noqa: E402
from mcp_gateway.policy import DeterministicPolicy, PolicyRule  # noqa: E402
from mcp_gateway.registry import RegisteredServer  # noqa: E402
from mcp_gateway.transport import (  # noqa: E402
    CALL_TIMEOUT,
    CallTimeout,
    GatewayInterceptor,
    HttpProxy,
    TransportError,
)

SERVER_ID = "remote-server"


def interceptor():
    policy = DeterministicPolicy(
        {SERVER_ID: ["read_file"]},
        [PolicyRule("allow-read", "allow", SERVER_ID, "read_file")],
    )
    server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "remote"})
    return GatewayInterceptor(policy, SERVER_ID, baseline_servers=[server])


def call(request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {}}}


def audit_log_with(count: int, tmp_path: Path) -> Path:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for index in range(count):
        log.record({"direction": "request", "method": "tools/call", "request_id": index,
                    "action": "allow", "reason_code": "policy_allow", "rule_id": "r1",
                    "detail": {}}, server_id=SERVER_ID)
    return path


# ── 문서가 안내하는 CLI ────────────────────────────────────────────────────

def verify(path: Path) -> tuple[int, str]:
    """README가 적어둔 그대로 하위 프로세스로 부른다. `main()`을 직접 부르면
    `python3 -m ...`이 실제로 되는지는 여전히 확인되지 않는다 — 이 저장소는
    'import가 되는 것과 경로가 맞는 것은 다르다'로 이미 한 번 데었다."""
    finished = subprocess.run(
        [sys.executable, "-m", "mcp_gateway.audit", "verify", str(path)],
        capture_output=True, text=True, cwd=ROOT, timeout=120,
        env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
    )
    return finished.returncode, finished.stdout.strip()


class TestTheDocumentedCommand:
    def test_an_intact_log_verifies(self, tmp_path):
        code, output = verify(audit_log_with(3, tmp_path))
        assert code == 0
        assert output == "OK — 3 records, chain intact"

    def test_modified_content_is_reported(self, tmp_path):
        path = audit_log_with(3, tmp_path)
        lines = path.read_text(encoding="utf-8").splitlines()
        # 정규 JSON이라 공백이 없다. 이 단언이 없으면 치환이 헛돌아도 검사는
        # "OK"를 보고 통과한다 - 실제로 한 번 그렇게 헛돌았다.
        assert '"request_id":1' in lines[1], lines[1]
        lines[1] = lines[1].replace('"request_id":1', '"request_id":99', 1)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        code, output = verify(path)
        assert code == 1
        assert "content was modified" in output

    def test_a_removed_record_is_reported(self, tmp_path):
        path = audit_log_with(3, tmp_path)
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
        code, output = verify(path)
        assert code == 1
        assert "chain is broken" in output
        assert "sequence jumped" in output

    def test_a_missing_log_is_reported(self, tmp_path):
        code, output = verify(tmp_path / "nothing.jsonl")
        assert code == 1
        assert "does not exist" in output

    def test_the_readme_still_names_this_command(self):
        """검사만 남고 안내가 사라지면 이 파일은 아무도 쓰지 않는 것을 지킨다."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        assert "python3 -m mcp_gateway.audit verify" in readme

    def test_main_returns_the_same_verdicts_in_process(self, tmp_path, capsys):
        """하위 프로세스는 `python3 -m`이 되는지를 보고, 이건 반환값을 본다."""
        assert audit_main(["verify", str(audit_log_with(2, tmp_path))]) == 0
        assert "chain intact" in capsys.readouterr().out


class TestTheReportSaysWhatHappened:
    def test_an_ok_report_summarises_as_ok(self):
        assert AuditReport(3, (), "").summary() == "OK — 3 records, chain intact"

    def test_reading_a_log_that_is_not_there_yields_nothing(self, tmp_path):
        """빈 로그와 없는 로그를 구분하지 않으면, 감사기를 처음 켠 사람이
        '기록이 0건'과 '경로가 틀렸다'를 같은 화면으로 본다."""
        assert AuditLog(tmp_path / "absent.jsonl").read() == ()


# ── 실제 네트워크 경로 ─────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    status = 200
    delay = 0.0

    def do_POST(self):                                   # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        sent = json.loads(self.rfile.read(length) or b"{}")
        if type(self).delay:
            time.sleep(type(self).delay)
        body = json.dumps({"jsonrpc": "2.0", "id": sent.get("id"),
                           "result": {"ok": True}}).encode("utf-8")
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):                        # 테스트 출력을 더럽히지 않는다
        return

    def handle_one_request(self):
        # 클라이언트가 타임아웃으로 먼저 끊으면 여기서 BrokenPipe가 난다. 그것은
        # **시험하려는 것**(느린 서버)의 결과이지 실패가 아니므로 조용히 넘긴다.
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True


@pytest.fixture
def loopback():
    """127.0.0.1에 뜨는 이 프로세스의 서버. 바깥으로 나가지 않는다."""
    def start(*, status=200, delay=0.0):
        handler = type("Handler", (_Handler,), {"status": status, "delay": delay})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, f"http://127.0.0.1:{server.server_address[1]}/rpc"

    started = []
    def factory(**kwargs):
        server, url = start(**kwargs)
        started.append(server)
        return url
    yield factory
    for server in started:
        server.shutdown()
        server.server_close()


class TestTheRealNetworkPath:
    """`opener`를 넘기지 않으면 `urllib`을 쓰는 경로가 돈다. 스위트는 늘 스텁을
    넘겼으므로 **그 경로 전체가 한 번도 실행되지 않았다** — 그 안에 README가 약속한
    오류 구분 셋이 들어 있다."""

    def test_a_real_request_reaches_a_real_server(self, loopback):
        with HttpProxy(interceptor(), loopback()) as proxy:
            assert proxy.request(call())["result"] == {"ok": True}

    def test_an_http_error_becomes_a_transport_error(self, loopback):
        """서버에 **닿았고** 거부당했다. 도달하지 못한 것과 다르고, 그 차이가
        '이미 실행됐는가'를 가른다."""
        with HttpProxy(interceptor(), loopback(status=503)) as proxy:
            with pytest.raises(TransportError) as error:
                proxy.request(call())
        assert "503" in str(error.value)

    def test_an_unreachable_endpoint_is_reported_as_unreachable(self):
        """닫힌 포트. 타임아웃이 아니라 도달 실패이고, 둘을 같은 말로 보고하면
        '응답이 없다'와 '서버가 없다'가 구분되지 않는다."""
        with HttpProxy(interceptor(), "http://127.0.0.1:9/rpc") as proxy:
            with pytest.raises(TransportError) as error:
                proxy.request(call())
        assert "could not reach the server" in str(error.value)

    def test_a_slow_server_becomes_an_unknown_outcome(self, loopback):
        """타임아웃은 **예외로 새지 않는다.** 호출자에게 UNKNOWN 응답으로 돌아온다 —
        요청은 게이트웨이를 떠났고 서버가 이미 실행했는지 알 수 없기 때문이다.
        `TransportError`는 그대로 올라오는데(위 두 테스트) 이것만 다르게 다루는
        것이 설계다: **재시도해도 되는 실패와 재시도하면 안 되는 미상**은 다르다.

        처음에는 `pytest.raises(CallTimeout)`으로 썼고 통과하지 않았다. 실제
        경로를 처음 돌려봤기 때문에 알게 된 것이고, 스텁만 쓰는 동안에는 이
        구분이 코드에만 있고 확인된 적은 없었다.
        """
        url = loopback(delay=2.0)
        with HttpProxy(interceptor(), url) as proxy:
            reply = proxy.request(call(), timeout=0.2)
        assert reply["error"]["code"] == CALL_TIMEOUT
        assert reply["error"]["data"]["outcome"] == "UNKNOWN"
        assert reply["error"]["data"]["requires"] == "reconciliation"


# ── 나머지 한 줄짜리 갈래들 ────────────────────────────────────────────────
#
# 큰 덩어리 둘을 채운 뒤 남은 것들. 하나하나는 작지만 **각각 무언가를 말한다**.

class TestTheSmallBranches:
    def test_a_failed_report_lists_every_violation(self, tmp_path):
        """OK 갈래만 돌고 FAILED 갈래는 돌지 않았다. 무엇이 잘못됐는지 **줄 번호와
        함께** 말하는 것이 이 문자열의 일이다."""
        from mcp_gateway.audit import Violation

        report = AuditReport(2, (Violation(2, "chain is broken here", kind="chain_broken"),), "")
        assert report.summary() == "FAILED — line 2: chain is broken here"

    def test_blank_lines_are_not_records(self, tmp_path):
        """빈 줄을 기록으로 세면 "N건"이 파일의 줄 수가 된다. 이어쓰기와 검증
        양쪽에 같은 건너뛰기가 있고 **둘 다 한 번도 지나가지 않았다.**"""
        from mcp_gateway.audit import verify_audit_log

        path = audit_log_with(2, tmp_path)
        path.write_text(path.read_text(encoding="utf-8") + "\n\n", encoding="utf-8")
        report = verify_audit_log(path)
        assert report.records == 2 and report.ok
        # 이어쓰기도 같은 파일을 읽는다 - 빈 줄 때문에 번호가 어긋나면 안 된다
        log = AuditLog(path)
        log.record({"direction": "request", "method": "tools/call", "request_id": 9,
                    "action": "allow", "reason_code": "policy_allow", "rule_id": "r1",
                    "detail": {}}, server_id=SERVER_ID)
        assert verify_audit_log(path).ok

    def test_a_witness_that_has_never_seen_this_log_is_said_so(self, tmp_path):
        """"witness가 이 로그를 본 적이 없다"와 "롤백이다"는 다른 사고다. 앞의
        것은 앵커링이 아직 안 된 것이고, 뒤의 것은 누가 옛 사본을 보여준 것이다."""
        # 앵커링은 코어의 서명을 쓴다. 코어가 없는 환경에서는 이 저장소가
        # 정책·무결성 계층만으로 돌아야 하므로 **여기서 import하면 그 주장이
        # 깨진다** — `test_optional_core`가 실제로 그것을 잡아냈다(2026-08-22).
        pytest.importorskip("core.checkpoint",
                            reason="앵커링은 agent-safety-core의 서명을 쓴다")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from mcp_gateway.audit import anchor, verify_against_anchor

        key = ed25519.Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        class Signer:
            def sign(self, checkpoint):
                from core.checkpoint import Signer as CoreSigner
                return CoreSigner(key).sign(checkpoint)

        class BlindWitness:
            def publish(self, checkpoint, sequence=None, digest=None):
                # `anchor`는 호환 계층(`core.checkpoint.Witness`)처럼 Checkpoint
                # 하나로 부른다. 포트의 세 필드 형태도 받도록 둘 다 받아준다.
                return None
            def latest_sequence(self, log_id):
                return None
            def digest_at(self, log_id, sequence):
                return None

        path = audit_log_with(2, tmp_path)
        checkpoint = anchor(AuditLog(path), signer=Signer(), witness=BlindWitness(),
                            log_id="gateway", sequence=1, now=1_700_000_000.0)
        ok, notes = verify_against_anchor(path, checkpoint, public_key_pem=public,
                                          witness=BlindWitness())
        assert not ok
        assert any("never seen this log" in note for note in notes)

    def test_a_call_whose_params_are_not_an_object_is_not_intercepted(self):
        """`params`가 dict이 아니면 도구 이름을 꺼낼 수 없다. 여기서 추측하면
        **승인이 엉뚱한 도구에 묶인다.**"""
        from mcp_gateway.guard import ApprovalGuard

        guard = ApprovalGuard(None, server_id=SERVER_ID, run_id="r1", actor_id="agent:a",
                              consequential_tools=frozenset({"write_file"}),
                              policy_digest="d")
        assert guard.check({"method": "tools/call", "params": "read_file"}) is None

    def test_a_session_id_that_is_not_a_string_is_refused(self):
        from mcp_gateway.limits import normalize_session_id

        with pytest.raises(ValueError, match="must be a string"):
            normalize_session_id(5)

    def test_closing_an_unopenable_session_is_a_no_op(self):
        """열 수 없는 이름은 닫을 수도 없다. 여기서 예외를 내면 **정리 코드가
        정리 중에 죽는다** — `get`이 `None`을 주기로 한 것과 같은 이유다."""
        from mcp_gateway.limits import LimitEnforcer, SessionRegistry

        registry = SessionRegistry(lambda: LimitEnforcer())
        assert registry.close(5) is None
        assert registry.get(5) is None

    @pytest.mark.parametrize("constraints", ["not-a-tuple", 5, None])
    def test_constraints_that_are_not_a_tuple_are_malformed(self, constraints):
        from mcp_gateway.policy import _valid_constraints

        assert _valid_constraints(constraints) is False

    def test_a_quantity_ceiling_permits_only_what_is_below_it(self):
        """`permits`의 마지막 줄. 상한 비교 자체가 한 번도 돌지 않았다 — 앞의
        거부 갈래들만 지나갔다."""
        from decimal import Decimal

        from mcp_gateway.policy import QuantityConstraint

        ceiling = QuantityConstraint(name="amount", maximum=Decimal("100"), unit="USD")
        assert ceiling.permits(QuantityConstraint(name="amount", maximum=Decimal("50"), unit="USD"))
        assert not ceiling.permits(
            QuantityConstraint(name="amount", maximum=Decimal("150"), unit="USD"))

    def test_metadata_that_is_not_a_json_object_is_refused(self):
        """정규화 결과가 dict이 아닌 경우. 리스트를 메타데이터로 받으면 이후 모든
        무결성 비교가 다른 모양 위에서 이뤄진다."""
        from mcp_gateway.registry import RegistryValidationError

        with pytest.raises(RegistryValidationError, match="must be a JSON object"):
            RegisteredServer(identifier=SERVER_ID, metadata=["a", "b"])

    def test_a_tool_entry_without_a_name_is_skipped(self):
        """서버가 돌려준 도구 목록에 이상한 항목이 섞여도 나머지는 살린다.
        여기서 멈추면 **서버 하나가 목록 하나로 게이트웨이를 세울 수 있다.**"""
        from mcp_gateway.metadata_integrity import MetadataSnapshot

        server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "remote"})
        policy = DeterministicPolicy(
            {SERVER_ID: ["read_file"]},
            [PolicyRule("allow-read", "allow", SERVER_ID, "read_file")])
        # `baseline`이 없으면 이 함수는 즉시 `()`를 돌려주고 건너뛰기 갈래는
        # 지나가지 않는다 - 처음 쓴 판이 정확히 그래서 헛돌았다.
        with_baseline = GatewayInterceptor(
            policy, SERVER_ID, baseline=MetadataSnapshot.from_registered([server], []),
            baseline_servers=[server])
        changes = with_baseline.advertised_changes(
            {"tools": [{"name": "read_file"}, "not-a-dict", {"description": "no name"}]})
        assert all("not-a-dict" not in str(change) for change in changes)

    def test_the_base_dispatch_refuses_to_pretend(self):
        """`GatewayProxy._dispatch`는 전송이 채워야 하는 자리다. 기본 구현이
        조용히 `None`을 주면 **차단이 일어나지 않은 채 통과처럼 보인다.**"""
        from mcp_gateway.transport import GatewayProxy

        with pytest.raises(NotImplementedError):
            GatewayProxy(interceptor())._dispatch({}, request_id=1, timeout=1.0)

    def test_a_notification_gets_no_reply_over_http(self, loopback):
        """id가 없는 프레임은 알림이다. 응답을 기다리면 **알림 하나가 호출자를
        타임아웃까지 세운다.**"""
        with HttpProxy(interceptor(), loopback()) as proxy:
            assert proxy.request({"jsonrpc": "2.0", "method": "notifications/x"}) == {}

    def test_exiting_a_stdio_proxy_that_never_started_is_a_no_op(self):
        from mcp_gateway.transport import StdioProxy

        proxy = StdioProxy(interceptor(), ["true"])
        assert proxy.__exit__(None, None, None) is None

    def test_a_unit_mismatch_is_not_a_conversion(self):
        """`permits`의 이른 거부. 100 USD가 100 KRW를 덮는다고 보면 이 계층이
        **환산을 지어내는 것**이고, 그것은 정책이 할 일이 아니다."""
        from decimal import Decimal

        from mcp_gateway.policy import QuantityConstraint

        ceiling = QuantityConstraint(name="amount", maximum=Decimal("100"), unit="USD")
        assert not ceiling.permits(
            QuantityConstraint(name="amount", maximum=Decimal("50"), unit="KRW"))
        assert not ceiling.permits(
            QuantityConstraint(name="volume", maximum=Decimal("50"), unit="USD"))

    def test_constraints_that_cannot_be_compared_are_malformed(self):
        """중복 검사는 집합을 만든다. 해시할 수 없는 원소가 섞이면 `TypeError`가
        나는데, 그것을 "정상"으로 읽으면 **비교할 수 없는 것이 통과한다.**"""
        from mcp_gateway.policy import _valid_constraints

        assert _valid_constraints(([1, 2],)) is False

    def test_a_stdio_notification_gets_no_reply(self):
        """id 없는 프레임은 알림이다. stdio 쪽 갈래도 HTTP 쪽과 같아야 한다 —
        한쪽만 맞으면 전송을 바꾸는 순간 호출자가 멈춘다."""
        from mcp_gateway.transport import StdioProxy

        sent = []

        class Fake(StdioProxy):
            def _write(self, message):
                sent.append(message)
            def _read(self, *, timeout):        # 알림이면 불리면 안 된다
                raise AssertionError("알림에 응답을 기다렸다")

        proxy = Fake(interceptor(), ["true"])
        assert proxy.request({"jsonrpc": "2.0", "method": "notifications/x"}) == {}
        assert sent

    def test_a_ceiling_refuses_a_malformed_request(self):
        """이름도 단위도 맞는데 요청 자체가 말이 안 되는 경우. 음수 상한을
        "100 이하"로 읽으면 **거부해야 할 것을 허용한다.**"""
        from decimal import Decimal

        from mcp_gateway.policy import QuantityConstraint

        ceiling = QuantityConstraint(name="amount", maximum=Decimal("100"), unit="USD")
        malformed = QuantityConstraint(name="amount", maximum=Decimal("-5"), unit="USD")
        assert not malformed.valid()
        assert not ceiling.permits(malformed)

    def test_duplicate_constraints_are_malformed(self):
        """같은 제약을 두 번 보내는 요청. 중복을 통과시키면 **어느 쪽이 적용됐는지**
        말할 수 없고, 정책 판정은 그 말을 할 수 있어야 한다."""
        from mcp_gateway.policy import FilesystemConstraint, _valid_constraints

        one = FilesystemConstraint(operation="read", path="/tmp/work")
        assert _valid_constraints((one, one)) is False
        assert _valid_constraints((one,)) is True

    def test_a_timeout_wrapped_in_a_url_error_is_still_a_timeout(self, monkeypatch):
        """소켓 타임아웃은 `URLError` 안에 담겨 오기도 한다. 그것을 도달 실패로
        읽으면 **UNKNOWN이어야 할 것이 실패가 되고**, 실패는 재시도해도 되는
        것으로 읽힌다 — 이 저장소가 가장 조심하는 혼동이다."""
        import urllib.error
        import urllib.request

        def raising(request, timeout=None):
            raise urllib.error.URLError(TimeoutError("timed out"))

        monkeypatch.setattr(urllib.request, "urlopen", raising)
        with HttpProxy(interceptor(), "http://127.0.0.1:9/rpc") as proxy:
            reply = proxy.request(call(), timeout=0.1)
        assert reply["error"]["code"] == CALL_TIMEOUT
        assert reply["error"]["data"]["outcome"] == "UNKNOWN"


class TestTheBranchesNoTestEverTook:
    """구문 커버리지 100%를 세운 다음 날 **분기**로 다시 쟀다.

    줄이 전부 실행됐다는 것과 각 `if`가 양쪽으로 다 가봤다는 것은 다르다. 다섯 개의
    부분 분기가 나왔고, 그중 넷은 **입력이 예상 모양이 아닐 때**의 갈래였다.
    """

    def test_a_record_without_an_integer_sequence_is_not_compared(self, tmp_path):
        """순서 검사는 `sequence`가 정수일 때만 뜻이 있다. 문자열을 정수와 더하면
        터지고, **검증기가 터지는 것은 위반을 보고하는 것이 아니다.**"""
        from mcp_gateway.audit import verify_audit_log

        path = audit_log_with(1, tmp_path)
        line = path.read_text(encoding="utf-8").splitlines()[0]
        path.write_text(line.replace('"sequence":1', '"sequence":"one"') + "\n",
                        encoding="utf-8")
        report = verify_audit_log(path)
        assert not any("sequence jumped" in v.reason for v in report.violations)

    def test_stripping_a_lease_from_a_call_without_arguments(self):
        """`arguments`가 없는 호출에도 이 함수는 불린다. 없는 것을 지우려 들면
        터지고, **전달 직전에 터지는 것은 차단이 아니다.**"""
        from mcp_gateway.guard import ApprovalGuard

        guard = ApprovalGuard(None, server_id=SERVER_ID, run_id="r1", actor_id="agent:a",
                              consequential_tools=frozenset(), policy_digest="d")
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "read_file"}}
        assert guard.strip_lease(message) == message
        assert guard.strip_lease({"jsonrpc": "2.0", "id": 1}) == {"jsonrpc": "2.0", "id": 1}

    def test_a_tool_error_whose_content_is_not_a_list_is_still_a_failure(self):
        """서버가 `isError`는 맞게 주고 `content`를 다른 모양으로 준 경우.
        **오류라는 사실을 잃으면 실패가 성공으로 보고된다** — 여기서는 메시지만
        비고 상태는 FAILED로 남아야 한다."""
        from mcp_gateway.transport import _outcome_of

        observed = _outcome_of({"result": {"isError": True, "content": "boom"}})
        assert observed["state"] == "FAILED"
        assert observed["evidence"]["message"] == ""

    def test_exiting_a_proxy_whose_stdin_is_already_closed(self):
        """서버가 먼저 죽어 stdin이 닫힌 뒤의 정리. 닫힌 것을 또 닫으려 들면
        **정리 코드가 정리 중에 터진다.**"""
        from mcp_gateway.transport import StdioProxy

        class Dead:
            stdin = None
            def wait(self, timeout=None):
                return 0
            def kill(self):
                raise AssertionError("죽일 필요가 없다")

        proxy = StdioProxy(interceptor(), ["true"])
        proxy._process = Dead()
        assert proxy.__exit__(None, None, None) is None
