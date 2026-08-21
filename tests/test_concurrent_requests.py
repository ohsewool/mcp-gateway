"""동시에 프록시를 부르면 요청과 응답이 제대로 짝지어지는가.

`test_runtime_controls.py::test_duplicate_in_flight_request_id_is_refused`는
`proxy._pending[7]`에 값을 **손으로 넣어** 상황을 흉내 냈다. 가드는 시험됐지만
**그 상황은 한 번도 시험되지 않았다.**

실제로 만들어보니 가드가 성립하지 않았다. 같은 id를 단 프레임 8개를 동시에 넣으니
**2~6개가 가드를 통과**했다(2026-08-22, 20회 중 18회). 검사와 기록 사이에 서버
왕복이 통째로 들어가기 때문이다 — `modelmate`의 사용량 한도, 이 저장소의 감사 로그와
같은 자리다.

**고친 방향을 정확히 적는다.** 잠금은 가드가 동시에 성립하게 만들지 않는다. 동시성
자체를 없앤다. 프레임이 한 번에 하나씩 지나가므로 "이미 진행 중인 같은 id"라는 상황이
발생하지 않고, 각 호출은 자기 응답과 자기 정산을 갖는다. 같은 id를 **순차로** 다시
쓰는 것은 예전에도 통과했고 지금도 통과한다 — 바뀐 것은 겹칠 때의 결과다.

겹침을 허용하려면 id별 라우팅이 필요하고, 그때 이 가드는 다시 부하를 진다. stdio는
어차피 겹칠 수 없다 — 버퍼가 속성 하나이고, id가 다른 프레임은 **버린다.**
"""

from __future__ import annotations

import concurrent.futures
import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.policy import DeterministicPolicy, PolicyRule  # noqa: E402
from mcp_gateway.registry import RegisteredServer  # noqa: E402
from mcp_gateway.transport import GatewayInterceptor, HttpProxy  # noqa: E402

SERVER_ID = "remote-server"
ENDPOINT = "https://mcp.example.test/rpc"
WORKERS = 8


def interceptor() -> GatewayInterceptor:
    policy = DeterministicPolicy(
        {SERVER_ID: ["read_file"]},
        [PolicyRule("allow-read", "allow", SERVER_ID, "read_file")],
    )
    return GatewayInterceptor(
        policy, SERVER_ID,
        baseline_servers=[RegisteredServer(identifier=SERVER_ID, metadata={"kind": "remote"})],
    )


class DepthRecordingOpener:
    """서버가 답하는 동안 몇 개가 안에 들어와 있는지 센다.

    "동시에 불렀는데 문제가 없다"는 결과는 **애초에 겹치지 않았을 때도** 똑같이
    나온다. 겹침을 직접 재지 않으면 이 파일은 아무것도 확인하지 않는다.
    """

    def __init__(self, delay: float = 0.03) -> None:
        self.delay = delay
        self.max_depth = 0
        self._depth = 0
        self._lock = threading.Lock()

    def __call__(self, endpoint: str, body: str, timeout_seconds: float) -> str:
        with self._lock:
            self._depth += 1
            self.max_depth = max(self.max_depth, self._depth)
        try:
            time.sleep(self.delay)
            sent = json.loads(body)
            return json.dumps({"jsonrpc": "2.0", "id": sent.get("id"),
                               "result": {"ok": True, "echo": sent.get("id")}})
        finally:
            with self._lock:
                self._depth -= 1


def call(request_id: int) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {}}}


def send_together(proxy, ids: list[int]) -> list[dict]:
    barrier = threading.Barrier(len(ids), timeout=60)

    def send(request_id):
        barrier.wait()
        return proxy.request(call(request_id), timeout=5.0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ids)) as pool:
        return list(pool.map(send, ids))


class TestOneFrameAtATime:
    def test_calls_do_not_overlap(self):
        opener = DepthRecordingOpener()
        proxy = HttpProxy(interceptor(), ENDPOINT, opener=opener)
        send_together(proxy, list(range(WORKERS)))
        assert opener.max_depth == 1, f"서버 안에 동시에 {opener.max_depth}개가 있었다"

    def test_every_reply_matches_its_own_request(self):
        """겹치면 응답이 엉뚱한 호출에 붙는다. 그것이 이 가드가 막으려던 것이다."""
        proxy = HttpProxy(interceptor(), ENDPOINT, opener=DepthRecordingOpener())
        ids = list(range(WORKERS))
        replies = send_together(proxy, ids)
        assert [reply["result"]["echo"] for reply in replies] == ids

    def test_nothing_is_left_in_flight(self):
        """`_pending`에 남은 항목은 정산되지 않은 호출이다."""
        proxy = HttpProxy(interceptor(), ENDPOINT, opener=DepthRecordingOpener())
        send_together(proxy, list(range(WORKERS)))
        assert proxy._pending == {}

    def test_the_same_id_reused_is_serialised_not_dropped(self):
        """같은 id 8개를 동시에 넣으면 이제 하나씩 지나간다. 예전에는 2~6개가
        가드를 통과하고 나머지는 거절되면서 정산이 뒤엉켰다."""
        opener = DepthRecordingOpener()
        proxy = HttpProxy(interceptor(), ENDPOINT, opener=opener)
        replies = send_together(proxy, [7] * WORKERS)
        assert opener.max_depth == 1
        assert all("error" not in reply for reply in replies)
        assert proxy._pending == {}


class TestTheGuardStillRefusesAnOutstandingId:
    """겹칠 수 없게 만들었다고 가드를 지운 것은 아니다. 재진입 경로에서는 여전히 산다."""

    def test_an_outstanding_entry_is_refused(self):
        from mcp_gateway.transport import DUPLICATE_REQUEST

        proxy = HttpProxy(interceptor(), ENDPOINT, opener=DepthRecordingOpener())
        proxy._pending[7] = "tools/call"
        reply = proxy.request(call(7), timeout=5.0)
        assert reply["error"]["code"] == DUPLICATE_REQUEST


class TestTheHarnessCanSeeOverlap:
    """음성 대조. `max_depth == 1`은 스레드가 실제로 겹치려 하지 않았어도 나온다.

    같은 하네스를 **잠금 없는** 호출에 걸어 겹침이 보이는지 확인한다. 보이지 않으면
    위 검사들은 잠금이 아니라 우연을 재고 있는 것이다.
    """

    def test_an_unlocked_call_overlaps(self):
        opener = DepthRecordingOpener()
        barrier = threading.Barrier(WORKERS, timeout=60)

        def unlocked(index):
            barrier.wait()
            return opener(ENDPOINT, json.dumps({"id": index}), 5.0)

        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            list(pool.map(unlocked, range(WORKERS)))
        assert opener.max_depth > 1, (
            f"잠금 없이도 겹치지 않았다(max_depth={opener.max_depth}) — 이 하네스는 "
            f"겹침을 볼 수 없고, 그러면 위 검사들도 아무것도 확인하지 않는다."
        )

    def test_the_depth_counter_returns_to_zero(self):
        """세다가 새면 최대값이 부풀고, 위 검사가 잘못된 이유로 실패한다."""
        opener = DepthRecordingOpener(delay=0.0)
        opener(ENDPOINT, json.dumps({"id": 1}), 5.0)
        assert opener._depth == 0
