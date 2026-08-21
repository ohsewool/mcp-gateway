"""한 프로세스 안에서 동시에 불러도 성립하는가.

앞선 저장소에서 나온 형태를 들고 왔다. `modelmate`의 사용량 한도가 **읽고-판단하고-
쓰기를 나눠** 하는 바람에 한도 10에 동시 20건 중 12건이 통과했다. 같은 자리가 여기에
둘 있다.

**감사 로그.** `record`는 번호를 매기고, 꼬리 해시를 읽고, 파일에 붙이고, 꼬리를
갱신한다 — 네 단계였다. 2026-08-22에 쟀다: 동시 16건이 **40회 중 40회 체인을
분기**시켰다. 두 기록이 같은 `previous_hash`를 달고 나온다. `verify_audit_log`는
매번 잡아냈다(`chain_broken`·`sequence_regressed`) — 조용히 틀리지 않는다는 것은
좋은 절반이고, 나쁜 절반은 **동시에 두 건을 처리한 게이트웨이가 자기 검증을 통과하지
못하는 감사 로그를 남긴다**는 것이다. 그러면 안 된다는 말도 어디에도 없었다.

**세션 예산.** `consume`은 `check`로 판단한 뒤 값을 올렸다 — 두 단계다. 스레드 전환
간격을 줄여 300회 × 동시 32건을 예산 10에 부딪쳐보니 **1회에서 11건이 통과**했다.
드문 것과 불가능한 것은 다르고, **넘길 수 있는 예산은 상한이 아니다.**

둘 다 잠금으로 한 동작으로 묶었다. **프로세스 하나 안에서만이다** — 잠금은 프로세스를
넘지 못하고, 두 프로세스가 한 파일에 붙이면 체인은 여전히 갈라진다.
`agent-safety-core`는 그 문제를 SQLite의 단일 권위 시퀀스로 풀었다. 세션마다 하나인
JSONL 파일에는 그 모양이 맞지 않는다. **세션 하나, 프로세스 하나, 로그 하나.**
"""

from __future__ import annotations

import concurrent.futures
import json
import threading
from pathlib import Path

import pytest

# `sys.setswitchinterval`을 여기서 건드리지 않는다. 처음에는 모듈 최상위에서 줄였는데,
# 그건 **스위트 전체**의 스레드 스케줄링을 바꾸는 전역 부수효과다. 아래 검사들은
# 타이밍이 아니라 `Barrier`로 경합을 만든다 - 전환 간격에 기대지 않는다.
# (결함을 처음 재현할 때는 1e-6으로 줄여서 300회 중 1회 예산 초과를 봤다.
#  체인 분기는 기본 간격에서도 40회 중 40회 나왔다.)

from mcp_gateway.audit import AuditLog, verify_audit_log  # noqa: E402
from mcp_gateway.limits import LimitEnforcer, RateLimit  # noqa: E402

WORKERS = 16
BUDGET = 10


def interception(index: int) -> dict:
    return {
        "direction": "outbound",
        "method": "tools/call",
        "request_id": str(index),
        "action": "allow",
        "reason_code": "ok",
        "rule_id": None,
        "detail": {},
    }


def run_together(action, workers: int = WORKERS):
    """모든 스레드를 같은 지점에서 출발시킨다.

    타이밍에 기대면 대조가 어떤 날은 초과를 보고 어떤 날은 못 본다. 그러면 통과한
    날의 다른 검사들이 무엇을 확인했는지 알 수 없다 — 앞 저장소에서 실제로 겪었다.
    """
    barrier = threading.Barrier(workers, timeout=60)

    def synchronised(index):
        barrier.wait()
        return action(index)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(synchronised, range(workers)))


class TestTheChainSurvivesConcurrentAppends:
    def test_the_log_verifies(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path, session_id="s", clock=lambda: 0.0)
        run_together(lambda index: log.record(interception(index), server_id="srv"))
        report = verify_audit_log(path)
        assert report.ok, report.summary()

    def test_every_record_arrives(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path, session_id="s", clock=lambda: 0.0)
        run_together(lambda index: log.record(interception(index), server_id="srv"))
        assert len(log.read()) == WORKERS

    def test_no_two_records_share_a_parent(self, tmp_path):
        """분기의 정의 그대로. 검증기와 별개로 직접 본다 — 검증기가 틀릴 수도 있다."""
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path, session_id="s", clock=lambda: 0.0)
        run_together(lambda index: log.record(interception(index), server_id="srv"))
        parents = [record["integrity"]["previous_hash"] for record in log.read()]
        assert len(set(parents)) == len(parents)

    def test_the_sequence_has_no_duplicates_and_no_gaps(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path, session_id="s", clock=lambda: 0.0)
        run_together(lambda index: log.record(interception(index), server_id="srv"))
        sequences = sorted(record["sequence"] for record in log.read())
        assert sequences == list(range(1, WORKERS + 1))

    def test_the_returned_records_match_the_file(self, tmp_path):
        """반환값과 파일이 어긋나면 부르는 쪽은 있지도 않은 기록을 들고 간다."""
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path, session_id="s", clock=lambda: 0.0)
        returned = run_together(lambda index: log.record(interception(index), server_id="srv"))
        assert sorted(record["sequence"] for record in returned) == \
            sorted(record["sequence"] for record in log.read())


class TestTheBudgetIsABound:
    def test_exactly_the_budget_is_spent(self):
        enforcer = LimitEnforcer(session_budget=BUDGET, clock=lambda: 0.0)
        outcomes = run_together(lambda _: enforcer.consume("tool").allowed, workers=32)
        assert sum(outcomes) == BUDGET
        assert enforcer.spent == BUDGET

    def test_a_refused_call_spends_nothing(self):
        """조여진 호출이 예산을 먹으면, 정중하게 재시도하는 쪽이 벌을 받는다."""
        enforcer = LimitEnforcer(default_limit=RateLimit(capacity=1, per_second=1.0),
                                 session_budget=BUDGET, clock=lambda: 0.0)
        run_together(lambda _: enforcer.consume("tool").allowed, workers=32)
        assert enforcer.spent == 1

    def test_the_bucket_is_not_overdrawn(self):
        enforcer = LimitEnforcer(default_limit=RateLimit(capacity=5, per_second=1.0),
                                 clock=lambda: 0.0)
        outcomes = run_together(lambda _: enforcer.consume("tool").allowed, workers=32)
        assert sum(outcomes) == 5

    def test_check_stays_advisory(self):
        """`check`는 쓰지 않는다. 그 성질이 사라지면 "물어보기"가 "쓰기"가 된다."""
        enforcer = LimitEnforcer(session_budget=BUDGET, clock=lambda: 0.0)
        run_together(lambda _: enforcer.check("tool").allowed, workers=32)
        assert enforcer.spent == 0


class TestTheHarnessCanSeeTheFailures:
    """음성 대조. 고쳐진 코드가 통과하는 것만으로는 아무것도 증명되지 않는다 —
    스레드가 실제로 겹치지 않았어도 같은 결과가 나온다.

    나눠 하는 방식을 여기서 그대로 재현해 **초과와 분기를 실제로 본다.** 장벽을
    읽기와 쓰기 **사이**에 둬서 타이밍 운에 기대지 않는다.
    """

    def test_a_split_read_and_write_overruns_the_budget(self):
        enforcer = LimitEnforcer(session_budget=BUDGET, clock=lambda: 0.0)
        workers = 32
        barrier = threading.Barrier(workers, timeout=60)

        def split(_):
            allowed = enforcer.check("tool").allowed      # 판단
            barrier.wait()                                # 모두가 판단을 마칠 때까지
            if not allowed:
                return False
            enforcer._spent += 1                          # 쓰기 (예전 `consume`의 모양)
            return True

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            allowed = sum(pool.map(split, range(workers)))
        assert allowed > BUDGET, (
            f"나눠 하는 방식이 초과하지 않았다({allowed}) — 동시성이 실제로 일어나지 "
            f"않았다는 뜻이고, 그러면 위 검사들도 아무것도 확인하지 않는다."
        )

    def test_a_forked_chain_is_refused(self, tmp_path):
        """분기한 로그를 손으로 만들어, 검증기와 위 검사들이 그것을 잡는지 본다."""
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path, session_id="s", clock=lambda: 0.0)
        first = log.record(interception(1), server_id="srv")

        forked = dict(first)
        forked["request_id"] = "2"
        forked["sequence"] = 2
        # 같은 부모를 가리킨다 - 이것이 동시 append가 만들던 상태다.
        forked["integrity"] = dict(first["integrity"])
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(forked, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")) + "\n")

        records = [json.loads(line) for line in
                   path.read_text(encoding="utf-8").splitlines() if line.strip()]
        parents = [record["integrity"]["previous_hash"] for record in records]
        assert len(set(parents)) != len(parents), "손으로 만든 분기가 분기가 아니다"
        assert not verify_audit_log(path).ok


class TestWhatTheLockDoesNotCover:
    """잠금은 프로세스를 넘지 못한다. 그 사실을 코드가 말하게 둔다 — 말하지 않으면
    다음 사람은 두 프로세스에 같은 경로를 준다."""

    def test_the_class_says_one_process(self):
        assert "One process" in AuditLog.__doc__

    def test_it_points_at_the_repository_that_solved_the_other_half(self):
        assert "agent-safety-core" in AuditLog.__doc__


@pytest.mark.parametrize("rounds", [40])
def test_the_result_repeats(tmp_path, rounds):
    """한 번 통과한 것은 운일 수 있다. 분기는 고치기 전 40회 중 40회 나왔다."""
    for round_number in range(rounds):
        path = tmp_path / f"audit-{round_number}.jsonl"
        log = AuditLog(path, session_id="s", clock=lambda: 0.0)
        run_together(lambda index: log.record(interception(index), server_id="srv"))
        assert verify_audit_log(path).ok


class TestADegenerateLimitIsRefused:
    """비교 검사를 빠져나가는 값들.

    `capacity < 1`과 `per_second <= 0`으로 검사하고 있었는데 **`NaN`은 모든 비교에서
    거짓**이라 둘 다 통과했다. 그리고 통과한 뒤에는 버킷을 오염시킨다:
    `tokens + elapsed * nan`은 `nan`이고 `nan < 1`도 거짓이라 **전부 허용**된다.
    2026-08-22 실측 — capacity 5로 선언한 버킷이 100회 중 100회를 통과시켰다.
    `session_budget=nan`도 같다: `spent >= budget`이 영원히 거짓이다.

    `inf`는 다른 길로 같은 곳에 도착한다. 무한 capacity는 거절하지 않는 리미터이고,
    그것을 원한다면 `limits={}`가 이미 그 말을 한다 — 읽는 사람이 볼 수 있는 자리에서.

    같은 날 `agent-safety-core`에서 찾은 lease TTL과 같은 형태다. 퇴화한 float이
    비교 가드를 빠져나가 **가장 허용적인 동작**에 내려앉는다.
    """

    @pytest.mark.parametrize("capacity", [float("nan"), float("inf"), True, "5", None])
    def test_a_degenerate_capacity_is_refused(self, capacity):
        with pytest.raises(ValueError, match="capacity"):
            RateLimit(capacity=capacity, per_second=1.0)

    @pytest.mark.parametrize("rate", [float("nan"), float("inf"), True, "1.0", None])
    def test_a_degenerate_refill_is_refused(self, rate):
        with pytest.raises(ValueError, match="refill"):
            RateLimit(capacity=5, per_second=rate)

    @pytest.mark.parametrize("budget", [float("nan"), float("inf"), True, "10", -1])
    def test_a_degenerate_budget_is_refused(self, budget):
        with pytest.raises(ValueError):
            LimitEnforcer(session_budget=budget, clock=lambda: 0.0)

    def test_a_zero_budget_is_allowed_and_refuses_everything(self):
        """0은 퇴화가 아니라 "아무것도 하지 마라"다. `None`(무제한)과 구분된다."""
        enforcer = LimitEnforcer(session_budget=0, clock=lambda: 0.0)
        assert not enforcer.consume("tool").allowed
        assert LimitEnforcer(session_budget=None, clock=lambda: 0.0).consume("tool").allowed

    def test_the_normal_construction_still_works(self):
        """전부 거절하는 검증은 전부 거절하는 것으로도 통과한다."""
        enforcer = LimitEnforcer(default_limit=RateLimit(capacity=5, per_second=1.0),
                                 session_budget=10, clock=lambda: 0.0)
        assert enforcer.consume("tool").allowed

    def test_the_poisoned_bucket_would_have_allowed_everything(self):
        """이 결함이 왜 결함이었는지를 남긴다. 검증을 통과했다면 어떤 일이
        벌어졌는지 - 산술만으로 재현한다."""
        tokens = 5.0
        tokens = min(5.0, tokens + 1.0 * float("nan"))
        assert not tokens < 1, "NaN 토큰이 1보다 작다고 판정되면 이 결함은 성립하지 않는다"


class TestOneSessionIsOneBudget:
    """철자를 바꾸면 예산이 새로 생겼다.

    세션은 예산을 세는 단위인데 레지스트리는 넘겨받은 문자열을 그대로 키로 썼다.
    2026-08-22 실측: 예산 3에 `s-1`·`S-1`·`" s-1"`·`"s-1 "`·`"s-1\\n"`·`"s\\u20111"`
    여섯 철자가 각자 세션을 열어 **총 18회**를 통과시켰다. 세션 예산은 레이트 리밋
    아래로 기어가는 루프를 멈추는 마지막 한도인데, 이름을 다시 쓰면 초기화된다.

    **여기서 대소문자를 접는 것은 정책과 반대 판단이다.** 도구·서버 이름은 정책에서
    대소문자를 구분하고, 어긋나면 전부 **닫히는 쪽으로** 실패한다 — 같은 날 쟀다:
    요청의 대소문자가 등록과 다르면 `unknown_tool`, 규칙이 다르면 `default_deny`,
    공백이 섞이면 `malformed_request`. 이미 닫히는 이름을 접으면 규칙이 매치하는
    범위만 넓어진다. 세션 식별자는 정반대다 — 접지 않으면 새 예산을 내준다.
    """

    def session_registry(self, budget=3):
        from mcp_gateway.limits import SessionRegistry

        return SessionRegistry(lambda: LimitEnforcer(session_budget=budget,
                                                     clock=lambda: 0.0))

    @pytest.mark.parametrize("spelling", ["S-1", " s-1", "s-1 ", "s-1\n", "\ts-1"])
    def test_a_respelt_id_is_the_same_session(self, spelling):
        registry = self.session_registry()
        registry.open("s-1", server_id="srv")
        with pytest.raises(ValueError, match="already open"):
            registry.open(spelling, server_id="srv")

    def test_a_look_alike_id_is_refused_outright(self):
        """NFKC는 `\\u2011`을 ASCII 하이픈으로 접지 않는다."""
        registry = self.session_registry()
        with pytest.raises(ValueError, match="may only contain"):
            registry.open("s‑1", server_id="srv")

    def test_the_budget_is_not_reset_by_respelling(self):
        registry = self.session_registry(budget=3)
        scope = registry.open("s-1", server_id="srv")
        assert sum(scope.enforcer.consume("tool").allowed for _ in range(10)) == 3
        for spelling in ("S-1", " s-1", "s-1\n"):
            with pytest.raises(ValueError):
                registry.open(spelling, server_id="srv")
        assert len(registry) == 1

    def test_lookup_finds_it_however_it_is_spelt(self):
        registry = self.session_registry()
        registry.open("s-1", server_id="srv")
        for spelling in ("S-1", " s-1 ", "s-1\n"):
            assert registry.get(spelling) is not None

    def test_lookup_of_an_unusable_id_returns_none_rather_than_raising(self):
        """`get`은 없으면 `None`을 주기로 한 함수다. 조회 한 번이 호출자를
        죽이면 안 된다."""
        registry = self.session_registry()
        assert registry.get("s‑1") is None
        assert registry.get("") is None

    def test_closing_works_by_any_spelling(self):
        registry = self.session_registry()
        registry.open("s-1", server_id="srv")
        registry.close("S-1")
        assert len(registry) == 0

    def test_a_genuinely_different_session_still_opens(self):
        """대조. 전부 거절하는 레지스트리로도 위 검사들은 통과한다."""
        registry = self.session_registry()
        registry.open("s-1", server_id="srv")
        assert registry.open("s-2", server_id="srv") is not None
        assert len(registry) == 2

    def test_the_stored_id_is_the_normalised_one(self):
        registry = self.session_registry()
        assert registry.open("  S-1  ", server_id="SRV").session_id == "s-1"

    def test_the_server_id_is_normalised_too(self):
        registry = self.session_registry()
        assert registry.open("s-1", server_id="  SRV  ").server_id == "srv"


class TestThePolicyStaysCaseSensitiveOnPurpose:
    """접지 않는 쪽의 판단도 근거와 함께 고정한다. 어긋남이 전부 닫히는 방향이면
    접는 것은 규칙이 매치하는 범위만 넓힌다."""

    def decide(self, registered, rule_tool, requested):
        from mcp_gateway.policy import DeterministicPolicy, PolicyRequest, PolicyRule

        policy = DeterministicPolicy({"srv": [registered]},
                                     [PolicyRule("allow-it", "allow", "srv", rule_tool)])
        return policy.evaluate(PolicyRequest(server_id="srv", tool_id=requested,
                                             constraints=()))

    def test_an_exact_match_is_allowed(self):
        assert self.decide("read_file", "read_file", "read_file").allowed

    @pytest.mark.parametrize("registered,rule_tool,requested,reason", [
        ("read_file", "read_file", "READ_FILE", "unknown_tool"),
        ("READ_FILE", "read_file", "READ_FILE", "default_deny"),
        ("read_file", "READ_FILE", "read_file", "default_deny"),
        ("read_file", "read_file", " read_file", "malformed_request"),
    ])
    def test_every_case_mismatch_fails_closed(self, registered, rule_tool, requested, reason):
        decision = self.decide(registered, rule_tool, requested)
        assert not decision.allowed
        assert decision.reason_code == reason
