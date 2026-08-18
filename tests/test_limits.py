"""Volume controls: every call is allowed, and there are ten thousand of them."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.limits import (  # noqa: E402
    LimitEnforcer,
    RateLimit,
    SessionRegistry,
)
from mcp_gateway.policy import DeterministicPolicy, PolicyRule  # noqa: E402
from mcp_gateway.registry import RegisteredServer  # noqa: E402
from mcp_gateway.transport import RATE_LIMITED, GatewayInterceptor  # noqa: E402

SERVER_ID = "fs-server"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


class TestRateLimitConfig:
    def test_a_zero_capacity_bucket_is_refused(self):
        with pytest.raises(ValueError):
            RateLimit(capacity=0, per_second=1.0)

    def test_a_non_positive_refill_is_refused(self):
        with pytest.raises(ValueError):
            RateLimit(capacity=5, per_second=0)


class TestRateLimiting:
    def test_a_burst_up_to_capacity_is_permitted(self, clock):
        enforcer = LimitEnforcer(default_limit=RateLimit(3, 1.0), clock=clock)
        assert all(enforcer.consume("read").allowed for _ in range(3))

    def test_the_call_past_capacity_is_refused(self, clock):
        enforcer = LimitEnforcer(default_limit=RateLimit(2, 1.0), clock=clock)
        enforcer.consume("read")
        enforcer.consume("read")
        decision = enforcer.consume("read")
        assert not decision.allowed
        assert decision.reason_code == "rate_limited"

    def test_a_refusal_says_when_to_come_back(self, clock):
        enforcer = LimitEnforcer(default_limit=RateLimit(1, 2.0), clock=clock)
        enforcer.consume("read")
        decision = enforcer.consume("read")
        assert decision.retry_after == pytest.approx(0.5)

    def test_tokens_refill_over_time(self, clock):
        enforcer = LimitEnforcer(default_limit=RateLimit(2, 1.0), clock=clock)
        enforcer.consume("read")
        enforcer.consume("read")
        assert not enforcer.consume("read").allowed
        clock.advance(1.0)
        assert enforcer.consume("read").allowed

    def test_refill_never_exceeds_capacity(self, clock):
        """An idle hour must not buy an hour's worth of burst."""
        enforcer = LimitEnforcer(default_limit=RateLimit(2, 1.0), clock=clock)
        clock.advance(3600.0)
        assert enforcer.consume("read").allowed
        assert enforcer.consume("read").allowed
        assert not enforcer.consume("read").allowed

    def test_limits_are_per_tool(self, clock):
        """Exhausting a cheap tool must not block an expensive one."""
        enforcer = LimitEnforcer(
            limits={"read": RateLimit(1, 1.0), "write": RateLimit(1, 1.0)}, clock=clock
        )
        enforcer.consume("read")
        assert not enforcer.consume("read").allowed
        assert enforcer.consume("write").allowed

    def test_a_tool_without_a_limit_is_unbounded(self, clock):
        enforcer = LimitEnforcer(limits={"write": RateLimit(1, 1.0)}, clock=clock)
        assert all(enforcer.consume("read").allowed for _ in range(50))

    def test_checking_does_not_spend(self, clock):
        enforcer = LimitEnforcer(default_limit=RateLimit(1, 1.0), clock=clock)
        assert enforcer.check("read").allowed
        assert enforcer.check("read").allowed
        assert enforcer.consume("read").allowed


class TestSessionBudget:
    def test_the_budget_caps_the_whole_session(self, clock):
        """What a rate limit cannot say: 'no more than five calls for this task'."""
        enforcer = LimitEnforcer(session_budget=5, clock=clock)
        assert all(enforcer.consume("read").allowed for _ in range(5))
        decision = enforcer.consume("read")
        assert not decision.allowed
        assert decision.reason_code == "session_budget_exhausted"

    def test_the_budget_spans_every_tool(self, clock):
        enforcer = LimitEnforcer(session_budget=2, clock=clock)
        enforcer.consume("read")
        enforcer.consume("write")
        assert not enforcer.consume("list").allowed

    def test_a_slow_loop_still_hits_the_budget(self, clock):
        """The case a rate limit alone never stops: patient, endless retrying."""
        enforcer = LimitEnforcer(default_limit=RateLimit(1, 1.0),
                                 session_budget=3, clock=clock)
        for _ in range(3):
            assert enforcer.consume("read").allowed
            clock.advance(10.0)
        assert not enforcer.consume("read").allowed

    def test_a_throttled_call_does_not_consume_budget(self, clock):
        """Being throttled must not punish a client that retries politely."""
        enforcer = LimitEnforcer(default_limit=RateLimit(1, 1.0),
                                 session_budget=10, clock=clock)
        enforcer.consume("read")
        for _ in range(5):
            enforcer.consume("read")  # all rate-limited
        assert enforcer.spent == 1
        assert enforcer.budget_remaining == 9

    def test_remaining_budget_is_reported(self, clock):
        enforcer = LimitEnforcer(session_budget=3, clock=clock)
        assert enforcer.consume("read").remaining == 2

    def test_no_budget_means_no_ceiling(self, clock):
        enforcer = LimitEnforcer(clock=clock)
        assert all(enforcer.consume("read").allowed for _ in range(100))
        assert enforcer.budget_remaining is None


class TestSessionIsolation:
    def test_sessions_do_not_share_limiter_state(self, clock):
        """A noisy client must not throttle a quiet one."""
        registry = SessionRegistry(lambda: LimitEnforcer(default_limit=RateLimit(1, 1.0),
                                                         clock=clock))
        noisy = registry.open("noisy", server_id=SERVER_ID)
        quiet = registry.open("quiet", server_id=SERVER_ID)
        noisy.enforcer.consume("read")
        assert not noisy.enforcer.consume("read").allowed
        assert quiet.enforcer.consume("read").allowed

    def test_sessions_do_not_share_budgets(self, clock):
        registry = SessionRegistry(lambda: LimitEnforcer(session_budget=1, clock=clock))
        first = registry.open("a", server_id=SERVER_ID)
        second = registry.open("b", server_id=SERVER_ID)
        first.enforcer.consume("read")
        assert not first.enforcer.consume("read").allowed
        assert second.enforcer.consume("read").allowed

    def test_reopening_an_open_session_is_refused(self, clock):
        registry = SessionRegistry(lambda: LimitEnforcer(clock=clock))
        registry.open("a", server_id=SERVER_ID)
        with pytest.raises(ValueError):
            registry.open("a", server_id=SERVER_ID)

    def test_closing_frees_the_identifier(self, clock):
        registry = SessionRegistry(lambda: LimitEnforcer(clock=clock))
        registry.open("a", server_id=SERVER_ID)
        registry.close("a")
        assert registry.get("a") is None
        assert len(registry) == 0
        registry.open("a", server_id=SERVER_ID)  # reusable after closing

    def test_records_are_kept_per_session(self, clock):
        registry = SessionRegistry(lambda: LimitEnforcer(clock=clock))
        first = registry.open("a", server_id=SERVER_ID)
        second = registry.open("b", server_id=SERVER_ID)
        first.records.append({"kind": "call"})
        assert second.records == []


class TestGatewayIntegration:
    def build(self, clock, **kwargs):
        policy = DeterministicPolicy(
            {SERVER_ID: ["read_file"]},
            [PolicyRule("allow-read", "allow", SERVER_ID, "read_file")],
        )
        server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "fs"})
        return GatewayInterceptor(
            policy, SERVER_ID, baseline_servers=[server],
            limiter=LimitEnforcer(clock=clock, **kwargs),
        )

    def call(self, request_id=1):
        return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                "params": {"name": "read_file", "arguments": {}}}

    def test_an_allowed_call_passes_while_under_the_limit(self, clock):
        interceptor = self.build(clock, default_limit=RateLimit(2, 1.0))
        assert interceptor.inspect_request(self.call()).forward is not None

    def test_a_throttled_call_is_refused_with_retry_guidance(self, clock):
        interceptor = self.build(clock, default_limit=RateLimit(1, 2.0))
        interceptor.inspect_request(self.call(1))
        blocked = interceptor.inspect_request(self.call(2))
        assert blocked.forward is None
        assert blocked.reply["error"]["code"] == RATE_LIMITED
        assert blocked.reply["error"]["data"]["retry_after"] == pytest.approx(0.5)

    def test_budget_exhaustion_is_reported_to_the_client(self, clock):
        interceptor = self.build(clock, session_budget=1)
        interceptor.inspect_request(self.call(1))
        blocked = interceptor.inspect_request(self.call(2))
        assert blocked.record.reason_code == "session_budget_exhausted"
        assert blocked.reply["error"]["data"]["budget_remaining"] == 0

    def test_a_policy_denied_call_does_not_spend_the_budget(self, clock):
        """Refused by policy is not work done; it must not count against the task."""
        interceptor = self.build(clock, session_budget=5)
        denied = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "delete_file", "arguments": {}}}
        interceptor.inspect_request(denied)
        assert interceptor._limiter.spent == 0
