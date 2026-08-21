"""Bounding how much an agent can do, not just what it may do.

Policy answers "is this call permitted?" one call at a time, which leaves a
straightforward abuse open: every individual call is allowed, and there are ten
thousand of them. A read tool that is harmless once is a data exfiltration
channel at volume, and a retry loop that is correct in principle can exhaust a
downstream service in seconds.

Two limits, deliberately separate:

rate
    calls per window, per tool. A token bucket, so a burst is permitted up to
    the bucket size and sustained traffic is held to the refill rate. Bursts are
    normal in agent work - a plan produces several calls at once - and a hard
    per-second cap would break legitimate behaviour.

budget
    a total for the whole session, which a rate limit cannot express. "No more
    than 200 tool calls for this task" is the sentence an operator actually
    wants, and it is what stops a loop that is slow enough to pass the rate
    limit forever.

Time is injected rather than read from the clock, so the tests are exact instead
of timing-dependent.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Callable


def _finite_number(value: object) -> bool:
    """A real, finite number - and not a ``bool``.

    ``bool`` is a subclass of ``int``, so ``True`` slips through every numeric
    check and becomes ``1``. ``NetworkConstraint`` in ``policy.py`` already
    excludes it for the same reason.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value)


@dataclass(frozen=True)
class RateLimit:
    """A token bucket: ``capacity`` tokens, refilled at ``per_second``.

    Both must be finite. They were checked with ``< 1`` and ``<= 0``, and **NaN
    fails every comparison**, so it passed both guards and then poisoned the
    bucket: ``tokens + elapsed * nan`` is ``nan``, ``nan < 1`` is false, and the
    limiter allowed everything. Measured 2026-08-22 - a bucket declared with
    capacity 5 and ``per_second=nan`` passed **100 of 100** calls.

    ``inf`` gets there another way: an infinite capacity is a limiter that never
    refuses. If that is what someone wants, ``limits={}`` already says it, and it
    says it where a reader can see it.

    This is the same shape as ``agent-safety-core``'s lease TTL, found the same
    day: a degenerate float slipping past a comparison guard and landing on the
    most permissive behaviour available.
    """

    capacity: int
    per_second: float

    def __post_init__(self) -> None:
        if not _finite_number(self.capacity):
            raise ValueError("rate limit capacity must be a finite number")
        if not _finite_number(self.per_second):
            raise ValueError("rate limit refill must be a finite number")
        if self.capacity < 1:
            raise ValueError("rate limit capacity must be at least one call")
        if self.per_second <= 0:
            raise ValueError("rate limit refill must be positive")


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    reason_code: str = "within_limits"
    retry_after: float | None = None
    remaining: int | None = None


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class LimitEnforcer:
    """Per-tool rate limiting and a session-wide call budget.

    A refused call consumes nothing: being throttled must not eat the budget, or
    a client that retries politely would be punished for the throttling.

    ``consume`` is safe to call from several threads of one process. It was not:
    deciding and spending were two steps, so two callers could both see the last
    unit of budget and both take it. Measured on 2026-08-22 with a short thread
    switch interval - 300 rounds of 32 concurrent calls against a budget of 10,
    and **one round let 11 through**. Rare is not the same as impossible, and a
    budget that can be exceeded is not a bound.

    ``check`` is advisory and stays that way: it answers "would this be allowed"
    without spending. Calling ``check`` and then ``consume`` is still two steps,
    and the answer can go stale in between. Only ``consume`` decides.

    Note that ``check`` is not a pure read - it refills the bucket, which is a
    mutation. It takes the same lock for that reason.
    """

    def __init__(
        self,
        *,
        limits: dict[str, RateLimit] | None = None,
        default_limit: RateLimit | None = None,
        session_budget: int | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._limits = dict(limits or {})
        self._default = default_limit
        # 같은 이유로 예산도 검사한다. `nan`이면 `self._spent >= self._budget`이
        # 영원히 거짓이라 예산이 바닥나지 않는다 - 100회 중 100회 통과를 확인했다.
        if session_budget is not None:
            if not _finite_number(session_budget):
                raise ValueError("session budget must be a finite number")
            if session_budget < 0:
                raise ValueError("session budget cannot be negative")
        self._budget = session_budget
        self._clock = clock or time.monotonic
        self._buckets: dict[str, _Bucket] = {}
        self._spent = 0
        # 재진입 가능해야 한다 - `consume`이 잠근 채로 `check`를 부른다.
        self._lock = threading.RLock()

    @property
    def spent(self) -> int:
        return self._spent

    @property
    def budget_remaining(self) -> int | None:
        return None if self._budget is None else max(0, self._budget - self._spent)

    def _limit_for(self, tool_id: str) -> RateLimit | None:
        return self._limits.get(tool_id, self._default)

    def check(self, tool_id: str) -> LimitDecision:
        """Decide without consuming. Used to answer before dispatching."""
        with self._lock:
            return self._check_locked(tool_id)

    def _check_locked(self, tool_id: str) -> LimitDecision:
        if self._budget is not None and self._spent >= self._budget:
            return LimitDecision(False, "session_budget_exhausted", remaining=0)

        limit = self._limit_for(tool_id)
        if limit is None:
            return LimitDecision(True, remaining=self.budget_remaining)

        bucket = self._refill(tool_id, limit)
        if bucket.tokens < 1:
            deficit = 1 - bucket.tokens
            return LimitDecision(
                False, "rate_limited",
                retry_after=round(deficit / limit.per_second, 6),
                remaining=self.budget_remaining,
            )
        return LimitDecision(True, remaining=self.budget_remaining)

    def consume(self, tool_id: str) -> LimitDecision:
        """Check and, if permitted, spend one call. One step, not two."""
        with self._lock:
            decision = self._check_locked(tool_id)
            if not decision.allowed:
                return decision
            limit = self._limit_for(tool_id)
            if limit is not None:
                self._buckets[tool_id].tokens -= 1
            self._spent += 1
            return LimitDecision(True, remaining=self.budget_remaining)

    def _refill(self, tool_id: str, limit: RateLimit) -> _Bucket:
        now = self._clock()
        bucket = self._buckets.get(tool_id)
        if bucket is None:
            bucket = _Bucket(tokens=float(limit.capacity), last_refill=now)
            self._buckets[tool_id] = bucket
            return bucket
        elapsed = max(0.0, now - bucket.last_refill)
        bucket.tokens = min(float(limit.capacity), bucket.tokens + elapsed * limit.per_second)
        bucket.last_refill = now
        return bucket


@dataclass
class SessionScope:
    """One client's view of one server, kept apart from every other session.

    Sharing limiter state across sessions would let a noisy client throttle a
    quiet one, and sharing approval state would be worse: a lease issued for one
    session could be spent by another. Each session gets its own enforcer and its
    own record of what it has been told.
    """

    session_id: str
    server_id: str
    enforcer: LimitEnforcer
    records: list = field(default_factory=list)


class SessionRegistry:
    """Creates and looks up isolated sessions."""

    def __init__(self, factory: Callable[[], LimitEnforcer]) -> None:
        self._factory = factory
        self._sessions: dict[str, SessionScope] = {}

    def open(self, session_id: str, *, server_id: str) -> SessionScope:
        if session_id in self._sessions:
            raise ValueError(f"session already open: {session_id}")
        scope = SessionScope(session_id, server_id, self._factory())
        self._sessions[session_id] = scope
        return scope

    def get(self, session_id: str) -> SessionScope | None:
        return self._sessions.get(session_id)

    def close(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def __len__(self) -> int:
        return len(self._sessions)
