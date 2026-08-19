"""JIT approval: a consequential call is held, approved once, and never replayed.

The authority under test is the real transactional ledger from `agent-safety-core`
when it is importable; this doubles as cross-repo integration evidence that the
core's execution model actually serves an MCP vertical.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.guard import (  # noqa: E402
    APPROVAL_INVALID,
    APPROVAL_REQUIRED,
    LEASE_ARGUMENT,
    ApprovalGuard,
    canonical_digest,
)

ledger_module = pytest.importorskip("core.ledger", reason="agent-safety-core is unavailable")
ExecutionLedger = ledger_module.ExecutionLedger

SERVER_ID = "fs-server"
POLICY_DIGEST = "p" * 64


@pytest.fixture
def ledger(tmp_path):
    instance = ExecutionLedger(str(tmp_path / "guard.db"))
    yield instance
    instance.close()


@pytest.fixture
def guard(ledger):
    return ApprovalGuard(
        ledger,
        server_id=SERVER_ID,
        run_id="run-1",
        actor_id="agent-1",
        consequential_tools=frozenset({"write_file"}),
        policy_digest=POLICY_DIGEST,
        context_digest="ctx-a",
    )


def call(tool, arguments=None, request_id=1):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments or {}},
    }


def approve(ledger, execution_id, guard, tool, arguments):
    """Human approval, out of band, bound to the same scope the gateway computed."""
    return ledger.approve(
        execution_id,
        approver_id="human-1",
        scope_digest=guard.binding_for(tool, arguments).digest(),
        ttl_seconds=60,
    )


class TestCanonicalDigest:
    def test_key_order_does_not_change_the_digest(self):
        assert canonical_digest({"a": 1, "b": 2}) == canonical_digest({"b": 2, "a": 1})

    def test_value_change_changes_the_digest(self):
        assert canonical_digest({"path": "/a"}) != canonical_digest({"path": "/b"})

    def test_non_finite_numbers_are_rejected(self):
        with pytest.raises(ValueError):
            canonical_digest({"amount": float("inf")})


class TestApprovalGate:
    def test_harmless_tool_passes_the_guard(self, guard):
        assert guard.check(call("read_file", {"path": "/tmp/a"})) is None

    def test_consequential_tool_is_held_for_approval(self, guard):
        held = guard.check(call("write_file", {"path": "/tmp/a", "content": "x"}))
        assert held is not None
        assert held.forward is None
        assert held.reply["error"]["code"] == APPROVAL_REQUIRED
        assert held.reply["error"]["data"]["execution_id"]

    def test_approved_lease_admits_the_call_once(self, ledger, guard):
        arguments = {"path": "/tmp/a", "content": "x"}
        held = guard.check(call("write_file", arguments))
        execution_id = held.reply["error"]["data"]["execution_id"]
        lease = approve(ledger, execution_id, guard, "write_file", arguments)

        retried = call("write_file", {**arguments, LEASE_ARGUMENT: lease}, request_id=2)
        assert guard.check(retried) is None  # admitted
        assert guard.pending(2) == execution_id

        # A second attempt with the same lease is refused: the lease is spent.
        again = call("write_file", {**arguments, LEASE_ARGUMENT: lease}, request_id=3)
        refused = guard.check(again)
        assert refused.reply["error"]["code"] == APPROVAL_INVALID

    def test_lease_is_not_forwarded_to_the_server(self, ledger, guard):
        arguments = {"path": "/tmp/a", "content": "x"}
        held = guard.check(call("write_file", arguments))
        lease = approve(ledger, held.reply["error"]["data"]["execution_id"], guard,
                        "write_file", arguments)
        message = call("write_file", {**arguments, LEASE_ARGUMENT: lease}, request_id=2)
        stripped = guard.strip_lease(message)
        assert LEASE_ARGUMENT not in stripped["params"]["arguments"]
        assert stripped["params"]["arguments"]["path"] == "/tmp/a"

    def test_changed_arguments_invalidate_the_approval(self, ledger, guard):
        """The approval was for the old call; a different call must not reuse it."""
        original = {"path": "/tmp/a", "content": "x"}
        held = guard.check(call("write_file", original))
        lease = approve(ledger, held.reply["error"]["data"]["execution_id"], guard,
                        "write_file", original)

        tampered = call("write_file", {"path": "/etc/passwd", "content": "x",
                                       LEASE_ARGUMENT: lease}, request_id=2)
        refused = guard.check(tampered)
        assert refused.reply["error"]["code"] == APPROVAL_INVALID

    def test_revoked_approval_cannot_be_used(self, ledger, guard):
        arguments = {"path": "/tmp/a", "content": "x"}
        held = guard.check(call("write_file", arguments))
        execution_id = held.reply["error"]["data"]["execution_id"]
        lease = approve(ledger, execution_id, guard, "write_file", arguments)
        ledger.revoke(execution_id, revoker_id="human-1", reason="risk found")

        retried = call("write_file", {**arguments, LEASE_ARGUMENT: lease}, request_id=2)
        assert guard.check(retried).reply["error"]["code"] == APPROVAL_INVALID

    def test_unknown_lease_is_refused(self, guard):
        message = call("write_file", {"path": "/tmp/a", LEASE_ARGUMENT: "deadbeef"})
        assert guard.check(message).reply["error"]["code"] == APPROVAL_INVALID

    def test_unbindable_arguments_are_refused(self, guard):
        message = call("write_file", {"amount": float("nan")})
        assert guard.check(message).reply["error"]["code"] == APPROVAL_INVALID


class TestOutcomeRecording:
    def test_success_is_settled_in_the_ledger(self, ledger, guard):
        arguments = {"path": "/tmp/a", "content": "x"}
        held = guard.check(call("write_file", arguments))
        execution_id = held.reply["error"]["data"]["execution_id"]
        lease = approve(ledger, execution_id, guard, "write_file", arguments)
        guard.check(call("write_file", {**arguments, LEASE_ARGUMENT: lease}, request_id=2))

        assert guard.settle(2, state="SUCCEEDED", evidence={"observed": "response"}) == execution_id
        assert ledger.get(execution_id).state == "SUCCEEDED"

    def test_lost_response_settles_as_unknown_not_failed(self, ledger, guard):
        """A timeout is not a failure: the side effect may already have happened."""
        arguments = {"path": "/tmp/a", "content": "x"}
        held = guard.check(call("write_file", arguments))
        execution_id = held.reply["error"]["data"]["execution_id"]
        lease = approve(ledger, execution_id, guard, "write_file", arguments)
        guard.check(call("write_file", {**arguments, LEASE_ARGUMENT: lease}, request_id=2))

        guard.settle(2, state="UNKNOWN", evidence={"reason": "server closed the connection"})
        assert ledger.get(execution_id).state == "UNKNOWN"

        # Invariant 3B: no new authorization without reconciliation.
        assert ledger.claim_lease(lease, scope_digest=guard.binding_for("write_file", arguments).digest()) is None

    def test_settling_an_unknown_request_id_is_a_noop(self, guard):
        assert guard.settle(99, state="SUCCEEDED", evidence={}) is None
