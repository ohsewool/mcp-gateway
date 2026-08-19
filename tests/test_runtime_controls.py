"""Runtime controls: bounded calls, honest timeouts, no duplicate dispatch.

These use a scripted fake server process rather than the reference server, so a
hang or a slow response can be produced deterministically.
"""

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.policy import DeterministicPolicy, PolicyRule  # noqa: E402
from mcp_gateway.registry import RegisteredServer  # noqa: E402
from mcp_gateway.transport import (  # noqa: E402
    CALL_TIMEOUT,
    DUPLICATE_REQUEST,
    GatewayInterceptor,
    StdioProxy,
)


SERVER_ID = "fake-server"


def scripted_server(tmp_path: Path, body: str) -> list[str]:
    """Write a tiny stdio server whose behaviour we control exactly."""
    script = tmp_path / "server.py"
    script.write_text(
        textwrap.dedent(
            """
            import json, sys, time

            def reply(message):
                sys.stdout.write(json.dumps(message) + "\\n")
                sys.stdout.flush()

            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                request = json.loads(line)
            """
        )
        + textwrap.indent(textwrap.dedent(body), "    "),
        encoding="utf-8",
    )
    return [sys.executable, "-u", str(script)]


def make_interceptor():
    policy = DeterministicPolicy(
        {SERVER_ID: ["slow_tool", "echo"]},
        [
            PolicyRule("allow-slow", "allow", SERVER_ID, "slow_tool"),
            PolicyRule("allow-echo", "allow", SERVER_ID, "echo"),
        ],
    )
    server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "fake"})
    return GatewayInterceptor(policy, SERVER_ID, baseline_servers=[server])


def tool_call(name, request_id=1, arguments=None):
    return {
        "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def test_call_that_never_answers_times_out_as_unknown(tmp_path):
    """A wedged server must not hang the gateway; the outcome is UNKNOWN."""
    command = scripted_server(tmp_path, "time.sleep(30)")
    with StdioProxy(make_interceptor(), command) as proxy:
        response = proxy.request(tool_call("slow_tool"), timeout=1.0)
    assert response["error"]["code"] == CALL_TIMEOUT
    assert response["error"]["data"]["outcome"] == "UNKNOWN"
    assert response["error"]["data"]["requires"] == "reconciliation"


def test_timeout_settles_the_execution_as_unknown_in_the_ledger(tmp_path):
    """The honest classification must reach the ledger, not just the client."""
    ledger_module = pytest.importorskip("core.ledger")
    from mcp_gateway.guard import LEASE_ARGUMENT, ApprovalGuard

    ledger = ledger_module.ExecutionLedger(str(tmp_path / "timeout.db"))
    try:
        guard = ApprovalGuard(
            ledger, server_id=SERVER_ID, run_id="r", actor_id="a",
            consequential_tools=frozenset({"slow_tool"}), policy_digest="p" * 64,
        )
        arguments = {"amount": 100}
        held = guard.check(tool_call("slow_tool", arguments=arguments))
        execution_id = held.reply["error"]["data"]["execution_id"]
        lease = ledger.approve(
            execution_id, approver_id="h",
            scope_digest=guard.binding_for("slow_tool", arguments).digest(),
            ttl_seconds=60,
        )

        command = scripted_server(tmp_path, "time.sleep(30)")
        with StdioProxy(make_interceptor(), command, guard=guard) as proxy:
            response = proxy.request(
                tool_call("slow_tool", arguments={**arguments, LEASE_ARGUMENT: lease}),
                timeout=1.0,
            )
        assert response["error"]["code"] == CALL_TIMEOUT
        assert ledger.get(execution_id).state == "UNKNOWN"
        # Invariant 3B: the spent lease cannot authorise a retry.
        assert ledger.claim_lease(
            lease, scope_digest=guard.binding_for("slow_tool", arguments).digest()
        ) is None
    finally:
        ledger.close()


def test_slow_but_answering_call_still_succeeds(tmp_path):
    """The deadline must not cut off a server that is merely slow."""
    command = scripted_server(
        tmp_path,
        'time.sleep(0.3)\nreply({"jsonrpc": "2.0", "id": request["id"], "result": {"ok": True}})',
    )
    with StdioProxy(make_interceptor(), command) as proxy:
        response = proxy.request(tool_call("echo"), timeout=5.0)
    assert response["result"] == {"ok": True}


def test_unrelated_server_frames_do_not_consume_the_deadline(tmp_path):
    """Server-initiated traffic is skipped without losing the awaited response."""
    command = scripted_server(
        tmp_path,
        'reply({"jsonrpc": "2.0", "method": "notifications/message", "params": {}})\n'
        'reply({"jsonrpc": "2.0", "id": request["id"], "result": {"ok": True}})',
    )
    with StdioProxy(make_interceptor(), command) as proxy:
        response = proxy.request(tool_call("echo"), timeout=5.0)
    assert response["result"] == {"ok": True}


def test_duplicate_in_flight_request_id_is_refused(tmp_path):
    """Two calls sharing an id would make responses unattributable."""
    command = scripted_server(
        tmp_path, 'reply({"jsonrpc": "2.0", "id": request["id"], "result": {"ok": True}})'
    )
    proxy = StdioProxy(make_interceptor(), command)
    with proxy:
        proxy._pending[7] = "tools/call"  # simulate an outstanding request
        response = proxy.request(tool_call("echo", request_id=7), timeout=5.0)
    assert response["error"]["code"] == DUPLICATE_REQUEST
