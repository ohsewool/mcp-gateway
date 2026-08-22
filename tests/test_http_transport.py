"""HTTP transport: same rules as stdio, different wire."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.policy import DeterministicPolicy, PolicyRule
from mcp_gateway.registry import RegisteredServer
from mcp_gateway.transport import (
    CALL_TIMEOUT,
    POLICY_DENIED,
    CallTimeout,
    GatewayProxy,
    HttpProxy,
    GatewayInterceptor,
    StdioProxy,
    TransportError,
)

SERVER_ID = "remote-server"
ENDPOINT = "https://mcp.example.test/rpc"


def interceptor():
    policy = DeterministicPolicy(
        {SERVER_ID: ["read_file", "delete_file"]},
        [PolicyRule("allow-read", "allow", SERVER_ID, "read_file"),
         PolicyRule("deny-delete", "deny", SERVER_ID, "delete_file")],
    )
    server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "remote"})
    return GatewayInterceptor(policy, SERVER_ID, baseline_servers=[server])


def call(tool="read_file", request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}}


def responder(result=None, *, echo_id=True, status=None, timeout=False, empty=False,
              record=None):
    """A stand-in for the network, so the transport is testable without one."""
    def opener(endpoint, body, timeout_seconds):
        if record is not None:
            record.append({"endpoint": endpoint, "body": json.loads(body),
                           "timeout": timeout_seconds})
        if timeout:
            raise CallTimeout(f"no response within {timeout_seconds}s")
        if status is not None:
            raise TransportError(f"server returned HTTP {status}")
        if empty:
            return ""
        sent = json.loads(body)
        reply = {"jsonrpc": "2.0", "result": result if result is not None else {"ok": True}}
        reply["id"] = sent.get("id") if echo_id else 999
        return json.dumps(reply)
    return opener


class TestEndpointValidation:
    def test_a_non_http_endpoint_is_refused(self):
        with pytest.raises(TransportError):
            HttpProxy(interceptor(), "ftp://example.test/rpc")

    @pytest.mark.parametrize("endpoint", ["https://a.test/rpc", "http://a.test/rpc"])
    def test_http_and_https_are_accepted(self, endpoint):
        assert HttpProxy(interceptor(), endpoint)


class TestSharedPipeline:
    def test_the_http_proxy_uses_the_same_pipeline_as_stdio(self):
        """A second transport must not be able to enforce a weaker version."""
        assert issubclass(HttpProxy, GatewayProxy)
        assert issubclass(StdioProxy, GatewayProxy)
        assert HttpProxy.request is GatewayProxy.request

    def test_an_allowed_call_reaches_the_endpoint(self):
        sent = []
        with HttpProxy(interceptor(), ENDPOINT, opener=responder(record=sent)) as proxy:
            reply = proxy.request(call())
        assert reply["result"] == {"ok": True}
        assert sent[0]["endpoint"] == ENDPOINT
        assert sent[0]["body"]["params"]["name"] == "read_file"

    def test_a_denied_call_never_leaves_the_gateway(self):
        sent = []
        with HttpProxy(interceptor(), ENDPOINT, opener=responder(record=sent)) as proxy:
            reply = proxy.request(call(tool="delete_file"))
        assert reply["error"]["code"] == POLICY_DENIED
        assert sent == []

    def test_a_duplicate_request_id_is_refused_here_too(self):
        proxy = HttpProxy(interceptor(), ENDPOINT, opener=responder())
        proxy._pending[7] = "tools/call"
        reply = proxy.request(call(request_id=7))
        assert "error" in reply

    def test_headers_are_sent_where_supplied(self):
        proxy = HttpProxy(interceptor(), ENDPOINT, headers={"Authorization": "Bearer x"},
                          opener=responder())
        assert proxy._headers["Authorization"] == "Bearer x"


class TestNetworkFailures:
    def test_a_timeout_is_unknown_not_failed(self):
        """The request was delivered; the effect may have happened."""
        with HttpProxy(interceptor(), ENDPOINT, opener=responder(timeout=True)) as proxy:
            reply = proxy.request(call(), timeout=1.0)
        assert reply["error"]["code"] == CALL_TIMEOUT
        assert reply["error"]["data"]["outcome"] == "UNKNOWN"

    def test_an_http_error_status_is_surfaced(self):
        with HttpProxy(interceptor(), ENDPOINT, opener=responder(status=500)) as proxy:
            with pytest.raises(TransportError) as error:
                proxy.request(call())
        assert "500" in str(error.value)

    def test_an_empty_body_is_refused(self):
        """The message is pinned, not just the type. Without the empty-body check
        the very next line calls `decode_frame("")`, which raises the same
        `TransportError` with a different reason - so a type-only assertion passes
        whether or not the check exists. Measured on 2026-08-22: deleting the check
        left all 320 tests green. The test one line above already pinned its
        message; the rule had split inside a single file."""
        with HttpProxy(interceptor(), ENDPOINT, opener=responder(empty=True)) as proxy:
            with pytest.raises(TransportError) as error:
                proxy.request(call())
        assert "empty body" in str(error.value)

    def test_a_mismatched_response_id_is_refused(self):
        """One request, one response: a wrong id cannot be attributed."""
        with HttpProxy(interceptor(), ENDPOINT, opener=responder(echo_id=False)) as proxy:
            with pytest.raises(TransportError) as error:
                proxy.request(call())
        assert "does not match" in str(error.value)

    def test_a_duplicate_key_in_the_response_is_refused(self):
        def opener(endpoint, body, timeout):
            return '{"jsonrpc":"2.0","id":1,"result":{},"result":{"x":1}}'

        with HttpProxy(interceptor(), ENDPOINT, opener=opener) as proxy:
            with pytest.raises(TransportError):
                proxy.request(call())


class TestGuardIntegration:
    def test_the_guard_holds_a_consequential_call_before_any_request(self):
        """Skipped by asking whether the module imports, not whether a path exists.

        This checked for /home/jovyan/work/agent-safety-core - one machine's
        layout. Anywhere else the directory is absent and the test skips
        silently; on that machine with the package uninstalled the directory is
        present, the import still fails, and the test errors. It was the only
        one of the five core-dependent tests here that did not use
        `importorskip`, and the only one that broke when the core was genuinely
        unavailable.
        """
        ledger_module = pytest.importorskip(
            "core.ledger", reason="agent-safety-core is unavailable")
        ExecutionLedger = ledger_module.ExecutionLedger
        from mcp_gateway.guard import APPROVAL_REQUIRED, ApprovalGuard

        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            ledger = ExecutionLedger(str(Path(folder) / "l.db"))
            try:
                guard = ApprovalGuard(
                    ledger, server_id=SERVER_ID, run_id="r", actor_id="a",
                    consequential_tools=frozenset({"read_file"}), policy_digest="p" * 64,
                )
                sent = []
                with HttpProxy(interceptor(), ENDPOINT, guard=guard,
                               opener=responder(record=sent)) as proxy:
                    reply = proxy.request(call())
                assert reply["error"]["code"] == APPROVAL_REQUIRED
                assert sent == []  # nothing was sent over the network
            finally:
                ledger.close()
