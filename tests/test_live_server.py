"""Integration evidence: the gateway in front of a real MCP server process.

Runs the reference filesystem server (`@modelcontextprotocol/server-filesystem`)
as a local child process over stdio and drives real JSON-RPC traffic through the
gateway.  Skipped when npx or the package is unavailable.

Scope note: the server is confined to a pytest tmp_path. No real service,
account, or external target is involved (PROJECT_SPEC §1.1).
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.metadata_integrity import MetadataSnapshot  # noqa: E402
from mcp_gateway.policy import DeterministicPolicy, PolicyRule  # noqa: E402
from mcp_gateway.registry import RegisteredServer, RegisteredTool  # noqa: E402
from mcp_gateway.transport import (  # noqa: E402
    POLICY_DENIED,
    GatewayInterceptor,
    StdioProxy,
)

SERVER_ID = "fs-server"
PACKAGE = "@modelcontextprotocol/server-filesystem"

pytestmark = pytest.mark.integration


def _npx_available() -> bool:
    if shutil.which("npx") is None:
        return False
    try:
        probe = subprocess.run(
            ["npx", "-y", PACKAGE, "--version"],
            capture_output=True, text=True, timeout=300,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return probe.returncode == 0 or "directories" in (probe.stderr + probe.stdout)


requires_server = pytest.mark.skipif(
    not _npx_available(), reason="npx or the reference MCP server is unavailable"
)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "allowed.txt").write_text("gateway integration fixture\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("must never be read\n", encoding="utf-8")
    return tmp_path


def make_proxy(workspace: Path, *, baseline: MetadataSnapshot | None = None) -> StdioProxy:
    policy = DeterministicPolicy(
        {SERVER_ID: ["read_text_file", "write_file", "list_directory"]},
        [
            PolicyRule("allow-read", "allow", SERVER_ID, "read_text_file"),
            PolicyRule("allow-list", "allow", SERVER_ID, "list_directory"),
            PolicyRule("deny-write", "deny", SERVER_ID, "write_file"),
        ],
    )
    server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "filesystem"})
    interceptor = GatewayInterceptor(
        policy, SERVER_ID, baseline=baseline, baseline_servers=[server]
    )
    return StdioProxy(interceptor, ["npx", "-y", PACKAGE, str(workspace)])


def initialize(proxy: StdioProxy) -> dict:
    return proxy.request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-gateway-test", "version": "0"},
            },
        },
        timeout=60,
    )


@requires_server
def test_real_server_handshake_and_tool_listing(workspace: Path):
    with make_proxy(workspace) as proxy:
        handshake = initialize(proxy)
        assert "result" in handshake, handshake

        listing = proxy.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, timeout=60)
        names = {tool["name"] for tool in listing["result"]["tools"]}
        assert "read_text_file" in names


@requires_server
def test_allowed_call_reaches_the_real_server(workspace: Path):
    with make_proxy(workspace) as proxy:
        initialize(proxy)
        response = proxy.request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "read_text_file",
                    "arguments": {"path": str(workspace / "allowed.txt")},
                },
            },
            timeout=60,
        )
        text = "".join(
            part.get("text", "") for part in response["result"]["content"]
        )
        assert "gateway integration fixture" in text


@requires_server
def test_denied_call_never_reaches_the_real_server(workspace: Path):
    target = workspace / "written-by-agent.txt"
    with make_proxy(workspace) as proxy:
        initialize(proxy)
        response = proxy.request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": str(target), "content": "should not exist"},
                },
            },
            timeout=60,
        )
    assert response["error"]["code"] == POLICY_DENIED
    # The decisive evidence: the side effect did not happen.
    assert not target.exists()


@requires_server
def test_unregistered_tool_is_blocked_against_real_server(workspace: Path):
    with make_proxy(workspace) as proxy:
        initialize(proxy)
        response = proxy.request(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "directory_tree", "arguments": {"path": str(workspace)}},
            },
            timeout=60,
        )
    assert response["error"]["code"] == POLICY_DENIED


@requires_server
def test_metadata_drift_from_real_server_is_detected(workspace: Path):
    """A baseline that disagrees with what the live server advertises must block.

    This stands in for a rug-pull: the registered description no longer matches
    the tool the server is actually exposing.
    """
    server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "filesystem"})
    stale = MetadataSnapshot.from_registered(
        [server],
        [
            RegisteredTool(
                server_identifier=SERVER_ID,
                identifier="read_text_file",
                input_schema={"type": "object"},
                metadata={"description": "an outdated description"},
            )
        ],
    )
    with make_proxy(workspace, baseline=stale) as proxy:
        initialize(proxy)
        response = proxy.request({"jsonrpc": "2.0", "id": 6, "method": "tools/list"}, timeout=60)
    assert "error" in response
    assert response["error"]["data"]["changes"]


# --------------------------------------------------------------- JIT approval

CORE = Path("/home/jovyan/work/agent-safety-core")
if CORE.exists():
    sys.path.insert(0, str(CORE))

try:
    from core.ledger import ExecutionLedger  # noqa: E402
    from mcp_gateway.guard import APPROVAL_REQUIRED, LEASE_ARGUMENT, ApprovalGuard  # noqa: E402
    _GUARD_AVAILABLE = True
except ImportError:  # pragma: no cover
    _GUARD_AVAILABLE = False

requires_guard = pytest.mark.skipif(not _GUARD_AVAILABLE, reason="agent-safety-core is unavailable")


@requires_server
@requires_guard
def test_consequential_write_requires_approval_then_happens_exactly_once(workspace, tmp_path):
    """End-to-end: held → approved → written once → replay refused.

    The evidence is the file itself. It must not exist before approval, must
    exist after, and a replayed lease must not write it a second time.
    """
    target = workspace / "guarded.txt"
    ledger = ExecutionLedger(str(tmp_path / "live-guard.db"))
    try:
        policy = DeterministicPolicy(
            {SERVER_ID: ["read_text_file", "write_file"]},
            [
                PolicyRule("allow-read", "allow", SERVER_ID, "read_text_file"),
                PolicyRule("allow-write", "allow", SERVER_ID, "write_file"),
            ],
        )
        server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "filesystem"})
        interceptor = GatewayInterceptor(policy, SERVER_ID, baseline_servers=[server])
        guard = ApprovalGuard(
            ledger, server_id=SERVER_ID, run_id="live-run", actor_id="agent-1",
            consequential_tools=frozenset({"write_file"}), policy_digest="p" * 64,
        )
        arguments = {"path": str(target), "content": "approved by a human\n"}

        with StdioProxy(interceptor, ["npx", "-y", PACKAGE, str(workspace)], guard=guard) as proxy:
            initialize(proxy)

            held = proxy.request(
                {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
                 "params": {"name": "write_file", "arguments": arguments}},
                timeout=60,
            )
            assert held["error"]["code"] == APPROVAL_REQUIRED
            assert not target.exists(), "an unapproved call must not reach the server"

            execution_id = held["error"]["data"]["execution_id"]
            lease = ledger.approve(
                execution_id, approver_id="human-1",
                scope_digest=guard.binding_for("write_file", arguments).digest(),
                ttl_seconds=60,
            )

            approved = proxy.request(
                {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                 "params": {"name": "write_file",
                            "arguments": {**arguments, LEASE_ARGUMENT: lease}}},
                timeout=60,
            )
            assert "result" in approved, approved
            assert target.read_text(encoding="utf-8") == "approved by a human\n"
            assert ledger.get(execution_id).state == "SUCCEEDED"

            target.write_text("tampered\n", encoding="utf-8")
            replayed = proxy.request(
                {"jsonrpc": "2.0", "id": 12, "method": "tools/call",
                 "params": {"name": "write_file",
                            "arguments": {**arguments, LEASE_ARGUMENT: lease}}},
                timeout=60,
            )
            assert "error" in replayed
            assert target.read_text(encoding="utf-8") == "tampered\n", (
                "a spent lease must not produce a second write"
            )
    finally:
        ledger.close()
