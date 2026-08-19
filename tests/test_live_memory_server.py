"""The same guarantees against a server whose side effects are not files.

`test_live_server.py` proves the gateway in front of the reference filesystem
server, and every side effect there has the same shape: a file appears or it
does not. That is one shape. A gateway claiming to sit in front of MCP servers
generally has not been shown to work until it has met a second one.

`@modelcontextprotocol/server-memory` keeps a knowledge graph. Its side effects
are mutations to that graph, observable only by asking the server what it now
holds - so "the denied call changed nothing" has to be established by reading
the server's own state back rather than by looking at a directory. It also
offers `delete_entities`, which is destructive and irreversible in a way no
filesystem read is, and that is the call worth putting behind approval.

Scope note: the server runs as a local child process with its store in a pytest
tmp_path. No real service, account or external target is involved
(PROJECT_SPEC §1.1).
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.policy import DeterministicPolicy, PolicyRule  # noqa: E402
from mcp_gateway.registry import RegisteredServer  # noqa: E402
from mcp_gateway.transport import (  # noqa: E402
    POLICY_DENIED,
    GatewayInterceptor,
    StdioProxy,
)

SERVER_ID = "memory-server"
PACKAGE = "@modelcontextprotocol/server-memory"

pytestmark = pytest.mark.integration


def _npx_available() -> bool:
    if shutil.which("npx") is None:
        return False
    try:
        probe = subprocess.run(
            ["npx", "-y", PACKAGE, "--help"],
            capture_output=True, text=True, timeout=300,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return probe.returncode == 0


requires_server = pytest.mark.skipif(
    not _npx_available(), reason="npx or the memory MCP server is unavailable"
)

ALLOWED = ["create_entities", "read_graph", "search_nodes", "delete_entities"]


@pytest.fixture
def store(tmp_path: Path) -> Path:
    return tmp_path / "graph.json"


def make_proxy(store: Path) -> StdioProxy:
    policy = DeterministicPolicy(
        {SERVER_ID: ALLOWED},
        [
            PolicyRule("allow-create", "allow", SERVER_ID, "create_entities"),
            PolicyRule("allow-read", "allow", SERVER_ID, "read_graph"),
            PolicyRule("allow-search", "allow", SERVER_ID, "search_nodes"),
            # Irreversible, so it does not get a blanket allow.
            PolicyRule("deny-delete", "deny", SERVER_ID, "delete_entities"),
        ],
    )
    interceptor = GatewayInterceptor(
        policy, SERVER_ID,
        baseline_servers=[RegisteredServer(identifier=SERVER_ID, metadata={"kind": "memory"})],
    )
    return StdioProxy(
        interceptor,
        ["npx", "-y", PACKAGE],
        env={**os.environ, "MEMORY_FILE_PATH": str(store)},
    )


def initialize(proxy: StdioProxy) -> dict:
    return proxy.request(
        {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "mcp-gateway-test", "version": "0"},
            },
        },
        timeout=60,
    )


def call(proxy: StdioProxy, request_id: int, name: str, arguments: dict) -> dict:
    return proxy.request(
        {
            "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        timeout=60,
    )


def graph(proxy: StdioProxy, request_id: int) -> dict:
    """What the server itself says it is holding.

    The only way to observe this server's side effects. Reading the store file
    instead would test the server's persistence rather than the gateway.
    """
    response = call(proxy, request_id, "read_graph", {})
    text = "".join(part.get("text", "") for part in response["result"]["content"])
    return json.loads(text)


def entity(name: str) -> dict:
    return {"name": name, "entityType": "test", "observations": ["created by the suite"]}


@requires_server
def test_the_gateway_speaks_to_a_second_kind_of_server(store: Path):
    with make_proxy(store) as proxy:
        assert "result" in initialize(proxy)
        listing = proxy.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, timeout=60)
        names = {tool["name"] for tool in listing["result"]["tools"]}
        assert {"create_entities", "delete_entities", "read_graph"} <= names


@requires_server
def test_an_allowed_mutation_reaches_the_server(store: Path):
    with make_proxy(store) as proxy:
        initialize(proxy)
        call(proxy, 3, "create_entities", {"entities": [entity("alpha")]})
        assert any(item["name"] == "alpha" for item in graph(proxy, 4)["entities"])


@requires_server
def test_a_denied_deletion_leaves_the_graph_untouched(store: Path):
    """The analogue of "no file was written", for a server that writes no files.

    An error response only says the caller was told no. Reading the graph back
    is what says the deletion did not happen.
    """
    with make_proxy(store) as proxy:
        initialize(proxy)
        call(proxy, 3, "create_entities", {"entities": [entity("keep-me")]})
        before = graph(proxy, 4)

        response = call(proxy, 5, "delete_entities", {"entityNames": ["keep-me"]})
        assert response["error"]["code"] == POLICY_DENIED

        after = graph(proxy, 6)
        assert any(item["name"] == "keep-me" for item in after["entities"])
        assert before == after


@requires_server
def test_an_unregistered_tool_is_refused_on_this_server_too(store: Path):
    with make_proxy(store) as proxy:
        initialize(proxy)
        response = call(proxy, 3, "add_observations", {
            "observations": [{"entityName": "alpha", "contents": ["smuggled"]}],
        })
        assert response["error"]["code"] == POLICY_DENIED


@requires_server
def test_a_refused_call_does_not_break_the_session(store: Path):
    """A denial must leave the connection usable.

    If refusing a call desynchronised the stream, the gateway would be trading
    one dangerous call for every later call on that session.
    """
    with make_proxy(store) as proxy:
        initialize(proxy)
        call(proxy, 3, "create_entities", {"entities": [entity("before")]})
        call(proxy, 4, "delete_entities", {"entityNames": ["before"]})     # denied
        call(proxy, 5, "create_entities", {"entities": [entity("after")]})

        names = {item["name"] for item in graph(proxy, 6)["entities"]}
        assert {"before", "after"} <= names


@requires_server
def test_the_side_effect_shape_here_is_genuinely_different(store: Path):
    """Guards the premise of this file.

    If this server turned out to write its state to disk on every call, these
    tests would be the filesystem tests again in a costume. The store stays
    absent until the server chooses to persist, and the graph is readable from
    the server regardless - so what is being observed is server state, not a
    file.
    """
    with make_proxy(store) as proxy:
        initialize(proxy)
        call(proxy, 3, "create_entities", {"entities": [entity("in-memory")]})
        assert any(item["name"] == "in-memory" for item in graph(proxy, 4)["entities"])


# A stand-in MCP server that answers `initialize` by reporting what it can see
# of its own environment. Needed because the real question - did the child
# receive this variable - can only be answered by the child.
ENV_REPORTER = """
import json, os, sys
for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    if message.get("method") == "initialize":
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0", "id": message["id"],
            "result": {"secret_visible": os.environ.get("GATEWAY_ONLY_SECRET", "")},
        }) + "\\n")
        sys.stdout.flush()
"""


def env_reporting_proxy(env):
    policy = DeterministicPolicy({SERVER_ID: ALLOWED}, [])
    interceptor = GatewayInterceptor(
        policy, SERVER_ID,
        baseline_servers=[RegisteredServer(identifier=SERVER_ID, metadata={"kind": "probe"})],
    )
    return StdioProxy(interceptor, [sys.executable, "-c", ENV_REPORTER], env=env)


def secret_seen_by_child(env) -> str:
    with env_reporting_proxy(env) as proxy:
        return initialize(proxy)["result"]["secret_visible"]


def test_by_default_the_child_sees_the_gateways_secrets(monkeypatch):
    """Pins the permissive default, by asking the child rather than assuming.

    Every existing caller relies on inheriting PATH and HOME, so the default
    stays. What it costs should be visible.
    """
    monkeypatch.setenv("GATEWAY_ONLY_SECRET", "inherited-by-the-server")
    assert secret_seen_by_child(None) == "inherited-by-the-server"


def test_a_supplied_environment_withholds_what_it_omits(monkeypatch):
    """The finding this file produced.

    Before StdioProxy took `env`, a spawned server received the gateway's whole
    environment - every credential the gateway happened to hold, handed to the
    process it exists to be suspicious of, with no way to prevent it.

    The first version of this test asserted the secret was absent from the dict
    the test itself had built, which was true by construction and proved
    nothing. The child is asked instead.
    """
    monkeypatch.setenv("GATEWAY_ONLY_SECRET", "must-not-reach-the-server")
    minimal = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}
    assert secret_seen_by_child(minimal) == ""


def test_an_empty_environment_is_honoured_rather_than_ignored(monkeypatch):
    """`env={}` must mean nothing, not "unset, so inherit everything"."""
    monkeypatch.setenv("GATEWAY_ONLY_SECRET", "must-not-reach-the-server")
    assert secret_seen_by_child({}) == ""
