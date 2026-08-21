"""Real MCP wire transport: a stdio JSON-RPC 2.0 proxy with policy interception.

The gateway sits between an MCP client and one MCP server process:

    client --stdin/stdout--> gateway --stdin/stdout--> server

Messages are relayed verbatim except for two interception points:

``tools/list`` responses
    The advertised tool set is captured as a metadata snapshot.  Comparing it
    with the registered baseline detects a server that silently changes a tool's
    description or input schema after registration (a rug-pull).

``tools/call`` requests
    Evaluated by :class:`~mcp_gateway.policy.DeterministicPolicy` *before* the
    request reaches the server.  A denied call never leaves the gateway; the
    client receives a JSON-RPC error instead.  This is fail-closed: any
    unexpected condition denies rather than forwards.

Reading a duplicate JSON key is rejected outright.  Two components that resolve
duplicates differently (first-wins vs last-wins) would otherwise disagree about
what was authorized versus what is executed.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from .metadata_integrity import MetadataChange, MetadataSnapshot, compare_metadata
from .policy import DeterministicPolicy, PolicyDecision, PolicyRequest
from .registry import RegisteredServer, RegisteredTool

# JSON-RPC 2.0 reserved codes; -32000..-32099 is the implementation-defined range.
INVALID_REQUEST = -32600
POLICY_DENIED = -32001
INTEGRITY_VIOLATION = -32002
CALL_TIMEOUT = -32005
DUPLICATE_REQUEST = -32006
RATE_LIMITED = -32007


class TransportError(ValueError):
    """Raised when a frame cannot be parsed safely."""


class CallTimeout(TransportError):
    """Raised when the server does not answer within the deadline.

    Distinct from other transport errors because the outcome is genuinely
    unknown: the request was already delivered, so the side effect may have
    happened. Callers must not retry it blindly.
    """


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise TransportError(f"duplicate JSON key is not permitted: {key!r}")
        seen.add(key)
    return dict(pairs)


def decode_frame(line: str) -> dict[str, Any]:
    """Parse one newline-delimited JSON-RPC frame, rejecting duplicate keys."""
    try:
        message = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise TransportError("frame is not valid JSON") from error
    if not isinstance(message, dict):
        raise TransportError("frame must be a JSON object")
    return message


def encode_frame(message: Mapping[str, Any]) -> str:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n"


def error_response(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _outcome_of(reply: Mapping[str, Any]) -> dict[str, Any]:
    """What the ledger should record for this response.

    Two ways an MCP call fails, and only one of them is a JSON-RPC error.

    A protocol-level failure - unknown method, malformed request - comes back
    with an `error` member. A *tool* failure does not: the call succeeded as
    far as JSON-RPC is concerned and the result carries `isError: true`, with
    the message in its content. Reading only the top-level `error` therefore
    recorded a tool that failed as SUCCEEDED, which is the opposite of what the
    ledger exists to say. Verified against the reference filesystem server:
    reading a missing file returns no `error` field and `result.isError` true.

    The distinction is kept in the evidence rather than flattened, because
    "the server refused the request" and "the tool ran and failed" call for
    different responses from whoever reads this later.
    """
    if "error" in reply:
        return {"state": "FAILED",
                "evidence": {"observed": "jsonrpc_error",
                             "code": (reply.get("error") or {}).get("code")}}

    result = reply.get("result")
    if isinstance(result, Mapping) and result.get("isError") is True:
        message = ""
        content = result.get("content")
        if isinstance(content, list):
            message = " ".join(
                str(part.get("text", "")) for part in content if isinstance(part, Mapping)
            )[:500]
        return {"state": "FAILED",
                "evidence": {"observed": "tool_error", "message": message}}

    return {"state": "SUCCEEDED", "evidence": {"observed": "server_response"}}


@dataclass(frozen=True)
class InterceptionRecord:
    """One audit-relevant decision made by the gateway."""

    direction: str
    method: str | None
    request_id: Any
    action: str
    reason_code: str
    rule_id: str | None = None
    detail: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Interception:
    """The outcome of inspecting one frame."""

    forward: dict[str, Any] | None
    reply: dict[str, Any] | None
    record: InterceptionRecord


class GatewayInterceptor:
    """Applies registry, policy, and metadata-integrity checks to live frames.

    The interceptor is transport-agnostic and side-effect free: it decides, it
    does not perform I/O.  :class:`StdioProxy` supplies the I/O.
    """

    def __init__(
        self,
        policy: DeterministicPolicy,
        server_id: str,
        *,
        baseline: MetadataSnapshot | None = None,
        baseline_servers: Sequence[RegisteredServer] = (),
        constraints_for: Callable[[str, Mapping[str, Any]], tuple] | None = None,
        limiter: Any = None,
        audit_log: Any = None,
    ) -> None:
        """`audit_log` persists every decision; without one they stay in memory.

        The README has claimed persistent auditing as a finished feature - "a
        decision that only lives in memory is no use, the person asking days
        later was not in the room" - while `_log` appended to a list and
        `AuditLog` was imported by nothing but its own tests. The mechanism was
        written, tested, and never connected to the thing that makes decisions.

        Optional rather than required, because the interceptor is used without
        one in unit tests and by callers who keep their own record. What is new
        is that supplying one works.
        """
        self._policy = policy
        self._server_id = server_id
        self._audit_log = audit_log
        self._audit_failures: list[str] = []
        self._baseline = baseline
        self._baseline_servers = tuple(baseline_servers)
        self._constraints_for = constraints_for or (lambda tool_id, arguments: ())
        self._limiter = limiter
        self._records: list[InterceptionRecord] = []

    @property
    def records(self) -> tuple[InterceptionRecord, ...]:
        return tuple(self._records)

    @property
    def audit_failures(self) -> tuple[str, ...]:
        """Decisions that were made but could not be written down.

        Surfaced rather than raised: a gateway that stops deciding because its
        disk is full has turned a logging problem into an availability one. But
        a silent gap in an audit log reads as "nothing happened", so the count
        has to be reachable.
        """
        return tuple(self._audit_failures)

    def _log(self, record: InterceptionRecord) -> InterceptionRecord:
        self._records.append(record)
        if self._audit_log is not None:
            # Appending must not swallow the decision it is recording: a gateway
            # that stops deciding because its disk is full has turned a logging
            # problem into an availability one. The failure is surfaced on the
            # record instead, so a reader can see the gap rather than infer it
            # from an absence.
            try:
                # AuditLog.record was written to take exactly this object. The
                # two were built to fit and never introduced.
                self._audit_log.record(record, server_id=self._server_id)
            except Exception as error:                      # noqa: BLE001
                self._audit_failures.append(str(error))
        return record

    def inspect_request(self, message: Mapping[str, Any]) -> Interception:
        """Decide whether a client->server frame may be forwarded."""
        method = message.get("method")
        request_id = message.get("id")

        if method != "tools/call":
            record = self._log(
                InterceptionRecord("request", method if isinstance(method, str) else None,
                                   request_id, "forwarded", "not_a_tool_call")
            )
            return Interception(dict(message), None, record)

        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            record = self._log(
                InterceptionRecord("request", "tools/call", request_id, "blocked", "malformed_request")
            )
            return Interception(
                None,
                error_response(request_id, INVALID_REQUEST, "malformed tools/call parameters"),
                record,
            )

        tool_id = params["name"]
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}

        if self._limiter is not None:
            # Checked before the policy decision so a throttled call is never
            # evaluated, and refused before anything is spent.
            allowance = self._limiter.check(tool_id)
            if not allowance.allowed:
                record = self._log(
                    InterceptionRecord("request", "tools/call", request_id, "blocked",
                                       allowance.reason_code, detail={"tool": tool_id})
                )
                data: dict[str, Any] = {"tool": tool_id}
                if allowance.retry_after is not None:
                    data["retry_after"] = allowance.retry_after
                if allowance.remaining is not None:
                    data["budget_remaining"] = allowance.remaining
                return Interception(
                    None,
                    error_response(request_id, RATE_LIMITED,
                                   f"gateway refused tool call: {allowance.reason_code}", data),
                    record,
                )

        try:
            constraints = self._constraints_for(tool_id, arguments)
        except Exception:  # fail closed: a constraint mapper error must not forward
            record = self._log(
                InterceptionRecord("request", "tools/call", request_id, "blocked",
                                   "constraint_resolution_failed", detail={"tool": tool_id})
            )
            return Interception(
                None,
                error_response(request_id, POLICY_DENIED, "gateway denied: constraints unavailable"),
                record,
            )

        decision: PolicyDecision = self._policy.evaluate(
            PolicyRequest(server_id=self._server_id, tool_id=tool_id, constraints=constraints)
        )
        if not decision.allowed:
            record = self._log(
                InterceptionRecord("request", "tools/call", request_id, "blocked",
                                   decision.reason_code, decision.rule_id, {"tool": tool_id})
            )
            return Interception(
                None,
                error_response(
                    request_id,
                    POLICY_DENIED,
                    f"gateway denied tool call: {decision.reason_code}",
                    {"tool": tool_id, "rule_id": decision.rule_id},
                ),
                record,
            )

        if self._limiter is not None:
            self._limiter.consume(tool_id)
        record = self._log(
            InterceptionRecord("request", "tools/call", request_id, "forwarded",
                               decision.reason_code, decision.rule_id, {"tool": tool_id})
        )
        return Interception(dict(message), None, record)

    def inspect_response(self, message: Mapping[str, Any], *, method: str | None) -> Interception:
        """Inspect a server->client frame; currently guards ``tools/list``."""
        request_id = message.get("id")
        if method != "tools/list" or not isinstance(message.get("result"), dict):
            record = self._log(
                InterceptionRecord("response", method, request_id, "forwarded", "not_inspected")
            )
            return Interception(dict(message), None, record)

        changes = self.advertised_changes(message["result"])
        if changes:
            record = self._log(
                InterceptionRecord(
                    "response", "tools/list", request_id, "blocked", "metadata_integrity_violation",
                    detail={"changes": [
                        {"tool": change.tool_identifier, "classification": change.classification,
                         "reason": change.reason} for change in changes
                    ]},
                )
            )
            return Interception(
                None,
                error_response(
                    request_id,
                    INTEGRITY_VIOLATION,
                    "gateway blocked tools/list: advertised metadata differs from the registered baseline",
                    record.detail,
                ),
                record,
            )

        record = self._log(
            InterceptionRecord("response", "tools/list", request_id, "forwarded", "metadata_unchanged")
        )
        return Interception(dict(message), None, record)

    def advertised_changes(self, result: Mapping[str, Any]) -> tuple[MetadataChange, ...]:
        """Compare a ``tools/list`` result against the registered baseline.

        The advertised tools are re-registered as :class:`RegisteredTool` values so
        that the integrity identifiers are computed by exactly the same code path
        that produced the baseline — a tool whose description or schema drifted
        yields a different identifier and is reported as ``changed``.
        """
        if self._baseline is None:
            return ()
        advertised: list[RegisteredTool] = []
        for tool in result.get("tools", []):
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                continue
            advertised.append(
                RegisteredTool(
                    server_identifier=self._server_id,
                    identifier=tool["name"],
                    input_schema=tool.get("inputSchema") or {"type": "object"},
                    metadata={"description": tool.get("description", "")},
                )
            )
        current = MetadataSnapshot.from_registered(self._baseline_servers, advertised)
        return compare_metadata(self._baseline, current)


class GatewayProxy:
    """The decision pipeline, independent of how bytes reach the server.

    Every rule the gateway enforces lives here so a second transport cannot
    quietly enforce a weaker version of it: the same guard, the same policy
    interception, the same settlement of outcomes. A transport supplies only
    ``_dispatch``, which sends one frame and returns the matching reply.

    **One frame at a time.** ``request`` holds a lock for the whole pipeline.
    Without it the duplicate-request guard below was a check followed by a write
    with the entire server round trip in between, and it did not hold: eight
    concurrent frames carrying the same id got **two to six** of them past the
    guard in 18 of 20 rounds measured on 2026-08-22. That guard exists so one id
    maps to one outcome; several in-flight requests sharing an id collapse the
    settlement bookkeeping, because the first reply pops the entry and the rest
    settle against nothing.

    The stdio transport could not overlap anyway - it buffers bytes in one
    attribute and discards frames whose id does not match, so a second caller's
    reply would be thrown away and the first would appear to time out. HTTP could
    in principle overlap, but it shares ``_pending``, the interceptor and the
    audit log with every other call, so overlapping would need each of those
    locked separately for a throughput gain nothing here has asked for. Serialise
    now, and say so, rather than leave it undefined.
    """

    def __init__(self, interceptor: GatewayInterceptor, *, guard: Any = None) -> None:
        self._interceptor = interceptor
        self._guard = guard
        self._pending: dict[Any, str] = {}
        self._lock = threading.RLock()

    def _dispatch(self, message: Mapping[str, Any], *, request_id: Any,
                  timeout: float) -> dict[str, Any] | None:
        """Send one frame and return the reply, or None when none is expected."""
        raise NotImplementedError

    def request(self, message: Mapping[str, Any], *, timeout: float = 10.0) -> dict[str, Any]:
        """Send one client frame through the gateway and return the client's reply.

        A blocked frame never reaches the server; the gateway's error response is
        returned instead.
        """
        with self._lock:
            return self._request_locked(message, timeout=timeout)

    def _request_locked(self, message: Mapping[str, Any], *,
                        timeout: float) -> dict[str, Any]:
        method = message.get("method")
        request_id = message.get("id")

        if request_id is not None and request_id in self._pending:
            return error_response(
                request_id, DUPLICATE_REQUEST,
                "gateway denied: a request with this id is already in flight",
            )

        if self._guard is not None and method == "tools/call":
            held = self._guard.check(message)
            if held is not None and held.reply is not None:
                return held.reply
            message = self._guard.strip_lease(message)

        interception = self._interceptor.inspect_request(message)
        if interception.reply is not None:
            # A claimed lease must not be left dangling when policy refuses later.
            self._settle(request_id, state="FAILED",
                         evidence={"reason": interception.record.reason_code})
            return interception.reply
        assert interception.forward is not None
        if request_id is not None and isinstance(method, str):
            self._pending[request_id] = method

        try:
            frame = self._dispatch(interception.forward, request_id=request_id,
                                   timeout=timeout)
            if frame is None:
                return {}
            origin = self._pending.pop(request_id, None)
            outcome = self._interceptor.inspect_response(frame, method=origin)
            reply = outcome.reply if outcome.reply is not None else (outcome.forward or {})
            self._settle(request_id, **_outcome_of(reply))
            return reply
        except CallTimeout as error:
            # The request left the gateway but no result was observed. The side
            # effect may or may not have happened: that is UNKNOWN, not a failure,
            # and it must not be retried without reconciliation.
            self._pending.pop(request_id, None)
            self._settle(request_id, state="UNKNOWN", evidence={"reason": str(error)})
            return error_response(
                request_id, CALL_TIMEOUT,
                "gateway could not determine the outcome: the call timed out after dispatch",
                {"outcome": "UNKNOWN", "requires": "reconciliation"},
            )
        except TransportError as error:
            self._pending.pop(request_id, None)
            self._settle(request_id, state="UNKNOWN", evidence={"reason": str(error)})
            raise

    def _settle(self, request_id: Any, *, state: str, evidence: Mapping[str, Any]) -> None:
        if self._guard is not None:
            self._guard.settle(request_id, state=state, evidence=evidence)


class StdioProxy(GatewayProxy):
    """Relays newline-delimited JSON-RPC to a server running as a child process."""

    def __init__(
        self,
        interceptor: GatewayInterceptor,
        server_command: Sequence[str],
        *,
        guard: Any = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        """`env` is the child server's entire environment when supplied.

        Left unset, the server inherits the gateway's environment - which is
        every credential the gateway process happens to hold. A component whose
        job is to stand between an agent and a server it does not trust should
        not hand that server its own secrets on the way past, and until this
        parameter existed there was no way not to.

        The default is unchanged, because changing it would break every caller
        whose server needs PATH or HOME to start. What is new is the ability to
        say what the server gets.
        """
        super().__init__(interceptor, guard=guard)
        self._command = tuple(server_command)
        self._env = dict(env) if env is not None else None
        self._process: Any = None
        self._buffer = b""

    def __enter__(self) -> "StdioProxy":
        import subprocess

        self._process = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            env=self._env,
        )
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._process is None:
            return
        try:
            if self._process.stdin and not self._process.stdin.closed:
                self._process.stdin.close()
            self._process.wait(timeout=5)
        except Exception:
            self._process.kill()
        finally:
            self._process = None

    def _dispatch(self, message: Mapping[str, Any], *, request_id: Any,
                  timeout: float) -> dict[str, Any] | None:
        self._write(message)
        if request_id is None:  # notification: no response expected
            return None
        while True:
            frame = decode_frame(self._read(timeout=timeout))
            if frame.get("id") != request_id:
                continue  # unrelated server-initiated traffic; ignore for the MVP
            return frame

    def _write(self, message: Mapping[str, Any]) -> None:
        if self._process is None or self._process.stdin is None:
            raise TransportError("server process is not running")
        self._process.stdin.write(encode_frame(message).encode("utf-8"))
        self._process.stdin.flush()

    def _read(self, *, timeout: float) -> str:
        """Read one frame, or raise once the deadline passes.

        Frames are buffered here rather than by a text wrapper: ``select`` can
        only observe the OS pipe, so a wrapper that read ahead would leave a
        complete frame invisible and the call would appear to time out.
        """
        import select
        import time

        if self._process is None or self._process.stdout is None:
            raise TransportError("server process is not running")
        deadline = time.monotonic() + timeout
        while True:
            if b"\n" in self._buffer:
                line, self._buffer = self._buffer.split(b"\n", 1)
                return line.decode("utf-8")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CallTimeout(f"no response within {timeout}s")
            ready, _, _ = select.select([self._process.stdout], [], [], remaining)
            if not ready:
                continue
            chunk = self._process.stdout.read(4096)
            if not chunk:
                raise TransportError("server closed the connection")
            self._buffer += chunk


class HttpProxy(GatewayProxy):
    """Relays JSON-RPC to a server that speaks HTTP rather than stdio.

    The same pipeline as :class:`StdioProxy` — it inherits every decision — so
    moving a deployment from a child process to a remote endpoint cannot quietly
    weaken what the gateway enforces. Only the transport differs.

    Two things change with the network that a pipe did not have. A remote server
    can answer slowly for reasons that are not its fault, and it can answer with
    an HTTP status instead of a JSON-RPC error. Both are treated the way a lost
    pipe response is: the request was delivered, so an unobserved result is
    UNKNOWN rather than a failure.

    ``opener`` is injected so the transport can be exercised without a network.
    """

    def __init__(
        self,
        interceptor: GatewayInterceptor,
        endpoint: str,
        *,
        guard: Any = None,
        headers: Mapping[str, str] | None = None,
        opener: Any = None,
    ) -> None:
        super().__init__(interceptor, guard=guard)
        if not endpoint.startswith(("http://", "https://")):
            raise TransportError("endpoint must be an http or https URL")
        self._endpoint = endpoint
        self._headers = dict(headers or {})
        self._opener = opener

    def __enter__(self) -> "HttpProxy":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def _dispatch(self, message: Mapping[str, Any], *, request_id: Any,
                  timeout: float) -> dict[str, Any] | None:
        body = encode_frame(message).encode("utf-8")
        raw = self._post(body, timeout=timeout)
        if request_id is None:
            return None
        if not raw.strip():
            raise TransportError("server returned an empty body")
        frame = decode_frame(raw)
        if frame.get("id") != request_id:
            # Unlike stdio there is no stream to skip ahead in: one request, one
            # response. A mismatched id means the reply cannot be attributed.
            raise TransportError(
                f"response id {frame.get('id')!r} does not match request {request_id!r}"
            )
        return frame

    def _post(self, body: bytes, *, timeout: float) -> str:
        import urllib.error
        import urllib.request

        if self._opener is not None:
            return self._opener(self._endpoint, body, timeout)

        request = urllib.request.Request(
            self._endpoint, data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Accept": "application/json", **self._headers},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            # The server was reached and refused. Whether it acted first is not
            # knowable from the status alone.
            raise TransportError(f"server returned HTTP {error.code}") from error
        except TimeoutError as error:
            raise CallTimeout(f"no response within {timeout}s") from error
        except urllib.error.URLError as error:
            reason = getattr(error, "reason", error)
            if isinstance(reason, TimeoutError):
                raise CallTimeout(f"no response within {timeout}s") from error
            raise TransportError(f"could not reach the server: {reason}") from error
