"""Just-in-time approval for consequential tool calls, backed by an execution ledger.

The policy engine answers "may this tool be called at all?".  This module answers
the harder question: "this call has real consequences — has a human authorised
*exactly this* call, and has that authorisation been used already?"

Flow for a consequential tool:

1. The client calls the tool.  The gateway computes a scope digest over the
   request, records an intent in the ledger, and replies with an error carrying
   an ``execution_id``.  Nothing reaches the server.
2. A human approves that execution out of band, which issues a single-use lease.
3. The client retries the same call with ``_lease`` in the arguments.  The
   gateway recomputes the scope digest; if it still matches, the lease is claimed
   atomically and the call is forwarded exactly once.

Changing any bound element between steps 1 and 3 changes the digest, so the lease
cannot be claimed — the approval was for the old call, not the new one.

The ledger is injected as a :class:`ExecutionAuthority` port.  The gateway does
not care whether it is backed by SQLite, a stub, or something else; it only
requires that ``claim_lease`` is atomic and durable *before* the call is
forwarded, which is what makes at-most-once dispatch provable.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable

from .transport import (
    Interception,
    InterceptionRecord,
    error_response,
)

APPROVAL_REQUIRED = -32003
APPROVAL_INVALID = -32004

LEASE_ARGUMENT = "_lease"


@runtime_checkable
class ExecutionAuthority(Protocol):
    """The subset of an execution ledger that the gateway depends on."""

    def create(self, *, run_id: str, actor_id: str, tool_id: str, operation: str,
               scope_digest: str) -> str: ...

    def claim_lease(self, lease_id: str, *, scope_digest: str) -> str | None: ...

    def record_outcome(self, execution_id: str, *, state: str,
                       evidence: Mapping[str, Any]) -> None: ...


def canonical_digest(value: Any) -> str:
    """Stable digest of a JSON value.

    Rejects the shapes that make two components disagree about what a payload
    means: non-finite numbers cannot be represented in strict JSON, and
    non-string keys have no canonical ordering.
    """
    def check(node: Any) -> Any:
        if isinstance(node, float) and (node != node or node in (float("inf"), float("-inf"))):
            raise ValueError("non-finite numbers are not permitted in bound arguments")
        if isinstance(node, dict):
            if any(not isinstance(key, str) for key in node):
                raise ValueError("argument keys must be strings")
            return {key: check(item) for key, item in node.items()}
        if isinstance(node, list):
            return [check(item) for item in node]
        return node

    payload = json.dumps(
        check(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ScopeBinding:
    """Everything an approval is bound to. Any change invalidates the approval."""

    run_id: str
    actor_id: str
    server_id: str
    tool_id: str
    arguments_digest: str
    policy_digest: str
    context_digest: str

    def digest(self) -> str:
        return canonical_digest(
            {
                "run_id": self.run_id,
                "actor_id": self.actor_id,
                "server_id": self.server_id,
                "tool_id": self.tool_id,
                "arguments_digest": self.arguments_digest,
                "policy_digest": self.policy_digest,
                "context_digest": self.context_digest,
            }
        )


class ApprovalGuard:
    """Gates consequential tool calls behind a single-use, scope-bound approval."""

    def __init__(
        self,
        authority: ExecutionAuthority,
        *,
        server_id: str,
        run_id: str,
        actor_id: str,
        consequential_tools: frozenset[str],
        policy_digest: str,
        context_digest: str = "",
    ) -> None:
        self._authority = authority
        self._server_id = server_id
        self._run_id = run_id
        self._actor_id = actor_id
        self._consequential = frozenset(consequential_tools)
        self._policy_digest = policy_digest
        self._context_digest = context_digest
        self._dispatched: dict[Any, str] = {}

    def requires_approval(self, tool_id: str) -> bool:
        return tool_id in self._consequential

    def binding_for(self, tool_id: str, arguments: Mapping[str, Any]) -> ScopeBinding:
        """Bind to the arguments the server will actually receive (lease excluded)."""
        effective = {key: value for key, value in arguments.items() if key != LEASE_ARGUMENT}
        return ScopeBinding(
            run_id=self._run_id,
            actor_id=self._actor_id,
            server_id=self._server_id,
            tool_id=tool_id,
            arguments_digest=canonical_digest(effective),
            policy_digest=self._policy_digest,
            context_digest=self._context_digest,
        )

    def check(self, message: Mapping[str, Any]) -> Interception | None:
        """Return an interception when the call must be stopped, else ``None``.

        ``None`` means "the guard has no objection"; the caller continues with the
        policy interceptor.  A returned :class:`Interception` is final.
        """
        params = message.get("params")
        if not isinstance(params, dict):
            return None
        tool_id = params.get("name")
        if not isinstance(tool_id, str) or not self.requires_approval(tool_id):
            return None

        request_id = message.get("id")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}

        try:
            binding = self.binding_for(tool_id, arguments)
            scope_digest = binding.digest()
        except ValueError as error:
            record = InterceptionRecord("request", "tools/call", request_id, "blocked",
                                        "unbindable_arguments", detail={"tool": tool_id})
            return Interception(
                None,
                error_response(request_id, APPROVAL_INVALID, f"gateway denied: {error}"),
                record,
            )

        lease_id = arguments.get(LEASE_ARGUMENT)
        if not isinstance(lease_id, str) or not lease_id:
            execution_id = self._authority.create(
                run_id=self._run_id, actor_id=self._actor_id, tool_id=tool_id,
                operation="tools/call", scope_digest=scope_digest,
            )
            record = InterceptionRecord(
                "request", "tools/call", request_id, "blocked", "approval_required",
                detail={"tool": tool_id, "execution_id": execution_id},
            )
            return Interception(
                None,
                error_response(
                    request_id, APPROVAL_REQUIRED,
                    "gateway held tool call: human approval required",
                    {"execution_id": execution_id, "tool": tool_id},
                ),
                record,
            )

        execution_id = self._authority.claim_lease(lease_id, scope_digest=scope_digest)
        if execution_id is None:
            record = InterceptionRecord(
                "request", "tools/call", request_id, "blocked", "lease_refused",
                detail={"tool": tool_id},
            )
            return Interception(
                None,
                error_response(
                    request_id, APPROVAL_INVALID,
                    "gateway denied: lease is unusable (consumed, expired, revoked, or bound to a different call)",
                    {"tool": tool_id},
                ),
                record,
            )

        # The lease is durably consumed; the call may now be dispatched exactly once.
        self._dispatched[request_id] = execution_id
        return None

    def strip_lease(self, message: Mapping[str, Any]) -> dict[str, Any]:
        """Remove the gateway's lease argument before forwarding to the server."""
        forwarded = json.loads(json.dumps(message))
        params = forwarded.get("params")
        if isinstance(params, dict) and isinstance(params.get("arguments"), dict):
            params["arguments"].pop(LEASE_ARGUMENT, None)
        return forwarded

    def settle(self, request_id: Any, *, state: str, evidence: Mapping[str, Any]) -> str | None:
        """Record the outcome of a dispatched call. Returns the execution id."""
        execution_id = self._dispatched.pop(request_id, None)
        if execution_id is None:
            return None
        self._authority.record_outcome(execution_id, state=state, evidence=dict(evidence))
        return execution_id

    def pending(self, request_id: Any) -> str | None:
        return self._dispatched.get(request_id)
