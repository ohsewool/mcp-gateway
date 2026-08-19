"""Deterministic, side-effect-free policy decisions for registered MCP tools.

Rule evaluation is deliberately small and predictable:

1. malformed requests and unknown registry identifiers are denied;
2. matching deny rules win, ordered by specificity then ``rule_id``;
3. one highest-precedence allow rule permits the request;
4. tied allow rules are ambiguous and are denied; and
5. all other requests are denied by default.

Constraints are synthetic descriptions only.  Evaluating a policy never opens a
file, starts a command, or connects to a network service.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping, Sequence


_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/"
)


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and all(character in _IDENTIFIER_CHARS for character in value)
    )


@dataclass(frozen=True)
class FilesystemConstraint:
    """A synthetic filesystem permission; ``path`` must be an absolute path."""

    operation: str
    path: str

    def valid(self) -> bool:
        return (
            self.operation in ("read", "write")
            and isinstance(self.path, str)
            and self.path.startswith("/")
        )

    def permits(self, requested: "Constraint") -> bool:
        """Does granting this permit the requested access?

        A grant on a directory covers what is under it. Written with path
        components rather than string prefixes, because `/tmp/work` is a prefix
        of `/tmp/work-evil` and a rule scoped to one directory would silently
        cover a sibling. Traversal is handled by refusing `..` outright rather
        than resolving it - resolution here would disagree with whatever the
        server does later, and the two must not differ.
        """
        if not isinstance(requested, FilesystemConstraint):
            return False
        if self.operation != requested.operation:
            return False
        if ".." in PurePosixPath(requested.path).parts:
            return False
        granted = PurePosixPath(self.path).parts
        return PurePosixPath(requested.path).parts[:len(granted)] == granted


@dataclass(frozen=True)
class NetworkConstraint:
    """A synthetic network destination permission."""

    protocol: str
    host: str
    port: int

    def valid(self) -> bool:
        return (
            self.protocol in ("http", "https")
            and _valid_identifier(self.host)
            and isinstance(self.port, int)
            and not isinstance(self.port, bool)
            and 1 <= self.port <= 65535
        )

    def permits(self, requested: "Constraint") -> bool:
        """Exact. A host and port are not a range, and treating them as a
        hierarchy - `api.example.com` under `example.com` - would let anyone who
        controls a subdomain inherit the grant."""
        return self == requested


@dataclass(frozen=True)
class CommandConstraint:
    """A synthetic command name permission, with no execution capability."""

    command: str

    def valid(self) -> bool:
        return _valid_identifier(self.command)

    def permits(self, requested: "Constraint") -> bool:
        return self == requested


@dataclass(frozen=True)
class ResourceConstraint:
    """A synthetic named-resource permission."""

    resource: str

    def valid(self) -> bool:
        return _valid_identifier(self.resource)

    def permits(self, requested: "Constraint") -> bool:
        return self == requested


Constraint = (
    FilesystemConstraint | NetworkConstraint | CommandConstraint | ResourceConstraint
)


@dataclass(frozen=True)
class PolicyRequest:
    server_id: str
    tool_id: str
    constraints: tuple[Constraint, ...] = ()


@dataclass(frozen=True)
class PolicyRule:
    """An exact, least-privilege rule for one registered server and tool."""

    rule_id: str
    effect: str
    server_id: str
    tool_id: str
    constraints: tuple[Constraint, ...] = ()

    def valid(self) -> bool:
        return (
            _valid_identifier(self.rule_id)
            and self.effect in {"allow", "deny"}
            and _valid_identifier(self.server_id)
            and _valid_identifier(self.tool_id)
            and _valid_constraints(self.constraints)
        )

    def matches(self, request: PolicyRequest) -> bool:
        """Does this rule govern the request?

        Constraints used to be compared with `==`, which made a rule scoped to
        `/tmp/work` govern only a request naming that exact path - so
        `/tmp/work/report.txt` fell through to default_deny and "allow writes
        under this directory" could not be written at all.

        Now every constraint the request asks for must be permitted by one this
        rule grants. A request that asks for nothing matches a rule that grants
        nothing, which keeps plain tool-level allow/deny working as before.
        """
        if self.server_id != request.server_id or self.tool_id != request.tool_id:
            return False
        if not self.constraints:
            return not request.constraints
        if not request.constraints:
            # `all()` over nothing is true, so an unconstrained request matched
            # a scoped rule and was allowed without any scope being checked.
            # That is the failure direction to avoid: when the gateway cannot
            # derive a path from the arguments it produces no constraints, and
            # the scoped rule would then approve a call it knows nothing about.
            return False
        return all(
            any(granted.permits(asked) for granted in self.constraints)
            for asked in request.constraints
        )

    @property
    def specificity(self) -> int:
        # The identifiers are always exact; each requested constraint narrows scope.
        return 2 + len(self.constraints)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str
    rule_id: str | None = None


def _valid_constraints(constraints: object) -> bool:
    if not isinstance(constraints, tuple):
        return False
    try:
        if len(set(constraints)) != len(constraints):
            return False
    except TypeError:
        return False
    return all(
        isinstance(
            constraint,
            (FilesystemConstraint, NetworkConstraint, CommandConstraint, ResourceConstraint),
        )
        and constraint.valid()
        for constraint in constraints
    )


class DeterministicPolicy:
    """Evaluate immutable rules against an immutable view of the MCP registry."""

    def __init__(
        self,
        registered_tools: Mapping[str, Sequence[str]],
        rules: Sequence[PolicyRule],
    ) -> None:
        self._registered_tools = tuple(
            sorted((server_id, frozenset(tool_ids)) for server_id, tool_ids in registered_tools.items())
        )
        self._rules = tuple(rules)

    def evaluate(self, request: object) -> PolicyDecision:
        if not self._valid_request(request):
            return PolicyDecision(False, "malformed_request")
        assert isinstance(request, PolicyRequest)

        tools = dict(self._registered_tools)
        if request.server_id not in tools:
            return PolicyDecision(False, "unknown_server")
        if request.tool_id not in tools[request.server_id]:
            return PolicyDecision(False, "unknown_tool")

        matching = [rule for rule in self._rules if rule.valid() and rule.matches(request)]
        denies = self._ordered(rule for rule in matching if rule.effect == "deny")
        allows = self._ordered(rule for rule in matching if rule.effect == "allow")

        if denies and allows:
            return PolicyDecision(False, "conflicting_rules", denies[0].rule_id)
        if denies:
            return PolicyDecision(False, "explicit_deny", denies[0].rule_id)
        if not allows:
            return PolicyDecision(False, "default_deny")

        highest_specificity = allows[0].specificity
        best = [rule for rule in allows if rule.specificity == highest_specificity]
        if len(best) != 1:
            return PolicyDecision(False, "ambiguous_rules", best[0].rule_id)
        return PolicyDecision(True, "explicit_allow", best[0].rule_id)

    @staticmethod
    def _ordered(rules: Sequence[PolicyRule] | object) -> list[PolicyRule]:
        return sorted(rules, key=lambda rule: (-rule.specificity, rule.rule_id))

    @staticmethod
    def _valid_request(request: object) -> bool:
        return (
            isinstance(request, PolicyRequest)
            and _valid_identifier(request.server_id)
            and _valid_identifier(request.tool_id)
            and _valid_constraints(request.constraints)
        )
