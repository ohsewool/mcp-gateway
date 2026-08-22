"""Deterministic metadata and schema integrity snapshots for registered MCP tools."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from typing import Iterable

from .registry import (
    RegisteredServer,
    RegisteredTool,
    RegistryConflictError,
    RegistryValidationError,
    ServerToolRegistry,
)


class MetadataIntegrityError(ValueError):
    """Raised when an integrity snapshot cannot be constructed or compared."""


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            _json_value(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:  # pragma: no cover - registry refuses first
        # Unreachable while the registry validates: `RegisteredServer` and
        # `RegisteredTool` refuse non-finite metadata at construction, so nothing
        # that reaches here can fail. Measured on 2026-08-22 by deleting this
        # raise - 320 tests stayed green - and then by trying to build a snapshot
        # from NaN metadata, which the registry refuses first.
        #
        # Kept rather than deleted: a caller that builds a snapshot from records
        # made some other way would need it. `tests/test_rejections_that_were_
        # never_fired.py` pins the outer check instead, so if the registry ever
        # stops validating, that test fails and this branch becomes live.
        raise MetadataIntegrityError(
            "snapshot content must be finite JSON data") from error


def _json_value(value: object) -> object:
    """Convert the registry's immutable JSON containers back to JSON values."""
    if isinstance(value, Mapping):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def _integrity_id(kind: str, value: object) -> str:
    return hashlib.sha256(_canonical_json({"kind": kind, "value": value}).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ServerMetadataSnapshot:
    """Immutable integrity record for one registered server."""

    identifier: str
    integrity_id: str
    metadata_integrity_id: str

    @classmethod
    def from_registered(cls, server: RegisteredServer) -> "ServerMetadataSnapshot":
        if not isinstance(server, RegisteredServer):
            raise MetadataIntegrityError("server snapshot requires a RegisteredServer")
        return cls(server.identifier, server.integrity_id, _integrity_id("server_metadata", server.metadata))


@dataclass(frozen=True, slots=True)
class ToolMetadataSnapshot:
    """Immutable integrity record for one registered tool and its input schema."""

    server_identifier: str
    identifier: str
    integrity_id: str
    schema_integrity_id: str
    metadata_integrity_id: str

    @classmethod
    def from_registered(cls, tool: RegisteredTool) -> "ToolMetadataSnapshot":
        if not isinstance(tool, RegisteredTool):
            raise MetadataIntegrityError("tool snapshot requires a RegisteredTool")
        return cls(
            tool.server_identifier,
            tool.identifier,
            tool.integrity_id,
            _integrity_id("tool_schema", tool.input_schema),
            _integrity_id("tool_metadata", tool.metadata),
        )


@dataclass(frozen=True, slots=True)
class MetadataSnapshot:
    """A complete immutable view of registered metadata at one comparison point."""

    servers: tuple[ServerMetadataSnapshot, ...]
    tools: tuple[ToolMetadataSnapshot, ...]

    @classmethod
    def from_registry(cls, registry: ServerToolRegistry) -> "MetadataSnapshot":
        if not isinstance(registry, ServerToolRegistry):
            raise MetadataIntegrityError("snapshot requires a ServerToolRegistry")
        return cls.from_registered(registry.registered_servers(), registry.registered_tools())

    @classmethod
    def from_registered(
        cls,
        servers: Iterable[RegisteredServer],
        tools: Iterable[RegisteredTool],
    ) -> "MetadataSnapshot":
        try:
            server_records = tuple(ServerMetadataSnapshot.from_registered(server) for server in servers)
            tool_records = tuple(ToolMetadataSnapshot.from_registered(tool) for tool in tools)
        except (RegistryValidationError, TypeError) as error:
            raise MetadataIntegrityError("invalid registered metadata") from error
        ordered_servers = tuple(sorted(server_records, key=lambda item: item.identifier))
        ordered_tools = tuple(sorted(tool_records, key=lambda item: (item.server_identifier, item.identifier)))
        if len({item.identifier for item in ordered_servers}) != len(ordered_servers):
            raise MetadataIntegrityError("conflicting server identifiers in snapshot")
        tool_keys = {(item.server_identifier, item.identifier) for item in ordered_tools}
        if len(tool_keys) != len(ordered_tools):
            raise MetadataIntegrityError("conflicting tool identifiers in snapshot")
        server_ids = {item.identifier for item in ordered_servers}
        if any(item.server_identifier not in server_ids for item in ordered_tools):
            raise MetadataIntegrityError("tool snapshot references an unregistered server")
        return cls(ordered_servers, ordered_tools)


@dataclass(frozen=True, slots=True)
class MetadataChange:
    """One deterministic classification of a server or tool integrity difference."""

    subject: str
    server_identifier: str
    tool_identifier: str | None
    classification: str
    reason: str


def compare_metadata(
    baseline: MetadataSnapshot,
    current: MetadataSnapshot,
) -> tuple[MetadataChange, ...]:
    """Classify added, removed, and changed registered metadata deterministically."""
    if not isinstance(baseline, MetadataSnapshot) or not isinstance(current, MetadataSnapshot):
        raise MetadataIntegrityError("comparisons require MetadataSnapshot instances")
    changes: list[MetadataChange] = []
    baseline_servers = {item.identifier: item for item in baseline.servers}
    current_servers = {item.identifier: item for item in current.servers}
    for identifier in sorted(baseline_servers.keys() | current_servers.keys()):
        before, after = baseline_servers.get(identifier), current_servers.get(identifier)
        if before is None:
            changes.append(MetadataChange("server", identifier, None, "added", "server_added"))
        elif after is None:
            changes.append(MetadataChange("server", identifier, None, "removed", "server_removed"))
        elif before.integrity_id != after.integrity_id:
            changes.append(MetadataChange("server", identifier, None, "changed", "server_metadata_changed"))
    baseline_tools = {(item.server_identifier, item.identifier): item for item in baseline.tools}
    current_tools = {(item.server_identifier, item.identifier): item for item in current.tools}
    for server_id, tool_id in sorted(baseline_tools.keys() | current_tools.keys()):
        before, after = baseline_tools.get((server_id, tool_id)), current_tools.get((server_id, tool_id))
        if before is None:
            changes.append(MetadataChange("tool", server_id, tool_id, "added", "tool_added"))
        elif after is None:
            changes.append(MetadataChange("tool", server_id, tool_id, "removed", "tool_removed"))
        elif before.integrity_id != after.integrity_id:
            schema_changed = before.schema_integrity_id != after.schema_integrity_id
            metadata_changed = before.metadata_integrity_id != after.metadata_integrity_id
            reason = (
                "tool_schema_and_metadata_changed" if schema_changed and metadata_changed else
                "tool_schema_changed" if schema_changed else
                "tool_metadata_changed" if metadata_changed else
                "tool_integrity_changed"
            )
            changes.append(MetadataChange("tool", server_id, tool_id, "changed", reason))
    return tuple(changes)
