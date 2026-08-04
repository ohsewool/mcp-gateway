"""A small, deterministic, deny-by-default MCP server and tool registry."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping


_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


class RegistryError(Exception):
    """Base exception for registry failures."""


class RegistryValidationError(RegistryError, ValueError):
    """Raised when a server, tool, or schema is malformed."""


class RegistryConflictError(RegistryError):
    """Raised for duplicate identifiers or incompatible registrations."""


class RegistryLookupError(RegistryError, LookupError):
    """Raised when deny-by-default lookup cannot find a registration."""


def _validate_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise RegistryValidationError(
            f"{field_name} must start with a letter and contain only letters, "
            "digits, underscores, or hyphens (maximum 64 characters)"
        )


def _canonical_json(value: Any) -> str:
    """Return a stable JSON representation, rejecting non-JSON values."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise RegistryValidationError("metadata must contain only finite JSON values") from error


def _copy_json_object(value: Mapping[str, Any], field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RegistryValidationError(f"{field_name} must be a JSON object")
    try:
        copied = json.loads(_canonical_json(dict(value)))
    except (TypeError, json.JSONDecodeError) as error:  # defensive for mappings
        raise RegistryValidationError(f"{field_name} must be a JSON object") from error
    if not isinstance(copied, dict):
        raise RegistryValidationError(f"{field_name} must be a JSON object")
    return copied


def _freeze_json(value: Any) -> Any:
    """Convert copied JSON data into recursively immutable standard-library values."""
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _validate_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    copied = _copy_json_object(schema, "input_schema")
    if copied.get("type") != "object":
        raise RegistryValidationError("input_schema must declare type 'object'")
    properties = copied.get("properties", {})
    if not isinstance(properties, dict):
        raise RegistryValidationError("input_schema properties must be an object")
    required = copied.get("required", [])
    if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
        raise RegistryValidationError("input_schema required must be a list of strings")
    if len(required) != len(set(required)):
        raise RegistryValidationError("input_schema required must not contain duplicates")
    if any(item not in properties for item in required):
        raise RegistryValidationError("input_schema required entries must name properties")
    return copied


def _integrity_id(kind: str, payload: Mapping[str, Any]) -> str:
    encoded = _canonical_json({"kind": kind, **payload}).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class RegisteredServer:
    """Immutable description of one allowed synthetic MCP server."""

    identifier: str
    metadata: Mapping[str, Any]
    integrity_id: str = ""

    def __post_init__(self) -> None:
        _validate_identifier(self.identifier, "server identifier")
        metadata = _copy_json_object(self.metadata, "metadata")
        calculated = _integrity_id("server", {"identifier": self.identifier, "metadata": metadata})
        if self.integrity_id and self.integrity_id != calculated:
            raise RegistryValidationError("server integrity_id does not match its content")
        object.__setattr__(self, "metadata", _freeze_json(metadata))
        object.__setattr__(self, "integrity_id", calculated)


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    """Immutable description of one allowed tool exposed by a server."""

    server_identifier: str
    identifier: str
    input_schema: Mapping[str, Any]
    metadata: Mapping[str, Any]
    integrity_id: str = ""

    def __post_init__(self) -> None:
        _validate_identifier(self.server_identifier, "server identifier")
        _validate_identifier(self.identifier, "tool identifier")
        schema = _validate_schema(self.input_schema)
        metadata = _copy_json_object(self.metadata, "metadata")
        calculated = _integrity_id(
            "tool",
            {
                "server_identifier": self.server_identifier,
                "identifier": self.identifier,
                "input_schema": schema,
                "metadata": metadata,
            },
        )
        if self.integrity_id and self.integrity_id != calculated:
            raise RegistryValidationError("tool integrity_id does not match its content")
        object.__setattr__(self, "input_schema", _freeze_json(schema))
        object.__setattr__(self, "metadata", _freeze_json(metadata))
        object.__setattr__(self, "integrity_id", calculated)


class ServerToolRegistry:
    """Controlled registration with deny-by-default server and tool lookup."""

    def __init__(self) -> None:
        self._servers: dict[str, RegisteredServer] = {}
        self._tools: dict[tuple[str, str], RegisteredTool] = {}

    def register_server(self, server: RegisteredServer) -> None:
        if not isinstance(server, RegisteredServer):
            raise RegistryValidationError("server must be a RegisteredServer")
        if server.identifier in self._servers:
            raise RegistryConflictError(f"server '{server.identifier}' is already registered")
        self._servers[server.identifier] = server

    def register_tool(self, tool: RegisteredTool) -> None:
        if not isinstance(tool, RegisteredTool):
            raise RegistryValidationError("tool must be a RegisteredTool")
        if tool.server_identifier not in self._servers:
            raise RegistryError(f"server '{tool.server_identifier}' is not registered")
        key = (tool.server_identifier, tool.identifier)
        if key in self._tools:
            raise RegistryConflictError(
                f"tool '{tool.identifier}' is already registered for server "
                f"'{tool.server_identifier}'"
            )
        self._tools[key] = tool

    def get_server(self, identifier: str) -> RegisteredServer:
        _validate_identifier(identifier, "server identifier")
        try:
            return self._servers[identifier]
        except KeyError as error:
            raise RegistryLookupError(f"server '{identifier}' is not registered") from error

    def get_tool(self, server_identifier: str, identifier: str) -> RegisteredTool:
        _validate_identifier(server_identifier, "server identifier")
        _validate_identifier(identifier, "tool identifier")
        try:
            return self._tools[(server_identifier, identifier)]
        except KeyError as error:
            raise RegistryLookupError(
                f"tool '{identifier}' is not registered for server '{server_identifier}'"
            ) from error

    def registered_servers(self) -> tuple[RegisteredServer, ...]:
        """Return registered servers in deterministic identifier order."""
        return tuple(self._servers[identifier] for identifier in sorted(self._servers))

    def registered_tools(self) -> tuple[RegisteredTool, ...]:
        """Return registered tools in deterministic server/tool order."""
        return tuple(self._tools[key] for key in sorted(self._tools))
