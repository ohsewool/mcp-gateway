"""Deterministic tests for the bounded MCP registry."""

import unittest

from mcp_gateway.registry import (
    RegisteredServer,
    RegisteredTool,
    RegistryConflictError,
    RegistryError,
    RegistryLookupError,
    RegistryValidationError,
    ServerToolRegistry,
)


def server(metadata=None):
    return RegisteredServer("demo_server", metadata or {"label": "Demo"})


def tool(metadata=None, schema=None):
    return RegisteredTool(
        "demo_server",
        "read_item",
        schema or {"type": "object", "properties": {"item_id": {"type": "string"}}, "required": ["item_id"]},
        metadata or {"description": "Read a synthetic item"},
    )


class RegistryTests(unittest.TestCase):
    def test_integrity_identifier_is_stable_for_equivalent_mapping_order(self):
        first = RegisteredServer("demo_server", {"label": "Demo", "version": 1})
        second = RegisteredServer("demo_server", {"version": 1, "label": "Demo"})
        self.assertEqual(first.integrity_id, second.integrity_id)

    def test_changed_metadata_changes_integrity_identifier(self):
        self.assertNotEqual(server({"label": "Demo"}).integrity_id, server({"label": "Changed"}).integrity_id)

    def test_register_and_lookup_server_and_tool(self):
        registry = ServerToolRegistry()
        registered_server = server()
        registered_tool = tool()
        registry.register_server(registered_server)
        registry.register_tool(registered_tool)
        self.assertIs(registry.get_server("demo_server"), registered_server)
        self.assertIs(registry.get_tool("demo_server", "read_item"), registered_tool)

    def test_duplicate_server_and_tool_are_rejected(self):
        registry = ServerToolRegistry()
        registry.register_server(server())
        with self.assertRaises(RegistryConflictError):
            registry.register_server(server())
        registry.register_tool(tool())
        with self.assertRaises(RegistryConflictError):
            registry.register_tool(tool())

    def test_conflicting_registration_is_rejected(self):
        registry = ServerToolRegistry()
        registry.register_server(server())
        registry.register_tool(tool())
        with self.assertRaises(RegistryConflictError):
            registry.register_tool(tool({"description": "Different"}))

    def test_malformed_input_is_rejected(self):
        with self.assertRaises(RegistryValidationError):
            RegisteredServer("bad identifier", {})
        with self.assertRaises(RegistryValidationError):
            RegisteredTool("demo_server", "read_item", {"type": "array"}, {})
        with self.assertRaises(RegistryValidationError):
            RegisteredTool("demo_server", "read_item", {"type": "object", "required": ["missing"]}, {})

    def test_unknown_lookups_are_denied(self):
        registry = ServerToolRegistry()
        with self.assertRaises(RegistryLookupError):
            registry.get_server("unknown")
        registry.register_server(server())
        with self.assertRaises(RegistryLookupError):
            registry.get_tool("demo_server", "unknown")


if __name__ == "__main__":
    unittest.main()
