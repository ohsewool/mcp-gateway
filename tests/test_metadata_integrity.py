"""Synthetic unit tests for deterministic metadata-integrity validation."""

import unittest

from mcp_gateway.metadata_integrity import MetadataIntegrityError, MetadataSnapshot, compare_metadata
from mcp_gateway.registry import (
    RegisteredServer,
    RegisteredTool,
    RegistryValidationError,
    ServerToolRegistry,
)


def registry(label="Demo", description="Read", schema=None):
    value = ServerToolRegistry()
    value.register_server(RegisteredServer("demo_server", {"label": label}))
    value.register_tool(RegisteredTool(
        "demo_server", "read_item",
        schema or {"type": "object", "properties": {"item": {"type": "string"}}},
        {"description": description},
    ))
    return value


class MetadataIntegrityTests(unittest.TestCase):
    def test_unchanged_snapshot_has_no_classifications(self):
        baseline = MetadataSnapshot.from_registry(registry())
        self.assertEqual(compare_metadata(baseline, MetadataSnapshot.from_registry(registry())), ())

    def test_metadata_and_schema_changes_have_explicit_reasons(self):
        baseline = MetadataSnapshot.from_registry(registry())
        changed = MetadataSnapshot.from_registry(registry(
            label="Changed", description="Changed",
            schema={"type": "object", "properties": {"other": {"type": "integer"}}},
        ))
        self.assertEqual(
            [(item.subject, item.classification, item.reason) for item in compare_metadata(baseline, changed)],
            [("server", "changed", "server_metadata_changed"),
             ("tool", "changed", "tool_schema_and_metadata_changed")],
        )

    def test_missing_and_added_tools_are_classified(self):
        baseline = MetadataSnapshot.from_registry(registry())
        current = MetadataSnapshot.from_registered([RegisteredServer("demo_server", {"label": "Demo"})], [])
        self.assertEqual(compare_metadata(baseline, current)[0].reason, "tool_removed")
        self.assertEqual(compare_metadata(current, baseline)[0].reason, "tool_added")

    def test_conflicting_snapshot_entries_are_rejected(self):
        server = RegisteredServer("demo_server", {"label": "Demo"})
        with self.assertRaises(MetadataIntegrityError):
            MetadataSnapshot.from_registered([server, server], [])

    def test_invalid_registered_metadata_is_rejected_before_snapshot(self):
        with self.assertRaises(RegistryValidationError):
            RegisteredTool("demo_server", "read_item", {"type": "array"}, {})

    def test_repeated_comparisons_are_identical(self):
        baseline = MetadataSnapshot.from_registry(registry())
        current = MetadataSnapshot.from_registry(registry(description="Changed"))
        self.assertEqual(compare_metadata(baseline, current), compare_metadata(baseline, current))


if __name__ == "__main__":
    unittest.main()
