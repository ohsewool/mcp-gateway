"""Tests for the side-effect-free deterministic policy model."""

import unittest

from mcp_gateway.policy import (
    CommandConstraint,
    DeterministicPolicy,
    FilesystemConstraint,
    NetworkConstraint,
    PolicyRequest,
    PolicyRule,
    ResourceConstraint,
)


REGISTRY = {"synthetic-server": ("read-tool", "write-tool")}


class DeterministicPolicyTests(unittest.TestCase):
    def policy(self, *rules):
        return DeterministicPolicy(REGISTRY, rules)

    def test_explicit_least_privilege_allow(self):
        request = PolicyRequest("synthetic-server", "read-tool")
        rule = PolicyRule("allow-read", "allow", "synthetic-server", "read-tool")
        self.assertEqual(self.policy(rule).evaluate(request).reason_code, "explicit_allow")

    def test_unmatched_request_is_denied_by_default(self):
        request = PolicyRequest("synthetic-server", "write-tool")
        decision = self.policy(
            PolicyRule("allow-read", "allow", "synthetic-server", "read-tool")
        ).evaluate(request)
        self.assertEqual((decision.allowed, decision.reason_code), (False, "default_deny"))

    def test_malformed_requests_are_denied(self):
        request = PolicyRequest(" synthetic-server", "read-tool")
        self.assertEqual(self.policy().evaluate(request).reason_code, "malformed_request")
        malformed_constraint = PolicyRequest("synthetic-server", "read-tool", ([],))
        self.assertEqual(self.policy().evaluate(malformed_constraint).reason_code, "malformed_request")

    def test_unknown_server_and_tool_are_denied(self):
        policy = self.policy()
        self.assertEqual(
            policy.evaluate(PolicyRequest("missing-server", "read-tool")).reason_code,
            "unknown_server",
        )
        self.assertEqual(
            policy.evaluate(PolicyRequest("synthetic-server", "missing-tool")).reason_code,
            "unknown_tool",
        )

    def test_conflicting_rules_are_denied(self):
        request = PolicyRequest("synthetic-server", "read-tool")
        decision = self.policy(
            PolicyRule("allow", "allow", "synthetic-server", "read-tool"),
            PolicyRule("deny", "deny", "synthetic-server", "read-tool"),
        ).evaluate(request)
        self.assertEqual((decision.allowed, decision.reason_code), (False, "conflicting_rules"))

    def test_rule_order_is_deterministic(self):
        request = PolicyRequest("synthetic-server", "read-tool")
        decision = self.policy(
            PolicyRule("z-rule", "deny", "synthetic-server", "read-tool"),
            PolicyRule("a-rule", "deny", "synthetic-server", "read-tool"),
        ).evaluate(request)
        self.assertEqual((decision.reason_code, decision.rule_id), ("explicit_deny", "a-rule"))

    def test_decision_reason_is_stable(self):
        request = PolicyRequest("synthetic-server", "write-tool")
        policy = self.policy()
        self.assertEqual(policy.evaluate(request), policy.evaluate(request))

    def test_multiple_equivalent_allows_are_ambiguous(self):
        request = PolicyRequest("synthetic-server", "read-tool")
        decision = self.policy(
            PolicyRule("first", "allow", "synthetic-server", "read-tool"),
            PolicyRule("second", "allow", "synthetic-server", "read-tool"),
        ).evaluate(request)
        self.assertEqual(decision.reason_code, "ambiguous_rules")

    def test_synthetic_constraint_scope_is_exact(self):
        constraints = (
            FilesystemConstraint("read", "/synthetic/reports"),
            NetworkConstraint("https", "api.synthetic", 443),
            CommandConstraint("synthetic-report"),
            ResourceConstraint("report-42"),
        )
        rule = PolicyRule(
            "scoped-read", "allow", "synthetic-server", "read-tool", constraints
        )
        allowed = self.policy(rule).evaluate(
            PolicyRequest("synthetic-server", "read-tool", constraints)
        )
        changed_path = constraints[:-1] + (ResourceConstraint("report-43"),)
        denied = self.policy(rule).evaluate(
            PolicyRequest("synthetic-server", "read-tool", changed_path)
        )
        self.assertEqual(allowed.reason_code, "explicit_allow")
        self.assertEqual(denied.reason_code, "default_deny")

    def test_invalid_synthetic_constraints_are_malformed(self):
        request = PolicyRequest(
            "synthetic-server", "read-tool", (NetworkConstraint("ftp", "api.synthetic", 21),)
        )
        self.assertEqual(self.policy().evaluate(request).reason_code, "malformed_request")


if __name__ == "__main__":
    unittest.main()
