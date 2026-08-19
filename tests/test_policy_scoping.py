"""Constraints that describe a scope rather than a single exact value.

The policy layer had constraint types for filesystem, network, command and
resource, and compared them with `==`. So a rule scoped to `/tmp/work` governed
only a request naming that exact string: writing `/tmp/work/report.txt` matched
no rule and fell through to default_deny. "Allow writes under this directory" -
the ordinary shape of a least-privilege rule - could not be written at all.

The types looked like a scoping system and behaved like an exact-match key.

Containment is written over path components, not string prefixes. `/tmp/work`
is a prefix of `/tmp/work-evil`, and a rule meant for one directory that quietly
covers a sibling is worse than no rule - it reads as least privilege in a review
and grants more than it says.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.policy import (
    CommandConstraint,
    DeterministicPolicy,
    FilesystemConstraint,
    NetworkConstraint,
    PolicyRequest,
    PolicyRule,
)

REGISTRY = {"fs": ["read_file", "write_file"], "net": ["fetch"]}


def policy(*rules):
    return DeterministicPolicy(REGISTRY, list(rules))


def allow_under(path, operation="write", tool="write_file", rule_id="r1"):
    return PolicyRule(rule_id=rule_id, effect="allow", server_id="fs", tool_id=tool,
                      constraints=(FilesystemConstraint(operation, path),))


def asks(path, operation="write", tool="write_file"):
    return PolicyRequest(server_id="fs", tool_id=tool,
                         constraints=(FilesystemConstraint(operation, path),))


class TestADirectoryGrantCoversWhatIsUnderIt:
    def test_the_directory_itself(self):
        assert policy(allow_under("/tmp/work")).evaluate(asks("/tmp/work")).allowed

    def test_a_file_directly_inside(self):
        assert policy(allow_under("/tmp/work")).evaluate(asks("/tmp/work/report.txt")).allowed

    def test_a_file_several_levels_down(self):
        decision = policy(allow_under("/tmp/work")).evaluate(asks("/tmp/work/a/b/c.txt"))
        assert decision.allowed

    def test_an_unrelated_path_is_still_denied(self):
        decision = policy(allow_under("/tmp/work")).evaluate(asks("/etc/passwd"))
        assert not decision.allowed
        assert decision.reason_code == "default_deny"


class TestTheSiblingDirectoryTrap:
    """`/tmp/work` is a string prefix of `/tmp/work-evil`."""

    @pytest.mark.parametrize("path", [
        "/tmp/work-evil/steal.txt",
        "/tmp/workshop/notes.txt",
        "/tmp/work2",
    ])
    def test_a_prefix_sibling_is_not_covered(self, path):
        assert not policy(allow_under("/tmp/work")).evaluate(asks(path)).allowed

    def test_a_deeper_prefix_sibling_is_not_covered(self):
        decision = policy(allow_under("/srv/data")).evaluate(asks("/srv/database/dump.sql"))
        assert not decision.allowed


class TestTraversalIsRefusedRatherThanResolved:
    """Resolving `..` here would disagree with whatever the server does later.

    Two components that normalise a path differently are two components that
    can disagree about what was approved, so the request is refused instead.
    """

    @pytest.mark.parametrize("path", [
        "/tmp/work/../../etc/passwd",
        "/tmp/work/../work-evil/x",
        "/tmp/work/subdir/../../../root/.ssh/id_rsa",
    ])
    def test_a_path_containing_dotdot_is_refused(self, path):
        assert not policy(allow_under("/tmp/work")).evaluate(asks(path)).allowed


class TestTheOperationIsPartOfTheGrant:
    def test_a_write_grant_does_not_confer_read(self):
        decision = policy(allow_under("/tmp/work", "write")).evaluate(
            asks("/tmp/work/a.txt", "read"))
        assert not decision.allowed

    def test_a_read_grant_does_not_confer_write(self):
        decision = policy(allow_under("/tmp/work", "read", tool="read_file")).evaluate(
            asks("/tmp/work/a.txt", "write", tool="read_file"))
        assert not decision.allowed


class TestNonHierarchicalConstraintsStayExact:
    """Only paths are a hierarchy. Treating a host as one would let whoever
    controls a subdomain inherit a grant made for the parent."""

    def test_a_host_grant_does_not_cover_a_subdomain(self):
        rule = PolicyRule(rule_id="n1", effect="allow", server_id="net", tool_id="fetch",
                          constraints=(NetworkConstraint("https", "example.com", 443),))
        request = PolicyRequest(server_id="net", tool_id="fetch",
                                constraints=(NetworkConstraint("https", "api.example.com", 443),))
        assert not policy(rule).evaluate(request).allowed

    def test_a_host_grant_does_not_cover_another_port(self):
        rule = PolicyRule(rule_id="n1", effect="allow", server_id="net", tool_id="fetch",
                          constraints=(NetworkConstraint("https", "example.com", 443),))
        request = PolicyRequest(server_id="net", tool_id="fetch",
                                constraints=(NetworkConstraint("https", "example.com", 8443),))
        assert not policy(rule).evaluate(request).allowed

    def test_an_exact_host_still_matches(self):
        constraint = NetworkConstraint("https", "example.com", 443)
        rule = PolicyRule(rule_id="n1", effect="allow", server_id="net", tool_id="fetch",
                          constraints=(constraint,))
        request = PolicyRequest(server_id="net", tool_id="fetch", constraints=(constraint,))
        assert policy(rule).evaluate(request).allowed

    def test_a_command_grant_is_exact(self):
        rule = PolicyRule(rule_id="c1", effect="allow", server_id="fs", tool_id="write_file",
                          constraints=(CommandConstraint("git"),))
        request = PolicyRequest(server_id="fs", tool_id="write_file",
                                constraints=(CommandConstraint("gitk"),))
        assert not policy(rule).evaluate(request).allowed


class TestDenyRulesScopeTheSameWay:
    def test_a_deny_covers_everything_under_its_path(self):
        decision = policy(
            allow_under("/tmp"),
            PolicyRule(rule_id="d1", effect="deny", server_id="fs", tool_id="write_file",
                       constraints=(FilesystemConstraint("write", "/tmp/secrets"),)),
        ).evaluate(asks("/tmp/secrets/key.pem"))
        assert not decision.allowed

    def test_a_deny_does_not_reach_a_sibling(self):
        decision = policy(
            allow_under("/tmp"),
            PolicyRule(rule_id="d1", effect="deny", server_id="fs", tool_id="write_file",
                       constraints=(FilesystemConstraint("write", "/tmp/secrets"),)),
        ).evaluate(asks("/tmp/secretsafe/note.txt"))
        assert decision.allowed


class TestUnconstrainedRulesAreUnchanged:
    """Plain tool-level allow/deny must keep working; most rules have no scope."""

    def test_a_rule_without_constraints_allows_an_unconstrained_request(self):
        rule = PolicyRule(rule_id="t1", effect="allow", server_id="fs", tool_id="read_file")
        request = PolicyRequest(server_id="fs", tool_id="read_file")
        assert policy(rule).evaluate(request).allowed

    def test_a_rule_without_constraints_does_not_cover_a_constrained_request(self):
        """A rule that says nothing about scope must not silently grant every
        scope; the request asked about a path and the rule did not answer."""
        rule = PolicyRule(rule_id="t1", effect="allow", server_id="fs", tool_id="write_file")
        assert not policy(rule).evaluate(asks("/tmp/work/a.txt")).allowed

    def test_a_constrained_rule_does_not_cover_an_unconstrained_request(self):
        request = PolicyRequest(server_id="fs", tool_id="write_file")
        assert not policy(allow_under("/tmp/work")).evaluate(request).allowed
