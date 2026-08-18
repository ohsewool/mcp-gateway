"""Audit persistence: the record has to survive the process that made it."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.audit import AuditLog, verify_audit_log  # noqa: E402
from mcp_gateway.policy import DeterministicPolicy, PolicyRule  # noqa: E402
from mcp_gateway.registry import RegisteredServer  # noqa: E402
from mcp_gateway.transport import GatewayInterceptor  # noqa: E402

SERVER_ID = "fs-server"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        self.now += 1
        return self.now


@pytest.fixture
def log(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl", session_id="s1", clock=Clock())


def decision(action="forwarded", reason="explicit_allow", request_id=1):
    return {"direction": "request", "method": "tools/call", "request_id": request_id,
            "action": action, "reason_code": reason, "rule_id": "allow-read",
            "detail": {"tool": "read_file"}}


def interceptor():
    policy = DeterministicPolicy(
        {SERVER_ID: ["read_file", "delete_file"]},
        [PolicyRule("allow-read", "allow", SERVER_ID, "read_file"),
         PolicyRule("deny-delete", "deny", SERVER_ID, "delete_file")],
    )
    server = RegisteredServer(identifier=SERVER_ID, metadata={"kind": "fs"})
    return GatewayInterceptor(policy, SERVER_ID, baseline_servers=[server])


class TestWriting:
    def test_a_record_is_written_and_readable(self, log):
        log.record(decision(), server_id=SERVER_ID)
        stored = log.read()
        assert len(stored) == 1
        assert stored[0]["reason_code"] == "explicit_allow"
        assert stored[0]["server_id"] == SERVER_ID
        assert stored[0]["session_id"] == "s1"

    def test_records_are_numbered_in_order(self, log):
        for index in range(3):
            log.record(decision(request_id=index), server_id=SERVER_ID)
        assert [item["sequence"] for item in log.read()] == [1, 2, 3]

    def test_the_first_record_starts_from_genesis(self, log):
        log.record(decision(), server_id=SERVER_ID)
        assert log.read()[0]["integrity"]["previous_hash"] == "0" * 64

    def test_each_record_links_to_the_last(self, log):
        log.record(decision(request_id=1), server_id=SERVER_ID)
        log.record(decision(request_id=2), server_id=SERVER_ID)
        first, second = log.read()
        assert second["integrity"]["previous_hash"] == first["integrity"]["record_hash"]

    def test_interception_records_are_accepted_directly(self, tmp_path):
        """The gateway's own decision objects, not just dictionaries."""
        gateway = interceptor()
        gateway.inspect_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": "delete_file", "arguments": {}}})
        log = AuditLog(tmp_path / "audit.jsonl", clock=Clock())
        written = log.record_all(gateway.records, server_id=SERVER_ID)
        assert written == 1
        assert log.read()[0]["action"] == "blocked"


class TestDurability:
    def test_a_reopened_log_continues_the_chain(self, tmp_path):
        """A restart must extend the history, not start a second chain inside it."""
        first = AuditLog(tmp_path / "audit.jsonl", clock=Clock())
        first.record(decision(request_id=1), server_id=SERVER_ID)
        tip = first.tip_hash

        second = AuditLog(tmp_path / "audit.jsonl", clock=Clock())
        assert second.tip_hash == tip
        second.record(decision(request_id=2), server_id=SERVER_ID)

        assert verify_audit_log(tmp_path / "audit.jsonl").ok
        assert [item["sequence"] for item in second.read()] == [1, 2]

    def test_each_record_is_flushed_as_it_is_written(self, tmp_path):
        """A crash may lose the call in flight; it must not lose the history."""
        log = AuditLog(tmp_path / "audit.jsonl", clock=Clock())
        log.record(decision(), server_id=SERVER_ID)
        # Read from disk through a separate handle, without closing the log.
        contents = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        assert contents.strip()


class TestVerification:
    def test_an_untouched_log_verifies(self, log):
        for index in range(4):
            log.record(decision(request_id=index), server_id=SERVER_ID)
        report = verify_audit_log(log.path)
        assert report.ok
        assert report.records == 4

    def test_an_edited_record_is_reported_with_its_line(self, log):
        """Rewriting a refusal into a pass is exactly what an audit log must catch."""
        log.record(decision(request_id=0), server_id=SERVER_ID)
        log.record(decision(action="blocked", reason="explicit_deny", request_id=1),
                   server_id=SERVER_ID)
        log.record(decision(request_id=2), server_id=SERVER_ID)

        lines = log.path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[1])
        assert record["action"] == "blocked"
        record["action"] = "forwarded"
        record["reason_code"] = "explicit_allow"
        lines[1] = json.dumps(record, ensure_ascii=False, sort_keys=True)
        log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = verify_audit_log(log.path)
        assert not report.ok
        assert any(violation.line == 2 for violation in report.violations)

    def test_a_deleted_record_breaks_the_chain(self, log):
        for index in range(3):
            log.record(decision(request_id=index), server_id=SERVER_ID)
        lines = log.path.read_text(encoding="utf-8").splitlines()
        log.path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
        report = verify_audit_log(log.path)
        assert not report.ok
        assert any("chain is broken" in violation.reason for violation in report.violations)

    def test_reordering_is_detected(self, log):
        for index in range(3):
            log.record(decision(request_id=index), server_id=SERVER_ID)
        lines = log.path.read_text(encoding="utf-8").splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert not verify_audit_log(log.path).ok

    def test_a_missing_log_is_reported_rather_than_passing(self, tmp_path):
        """An absent log must not read as a clean one."""
        report = verify_audit_log(tmp_path / "nothing.jsonl")
        assert not report.ok

    def test_truncation_at_the_end_still_verifies(self, log):
        """The honest limit: a file cannot testify about what was removed after it."""
        for index in range(4):
            log.record(decision(request_id=index), server_id=SERVER_ID)
        lines = log.path.read_text(encoding="utf-8").splitlines()
        log.path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        assert verify_audit_log(log.path).ok  # documents the gap an anchor must close


class TestGatewayFlow:
    def test_allowed_and_blocked_calls_both_land_in_the_log(self, tmp_path):
        gateway = interceptor()
        gateway.inspect_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": "read_file", "arguments": {}}})
        gateway.inspect_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                 "params": {"name": "delete_file", "arguments": {}}})
        log = AuditLog(tmp_path / "audit.jsonl", clock=Clock())
        log.record_all(gateway.records, server_id=SERVER_ID)

        actions = [item["action"] for item in log.read()]
        assert actions == ["forwarded", "blocked"]
        assert verify_audit_log(log.path).ok

    def test_the_refusal_reason_survives_to_the_log(self, tmp_path):
        gateway = interceptor()
        gateway.inspect_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": "delete_file", "arguments": {}}})
        log = AuditLog(tmp_path / "audit.jsonl", clock=Clock())
        log.record_all(gateway.records, server_id=SERVER_ID)
        assert log.read()[0]["reason_code"] == "explicit_deny"
