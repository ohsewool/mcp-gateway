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


CORE = Path("/home/jovyan/work/agent-safety-core")
if CORE.exists():
    sys.path.insert(0, str(CORE))

checkpoint_module = pytest.importorskip(
    "core.checkpoint", reason="agent-safety-core is unavailable"
)


class TestExternalAnchoring:
    """Truncation is undetectable inside a file; an anchor is what closes that."""

    @pytest.fixture
    def anchored(self, tmp_path):
        from mcp_gateway.audit import anchor

        log = AuditLog(tmp_path / "audit.jsonl", clock=Clock())
        for index in range(4):
            log.record(decision(request_id=index), server_id=SERVER_ID)

        signer = checkpoint_module.Signer.generate()
        witness = checkpoint_module.Witness(tmp_path / "witness.jsonl")
        checkpoint = anchor(log, signer=signer, witness=witness,
                            log_id="gateway-1", sequence=1, now=1000.0)
        return {"log": log, "signer": signer, "witness": witness,
                "checkpoint": checkpoint, "tmp": tmp_path}

    def test_an_anchored_log_verifies(self, anchored):
        from mcp_gateway.audit import verify_against_anchor

        ok, notes = verify_against_anchor(
            anchored["log"].path, anchored["checkpoint"],
            public_key_pem=anchored["signer"].public_key_pem(),
            witness=anchored["witness"],
        )
        assert ok, notes

    def test_truncation_after_the_anchor_is_now_detected(self, anchored):
        """The gap the standalone verifier documented, closed."""
        from mcp_gateway.audit import verify_against_anchor

        path = anchored["log"].path
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

        # The file alone still looks fine.
        assert verify_audit_log(path).ok

        ok, notes = verify_against_anchor(
            path, anchored["checkpoint"],
            public_key_pem=anchored["signer"].public_key_pem(),
            witness=anchored["witness"],
        )
        assert not ok
        assert any("does not end where the checkpoint" in note for note in notes)

    def test_an_old_anchor_cannot_be_presented_as_current(self, anchored):
        """Rollback: an authentic checkpoint from an earlier state."""
        from mcp_gateway.audit import anchor, verify_against_anchor

        stale = anchored["checkpoint"]
        anchored["log"].record(decision(request_id=99), server_id=SERVER_ID)
        anchor(anchored["log"], signer=anchored["signer"], witness=anchored["witness"],
               log_id="gateway-1", sequence=2, previous=stale, now=2000.0)

        ok, notes = verify_against_anchor(
            anchored["log"].path, stale,
            public_key_pem=anchored["signer"].public_key_pem(),
            witness=anchored["witness"],
        )
        assert not ok
        assert any("rollback" in note for note in notes)

    def test_an_unpublished_anchor_is_rejected(self, anchored):
        from mcp_gateway.audit import verify_against_anchor

        unpublished = anchored["signer"].sign(
            checkpoint_module.Checkpoint(
                log_id="gateway-1", sequence=9,
                journal_tip_hash=anchored["log"].tip_hash,
                previous_checkpoint_hash="0" * 64, signed_at=3000.0,
            )
        )
        ok, notes = verify_against_anchor(
            anchored["log"].path, unpublished,
            public_key_pem=anchored["signer"].public_key_pem(),
            witness=anchored["witness"],
        )
        assert not ok
        assert any("fork" in note for note in notes)

    def test_each_failing_dimension_is_named_separately(self, anchored):
        """'someone edited line 3' and 'this is an old copy' need different responses."""
        from mcp_gateway.audit import verify_against_anchor

        path = anchored["log"].path
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["action"] = "tampered"
        lines[0] = json.dumps(record, ensure_ascii=False, sort_keys=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, notes = verify_against_anchor(
            path, anchored["checkpoint"],
            public_key_pem=anchored["signer"].public_key_pem(),
            witness=anchored["witness"],
        )
        assert not ok
        assert any("chain is broken" in note for note in notes)

    def test_a_forged_signature_is_caught(self, anchored):
        from mcp_gateway.audit import verify_against_anchor

        ok, notes = verify_against_anchor(
            anchored["log"].path, anchored["checkpoint"],
            public_key_pem=checkpoint_module.Signer.generate().public_key_pem(),
            witness=anchored["witness"],
        )
        assert not ok
        assert any("signature" in note for note in notes)


class TestTheGatewayActuallyWritesToIt:
    """The log existed, was tested, and nothing wrote to it.

    The README has claimed persistent auditing as finished - "a decision that
    only lives in memory is no use; the person asking days later was not in the
    room" - while GatewayInterceptor._log appended to a list and AuditLog was
    imported by nothing outside this file. Both halves were built. They were
    never introduced.
    """

    def interceptor(self, log=None):
        from mcp_gateway.policy import DeterministicPolicy, PolicyRule
        from mcp_gateway.registry import RegisteredServer
        from mcp_gateway.transport import GatewayInterceptor

        policy = DeterministicPolicy(
            {"fs": ["read_file", "write_file"]},
            [PolicyRule("allow-read", "allow", "fs", "read_file")],
        )
        return GatewayInterceptor(
            policy, "fs",
            baseline_servers=[RegisteredServer(identifier="fs", metadata={})],
            audit_log=log,
        )

    def call(self, interceptor, tool):
        return interceptor.inspect_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": {}},
        })

    def test_a_decision_reaches_the_file(self, tmp_path):
        from mcp_gateway.audit import AuditLog

        path = tmp_path / "audit.jsonl"
        interceptor = self.interceptor(AuditLog(path, session_id="s1"))
        self.call(interceptor, "read_file")
        assert path.exists() and path.read_text(encoding="utf-8").strip()

    def test_both_allowed_and_denied_decisions_are_written(self, tmp_path):
        """A log of only the refusals cannot answer "what did it let through"."""
        import json

        from mcp_gateway.audit import AuditLog

        path = tmp_path / "audit.jsonl"
        interceptor = self.interceptor(AuditLog(path, session_id="s1"))
        self.call(interceptor, "read_file")
        self.call(interceptor, "write_file")

        actions = [json.loads(line)["action"]
                   for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert "forwarded" in actions and "blocked" in actions

    def test_the_reason_survives_to_disk(self, tmp_path):
        """"Blocked" without why is a record nobody can act on."""
        import json

        from mcp_gateway.audit import AuditLog

        path = tmp_path / "audit.jsonl"
        interceptor = self.interceptor(AuditLog(path, session_id="s1"))
        self.call(interceptor, "not_registered")

        last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
        assert last["reason_code"] == "unknown_tool"

    def test_the_written_chain_verifies(self, tmp_path):
        from mcp_gateway.audit import AuditLog, verify_audit_log

        path = tmp_path / "audit.jsonl"
        interceptor = self.interceptor(AuditLog(path, session_id="s1"))
        for tool in ("read_file", "write_file", "not_registered"):
            self.call(interceptor, tool)
        assert verify_audit_log(path).ok

    def test_the_memory_record_still_matches_the_file(self, tmp_path):
        """Two records of one decision must not disagree about how many."""
        from mcp_gateway.audit import AuditLog

        path = tmp_path / "audit.jsonl"
        interceptor = self.interceptor(AuditLog(path, session_id="s1"))
        for tool in ("read_file", "write_file"):
            self.call(interceptor, tool)

        written = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert len(written) == len(interceptor.records)

    def test_without_a_log_nothing_breaks(self, tmp_path):
        """Optional: unit tests and callers keeping their own record use none."""
        interceptor = self.interceptor(None)
        self.call(interceptor, "read_file")
        assert len(interceptor.records) == 1

    def test_a_failing_log_does_not_stop_the_gateway_deciding(self, tmp_path):
        """A full disk is a logging problem; refusing to decide would make it an
        availability one. The gap is surfaced rather than raised."""
        class Broken:
            def record(self, *args, **kwargs):
                raise OSError("no space left on device")

        interceptor = self.interceptor(Broken())
        interception = self.call(interceptor, "read_file")
        assert interception is not None
        assert interceptor.audit_failures

    def test_a_silent_gap_is_not_left_silent(self, tmp_path):
        """An absent record reads as "nothing happened", so the count is
        reachable."""
        class Broken:
            def record(self, *args, **kwargs):
                raise OSError("disk error")

        interceptor = self.interceptor(Broken())
        for tool in ("read_file", "write_file"):
            self.call(interceptor, tool)
        assert len(interceptor.audit_failures) == 2
