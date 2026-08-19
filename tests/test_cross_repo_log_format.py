"""The other half of an interoperability claim that was only ever tested once.

Both repositories say their two logs share a format, so one verifier reads
both. It was not true - the integrity field is `record_hash` here and
`event_hash` in agent-safety-core, and each verifier rejected the other's log as
a modified record. Both readers were taught to accept both names.

Only one of them was then tested. agent-safety-core pinned that it reads a
gateway record; nothing here pinned the reverse, and `event_hash` appeared
nowhere in this repository's tests. Deleting the fallback from
`_integrity_hash` passed all 192 tests.

A claim held up by two mechanisms, tested on one side, is the same defect this
project keeps finding in other clothes: a fix applied twice and verified once.

The sibling's records are constructed here by hand rather than imported, so
this suite does not gain a dependency on another repository to test its own
reader. `test_the_canonical_forms_are_the_same` pins the premise that makes
that legitimate - if the two canonical forms ever diverge, a hand-built record
stops representing the sibling and this whole file is testing a fiction.
"""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_gateway.audit import GENESIS_HASH, verify_audit_log

CORE_BODY = {
    "sequence": 1,
    "execution_id": "exec-1",
    "kind": "approved",
    "from_state": "PROPOSED",
    "to_state": "APPROVED",
    "detail": {"approver_id": "human-1"},
    "recorded_at": 1000.0,
}


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def core_style(tmp_path: Path, body=None, *, field: str = "event_hash") -> Path:
    """One record in agent-safety-core's format: `event_hash`, not `record_hash`."""
    body = dict(body or CORE_BODY)
    sealed = dict(body)
    sealed["integrity"] = {
        "previous_hash": GENESIS_HASH,
        field: hashlib.sha256(
            GENESIS_HASH.encode("ascii") + canonical(body).encode("utf-8")
        ).hexdigest(),
    }
    path = tmp_path / "core.jsonl"
    path.write_text(canonical(sealed) + "\n", encoding="utf-8")
    return path


class TestThisVerifierReadsTheSiblingsLog:
    def test_a_core_record_verifies_here(self, tmp_path):
        """The load-bearing case. Without the `event_hash` fallback this fails."""
        assert verify_audit_log(core_style(tmp_path)).ok

    def test_a_multi_record_core_chain_verifies(self, tmp_path):
        """One record exercises the hash; a chain exercises the linking too."""
        path = tmp_path / "chain.jsonl"
        previous = GENESIS_HASH
        lines = []
        for sequence in (1, 2, 3):
            body = {**CORE_BODY, "sequence": sequence, "execution_id": f"exec-{sequence}"}
            digest = hashlib.sha256(
                previous.encode("ascii") + canonical(body).encode("utf-8")
            ).hexdigest()
            lines.append(canonical({**body, "integrity": {"previous_hash": previous,
                                                          "event_hash": digest}}))
            previous = digest
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        assert verify_audit_log(path).ok

    def test_the_tip_hash_is_reported_for_a_core_log(self, tmp_path):
        """Anchoring needs the tip. Returning the genesis hash instead would
        silently anchor nothing."""
        report = verify_audit_log(core_style(tmp_path))
        assert report.tip_hash != GENESIS_HASH
        assert len(report.tip_hash) == 64


class TestAcceptingTheOtherNameAcceptsNothingElse:
    """A fallback that widens what verifies is only safe if it widens exactly
    one thing."""

    def test_tampering_with_a_core_record_is_still_caught(self, tmp_path):
        path = core_style(tmp_path)
        record = json.loads(path.read_text(encoding="utf-8"))
        record["to_state"] = "SUCCEEDED"
        path.write_text(canonical(record) + "\n", encoding="utf-8")

        assert "content_modified" in {v.kind for v in verify_audit_log(path).violations}

    def test_a_record_carrying_neither_name_is_refused(self, tmp_path):
        path = tmp_path / "odd.jsonl"
        path.write_text(canonical({"sequence": 1,
                                   "integrity": {"previous_hash": GENESIS_HASH}}) + "\n",
                        encoding="utf-8")
        assert not verify_audit_log(path).ok

    def test_an_integrity_block_with_a_wrong_name_is_refused(self, tmp_path):
        """`entry_hash` is neither of the two. A reader that shrugged at
        unrecognised names would verify anything."""
        assert not verify_audit_log(core_style(tmp_path, field="entry_hash")).ok

    def test_a_broken_chain_in_a_core_log_is_caught(self, tmp_path):
        path = core_style(tmp_path)
        record = json.loads(path.read_text(encoding="utf-8"))
        record["integrity"]["previous_hash"] = "f" * 64
        path.write_text(canonical(record) + "\n", encoding="utf-8")

        assert "chain_broken" in {v.kind for v in verify_audit_log(path).violations}


class TestThePremiseThatMakesAHandBuiltRecordLegitimate:
    def test_the_canonical_forms_are_the_same(self):
        """Sorted keys, no ASCII escaping, no separator padding - matching
        `core.canonical.dumps`. If these diverge the field name is the least of
        it, and the records built above stop standing in for the sibling's."""
        from mcp_gateway.audit import _canonical

        for value in ({"b": 1, "a": "가"}, {"x": [1, 2], "y": None}, {"n": 1.5}):
            assert _canonical(value) == json.dumps(value, ensure_ascii=False,
                                                   sort_keys=True, separators=(",", ":"))

    def test_the_chaining_rule_is_the_same(self):
        """previous_hash as ASCII, then the canonical body as UTF-8, SHA-256."""
        from mcp_gateway.audit import _record_hash

        body = {"a": 1}
        assert _record_hash(body, GENESIS_HASH) == hashlib.sha256(
            GENESIS_HASH.encode("ascii") + canonical(body).encode("utf-8")
        ).hexdigest()

    def test_this_repositorys_own_logs_still_use_record_hash(self, tmp_path):
        """The fallback exists to read the sibling, not to change what is
        written here. Renaming what this log emits would invalidate every log
        already on disk."""
        from mcp_gateway.audit import AuditLog

        log = AuditLog(tmp_path / "own.jsonl")
        log.record({"direction": "request", "method": "tools/call", "request_id": 1,
                    "action": "forwarded", "reason_code": "rule_match",
                    "rule_id": "r1", "detail": {}}, server_id="fs")

        record = json.loads((tmp_path / "own.jsonl").read_text(encoding="utf-8").splitlines()[0])
        assert "record_hash" in record["integrity"]
        assert "event_hash" not in record["integrity"]
