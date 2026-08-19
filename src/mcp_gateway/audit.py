"""Durable record of every gateway decision.

The interceptor keeps its decisions in memory, which is enough to test with and
useless afterwards: the questions people ask about an agent — what did it try,
what was refused, who approved the one thing that went through — are asked days
later, by someone who was not watching.

The records are written as newline-delimited JSON with a SHA-256 chain, the same
shape the core's evidence export uses, so a gateway log and a core ledger export
can be verified by the same reader. Writing is append-only and flushed per
record: a crash loses at most the call in flight, never the history.

What this proves and does not prove: an edited, deleted, or reordered record
breaks the chain and is reported with its line number. A log that was truncated
at the end still verifies on its own, because nothing inside a file can testify
about what was removed after it.

`anchor()` closes that gap by publishing the log's tip to an external witness —
the core's checkpoint machinery. Once a tip has been published, a shorter log
that ends before it is detectably incomplete rather than merely smaller.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

GENESIS_HASH = "0" * 64


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _integrity_hash(integrity: Mapping[str, Any]) -> str | None:
    """The record hash, whichever of the two names it was written under.

    agent-safety-core writes `event_hash`, this log writes `record_hash`. The
    canonical form and the chaining are the same, so the two were described as
    readable by a single verifier - and were not, because each rejected the
    other's field name as a modified record. Accepting both keeps every log
    already written valid.
    """
    return integrity.get("record_hash", integrity.get("event_hash"))


def _record_hash(body: Mapping[str, Any], previous_hash: str) -> str:
    return hashlib.sha256(
        previous_hash.encode("ascii") + _canonical(body).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class Violation:
    """One thing wrong with the log, and which thing.

    `reason` is for a person; `kind` is for whatever has to decide what to do.
    A missing log, an unreadable line and a broken chain call for different
    responses - the first may simply mean nothing has been written yet, the last
    means someone edited the record - and telling them apart used to require
    matching on the sentence.

    The same field exists on agent-safety-core's Violation, and the two logs
    share a format so that one verifier can read both. Sharing the vocabulary is
    part of that.
    """

    line: int
    reason: str
    kind: str = "unclassified"


@dataclass(frozen=True)
class AuditReport:
    records: int
    violations: tuple[Violation, ...]
    tip_hash: str

    @property
    def ok(self) -> bool:
        return not self.violations

    def summary(self) -> str:
        if self.ok:
            return f"OK — {self.records} records, chain intact"
        return "FAILED — " + "; ".join(
            f"line {violation.line}: {violation.reason}" for violation in self.violations
        )


class AuditLog:
    """Append-only, hash-chained record of interception decisions."""

    def __init__(self, path: Path | str, *, session_id: str = "default",
                 clock=None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._session_id = session_id
        self._clock = clock or (lambda: __import__("time").time())
        self._sequence = 0
        self._tip = GENESIS_HASH
        if self.path.exists():
            self._resume()

    def _resume(self) -> None:
        """Continue an existing log rather than starting a second chain in it."""
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            self._sequence = record["sequence"]
            self._tip = _integrity_hash(record["integrity"]) or GENESIS_HASH

    @property
    def tip_hash(self) -> str:
        return self._tip

    def record(self, interception: Any, *, server_id: str) -> dict[str, Any]:
        """Persist one decision. Accepts an InterceptionRecord or a mapping."""
        source = interception if isinstance(interception, Mapping) else {
            "direction": interception.direction,
            "method": interception.method,
            "request_id": interception.request_id,
            "action": interception.action,
            "reason_code": interception.reason_code,
            "rule_id": interception.rule_id,
            "detail": dict(interception.detail),
        }
        self._sequence += 1
        body = {
            "sequence": self._sequence,
            "session_id": self._session_id,
            "server_id": server_id,
            "recorded_at": self._clock(),
            **source,
        }
        sealed = dict(body)
        sealed["integrity"] = {
            "previous_hash": self._tip,
            "record_hash": _record_hash(body, self._tip),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(_canonical(sealed) + "\n")
            handle.flush()
        self._tip = sealed["integrity"]["record_hash"]
        return sealed

    def record_all(self, interceptions: Iterable[Any], *, server_id: str) -> int:
        return sum(1 for item in interceptions if self.record(item, server_id=server_id))

    def read(self) -> tuple[dict[str, Any], ...]:
        if not self.path.exists():
            return ()
        return tuple(
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )


def verify_audit_log(path: Path | str) -> AuditReport:
    """Check a gateway audit log using only the file."""
    path = Path(path)
    if not path.exists():
        return AuditReport(0, (Violation(0, "log does not exist", kind="missing_log"),), GENESIS_HASH)

    violations: list[Violation] = []
    previous = GENESIS_HASH
    count = 0
    last_sequence = 0

    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        count += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            violations.append(Violation(number, "record is not valid JSON", kind="malformed_line"))
            break
        integrity = record.pop("integrity", None)
        if not isinstance(integrity, dict):
            violations.append(Violation(number, "record has no integrity block", kind="missing_integrity"))
            break
        if integrity.get("previous_hash") != previous:
            violations.append(Violation(number, "chain is broken here", kind="chain_broken"))
        if _integrity_hash(integrity) != _record_hash(record, integrity.get("previous_hash", "")):
            violations.append(Violation(number, "record content was modified", kind="content_modified"))
        sequence = record.get("sequence")
        if isinstance(sequence, int):
            if sequence != last_sequence + 1:
                violations.append(
                    Violation(number, f"sequence jumped from {last_sequence} to {sequence}",
                              kind="sequence_regressed")
                )
            last_sequence = sequence
        previous = _integrity_hash(integrity) or ""

    return AuditReport(count, tuple(violations), previous)


def main(argv: list[str] | None = None) -> int:
    """``python -m mcp_gateway.audit verify <log.jsonl>``"""
    import argparse

    parser = argparse.ArgumentParser(description="Verify a gateway audit log.")
    parser.add_argument("command", choices=["verify"])
    parser.add_argument("path")
    arguments = parser.parse_args(argv)
    report = verify_audit_log(arguments.path)
    print(report.summary())
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


# --------------------------------------------------------------- anchoring


def anchor(log: "AuditLog", *, signer, witness, log_id: str, sequence: int,
           previous=None, now: float) -> Any:
    """Publish this log's tip to an external witness.

    Delegates to the core's checkpoint format so a gateway log and a ledger
    export are anchored the same way and read by the same verifier. Imported
    lazily: the gateway must keep working without the core installed, and only
    this one function needs it.
    """
    from core.checkpoint import Checkpoint  # noqa: PLC0415

    checkpoint = Checkpoint(
        log_id=log_id,
        sequence=sequence,
        journal_tip_hash=log.tip_hash,
        previous_checkpoint_hash=previous.digest() if previous else "0" * 64,
        signed_at=now,
    )
    signed = signer.sign(checkpoint)
    witness.publish(signed)
    return signed


def verify_against_anchor(path: Path | str, checkpoint: Any, *, public_key_pem: bytes,
                          witness) -> tuple[bool, tuple[str, ...]]:
    """Check a log for internal consistency *and* for being the current one.

    Returns (ok, notes). The second element names each failing dimension rather
    than collapsing them, since "someone edited line 3" and "you are being shown
    an old copy" call for different responses.
    """
    from core.checkpoint import verify_signature  # noqa: PLC0415

    notes: list[str] = []
    report = verify_audit_log(path)
    if not report.ok:
        notes.append(f"log chain is broken ({len(report.violations)} violation(s))")

    if not verify_signature(checkpoint, public_key_pem):
        notes.append("checkpoint signature is invalid")

    if report.tip_hash != checkpoint.journal_tip_hash:
        notes.append(
            "the log does not end where the checkpoint says it should - "
            "records after the anchored tip are missing or extra"
        )

    latest = witness.latest_sequence(checkpoint.log_id)
    if latest is None:
        notes.append("the witness has never seen this log")
    elif checkpoint.sequence < latest:
        notes.append(
            f"rollback: the witness holds checkpoint {latest}, "
            f"only {checkpoint.sequence} was presented"
        )
    elif checkpoint.sequence > latest:
        notes.append(f"fork: checkpoint {checkpoint.sequence} was never published")

    return (not notes), tuple(notes)
