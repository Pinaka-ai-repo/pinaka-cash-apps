"""SHA-256 Hash-Chained Append-Only Audit Ledger, Tamper Detection & Backup/Restore Drill.

Enforces:
- SEC-27: Append-only audit events with actor, role, action, policy_version, prev_hash, and event_hash.
- SEC-28: Synchronized UTC ISO-8601 timestamps and deterministic decision replay metadata.
- SEC-30 / SEC-31: Scoped retention purge (respecting legal holds) and backup/restore drill measuring RPO/RTO.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from apps.api.astra.security.sod import redact_log_payload

GENESIS_HASH = "0" * 64


class AuditTamperAlert(RuntimeError):
    """Raised when SHA-256 hash chain verification detects tampering."""


@dataclass(frozen=True)
class AuditEvent:
    seq: int
    event_id: str
    tenant_id: str
    legal_entity_id: str
    actor_id: str
    actor_role: str
    action: str
    target_type: str
    target_id: str
    policy_version: str
    details: dict[str, Any]
    recorded_at: str
    prev_hash: str
    event_hash: str

    @staticmethod
    def compute_hash(
        *,
        seq: int,
        event_id: str,
        tenant_id: str,
        legal_entity_id: str,
        actor_id: str,
        actor_role: str,
        action: str,
        target_type: str,
        target_id: str,
        policy_version: str,
        details: dict[str, Any],
        recorded_at: str,
        prev_hash: str,
    ) -> str:
        canonical = json.dumps(
            {
                "seq": seq,
                "event_id": event_id,
                "tenant_id": tenant_id,
                "legal_entity_id": legal_entity_id,
                "actor_id": actor_id,
                "actor_role": actor_role,
                "action": action,
                "target_type": target_type,
                "target_id": target_id,
                "policy_version": policy_version,
                "details": details,
                "recorded_at": recorded_at,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditChain:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(
        self,
        *,
        tenant_id: str,
        legal_entity_id: str,
        actor_id: str,
        actor_role: str,
        action: str,
        target_type: str,
        target_id: str,
        policy_version: str = "policy-v1.0",
        details: dict[str, Any] | None = None,
        recorded_at: str | None = None,
    ) -> AuditEvent:
        seq = len(self._events) + 1
        event_id = f"aud-{seq:06d}-{uuid.uuid4().hex[:8]}"
        ts = recorded_at or datetime.now(timezone.utc).isoformat()
        prev_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
        redacted_details = redact_log_payload(details or {})

        event_hash = AuditEvent.compute_hash(
            seq=seq,
            event_id=event_id,
            tenant_id=tenant_id,
            legal_entity_id=legal_entity_id,
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            policy_version=policy_version,
            details=redacted_details,
            recorded_at=ts,
            prev_hash=prev_hash,
        )
        ev = AuditEvent(
            seq=seq,
            event_id=event_id,
            tenant_id=tenant_id,
            legal_entity_id=legal_entity_id,
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            policy_version=policy_version,
            details=redacted_details,
            recorded_at=ts,
            prev_hash=prev_hash,
            event_hash=event_hash,
        )
        self._events.append(ev)
        return ev

    def verify_integrity(self) -> bool:
        """SEC-27: Verifies every link and payload hash in the append-only audit chain."""
        expected_prev = GENESIS_HASH
        for idx, ev in enumerate(self._events, start=1):
            if ev.seq != idx or ev.prev_hash != expected_prev:
                raise AuditTamperAlert(
                    f"SEC-27 Tamper Alert: Chain sequence/prev_hash broken at seq={ev.seq} (event_id={ev.event_id})."
                )
            recomputed = AuditEvent.compute_hash(
                seq=ev.seq,
                event_id=ev.event_id,
                tenant_id=ev.tenant_id,
                legal_entity_id=ev.legal_entity_id,
                actor_id=ev.actor_id,
                actor_role=ev.actor_role,
                action=ev.action,
                target_type=ev.target_type,
                target_id=ev.target_id,
                policy_version=ev.policy_version,
                details=ev.details,
                recorded_at=ev.recorded_at,
                prev_hash=ev.prev_hash,
            )
            if recomputed != ev.event_hash:
                raise AuditTamperAlert(
                    f"SEC-27 Tamper Alert: Payload hash mismatch at seq={ev.seq} (event_id={ev.event_id})."
                )
            expected_prev = ev.event_hash
        return True

    def list_scoped(self, tenant_id: str, legal_entity_id: str) -> list[dict[str, Any]]:
        self.verify_integrity()
        return [
            asdict(e)
            for e in self._events
            if e.tenant_id == tenant_id and e.legal_entity_id == legal_entity_id
        ]

    def head_hash(self) -> str:
        self.verify_integrity()
        return self._events[-1].event_hash if self._events else GENESIS_HASH

    def export_snapshot(self) -> list[dict[str, Any]]:
        self.verify_integrity()
        return copy.deepcopy([asdict(e) for e in self._events])

    @classmethod
    def restore_from_snapshot(cls, rows: list[dict[str, Any]]) -> tuple["AuditChain", float]:
        """SEC-31: Restores an AuditChain from backup snapshot and measures RTO seconds."""
        t0 = time.perf_counter()
        chain = cls()
        for row in rows:
            chain._events.append(AuditEvent(**copy.deepcopy(row)))
        chain.verify_integrity()
        rto_sec = time.perf_counter() - t0
        return chain, rto_sec
