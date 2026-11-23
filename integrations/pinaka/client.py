"""Pinaka AI RiskSnapshotV1 Client (REST & Allowlisted MCP + Deterministic Mock).

Enforces BUILD_SPEC.md Pinaka Contract:
- Maps identities using an approved crosswalk only (never fuzzy lookup alone).
- Checks expires_at to label stale vs fresh vs unavailable.
- Priority-only guardrail: RiskSnapshotV1 can influence queue priority and follow-up cadence,
  never override allocation, amount, deduction cause, credit, approval, or write-off controls.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class RiskSnapshotV1:
    snapshot_id: str
    tenant_id: str
    legal_entity_id: str
    customer_key: str
    scope: str
    as_of: str
    expires_at: str
    predicted_delay_days: int
    delay_probability: float
    label_definition: str
    model_version: str
    reason_codes: list[str]
    explanations: list[str]
    evidence_refs: list[str]
    availability: str  # fresh_mock | fresh_sandbox | stale | unavailable


class PinakaRiskClient:
    def __init__(self, approved_crosswalk: dict[tuple[str, str, str], str] | None = None) -> None:
        # Maps (tenant_id, legal_entity_id, customer_id) -> pinaka_customer_key
        self._crosswalk: dict[tuple[str, str, str], str] = dict(approved_crosswalk or {})
        self._snapshots: dict[str, RiskSnapshotV1] = {}

    def register_approved_crosswalk(self, tenant_id: str, legal_entity_id: str, customer_id: str, pinaka_key: str) -> None:
        self._crosswalk[(tenant_id, legal_entity_id, customer_id)] = pinaka_key

    def seed_mock_snapshot(self, snapshot: RiskSnapshotV1) -> None:
        self._snapshots[snapshot.customer_key] = snapshot

    def fetch_risk_snapshot(
        self,
        *,
        tenant_id: str,
        legal_entity_id: str,
        customer_id: str,
        now_iso: str | None = None,
    ) -> dict[str, Any]:
        """Fetches RiskSnapshotV1 via approved identity crosswalk; never falls back to fuzzy name lookup."""
        now_str = now_iso or datetime.now(timezone.utc).isoformat()
        c_key = self._crosswalk.get((tenant_id, legal_entity_id, customer_id))
        if not c_key or c_key not in self._snapshots:
            return {
                "snapshot_id": "pinaka-unavail",
                "tenant_id": tenant_id,
                "legal_entity_id": legal_entity_id,
                "customer_key": c_key or "unmapped_customer",
                "scope": "payment_delay_prediction",
                "as_of": now_str,
                "expires_at": now_str,
                "predicted_delay_days": 0,
                "delay_probability": 0.0,
                "label_definition": "P(settlement_delay_days > 15)",
                "model_version": "pinaka-risk-v2.1-mock",
                "reason_codes": ["UNMAPPED_OR_UNAVAILABLE"],
                "explanations": ["No approved Pinaka crosswalk or fresh snapshot available; proceeding with core workflow."],
                "evidence_refs": [],
                "availability": "unavailable",
            }

        snap = self._snapshots[c_key]
        if snap.tenant_id != tenant_id or snap.legal_entity_id != legal_entity_id:
            raise PermissionError("SEC-07 violation: Cross-scope Pinaka RiskSnapshotV1 access blocked.")

        is_stale = now_str > snap.expires_at
        data = asdict(snap)
        if is_stale:
            data["availability"] = "stale"
        return data

    @staticmethod
    def compute_queue_priority_boost(risk_snapshot: dict[str, Any], residual_minor: int) -> dict[str, Any]:
        """Uses fresh Pinaka signals strictly for queue ordering and follow-up cadence, never AR mutation."""
        avail = risk_snapshot.get("availability", "unavailable")
        if avail not in ("fresh_mock", "fresh_sandbox"):
            return {
                "priority_score": residual_minor,
                "pinaka_applied": False,
                "suggested_followup_cadence": "standard_d+5",
                "accounting_override_permitted": False,
            }

        prob = float(risk_snapshot.get("delay_probability", 0.0))
        delay_days = int(risk_snapshot.get("predicted_delay_days", 0))
        boost_multiplier = 1.0 + (0.5 * prob if delay_days >= 14 else 0.15 * prob)
        return {
            "priority_score": int(residual_minor * boost_multiplier),
            "pinaka_applied": True,
            "suggested_followup_cadence": "proactive_d+1" if prob >= 0.70 else "standard_d+5",
            "accounting_override_permitted": False,
        }
