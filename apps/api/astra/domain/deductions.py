"""Short-Pay DeductionCaseV1 Workflow, Durable Outbox Sync & Write-Off Maker-Checker Gate.

Enforces BUILD_SPEC.md Short-Pay & SEC-09 / SEC-46 Rules:
- A deduction is an open AR residual, never received cash.
- Extracted stated reason, predicted reason, and Pinaka RiskSnapshotV1 are stored separately.
- A suspected or predicted reason can NEVER automatically write off, approve, contact, or alter AR.
"""

from __future__ import annotations

import copy
import uuid
from typing import Any

from apps.api.astra.audit.chain import AuditChain
from apps.api.astra.security.sod import Principal, SecurityController
from integrations.pinaka.client import PinakaRiskClient
from ml.laya_adapter import BaselineRulesReasonClassifier, LayaConformalReasonClassifier


class DeductionWorkflowService:
    def __init__(
        self,
        security: SecurityController,
        audit: AuditChain,
        pinaka_client: PinakaRiskClient | None = None,
        use_laya_classifier: bool = False,
    ) -> None:
        self.security = security
        self.audit = audit
        self.pinaka = pinaka_client or PinakaRiskClient()
        self.use_laya = use_laya_classifier
        self._baseline_clf = BaselineRulesReasonClassifier()
        self._laya_clf = LayaConformalReasonClassifier()
        self._cases: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._outbox_synced: dict[str, dict[str, Any]] = {}

    def create_deduction_case(
        self,
        actor: Principal,
        *,
        tenant_id: str,
        legal_entity_id: str,
        customer_id: str,
        receipt_id: str,
        invoice_number: str,
        currency: str,
        received_minor: int,
        open_minor: int,
        extracted_stated_reason: str | None,
        remittance_note: str,
        evidence_locators: list[str],
    ) -> dict[str, Any]:
        self.security.authorize(actor, "deduction:propose", tenant_id, legal_entity_id)
        residual_minor = open_minor - received_minor
        if residual_minor <= 0:
            raise ValueError("DeductionCaseV1 requires a positive open AR residual (open_minor > received_minor).")
        if not evidence_locators:
            raise ValueError("DeductionCaseV1 requires at least one source evidence locator.")

        clf = self._laya_clf if self.use_laya else self._baseline_clf
        pred = clf.classify(remittance_note)
        risk_snap = self.pinaka.fetch_risk_snapshot(
            tenant_id=tenant_id,
            legal_entity_id=legal_entity_id,
            customer_id=customer_id,
        )
        priority_info = self.pinaka.compute_queue_priority_boost(risk_snap, residual_minor)

        case_id = f"ded-{uuid.uuid4().hex[:10]}"
        case_payload: dict[str, Any] = {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "legal_entity_id": legal_entity_id,
            "customer_id": customer_id,
            "receipt_id": receipt_id,
            "invoice_number": invoice_number,
            "currency": currency.upper(),
            "received_minor": received_minor,
            "open_minor": open_minor,
            "residual_minor": residual_minor,
            "taxonomy_version": "astra-deduction-taxonomy-v1.0",
            "extracted_stated_reason": extracted_stated_reason,
            "predicted_reason": pred.predicted_reason,
            "classifier_source": pred.classifier_source,
            "confidence": pred.confidence,
            "prediction_set": pred.prediction_set,
            "abstain": pred.abstain,
            "evidence_locators": list(evidence_locators),
            "approved_route": "pending_review",
            "risk_snapshot_ref": risk_snap["snapshot_id"],
            "pinaka_predicted_delay_days": risk_snap["predicted_delay_days"],
            "pinaka_delay_probability": risk_snap["delay_probability"],
            "pinaka_availability": risk_snap["availability"],
            "queue_priority_score": priority_info["priority_score"],
            "external_status": "draft",
            "preparer_id": actor.user_id,
            "approver_id": None,
            "ar_written_off_minor": 0,
        }
        self._cases[(tenant_id, legal_entity_id, case_id)] = case_payload

        self.audit.append(
            tenant_id=tenant_id,
            legal_entity_id=legal_entity_id,
            actor_id=actor.user_id,
            actor_role=actor.roles[0],
            action="deduction_case:created",
            target_type="deduction_case",
            target_id=case_id,
            details={
                "invoice_number": invoice_number,
                "residual_minor": residual_minor,
                "extracted_stated_reason": extracted_stated_reason,
                "predicted_reason": pred.predicted_reason,
                "classifier_source": pred.classifier_source,
            },
        )
        return copy.deepcopy(case_payload)

    def approve_adjustment_or_route(
        self,
        approver: Principal,
        *,
        tenant_id: str,
        legal_entity_id: str,
        case_id: str,
        approved_route: str,
        write_off_minor: int = 0,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """SEC-09 / SEC-46: Only an authorized Controller (distinct from preparer) can approve a write-off or external sync."""
        key = (tenant_id, legal_entity_id, case_id)
        if key not in self._cases:
            raise KeyError(f"DeductionCaseV1 '{case_id}' not found.")
        case = self._cases[key]

        action = "writeoff:approve" if write_off_minor > 0 else "posting:approve"
        self.security.enforce_maker_checker(
            preparer_id=case["preparer_id"],
            approver=approver,
            action=action,
            tenant_id=tenant_id,
            legal_entity_id=legal_entity_id,
        )
        if write_off_minor < 0 or write_off_minor > case["residual_minor"]:
            raise ValueError("Invalid write_off_minor amount.")

        case["approved_route"] = approved_route
        case["approver_id"] = approver.user_id
        case["ar_written_off_minor"] = write_off_minor
        case["external_status"] = "synced_external"

        if idempotency_key not in self._outbox_synced:
            self._outbox_synced[idempotency_key] = {
                "external_case_id": f"EXT-DISP-{len(self._outbox_synced) + 5001}",
                "case_id": case_id,
                "status": "synced_external",
            }

        self.audit.append(
            tenant_id=tenant_id,
            legal_entity_id=legal_entity_id,
            actor_id=approver.user_id,
            actor_role=approver.roles[0],
            action="deduction_case:approved",
            target_type="deduction_case",
            target_id=case_id,
            details={
                "approved_route": approved_route,
                "write_off_minor": write_off_minor,
                "preparer_id": case["preparer_id"],
            },
        )
        return copy.deepcopy(case)
