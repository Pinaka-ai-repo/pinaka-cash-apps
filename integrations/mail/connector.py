"""Gmail API & Microsoft Graph Inbound/Outbound Connector with Human Confirmation & Local Mail Sink.

Enforces BUILD_SPEC.md Mail & SEC-21 / SEC-46 Rules:
- Independent inbound and outbound OAuth scopes (no read/write broadening).
- Recipient resolved strictly from approved customer master; checked against suppression list.
- No model-driven sends: requires human analyst draft + Controller Maker-Checker approval (SEC-46).
- Pilot sends target local mail sink / approved test mailbox with idempotency deduplication.
"""

from __future__ import annotations

import copy
import uuid
from typing import Any

from apps.api.astra.audit.chain import AuditChain
from apps.api.astra.security.sod import Principal, SecurityController

INBOUND_SCOPES = {
    "gmail": frozenset({"https://www.googleapis.com/auth/gmail.readonly"}),
    "ms_graph": frozenset({"Mail.Read"}),
}

OUTBOUND_SCOPES = {
    "gmail": frozenset({"https://www.googleapis.com/auth/gmail.send"}),
    "ms_graph": frozenset({"Mail.Send"}),
}


class MailConnectorService:
    def __init__(
        self,
        security: SecurityController,
        audit: AuditChain,
        approved_customer_contacts: dict[tuple[str, str, str], str] | None = None,
        suppression_list: set[str] | None = None,
    ) -> None:
        self.security = security
        self.audit = audit
        # Maps (tenant_id, legal_entity_id, customer_id) -> approved_email
        self._contacts = dict(approved_customer_contacts or {})
        self._suppression = {e.lower() for e in (suppression_list or set())}
        self._drafts: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._sent_by_idempotency: dict[tuple[str, str, str], dict[str, Any]] = {}

    @staticmethod
    def verify_scope_isolation(provider: str, direction: str, granted_scopes: set[str]) -> bool:
        """SEC-21: Ensures inbound and outbound mail connectors never broaden OAuth scopes."""
        expected = INBOUND_SCOPES[provider] if direction == "inbound" else OUTBOUND_SCOPES[provider]
        if not granted_scopes.issubset(expected):
            raise PermissionError(
                f"SEC-21 violation: Mail connector ({provider}, {direction}) scope broadening rejected: {granted_scopes}"
            )
        return True

    def preview_and_draft_message(
        self,
        analyst: Principal,
        *,
        tenant_id: str,
        legal_entity_id: str,
        customer_id: str,
        provider: str,
        template_id: str,
        receipt_id: str,
        reason_summary: str,
        attachments: list[str] | None = None,
    ) -> dict[str, Any]:
        self.security.authorize(analyst, "mail:draft", tenant_id, legal_entity_id)
        ckey = (tenant_id, legal_entity_id, customer_id)
        if ckey not in self._contacts:
            raise ValueError(f"Customer '{customer_id}' has no approved contact in Customer Master.")
        recipient = self._contacts[ckey].lower()
        if recipient in self._suppression:
            raise PermissionError(f"Recipient '{recipient}' is on the outbound suppression list.")

        draft_id = f"mail-draft-{uuid.uuid4().hex[:8]}"
        draft = {
            "draft_id": draft_id,
            "tenant_id": tenant_id,
            "legal_entity_id": legal_entity_id,
            "customer_id": customer_id,
            "provider": provider,
            "recipient": recipient,
            "template_id": template_id,
            "receipt_id": receipt_id,
            "subject": f"[ASTRA Remittance Inquiry] Clarification requested for receipt {receipt_id}",
            "body_preview": f"Dear Customer ({customer_id}), please provide remittance details regarding {receipt_id}: {reason_summary}",
            "attachments": list(attachments or []),
            "preparer_id": analyst.user_id,
            "approver_id": None,
            "status": "pending_approval",
        }
        self._drafts[(tenant_id, legal_entity_id, draft_id)] = draft
        return copy.deepcopy(draft)

    def approve_and_send_to_sink(
        self,
        approver: Principal,
        *,
        tenant_id: str,
        legal_entity_id: str,
        draft_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """SEC-09 / SEC-46: Enforces human Maker-Checker approval before dispatching to local mail sink."""
        self.security.authorize(approver, "mail:approve", tenant_id, legal_entity_id)
        scoped_idem = (tenant_id, legal_entity_id, idempotency_key)
        if scoped_idem in self._sent_by_idempotency:
            return copy.deepcopy(self._sent_by_idempotency[scoped_idem])

        key = (tenant_id, legal_entity_id, draft_id)
        if key not in self._drafts:
            raise KeyError(f"Mail draft '{draft_id}' not found.")
        draft = self._drafts[key]

        self.security.enforce_maker_checker(
            preparer_id=draft["preparer_id"],
            approver=approver,
            action="mail:approve",
            tenant_id=tenant_id,
            legal_entity_id=legal_entity_id,
        )

        msg_id = f"sink-msg-{uuid.uuid4().hex[:10]}@astra.pinaka.local"
        sent = {
            **draft,
            "approver_id": approver.user_id,
            "status": "delivered_to_local_sink",
            "message_id": msg_id,
            "idempotency_key": idempotency_key,
        }
        self._drafts[key] = sent
        self._sent_by_idempotency[scoped_idem] = sent

        self.audit.append(
            tenant_id=tenant_id,
            legal_entity_id=legal_entity_id,
            actor_id=approver.user_id,
            actor_role=approver.roles[0],
            action="mail:approved_and_sent_to_sink",
            target_type="mail_message",
            target_id=msg_id,
            details={"draft_id": draft_id, "recipient": draft["recipient"], "preparer_id": draft["preparer_id"]},
        )
        return copy.deepcopy(sent)
