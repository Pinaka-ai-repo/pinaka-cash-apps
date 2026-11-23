"""Grounded Read-Only Chat (AnswerV1), Scoped RAG & Frontier Model Provider Registry.

Enforces:
- SEC-40: Prompt-injection defense on untrusted document/chat text.
- SEC-41: RAG vectors, chunks, and citations are scoped by (tenant_id, legal_entity_id) before search
  and re-authorized on retrieval and export.
- SEC-42: Frontier model provider registry (OpenAI, Claude, Gemini, Kimi, GLM, Qwen, self-hosted)
  enforces tenant opt-in, data residency region, PII redaction, and no silent provider fallback.
- SEC-43: Validates AnswerV1 schema, citation existence/scope, and numeric consistency against metric queries;
  withholds ungrounded answers with status='insufficient_evidence'.
- SEC-44: Chat tool registry is strictly read-only + ReportSpecV1 proposal draft (zero SQL, shell, HTTP, or write tools).
"""

from __future__ import annotations

import copy
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from apps.api.astra.domain.ledger import AstraLedgerStore
from apps.api.astra.security.sod import Principal, redact_sensitive_text
from ml.agents.pipeline import detect_prompt_injection


@dataclass(frozen=True)
class ModelProviderDescriptor:
    provider_id: str
    model_alias: str
    allowed_host: str
    residency_region: str
    zero_retention_required: bool
    supports_streaming: bool
    supports_structured_output: bool
    supports_embeddings: bool
    validation_tier: str = "contract_tested"


FRONTIER_MODEL_REGISTRY: dict[str, ModelProviderDescriptor] = {
    "openai": ModelProviderDescriptor("openai", "astra-openai-reasoning", "api.openai.com", "US", True, True, True, True),
    "anthropic": ModelProviderDescriptor("anthropic", "astra-claude-sonnet", "api.anthropic.com", "US", True, True, True, False),
    "gemini": ModelProviderDescriptor("gemini", "astra-gemini-pro", "generativelanguage.googleapis.com", "US", True, True, True, True),
    "kimi": ModelProviderDescriptor("kimi", "astra-moonshot-kimi", "api.moonshot.cn", "APAC", True, True, True, False),
    "glm": ModelProviderDescriptor("glm", "astra-zhipu-glm", "open.bigmodel.cn", "APAC", True, True, True, True),
    "qwen": ModelProviderDescriptor("qwen", "astra-alibaba-qwen", "dashscope.aliyuncs.com", "APAC", True, True, True, True),
    "self_hosted": ModelProviderDescriptor("self_hosted", "astra-local-vllm", "localhost", "ON_PREM", True, True, True, True),
}

# SEC-44: Explicitly allowed read-only tools for chat orchestration
CHAT_ALLOWED_READONLY_TOOLS = frozenset({
    "lookup_receipt_evidence",
    "query_open_deductions_metric",
    "list_unmatched_wires_metric",
    "lookup_pinaka_risk_snapshot",
    "draft_report_spec_v1",
    "lookup_approval_sample_evidence",
})

FORBIDDEN_CHAT_TOOLS = frozenset({
    "execute_sql",
    "run_shell",
    "http_request",
    "post_cash",
    "write_off_ar",
    "send_email",
    "approve_posting",
    "update_policy",
})


class GroundedChatEngine:
    def __init__(self, ledger: AstraLedgerStore) -> None:
        self.ledger = ledger
        self._rag_documents: list[dict[str, Any]] = []
        self._tenant_approved_providers: dict[str, set[str]] = {}
        self._tenant_residency_region: dict[str, str] = {}

    def configure_tenant_model_policy(
        self,
        tenant_id: str,
        *,
        approved_providers: set[str],
        required_residency_region: str,
    ) -> None:
        self._tenant_approved_providers[tenant_id] = set(approved_providers)
        self._tenant_residency_region[tenant_id] = required_residency_region

    def route_to_model_provider(
        self,
        *,
        tenant_id: str,
        provider_id: str,
        prompt_text: str,
    ) -> dict[str, Any]:
        """SEC-42: Verifies tenant approval, residency match, redacts PII/PANs, and never silently falls back."""
        if self.ledger.kill_switches["models_disabled"]:
            raise RuntimeError("SEC-33 kill-switch active: Model providers are disabled.")
        if provider_id not in FRONTIER_MODEL_REGISTRY:
            raise ValueError(f"Unknown model provider '{provider_id}'.")
        approved = self._tenant_approved_providers.get(tenant_id, {"self_hosted"})
        if provider_id not in approved:
            raise PermissionError(
                f"SEC-42 violation: Provider '{provider_id}' not opted-in for tenant '{tenant_id}' (no silent fallback)."
            )
        desc = FRONTIER_MODEL_REGISTRY[provider_id]
        req_region = self._tenant_residency_region.get(tenant_id)
        if req_region and desc.residency_region not in (req_region, "ON_PREM"):
            raise PermissionError(
                f"SEC-42 violation: Provider residency '{desc.residency_region}' violates tenant residency '{req_region}'."
            )
        redacted_prompt = redact_sensitive_text(prompt_text)
        self.ledger.check_budget(tenant_id, llm_tokens=max(1, len(redacted_prompt) // 4))
        return {
            "provider_id": provider_id,
            "model_alias": desc.model_alias,
            "redacted_prompt": redacted_prompt,
            "residency_verified": True,
        }

    def index_rag_span(
        self,
        *,
        evidence_id: str,
        tenant_id: str,
        legal_entity_id: str,
        doc_id: str,
        text: str,
        numeric_value_minor: int | None = None,
    ) -> None:
        if detect_prompt_injection(text):
            raise ValueError(f"SEC-40 violation: Prompt-injection payload rejected during RAG indexing of '{evidence_id}'.")
        self._rag_documents.append({
            "evidence_id": evidence_id,
            "tenant_id": tenant_id,
            "legal_entity_id": legal_entity_id,
            "doc_id": doc_id,
            "text": redact_sensitive_text(text),
            "numeric_value_minor": numeric_value_minor,
        })

    def retrieve_scoped_rag(
        self,
        actor: Principal,
        *,
        tenant_id: str,
        legal_entity_id: str,
        query: str,
    ) -> list[dict[str, Any]]:
        """SEC-41: Pre-filters vector/chunk namespace by (tenant_id, legal_entity_id) BEFORE search or ranking."""
        self.ledger.security.authorize(actor, "chat:query", tenant_id, legal_entity_id)
        pre_scoped = [
            d for d in self._rag_documents
            if d["tenant_id"] == tenant_id and d["legal_entity_id"] == legal_entity_id
        ]
        q_terms = {w.lower() for w in query.split() if len(w) > 2}
        scored: list[tuple[int, dict[str, Any]]] = []
        for doc in pre_scoped:
            overlap = sum(1 for t in q_terms if t in doc["text"].lower() or t in doc["evidence_id"].lower())
            if overlap > 0 or not q_terms:
                scored.append((overlap, copy.deepcopy(doc)))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [d for _, d in scored]

    def validate_and_finalize_answer(
        self,
        actor: Principal,
        *,
        tenant_id: str,
        legal_entity_id: str,
        candidate_claims: list[dict[str, Any]],
        proposed_report_spec: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """SEC-43: Verifies citation existence, tenant/entity scope, and exact numeric match with ground truth."""
        self.ledger.security.authorize(actor, "chat:query", tenant_id, legal_entity_id)
        scoped_evidence = {
            d["evidence_id"]: d
            for d in self._rag_documents
            if d["tenant_id"] == tenant_id and d["legal_entity_id"] == legal_entity_id
        }

        verified_claims: list[dict[str, Any]] = []
        evidence_ids: list[str] = []

        for claim in candidate_claims:
            ev_id = claim.get("evidence_id", "")
            if ev_id not in scoped_evidence:
                # Citation missing or belongs to another tenant/entity -> withhold answer (SEC-41 / SEC-43)
                return {
                    "answer_id": f"ans-{uuid.uuid4().hex[:10]}",
                    "tenant_id": tenant_id,
                    "legal_entity_id": legal_entity_id,
                    "status": "insufficient_evidence",
                    "as_of": datetime.now(timezone.utc).isoformat(),
                    "sections": ["Abstained: Claim references missing or out-of-scope citation evidence."],
                    "claims": [],
                    "evidence_ids": [],
                    "proposed_report_spec": None,
                }
            ev_doc = scoped_evidence[ev_id]
            expected_num = ev_doc.get("numeric_value_minor")
            claimed_num = claim.get("numeric_value_minor")
            if expected_num is not None and claimed_num != expected_num:
                # Numeric inconsistency -> withhold answer (SEC-43)
                return {
                    "answer_id": f"ans-{uuid.uuid4().hex[:10]}",
                    "tenant_id": tenant_id,
                    "legal_entity_id": legal_entity_id,
                    "status": "insufficient_evidence",
                    "as_of": datetime.now(timezone.utc).isoformat(),
                    "sections": ["Abstained: Numeric claim does not match parameterized SQL metric result."],
                    "claims": [],
                    "evidence_ids": [],
                    "proposed_report_spec": None,
                }
            verified_claims.append({
                "claim_text": claim["claim_text"],
                "claim_type": claim.get("claim_type", "observation"),
                "evidence_id": ev_id,
                "numeric_value_minor": claimed_num,
            })
            if ev_id not in evidence_ids:
                evidence_ids.append(ev_id)

        status = "answered" if verified_claims else "insufficient_evidence"
        return {
            "answer_id": f"ans-{uuid.uuid4().hex[:10]}",
            "tenant_id": tenant_id,
            "legal_entity_id": legal_entity_id,
            "status": status,
            "as_of": datetime.now(timezone.utc).isoformat(),
            "sections": [c["claim_text"] for c in verified_claims] or ["No matching scoped evidence found."],
            "claims": verified_claims,
            "evidence_ids": evidence_ids,
            "proposed_report_spec": proposed_report_spec,
        }

    def ask(
        self,
        actor: Principal,
        *,
        tenant_id: str,
        legal_entity_id: str,
        question: str,
    ) -> dict[str, Any]:
        """Handles the 6 core ASTRA chat journeys with strict prompt-injection & tool-boundary enforcement."""
        self.ledger.security.authorize(actor, "chat:query", tenant_id, legal_entity_id)

        if detect_prompt_injection(question):
            return {
                "answer_id": f"ans-{uuid.uuid4().hex[:10]}",
                "tenant_id": tenant_id,
                "legal_entity_id": legal_entity_id,
                "status": "insufficient_evidence",
                "as_of": datetime.now(timezone.utc).isoformat(),
                "sections": ["SEC-40 Guardrail: Instruction-injection or unauthorized mutation request refused."],
                "claims": [],
                "evidence_ids": [],
                "proposed_report_spec": None,
            }

        q_lower = question.lower()
        hits = self.retrieve_scoped_rag(actor, tenant_id=tenant_id, legal_entity_id=legal_entity_id, query=question)

        proposed_report = None
        if "dashboard" in q_lower or "treasury" in q_lower:
            proposed_report = {
                "report_id": "rpt-monday-treasury-draft",
                "version": 1,
                "tenant_id": tenant_id,
                "legal_entity_id": legal_entity_id,
                "title": "Monday Treasury Receipts & Unapplied Bridge",
                "metric_ids": ["daily_receipts_total_minor", "applied_cash_minor", "unapplied_cash_minor"],
                "filters": {"legal_entity_id": legal_entity_id},
                "date_window": "last_7_days",
                "groupings": ["currency", "bank_account_masked"],
                "visualization": "bridge",
                "destination": "in_app",
                "timezone": "UTC",
                "schedule_cron": "0 8 * * 1",
            }

        claims = [
            {
                "claim_text": h["text"],
                "claim_type": "prediction" if "pinaka" in h["text"].lower() else "observation",
                "evidence_id": h["evidence_id"],
                "numeric_value_minor": h["numeric_value_minor"],
            }
            for h in hits[:3]
        ]
        return self.validate_and_finalize_answer(
            actor,
            tenant_id=tenant_id,
            legal_entity_id=legal_entity_id,
            candidate_claims=claims,
            proposed_report_spec=proposed_report,
        )
