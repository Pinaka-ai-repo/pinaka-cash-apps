"""ASTRA Clean-Install Synthetic Demo Journey (`make demo`).

Proves first-time IT admin onboarding: ingests ISO 20022 camt.053 XML, runs the 10-agent matching pipeline,
enforces Maker-Checker SoD approval, tests all 6 ERP adapters (SAP S/4HANA, Oracle, NetSuite, Odoo, Sage, Universal),
and verifies the SHA-256 hash-chained audit trail.
"""

from __future__ import annotations

import json
from pathlib import Path

from apps.api.astra.domain.ledger import AstraLedgerStore, OpenARItem
from apps.api.astra.security.sod import Principal
from integrations.bank.intake import parse_camt053_xml
from integrations.erp.adapters import OpenERPConnectorHub
from ml.agents.pipeline import AgenticCashAppOrchestrator, PayerProfile

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def run_demo_journey() -> dict[str, object]:
    ledger = AstraLedgerStore()
    erp_hub = OpenERPConnectorHub()
    orch = AgenticCashAppOrchestrator()

    analyst = Principal(
        user_id="usr-analyst-01",
        tenant_id="TENANT-01",
        allowed_legal_entities=("US-CORP-01",),
        roles=("analyst",),
    )
    controller = Principal(
        user_id="usr-controller-01",
        tenant_id="TENANT-01",
        allowed_legal_entities=("US-CORP-01",),
        roles=("controller",),
        mfa_verified=True,
        step_up_verified=True,
    )
    treasury = Principal(
        user_id="usr-treasury-01",
        tenant_id="TENANT-01",
        allowed_legal_entities=("US-CORP-01",),
        roles=("treasury",),
    )

    open_items = [
        OpenARItem(
            item_id="IT-104",
            tenant_id="TENANT-01",
            legal_entity_id="US-CORP-01",
            customer_id="CUST-0104",
            invoice_number="INV-100104",
            po_number="PO-500104",
            currency="USD",
            original_amount_minor=4250000,
            open_amount_minor=4250000,
        ),
        OpenARItem(
            item_id="IT-219",
            tenant_id="TENANT-01",
            legal_entity_id="US-CORP-01",
            customer_id="CUST-0219",
            invoice_number="INV-100219",
            po_number="PO-500219",
            currency="USD",
            original_amount_minor=1850000,
            open_amount_minor=1850000,
        ),
    ]
    for it in open_items:
        ledger.upsert_open_item(analyst, it)

    profiles = {
        "CUST-0104": PayerProfile("CUST-0104", "Apex Precision Manufacturing Corp"),
        "CUST-0219": PayerProfile("CUST-0219", "Northstar Logistics LLC"),
    }

    camt_path = REPO_ROOT / "fixtures" / "synthetic" / "camt053_sample.xml"
    camt_bytes = camt_path.read_bytes()
    parsed_receipts = parse_camt053_xml(camt_bytes)

    erp_acks: list[dict[str, object]] = []
    erp_targets = ["sap_s4hana", "oracle_fusion", "netsuite", "odoo", "sage_intacct", "universal_rest_csv"]

    for idx, pr in enumerate(parsed_receipts):
        rec, _ = ledger.ingest_receipt(
            analyst,
            tenant_id="TENANT-01",
            legal_entity_id="US-CORP-01",
            idempotency_key=pr.idempotency_key,
            source_channel="camt.053",
            raw_payload_bytes=camt_bytes,
            mime_type="application/xml",
            bank_account_masked=pr.bank_account_masked,
            bank_reference=pr.bank_reference,
            payer_name_raw=pr.payer_name,
            customer_id=None,
            currency=pr.currency,
            gross_amount_minor=pr.gross_amount_minor,
        )

        decision = orch.process_payment(
            payment_id=rec.receipt_id,
            doc_id=rec.artifact_id,
            payer_name_raw=pr.payer_name,
            currency=pr.currency,
            net_amount_minor=rec.net_amount_minor,
            value_date=pr.value_date,
            remittance_text=pr.remittance_text,
            open_items=ledger.list_open_items(analyst, "TENANT-01", "US-CORP-01"),
            profiles=profiles,
        )

        rec = ledger.allocate_and_propose(
            analyst,
            tenant_id="TENANT-01",
            legal_entity_id="US-CORP-01",
            receipt_id=rec.receipt_id,
            expected_version=rec.version,
            proposed_allocations=decision["proposed_allocations"],
            match_tier=decision["match_tier"] or 1,
            confidence=decision["overall_confidence"],
            score_margin=decision["score_margin"],
            rationale=decision["rationale"],
        )

        target_erp = erp_targets[idx % len(erp_targets)]
        intent, _ = ledger.approve_and_create_posting_intent(
            controller,
            tenant_id="TENANT-01",
            legal_entity_id="US-CORP-01",
            receipt_id=rec.receipt_id,
            erp_target=target_erp,
            idempotency_key=f"post:{rec.idempotency_key}",
        )
        ack = erp_hub.post_to_erp(target_erp, intent)
        erp_acks.append(ack)
        ledger.attest_reconciliation(
            treasury,
            tenant_id="TENANT-01",
            legal_entity_id="US-CORP-01",
            receipt_id=rec.receipt_id,
        )

    return {
        "status": "reconciled",
        "receipts_processed": len(parsed_receipts),
        "erp_acknowledgments": erp_acks,
        "audit_chain_verified": ledger.audit.verify_integrity(),
        "audit_head_sha256": ledger.audit.head_hash(),
    }


if __name__ == "__main__":
    print(json.dumps(run_demo_journey(), indent=2))
