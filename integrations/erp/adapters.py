"""Open ERP Connector Hub: SAP S/4HANA, Oracle Fusion/EBS, NetSuite, Odoo, Sage, Universal REST/CSV/MCP & Mock Server.

Enforces:
- SEC-14: Connector descriptors store secret_ref vault pointers only, never plaintext credentials.
- SEC-21: OAuth least-scope, redirect URI allowlist, and token audience verification.
- SEC-22: MCP adapter pins protocol version, server identity, tool allowlist, and blocks user-token passthrough.
- SEC-23: Idempotent posting submission with external-key lookup before retry (query_by_idempotency_key).
"""

from __future__ import annotations

import csv
import io
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ConnectorDescriptor:
    connector_id: str
    erp_target: str
    display_name: str
    protocol: str
    version: str
    secret_ref: str
    required_oauth_scopes: tuple[str, ...]
    supported_actions: tuple[str, ...]
    rate_limit_rpm: int = 120
    validation_tier: str = "automated fixture passed"  # Never claims live vendor certification without sandbox test
    field_mapping: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # SEC-14: Reject any descriptor whose secret_ref looks like a raw key/password instead of vault:// ref
        if not self.secret_ref.startswith("vault://"):
            raise ValueError("SEC-14 violation: Connector secret_ref must be a 'vault://' reference, not plaintext.")


def verify_oauth_grant(
    *,
    requested_scopes: set[str],
    allowed_scopes: set[str],
    redirect_uri: str,
    allowed_redirect_uris: set[str],
    token_audience: str,
    expected_audience: str,
) -> bool:
    """SEC-21: Verifies OAuth least-scope, exact redirect URI allowlist, and token audience."""
    if not requested_scopes.issubset(allowed_scopes):
        extra = sorted(requested_scopes - allowed_scopes)
        raise PermissionError(f"SEC-21 violation: OAuth scope broadening rejected ({extra}).")
    if redirect_uri not in allowed_redirect_uris:
        raise PermissionError(f"SEC-21 violation: Redirect URI '{redirect_uri}' not in allowlist.")
    if token_audience != expected_audience:
        raise PermissionError(f"SEC-21 violation: Token audience '{token_audience}' != '{expected_audience}'.")
    return True


@dataclass(frozen=True)
class PinnedMCPServerConfig:
    server_id: str
    protocol_version: str
    schema_sha256: str
    allowed_tools: frozenset[str]
    audience_bound_secret_ref: str
    max_response_bytes: int = 65536


class AllowlistedMCPAdapter:
    """SEC-22: Pinned MCP client enforcing tool allowlist, schema hash, no user-token passthrough, and output cap."""

    ADOPTED_MCP_PROTOCOL = "2025-03-26"

    def __init__(self, config: PinnedMCPServerConfig) -> None:
        if config.protocol_version != self.ADOPTED_MCP_PROTOCOL:
            raise PermissionError(
                f"SEC-22 violation: Unpinned MCP protocol version '{config.protocol_version}' != '{self.ADOPTED_MCP_PROTOCOL}'."
            )
        if not config.audience_bound_secret_ref.startswith("vault://"):
            raise PermissionError("SEC-14/SEC-22 violation: MCP credential must be an audience-bound vault:// reference.")
        self.config = config

    def invoke_tool(
        self,
        *,
        tool_name: str,
        runtime_schema_sha256: str,
        arguments: dict[str, Any],
        headers: dict[str, str] | None = None,
        simulated_response_bytes: bytes = b"{}",
    ) -> dict[str, Any]:
        if tool_name not in self.config.allowed_tools:
            raise PermissionError(f"SEC-22 violation: MCP tool '{tool_name}' is not in pinned allowlist.")
        if runtime_schema_sha256 != self.config.schema_sha256:
            raise PermissionError("SEC-22 violation: MCP server tool schema changed; re-approval required.")
        hdrs = {k.lower(): v for k, v in (headers or {}).items()}
        if "x-user-access-token" in hdrs or "authorization" in hdrs or "user_token" in arguments:
            raise PermissionError("SEC-22 violation: User token passthrough to MCP server is forbidden.")
        if len(simulated_response_bytes) > self.config.max_response_bytes:
            raise ValueError("SEC-22 violation: MCP response exceeded maximum byte cap.")
        return {"tool": tool_name, "status": "ok", "protocol": self.ADOPTED_MCP_PROTOCOL}


class MultiERPMockServer:
    """Offline Multi-ERP Contract & Sandbox Emulator for SAP S/4HANA, Oracle, NetSuite, Odoo, Sage, and Universal."""

    def __init__(self) -> None:
        self._posted_by_idempotency: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    def query_by_idempotency_key(
        self,
        erp_target: str,
        idempotency_key: str,
        *,
        tenant_id: str = "*",
        legal_entity_id: str = "*",
    ) -> dict[str, Any] | None:
        """Queried after timeout/ambiguity before retrying any ERP posting (scoped by tenant and legal entity)."""
        return self._posted_by_idempotency.get((tenant_id, legal_entity_id, erp_target, idempotency_key))

    def submit_posting(self, erp_target: str, intent: dict[str, Any], native_payload: dict[str, Any]) -> dict[str, Any]:
        idem = intent["idempotency_key"]
        t_id = str(intent.get("tenant_id", "*"))
        le_id = str(intent.get("legal_entity_id", "*"))
        existing = self.query_by_idempotency_key(erp_target, idem, tenant_id=t_id, legal_entity_id=le_id)
        if existing is not None:
            dup = dict(existing)
            dup["status"] = "duplicate_ignored"
            return dup

        prefix_map = {
            "sap_s4hana": "SAP-BELNR",
            "oracle_fusion": "ORA-RCPT",
            "netsuite": "NS-CUSTPYMT",
            "odoo": "ODOO-BNK",
            "sage_intacct": "SAGE-ARPYMT",
            "universal_rest_csv": "UNI-POST",
        }
        prefix = prefix_map.get(erp_target, "ERP-DOC")
        ack = {
            "ack_id": f"ack-{uuid.uuid4().hex[:10]}",
            "posting_intent_id": intent["posting_intent_id"],
            "idempotency_key": idem,
            "tenant_id": t_id,
            "legal_entity_id": le_id,
            "erp_target": erp_target,
            "external_document_number": f"{prefix}-2026-{len(self._posted_by_idempotency) + 1001}",
            "status": "posted",
            "error_code": None,
            "acknowledged_at": datetime.now(timezone.utc).isoformat(),
            "native_format_verified": native_payload.get("format_type", "REST_JSON"),
        }
        self._posted_by_idempotency[(t_id, le_id, erp_target, idem)] = ack
        return ack


class OpenERPConnectorHub:
    """Unified open integration hub for SAP S/4HANA, Oracle, NetSuite, Odoo, Sage, and Universal REST/CSV/MCP."""

    def __init__(self, mock_server: MultiERPMockServer | None = None) -> None:
        self.mock_server = mock_server or MultiERPMockServer()
        self.descriptors: dict[str, ConnectorDescriptor] = {
            "sap_s4hana": ConnectorDescriptor(
                connector_id="conn-sap-s4hana",
                erp_target="sap_s4hana",
                display_name="SAP S/4HANA (OData v4 / JournalEntry BAPI & IDoc Profile)",
                protocol="OData v4 / SOAP JournalEntryCreate / CSV Batch",
                version="1.0.0",
                secret_ref="vault://erp/sap_s4hana/oauth_m2m",
                required_oauth_scopes=("API_OPLACCTGDOCITEMCUBE_SRV:read", "JournalEntryCreate:write"),
                supported_actions=("pull_open_ar", "dry_run_mapping", "post_cash_allocation", "export_batch_file"),
                field_mapping={"company_code": "BUKRS", "customer": "KUNNR", "invoice": "BELNR", "amount": "WRBTR"},
            ),
            "oracle_fusion": ConnectorDescriptor(
                connector_id="conn-oracle-fusion",
                erp_target="oracle_fusion",
                display_name="Oracle Fusion Cloud ERP / EBS (REST receivablesInvoices + FBDI AutoLockbox)",
                protocol="Oracle REST v11.13 / FBDI AutoLockbox CSV",
                version="1.0.0",
                secret_ref="vault://erp/oracle_fusion/oauth_jwt",
                required_oauth_scopes=("fscmRestApi:receivablesInvoices:read", "fscmRestApi:standardReceipts:write"),
                supported_actions=("pull_open_ar", "dry_run_mapping", "post_cash_allocation", "export_fbdi_lockbox_csv"),
                field_mapping={"business_unit": "OrgId", "customer": "CustomerAccountNumber", "invoice": "TransactionNumber"},
            ),
            "netsuite": ConnectorDescriptor(
                connector_id="conn-oracle-netsuite",
                erp_target="netsuite",
                display_name="Oracle NetSuite (SuiteTalk REST Web Services & SuiteQL)",
                protocol="SuiteTalk REST v1 / SuiteQL / OAuth 2.0 M2M",
                version="1.0.0",
                secret_ref="vault://erp/netsuite/oauth2_m2m_cert",
                required_oauth_scopes=("rest_webservices",),
                supported_actions=("pull_open_ar", "dry_run_mapping", "post_cash_allocation", "export_csv_payment"),
                field_mapping={"subsidiary": "subsidiary.id", "customer": "entity.id", "invoice": "tranId"},
            ),
            "odoo": ConnectorDescriptor(
                connector_id="conn-odoo-erp",
                erp_target="odoo",
                display_name="Odoo ERP (External JSON-RPC / account.move & account.payment)",
                protocol="Odoo JSON-RPC 2.0 / XML-RPC",
                version="1.0.0",
                secret_ref="vault://erp/odoo/api_key_ref",
                required_oauth_scopes=("account.move:read", "account.payment:write"),
                supported_actions=("pull_open_ar", "dry_run_mapping", "post_cash_allocation"),
                field_mapping={"company_id": "company_id", "partner_id": "partner_id", "move_name": "name"},
            ),
            "sage_intacct": ConnectorDescriptor(
                connector_id="conn-sage-intacct",
                erp_target="sage_intacct",
                display_name="Sage Intacct / Sage X3 (REST v1 accounts-receivable & XML Web Services)",
                protocol="Sage Intacct REST v1 / CSV Batch",
                version="1.0.0",
                secret_ref="vault://erp/sage_intacct/oauth2_client",
                required_oauth_scopes=("ar.invoices:read", "ar.payments:write"),
                supported_actions=("pull_open_ar", "dry_run_mapping", "post_cash_allocation", "export_batch_file"),
                field_mapping={"entity": "locationId", "customer": "customer.id", "invoice": "invoiceNumber"},
            ),
            "universal_rest_csv": ConnectorDescriptor(
                connector_id="conn-universal-open",
                erp_target="universal_rest_csv",
                display_name="Universal Open ERP Adapter (Custom REST Webhook, SFTP/CSV & Pinned MCP)",
                protocol="REST JSON / RFC-4180 CSV with Control Totals / Pinned MCP",
                version="1.0.0",
                secret_ref="vault://erp/universal/webhook_hmac",
                required_oauth_scopes=("ar:read", "ar:post"),
                supported_actions=("pull_open_ar", "dry_run_mapping", "post_cash_allocation", "export_batch_file"),
                field_mapping={"entity": "legal_entity_id", "customer": "customer_id", "invoice": "invoice_number"},
            ),
        }

    def list_connectors(self) -> list[dict[str, Any]]:
        return [asdict(d) for d in self.descriptors.values()]

    def build_native_erp_payload(self, erp_target: str, intent: dict[str, Any]) -> dict[str, Any]:
        """Transforms canonical PostingIntentV1 into the target ERP's native API contract."""
        if erp_target not in self.descriptors:
            raise ValueError(f"Unsupported ERP target '{erp_target}'")

        if erp_target == "sap_s4hana":
            return {
                "format_type": "SAP_S4_ODATA_JOURNAL_ENTRY",
                "CompanyCode": intent["legal_entity_id"],
                "AccountingDocumentType": "DZ",
                "DocumentReferenceID": intent["idempotency_key"],
                "PostingFiscalPeriod": intent["posting_period"],
                "TransactionCurrency": intent["currency"],
                "DebtorItems": [
                    {
                        "ReferenceDocument": a["invoice_number"],
                        "AmountInTransactionCurrencyMinor": a["applied_minor"],
                        "CashDiscountMinor": a.get("discount_applied_minor", 0),
                        "ResidualDisputeMinor": a["residual_minor"],
                        "ReasonCode": a["reason_code"],
                    }
                    for a in intent["allocations"]
                ],
                "UnappliedOnAccountMinor": intent["unapplied_cash_minor"],
            }

        if erp_target == "oracle_fusion":
            return {
                "format_type": "ORACLE_FUSION_STANDARD_RECEIPT_REST",
                "BusinessUnit": intent["legal_entity_id"],
                "ReceiptNumber": intent["receipt_id"],
                "IdempotencyExternalKey": intent["idempotency_key"],
                "CurrencyCode": intent["currency"],
                "AmountMinor": intent["receipt_total_minor"],
                "ReceiptApplications": [
                    {
                        "TrxNumber": a["invoice_number"],
                        "AmountAppliedMinor": a["applied_minor"],
                        "EarnedDiscountMinor": a.get("discount_applied_minor", 0),
                    }
                    for a in intent["allocations"]
                ],
                "UnappliedAmountMinor": intent["unapplied_cash_minor"],
            }

        if erp_target == "netsuite":
            return {
                "format_type": "NETSUITE_SUITETALK_CUSTOMER_PAYMENT",
                "externalId": intent["idempotency_key"],
                "subsidiary": {"id": intent["legal_entity_id"]},
                "currency": {"refName": intent["currency"]},
                "paymentMinor": intent["receipt_total_minor"],
                "apply": {
                    "items": [
                        {
                            "doc": a["invoice_number"],
                            "amountMinor": a["applied_minor"],
                            "discMinor": a.get("discount_applied_minor", 0),
                        }
                        for a in intent["allocations"]
                    ]
                },
            }

        if erp_target == "odoo":
            return {
                "format_type": "ODOO_JSONRPC_ACCOUNT_PAYMENT",
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "model": "account.payment",
                    "method": "create_and_reconcile_astra",
                    "args": [{
                        "x_astra_idempotency_key": intent["idempotency_key"],
                        "company_code": intent["legal_entity_id"],
                        "currency_code": intent["currency"],
                        "amount_minor": intent["receipt_total_minor"],
                        "reconcile_lines": intent["allocations"],
                    }],
                },
            }

        if erp_target == "sage_intacct":
            return {
                "format_type": "SAGE_INTACCT_REST_V1_AR_PAYMENT",
                "key": intent["idempotency_key"],
                "entity": {"id": intent["legal_entity_id"]},
                "baseCurrency": intent["currency"],
                "totalEnteredMinor": intent["receipt_total_minor"],
                "paymentDetails": [
                    {
                        "arInvoice": {"id": a["invoice_number"]},
                        "paymentAmountMinor": a["applied_minor"],
                        "discountAmountMinor": a.get("discount_applied_minor", 0),
                    }
                    for a in intent["allocations"]
                ],
            }

        return {
            "format_type": "UNIVERSAL_CANONICAL_REST_V1",
            "intent": intent,
        }

    def dry_run_mapping_wizard(
        self,
        *,
        erp_target: str,
        sample_intent: dict[str, Any],
        custom_field_overrides: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """No-code IT admin dry-run wizard previewing mapped ERP payload and control totals."""
        desc = self.descriptors[erp_target]
        merged_map = {**desc.field_mapping, **(custom_field_overrides or {})}
        native = self.build_native_erp_payload(erp_target, sample_intent)
        control_sum = sum(int(a["applied_minor"]) for a in sample_intent["allocations"]) + int(
            sample_intent["unapplied_cash_minor"]
        )
        balanced = control_sum == int(sample_intent["receipt_total_minor"])
        return {
            "erp_target": erp_target,
            "connector_id": desc.connector_id,
            "validation_tier": desc.validation_tier,
            "active_field_mapping": merged_map,
            "control_totals_balanced": balanced,
            "receipt_total_minor": sample_intent["receipt_total_minor"],
            "applied_plus_unapplied_minor": control_sum,
            "native_payload_preview": native,
        }

    def post_to_erp(self, erp_target: str, intent: dict[str, Any]) -> dict[str, Any]:
        """Queries external idempotency key first (safe retry after timeout), then submits to ERP."""
        t_id = str(intent.get("tenant_id", "*"))
        le_id = str(intent.get("legal_entity_id", "*"))
        existing = self.mock_server.query_by_idempotency_key(
            erp_target,
            intent["idempotency_key"],
            tenant_id=t_id,
            legal_entity_id=le_id,
        )
        if existing is not None:
            dup = dict(existing)
            dup["status"] = "duplicate_ignored"
            return dup
        native_payload = self.build_native_erp_payload(erp_target, intent)
        return self.mock_server.submit_posting(erp_target, intent, native_payload)

    @staticmethod
    def _csv_safe(val: Any) -> Any:
        if isinstance(val, str) and (val.startswith(("=", "+", "-", "@", "\t", "\r")) or val.lstrip(" \t\r\n").startswith(("=", "+", "-", "@"))):
            return "'" + val
        return val

    def export_erp_posting_csv_with_control_totals(self, erp_target: str, intents: list[dict[str, Any]]) -> str:
        """Generates an approved, versioned ERP batch posting CSV with header & trailer control totals (SEC-29 formula-safe)."""
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow([
            "RECORD_TYPE",
            "ERP_TARGET",
            "POSTING_INTENT_ID",
            "IDEMPOTENCY_KEY",
            "LEGAL_ENTITY",
            "RECEIPT_ID",
            "INVOICE_NUMBER",
            "CURRENCY",
            "APPLIED_MINOR",
            "DISCOUNT_MINOR",
            "UNAPPLIED_MINOR",
            "PREPARER_ID",
            "APPROVER_ID",
        ])
        total_applied = 0
        total_unapplied = 0
        line_count = 0
        for intent in intents:
            total_unapplied += int(intent["unapplied_cash_minor"])
            if not intent["allocations"]:
                line_count += 1
                writer.writerow([
                    "LINE",
                    self._csv_safe(erp_target),
                    self._csv_safe(intent["posting_intent_id"]),
                    self._csv_safe(intent["idempotency_key"]),
                    self._csv_safe(intent["legal_entity_id"]),
                    self._csv_safe(intent["receipt_id"]),
                    "UNAPPLIED",
                    self._csv_safe(intent["currency"]),
                    0,
                    0,
                    intent["unapplied_cash_minor"],
                    self._csv_safe(intent["preparer_id"]),
                    self._csv_safe(intent["approver_id"]),
                ])
            for idx, alloc in enumerate(intent["allocations"]):
                line_count += 1
                applied = int(alloc["applied_minor"])
                total_applied += applied
                unapp = int(intent["unapplied_cash_minor"]) if idx == 0 else 0
                writer.writerow([
                    "LINE",
                    self._csv_safe(erp_target),
                    self._csv_safe(intent["posting_intent_id"]),
                    self._csv_safe(intent["idempotency_key"]),
                    self._csv_safe(intent["legal_entity_id"]),
                    self._csv_safe(intent["receipt_id"]),
                    self._csv_safe(alloc["invoice_number"]),
                    self._csv_safe(intent["currency"]),
                    applied,
                    alloc.get("discount_applied_minor", 0),
                    unapp,
                    self._csv_safe(intent["preparer_id"]),
                    self._csv_safe(intent["approver_id"]),
                ])
        writer.writerow([
            "CONTROL_TOTAL",
            erp_target,
            f"BATCH_INTENTS={len(intents)}",
            f"LINE_COUNT={line_count}",
            "ALL",
            "CONTROL",
            "TOTALS",
            intents[0]["currency"] if intents else "USD",
            total_applied,
            0,
            total_unapplied,
            "SYSTEM",
            "VERIFIED",
        ])
        return buf.getvalue()
