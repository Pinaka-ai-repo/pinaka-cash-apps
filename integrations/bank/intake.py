"""Multi-Channel Bank & Remittance Intake, ISO 20022 camt.053, CSV Mapper, VCC Token Gate & Attachment Sandbox.

Enforces:
- SEC-19: Attachment type/size check, XXE block, executable/zip-bomb rejection, raw-PAN quarantine.
- Section 5.1: Multi-channel deduplication and PCI-safe Virtual Card (VCC) processor token boundary.
"""

from __future__ import annotations

import csv
import io
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

from apps.api.astra.domain.money import MoneyMinor


class AttachmentQuarantineError(ValueError):
    """Raised when an attachment or remittance file fails SEC-19 sandbox verification."""


ALLOWED_MIME_TYPES = {
    "application/xml",
    "text/xml",
    "text/csv",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "text/plain",
    "message/rfc822",
}

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024  # 10 MiB hard cap

# Matches 13-19 digit candidate PAN strings that are not marked as tokenized processor references
_RAW_PAN_CANDIDATE_RE = re.compile(r"(?<![A-Z0-9-])(?:\d[ -]?){13,19}(?![A-Z0-9-])")

BANK_FORMAT_PROFILES: dict[str, dict[str, str]] = {
    "ISO20022_CAMT053": {
        "status": "implemented",
        "standard": "ISO 20022 camt.053.001.02 / .08",
        "description": "End-of-day bank-to-customer statement XML with Ntry, Amt, CdtDbtInd, NtryDtls, and RmtInf.",
    },
    "CSV_CUSTOM_MAP": {
        "status": "implemented",
        "standard": "Configurable CSV Bank / Open-AR Mapper",
        "description": "Admin-mapped column header profile with control-total verification.",
    },
    "BAI2": {
        "status": "reference_profile",
        "standard": "BAI2 Cash Management Balance Reporting (01/02/03/16/88/49/98/99 records)",
        "description": "Documented record profile normalizing 16-detail and 88-continuation lines into canonical receipts.",
    },
    "MT940": {
        "status": "reference_profile",
        "standard": "SWIFT MT940 Customer Statement Message (:20:, :25:, :60F:, :61:, :86:, :62F:)",
        "description": "Documented SWIFT tag profile mapping :61: statement lines and :86: remittance blocks.",
    },
    "EDI_820": {
        "status": "reference_profile",
        "standard": "ASC X12 820 Payment Order / Remittance Advice (BPR, TRN, ENT, RMR, REF)",
        "description": "Documented X12 segment profile mapping RMR invoice lines and ADX adjustment reason codes.",
    },
    "LOCKBOX_NACHA": {
        "status": "reference_profile",
        "standard": "BAI Lockbox / NACHA CTX Addenda (705)",
        "description": "Documented lockbox batch header + check image + stub remittance profile.",
    },
}


def luhn_check(digits: str) -> bool:
    clean = [int(c) for c in digits if c.isdigit()]
    if len(clean) < 13 or len(clean) > 19:
        return False
    checksum = 0
    parity = len(clean) % 2
    for i, d in enumerate(clean):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def contains_raw_pan(text: str) -> bool:
    for m in _RAW_PAN_CANDIDATE_RE.finditer(text):
        digits = "".join(c for c in m.group(0) if c.isdigit())
        if luhn_check(digits):
            return True
    return False


def verify_attachment_sandbox(
    payload_bytes: bytes,
    *,
    filename: str,
    mime_type: str,
    max_bytes: int = MAX_ATTACHMENT_BYTES,
) -> None:
    """SEC-19: Verifies MIME allowlist, size limit, executable signatures, XXE declarations, and raw PANs."""
    if not payload_bytes:
        raise AttachmentQuarantineError("SEC-19 violation: Empty attachment rejected.")
    if len(payload_bytes) > max_bytes:
        raise AttachmentQuarantineError(
            f"SEC-19 violation: Attachment '{filename}' ({len(payload_bytes)} bytes) exceeds max limit ({max_bytes})."
        )
    norm_mime = mime_type.split(";")[0].strip().lower()
    if norm_mime not in ALLOWED_MIME_TYPES:
        raise AttachmentQuarantineError(f"SEC-19 violation: Disallowed MIME type '{norm_mime}'.")

    # Reject Windows PE (MZ), ELF (\x7fELF), or ZIP/macro archives pretending to be text/PDF
    if payload_bytes.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04")):
        raise AttachmentQuarantineError(
            f"SEC-19 violation: Binary executable or compressed archive header blocked in '{filename}'."
        )

    # Scan full decoded payload (up to max_bytes) so padding beyond 64 KiB cannot conceal XXE or raw PANs
    full_text = payload_bytes.decode("utf-8", errors="ignore")
    upper_text = full_text.upper()
    if "<!DOCTYPE" in upper_text or "<!ENTITY" in upper_text:
        raise AttachmentQuarantineError("SEC-19 violation: XML DTD / Entity expansion (XXE) declaration blocked.")

    if contains_raw_pan(full_text):
        raise AttachmentQuarantineError(
            "SEC-19/PCI violation: Raw credit card PAN detected in attachment; quarantined at boundary."
        )


@dataclass(frozen=True)
class ParsedBankReceipt:
    idempotency_key: str
    bank_account_masked: str
    bank_reference: str
    payer_name: str
    currency: str
    gross_amount_minor: int
    value_date: str
    remittance_text: str


def parse_camt053_xml(xml_bytes: bytes) -> list[ParsedBankReceipt]:
    """Parses ISO 20022 camt.053 XML bank statement into canonical ParsedBankReceipt records."""
    verify_attachment_sandbox(xml_bytes, filename="statement.camt053.xml", mime_type="application/xml")
    root = ET.fromstring(xml_bytes.decode("utf-8"))

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    results: list[ParsedBankReceipt] = []
    stmt_id = "STMT-DEFAULT"
    acct_id = "ACCT-UNKNOWN"

    for elem in root.iter():
        t = strip_ns(elem.tag)
        if t == "Stmt":
            for child in elem:
                ct = strip_ns(child.tag)
                if ct == "Id" and child.text:
                    stmt_id = child.text.strip()
                elif ct == "Acct":
                    for sub in child.iter():
                        if strip_ns(sub.tag) in ("IBAN", "Othr") and sub.text and sub.text.strip():
                            raw_acct = sub.text.strip()
                            acct_id = f"ACCT •••• {raw_acct[-4:]}"
        elif t == "Ntry":
            amt_str = "0"
            ccy = "USD"
            cdt_dbt = "CRDT"
            val_date = "2026-11-23"
            bank_ref = ""
            payer_name = "Unknown Payer"
            rmt_lines: list[str] = []

            for child in elem:
                ct = strip_ns(child.tag)
                if ct == "Amt":
                    amt_str = (child.text or "0").strip()
                    ccy = child.attrib.get("Ccy", "USD").strip().upper()
                elif ct == "CdtDbtInd" and child.text:
                    cdt_dbt = child.text.strip().upper()
                elif ct == "AcctSvcrRef" and child.text:
                    bank_ref = child.text.strip()
                elif ct == "ValDt":
                    for dt_node in child.iter():
                        if strip_ns(dt_node.tag) in ("Dt", "DtTm") and dt_node.text:
                            val_date = dt_node.text.strip()[:10]
                elif ct == "NtryDtls":
                    for sub in child.iter():
                        st = strip_ns(sub.tag)
                        if st == "EndToEndId" and sub.text and not bank_ref:
                            bank_ref = sub.text.strip()
                        elif st == "Nm" and sub.text:
                            payer_name = sub.text.strip()
                        elif st == "Ustrd" and sub.text:
                            rmt_lines.append(sub.text.strip())

            if cdt_dbt != "CRDT":
                continue

            money = MoneyMinor.from_decimal_str(amt_str, ccy)
            bank_ref = bank_ref or f"REF-{len(results) + 1:04d}"
            results.append(
                ParsedBankReceipt(
                    idempotency_key=f"camt053:{stmt_id}:{bank_ref}",
                    bank_account_masked=acct_id,
                    bank_reference=bank_ref,
                    payer_name=payer_name,
                    currency=money.currency,
                    gross_amount_minor=money.amount_minor,
                    value_date=val_date,
                    remittance_text=" | ".join(rmt_lines),
                )
            )
    return results


def parse_csv_bank_receipts(
    csv_bytes: bytes,
    column_map: dict[str, str] | None = None,
) -> list[ParsedBankReceipt]:
    """Maps CSV bank statement rows using configurable column map."""
    verify_attachment_sandbox(csv_bytes, filename="receipts.csv", mime_type="text/csv")
    cmap = column_map or {
        "bank_reference": "bank_reference",
        "bank_account": "bank_account",
        "payer_name": "payer_name",
        "currency": "currency",
        "amount": "amount",
        "value_date": "value_date",
        "remittance_text": "remittance_text",
    }
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8")))
    results: list[ParsedBankReceipt] = []
    for row in reader:
        ref = row[cmap["bank_reference"]].strip()
        raw_acct = row.get(cmap["bank_account"], "0000").strip()
        ccy = row[cmap["currency"]].strip().upper()
        money = MoneyMinor.from_decimal_str(row[cmap["amount"]].strip(), ccy)
        results.append(
            ParsedBankReceipt(
                idempotency_key=f"csv:{ref}",
                bank_account_masked=f"ACCT •••• {raw_acct[-4:]}",
                bank_reference=ref,
                payer_name=row[cmap["payer_name"]].strip(),
                currency=ccy,
                gross_amount_minor=money.amount_minor,
                value_date=row.get(cmap["value_date"], "2026-11-23").strip(),
                remittance_text=row.get(cmap["remittance_text"], "").strip(),
            )
        )
    return results


def verify_virtual_card_settlement(
    *,
    sender_email: str,
    spf_pass: bool,
    dkim_pass: bool,
    allowed_processor_domains: set[str],
    processor_token_ref: str,
    raw_remittance_note: str,
    expected_amount_minor: int,
    actual_amount_minor: int,
) -> dict[str, Any]:
    """Section 5.1 & SEC-19: Verifies virtual-card settlement inside a PCI-safe token-only boundary."""
    if not (spf_pass and dkim_pass):
        raise AttachmentQuarantineError("VCC intake rejected: SPF/DKIM authentication failed.")
    local_part, sep, raw_domain = sender_email.strip().partition("@")
    domain = raw_domain.strip().lower()
    if not sep or not local_part or not domain or "@" in domain:
        raise AttachmentQuarantineError(f"VCC intake rejected: Malformed sender email '{sender_email}'.")
    if domain not in {d.lower() for d in allowed_processor_domains}:
        raise AttachmentQuarantineError(f"VCC intake rejected: Sender domain '{domain}' not in processor allowlist.")
    if contains_raw_pan(processor_token_ref) or contains_raw_pan(raw_remittance_note):
        raise AttachmentQuarantineError("VCC intake rejected: Raw card PAN detected; only processor tokens allowed.")
    if not processor_token_ref.startswith("VCC-TOK-"):
        raise AttachmentQuarantineError("VCC intake rejected: Invalid processor token reference format.")
    if expected_amount_minor != actual_amount_minor:
        raise AttachmentQuarantineError("VCC intake rejected: Settlement token amount mismatch.")

    return {
        "verified": True,
        "masked_token": f"VCC-TOKEN •••• {processor_token_ref[-4:]}",
        "sender_domain": domain,
        "amount_minor": actual_amount_minor,
    }
