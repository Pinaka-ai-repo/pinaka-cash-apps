"""Stripe Test-Mode Settlement Adapter, Signed Webhook Verifier & Gross-to-Net Payout Bridge.

Enforces:
- SEC-20: Webhook HMAC-SHA256 verification, 300s clock tolerance, replay event deduplication, dual-key rotation.
- Accounting Bridge: Gross balance transactions - processor fees - refunds = Net payout matching bank line.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


class WebhookVerificationError(PermissionError):
    """Raised when a webhook signature, timestamp, or replay check fails (SEC-20)."""


@dataclass(frozen=True)
class StripePayoutBridgeResult:
    payout_id: str
    currency: str
    gross_charges_minor: int
    processor_fees_minor: int
    refunds_minor: int
    net_payout_minor: int
    matched_bank_line_minor: int
    reconciled: bool
    charge_references: list[str]


class StripeTestAdapter:
    def __init__(self, active_secrets: tuple[str, ...], clock_tolerance_seconds: int = 300) -> None:
        if not active_secrets or any(not s.strip() for s in active_secrets):
            raise ValueError("SEC-14/SEC-20: At least one non-empty webhook signing secret is required.")
        self._secrets = active_secrets
        self._tolerance = clock_tolerance_seconds
        self._seen_event_ids: set[str] = set()

    def rotate_secrets(self, new_primary: str, previous_secondary: str | None = None) -> None:
        """SEC-20: Supports zero-downtime webhook secret rotation."""
        self._secrets = (new_primary, previous_secondary) if previous_secondary else (new_primary,)

    @staticmethod
    def sign_payload(payload_bytes: bytes, secret: str, timestamp: int) -> str:
        signed = f"{timestamp}.".encode("utf-8") + payload_bytes
        sig = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
        return f"t={timestamp},v1={sig}"

    def verify_and_parse_webhook(
        self,
        payload_bytes: bytes,
        signature_header: str,
        *,
        now_epoch: float | None = None,
    ) -> dict[str, Any]:
        """SEC-20: Verifies HMAC-SHA256 signature, clock skew <= 300s, and rejects replayed event IDs."""
        now = time.time() if now_epoch is None else now_epoch
        parts: dict[str, str] = {}
        for item in signature_header.split(","):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                parts[k] = v

        if "t" not in parts or "v1" not in parts:
            raise WebhookVerificationError("SEC-20 violation: Malformed Stripe-Signature header.")

        ts = int(parts["t"])
        if abs(now - ts) > self._tolerance:
            raise WebhookVerificationError(
                f"SEC-20 violation: Webhook timestamp skew ({abs(now - ts):.0f}s) exceeds tolerance ({self._tolerance}s)."
            )

        signed_payload = f"{ts}.".encode("utf-8") + payload_bytes
        matched = False
        for sec in self._secrets:
            expected_sig = hmac.new(sec.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected_sig, parts["v1"]):
                matched = True
                break

        if not matched:
            raise WebhookVerificationError("SEC-20 violation: Invalid webhook HMAC signature.")

        event = json.loads(payload_bytes.decode("utf-8"))
        event_id = str(event.get("id", "")).strip()
        if not event_id:
            raise WebhookVerificationError("SEC-20 violation: Missing webhook event id.")
        if event_id in self._seen_event_ids:
            raise WebhookVerificationError(f"SEC-20 violation: Replayed webhook event '{event_id}' rejected.")

        self._seen_event_ids.add(event_id)
        return event

    def reconcile_payout_batch(
        self,
        *,
        payout_id: str,
        currency: str,
        balance_transactions: list[dict[str, Any]],
        bank_statement_net_minor: int,
    ) -> StripePayoutBridgeResult:
        """Models gross charges, Stripe fees, and refunds separately and bridges to the net bank line."""
        gross_minor = 0
        fees_minor = 0
        refunds_minor = 0
        refs: list[str] = []

        for txn in balance_transactions:
            ttype = txn.get("type", "charge")
            amt = int(txn["amount_minor"])
            fee = int(txn.get("fee_minor", 0))
            if ttype == "charge":
                gross_minor += amt
                fees_minor += fee
                if txn.get("invoice_ref"):
                    refs.append(str(txn["invoice_ref"]))
            elif ttype == "refund":
                refunds_minor += abs(amt)
                fees_minor += fee

        net_minor = gross_minor - fees_minor - refunds_minor
        return StripePayoutBridgeResult(
            payout_id=payout_id,
            currency=currency.upper(),
            gross_charges_minor=gross_minor,
            processor_fees_minor=fees_minor,
            refunds_minor=refunds_minor,
            net_payout_minor=net_minor,
            matched_bank_line_minor=bank_statement_net_minor,
            reconciled=(net_minor == bank_statement_net_minor),
            charge_references=refs,
        )
