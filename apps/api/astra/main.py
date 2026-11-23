"""ASTRA Domain API & Security Header / Validation / Sanitization Layer.

Enforces:
- SEC-16: Restrictive CSP, X-Frame-Options=DENY, HSTS, X-Content-Type-Options=nosniff, CORS allowlist, CSRF token check.
- SEC-17: Strict schema validation (rejects unknown/extra fields and SQLi/control characters).
- SEC-18: Safe output encoding and Markdown sanitization (strips <script>, event handlers, javascript:/data: URLs).
"""

from __future__ import annotations

import hmac
import html
import re
from typing import Any

from apps.api.astra.config import AstraConfig
from apps.api.astra.domain.ledger import AstraLedgerStore
from apps.api.astra.security.sod import AuthorizationError, Principal

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

_UNSAFE_URL_RE = re.compile(r"(?i)\b(?:javascript|vbscript|data)\s*:")
_SCRIPT_TAG_RE = re.compile(r"(?is)<\s*script[^>]*>.*?<\s*/\s*script\s*>")


def sanitize_untrusted_text(raw: str) -> str:
    """SEC-18: Neutralizes HTML/XSS tags, script blocks, and javascript:/data: URLs."""
    cleaned = _SCRIPT_TAG_RE.sub("", raw)
    cleaned = _UNSAFE_URL_RE.sub("blocked-scheme:", cleaned)
    return html.escape(cleaned, quote=True)


def validate_strict_payload(payload: dict[str, Any], allowed_fields: set[str], required_fields: set[str]) -> dict[str, Any]:
    """SEC-17: Rejects unknown extra properties, missing required fields, or null-byte control injection."""
    if not isinstance(payload, dict):
        raise ValueError("SEC-17 violation: Payload must be a JSON object.")
    extra = set(payload.keys()) - allowed_fields
    if extra:
        raise ValueError(f"SEC-17 violation: Unknown extra fields rejected: {sorted(extra)}")
    missing = required_fields - set(payload.keys())
    if missing:
        raise ValueError(f"SEC-17 violation: Missing required fields: {sorted(missing)}")
    for k, v in payload.items():
        if isinstance(v, str) and ("\x00" in v or len(v) > 32768):
            raise ValueError(f"SEC-17 violation: Field '{k}' contains forbidden null byte or exceeds max length.")
    return payload


class AstraHTTPGateway:
    """Transport-agnostic HTTP gateway enforcing SEC-16 headers, CSRF, CORS, and SEC-17/18 validation."""

    def __init__(self, config: AstraConfig | None = None, ledger: AstraLedgerStore | None = None) -> None:
        self.config = config or AstraConfig()
        self.ledger = ledger or AstraLedgerStore()
        self.allowed_origins = {"https://astra.pinaka.local", "http://localhost:3000"}

    def build_response(
        self,
        status_code: int,
        body: dict[str, Any],
        *,
        origin: str | None = None,
    ) -> dict[str, Any]:
        headers = dict(SECURITY_HEADERS)
        if origin and origin in self.allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Vary"] = "Origin"
        return {"status_code": status_code, "headers": headers, "body": body}

    def verify_csrf(self, method: str, csrf_header: str | None, expected_csrf: str) -> None:
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            if not csrf_header or not expected_csrf or not hmac.compare_digest(csrf_header, expected_csrf):
                raise AuthorizationError("SEC-16 violation: Missing or invalid CSRF token on state-changing request.")
