"""Segregation of Duties (SoD), Maker-Checker, OIDC/Session Security & Log Redaction.

Enforces:
- SEC-03..SEC-11: OIDC claims, MFA step-up, expiring/revocable sessions, 8-role deny-by-default RBAC,
  incompatible role pairs, maker-checker (no self-approval), service identity TTL/scope, offboarding & break-glass.
- SEC-26: Default redaction of PANs, IBANs, tokens, secrets, and raw prompts from logs.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any


class AuthorizationError(PermissionError):
    """Raised when RBAC, tenant/entity scope, SoD, or maker-checker checks fail."""


VALID_ROLES = {
    "analyst",           # Preparer: reviews queues, proposes matches/allocations/deductions
    "controller",        # Approver: approves postings, write-offs, reversals, learning rules, policies
    "treasury",          # Reconciling Reviewer: bank-to-book reconciliation, cash bridge & Treasury reports
    "connector_admin",   # Configures ERP/Bank/Stripe/Mail connectors (cannot post or approve cash)
    "security_admin",    # Manages IdP, vault refs, kill-switches (cannot grant self finance roles)
    "internal_auditor",  # Read-only audit queries, sampling, evidence ZIP export
    "external_auditor",  # Purpose-scoped read-only external audit sampling & evidence export
    "service_worker",    # Narrow task-scoped background worker identity with mandatory expiry
}

# Pairs of roles that cannot be held simultaneously by the same principal (SEC-09)
INCOMPATIBLE_ROLE_PAIRS: set[frozenset[str]] = {
    frozenset({"analyst", "controller"}),
    frozenset({"analyst", "treasury"}),
    frozenset({"controller", "treasury"}),
    frozenset({"security_admin", "analyst"}),
    frozenset({"security_admin", "controller"}),
    frozenset({"security_admin", "treasury"}),
    frozenset({"connector_admin", "controller"}),
    frozenset({"internal_auditor", "analyst"}),
    frozenset({"internal_auditor", "controller"}),
    frozenset({"internal_auditor", "treasury"}),
    frozenset({"external_auditor", "analyst"}),
    frozenset({"external_auditor", "controller"}),
    frozenset({"external_auditor", "treasury"}),
}

# Deny-by-default permission map per role (SEC-06)
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "analyst": {
        "receipt:read",
        "receipt:ingest",
        "match:propose",
        "deduction:propose",
        "mail:draft",
        "chat:query",
        "report:read",
        "report:draft",
    },
    "controller": {
        "receipt:read",
        "posting:approve",
        "posting:execute",
        "reversal:approve",
        "writeoff:approve",
        "policy:approve",
        "learning:approve",
        "mail:approve",
        "chat:query",
        "report:read",
        "report:publish",
        "audit:read",
    },
    "treasury": {
        "receipt:read",
        "reconciliation:attest",
        "chat:query",
        "report:read",
        "report:publish",
    },
    "connector_admin": {
        "connector:read",
        "connector:configure",
        "connector:dry_run",
    },
    "security_admin": {
        "security:read",
        "security:kill_switch",
        "security:secret_rotate",
        "user:offboard",
        "audit:read",
    },
    "internal_auditor": {
        "receipt:read",
        "audit:read",
        "audit:export_zip",
        "chat:query",
        "report:read",
    },
    "external_auditor": {
        "receipt:read",
        "audit:read",
        "audit:export_zip",
    },
    "service_worker": {
        "worker:lease_job",
        "worker:execute_intake",
        "worker:execute_ocr",
    },
}

PRIVILEGED_STEP_UP_ACTIONS = {
    "posting:approve",
    "posting:execute",
    "reversal:approve",
    "writeoff:approve",
    "policy:approve",
    "learning:approve",
    "security:kill_switch",
    "security:secret_rotate",
}


@dataclass
class Principal:
    user_id: str
    tenant_id: str
    allowed_legal_entities: tuple[str, ...]
    roles: tuple[str, ...]
    session_id: str = "sess-default"
    expires_at_epoch: float = field(default_factory=lambda: time.time() + 3600)
    mfa_verified: bool = True
    step_up_verified: bool = False
    task_scope: str | None = None
    break_glass_reason: str | None = None
    break_glass_expires_at: float | None = None

    def __post_init__(self) -> None:
        if not self.roles:
            raise AuthorizationError("SEC-06 violation: Principal must have at least one role.")
        for r in self.roles:
            if r not in VALID_ROLES:
                raise AuthorizationError(f"SEC-06 violation: Unknown role '{r}'.")
        self.verify_role_compatibility()

    def verify_role_compatibility(self) -> None:
        role_set = set(self.roles)
        for i_pair in INCOMPATIBLE_ROLE_PAIRS:
            if i_pair.issubset(role_set):
                roles_str = ", ".join(sorted(i_pair))
                raise AuthorizationError(f"SEC-09 violation: Incompatible Segregation of Duties roles ({roles_str}).")


class SecurityController:
    """Central authorization, session revocation, OIDC verification, and SoD gate."""

    def __init__(self) -> None:
        self._revoked_sessions: set[str] = set()
        self._offboarded_users: set[str] = set()

    def revoke_session(self, session_id: str) -> None:
        self._revoked_sessions.add(session_id)

    def offboard_user(self, actor: Principal, target_user_id: str) -> None:
        self.authorize(actor, "user:offboard", actor.tenant_id, actor.allowed_legal_entities[0])
        self._offboarded_users.add(target_user_id)

    def grant_role(self, actor: Principal, target_user_id: str, current_roles: tuple[str, ...], new_role: str) -> tuple[str, ...]:
        """SEC-09: Admin cannot grant themselves an incompatible finance role."""
        if actor.user_id == target_user_id:
            raise AuthorizationError("SEC-09 violation: Self-grant of roles is prohibited.")
        updated = tuple(sorted(set(current_roles) | {new_role}))
        # Validate compatibility via temporary principal
        Principal(
            user_id=target_user_id,
            tenant_id=actor.tenant_id,
            allowed_legal_entities=actor.allowed_legal_entities,
            roles=updated,
        )
        return updated

    def authorize(
        self,
        principal: Principal,
        action: str,
        tenant_id: str,
        legal_entity_id: str,
        *,
        required_task_scope: str | None = None,
    ) -> None:
        now = time.time()
        if principal.user_id in self._offboarded_users:
            raise AuthorizationError(f"SEC-11 violation: User '{principal.user_id}' has been offboarded.")
        if principal.session_id in self._revoked_sessions:
            raise AuthorizationError(f"SEC-05 violation: Session '{principal.session_id}' has been revoked.")
        if now >= principal.expires_at_epoch:
            raise AuthorizationError("SEC-05/SEC-10 violation: Session or service token has expired.")

        if principal.break_glass_expires_at is not None:
            if not principal.break_glass_reason or now >= principal.break_glass_expires_at:
                raise AuthorizationError("SEC-11 violation: Break-glass elevation expired or missing reason.")

        if principal.tenant_id != tenant_id:
            raise AuthorizationError(
                f"SEC-07 violation: Cross-tenant access denied ('{principal.tenant_id}' -> '{tenant_id}')."
            )
        if legal_entity_id not in principal.allowed_legal_entities:
            raise AuthorizationError(
                f"SEC-07/SEC-08 violation: Cross-legal-entity access denied for '{legal_entity_id}'."
            )

        permitted_actions: set[str] = set()
        for r in principal.roles:
            permitted_actions |= ROLE_PERMISSIONS.get(r, set())

        if action not in permitted_actions:
            raise AuthorizationError(
                f"SEC-06 violation: Role(s) {principal.roles} not permitted to perform '{action}'."
            )

        if "service_worker" in principal.roles:
            if not principal.task_scope:
                raise AuthorizationError("SEC-10 violation: service_worker requires an explicit task_scope.")
            if required_task_scope and principal.task_scope != required_task_scope:
                raise AuthorizationError(
                    f"SEC-10 violation: service_worker scope '{principal.task_scope}' != '{required_task_scope}'."
                )

        if action in PRIVILEGED_STEP_UP_ACTIONS:
            if not principal.mfa_verified or not principal.step_up_verified:
                raise AuthorizationError(
                    f"SEC-04 violation: Action '{action}' requires IdP MFA and step-up verification."
                )

    def enforce_maker_checker(
        self,
        *,
        preparer_id: str,
        approver: Principal,
        action: str,
        tenant_id: str,
        legal_entity_id: str,
        approval_expires_at: float | None = None,
    ) -> None:
        """SEC-09: Preparer cannot approve or attest to their own work."""
        self.authorize(approver, action, tenant_id, legal_entity_id)
        if not preparer_id:
            raise AuthorizationError("SEC-09 violation: Missing preparer_id on maker-checker gated object.")
        if preparer_id == approver.user_id:
            raise AuthorizationError(
                f"SEC-09 Maker-Checker violation: Principal '{approver.user_id}' cannot self-approve own work."
            )
        if approval_expires_at is not None and time.time() >= approval_expires_at:
            raise AuthorizationError("SEC-09 violation: Approval window has expired.")


def verify_oidc_token_claims(
    claims: dict[str, Any],
    *,
    expected_issuer: str,
    expected_audience: str,
    expected_nonce: str,
    now_epoch: float | None = None,
) -> dict[str, Any]:
    """SEC-03: Verifies OIDC JWT issuer, audience, nonce, signature flag, and expiration."""
    now = time.time() if now_epoch is None else now_epoch
    if not claims.get("signature_verified", False):
        raise AuthorizationError("SEC-03 violation: OIDC token signature verification failed.")
    if claims.get("iss") != expected_issuer:
        raise AuthorizationError("SEC-03 violation: OIDC issuer mismatch.")
    aud = claims.get("aud")
    aud_set = {aud} if isinstance(aud, str) else set(aud or [])
    if expected_audience not in aud_set:
        raise AuthorizationError("SEC-03 violation: OIDC audience mismatch.")
    if claims.get("nonce") != expected_nonce:
        raise AuthorizationError("SEC-03 violation: OIDC nonce mismatch.")
    exp = float(claims.get("exp", 0))
    if now >= exp:
        raise AuthorizationError("SEC-03 violation: OIDC token expired.")
    return claims


# SEC-26: Structured Log & Telemetry Redactor
_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_PAN]"),
    (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), "[REDACTED_IBAN]"),
    (re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*"), "[REDACTED_AUTH_TOKEN]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "[REDACTED_EMAIL]"),
]


def redact_sensitive_text(text: str) -> str:
    out = text
    for regex, replacement in _REDACT_PATTERNS:
        out = regex.sub(replacement, out)
    return out


def redact_log_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """SEC-26: Redacts PII, PANs, IBANs, secrets, and raw prompt contents from logs."""
    sensitive_keys = {"password", "secret", "token", "api_key", "raw_prompt", "prompt", "card_number", "pan", "iban"}
    sanitized: dict[str, Any] = {}
    for k, v in payload.items():
        if k.lower() in sensitive_keys:
            sanitized[k] = "[REDACTED_FIELD]"
        elif isinstance(v, str):
            sanitized[k] = redact_sensitive_text(v)
        elif isinstance(v, dict):
            sanitized[k] = redact_log_payload(v)
        else:
            sanitized[k] = v
    return sanitized
