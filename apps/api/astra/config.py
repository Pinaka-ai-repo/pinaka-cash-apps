"""ASTRA Runtime Configuration, Zero-Leak Egress Guard & Production Boot Validator.

Enforces:
- SEC-03 / SEC-39: Production rejects dev auth, default secrets, or external test sinks.
- SEC-12: Production enforces TLSv1.2+ and HSTS.
- SEC-14: Rejects static AWS keys (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) in app config.
- SEC-15: Denied-by-default egress policy; blocks IMDS (169.254.169.254) and unallowlisted hosts.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ConfigurationError(RuntimeError):
    """Raised when configuration violates security or production isolation rules."""


BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "192.0.0.192",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.azure.com",
    "kubernetes.default.svc",
}

FORBIDDEN_STATIC_CLOUD_KEYS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GCP_SERVICE_ACCOUNT_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS_JSON",
)


@dataclass(frozen=True)
class AstraConfig:
    env: str = "development"
    execution_policy: str = "local-no-egress"
    banner_mode: str = "DEMO"
    demo_capture_mode: bool = False
    auth_mode: str = "dev_persona"
    oidc_issuer_url: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    session_secret_key: str = "dev_only_local_ephemeral_secret_32b"
    tls_min_version: str = "TLSv1.3"
    require_https_ingress: bool = True
    encryption_at_rest_enabled: bool = True
    kms_key_owner: str = "customer-security-admin"
    mail_provider: str = "local_sink"
    allowed_egress_hosts: tuple[str, ...] = field(default_factory=lambda: ("localhost", "127.0.0.1"))
    laya_enabled: bool = False
    pinaka_mode: str = "mock"

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "AstraConfig":
        env_map = dict(os.environ if environ is None else environ)

        # SEC-14: Never accept static cloud access keys in application config
        for forbidden_key in FORBIDDEN_STATIC_CLOUD_KEYS:
            if env_map.get(forbidden_key, "").strip():
                raise ConfigurationError(
                    f"SEC-14 violation: Static cloud credential '{forbidden_key}' is forbidden in ASTRA configuration."
                )

        allowed_hosts_raw = env_map.get("ASTRA_ALLOWED_EGRESS_HOSTS", "localhost,127.0.0.1")
        allowed_hosts = tuple(h.strip().lower() for h in allowed_hosts_raw.split(",") if h.strip())

        cfg = cls(
            env=env_map.get("ASTRA_ENV", "development").strip().lower(),
            execution_policy=env_map.get("ASTRA_EXECUTION_POLICY", "local-no-egress").strip().lower(),
            banner_mode=env_map.get("ASTRA_BANNER_MODE", "DEMO").strip().upper(),
            demo_capture_mode=env_map.get("ASTRA_DEMO_CAPTURE_MODE", "false").strip().lower() == "true",
            auth_mode=env_map.get("ASTRA_AUTH_MODE", "dev_persona").strip().lower(),
            oidc_issuer_url=env_map.get("OIDC_ISSUER_URL", "").strip(),
            oidc_audience=env_map.get("OIDC_AUDIENCE", "").strip(),
            oidc_jwks_url=env_map.get("OIDC_JWKS_URL", "").strip(),
            session_secret_key=env_map.get("SESSION_SECRET_KEY", "dev_only_local_ephemeral_secret_32b").strip(),
            tls_min_version=env_map.get("ASTRA_TLS_MIN_VERSION", "TLSv1.3").strip(),
            require_https_ingress=env_map.get("ASTRA_REQUIRE_HTTPS", "true").strip().lower() == "true",
            encryption_at_rest_enabled=env_map.get("ASTRA_ENCRYPTION_AT_REST", "true").strip().lower() == "true",
            kms_key_owner=env_map.get("ASTRA_KMS_KEY_OWNER", "customer-security-admin").strip(),
            mail_provider=env_map.get("MAIL_PROVIDER", "local_sink").strip().lower(),
            allowed_egress_hosts=allowed_hosts,
            laya_enabled=env_map.get("LAYA_REASON_CLASSIFIER_ENABLED", "false").strip().lower() == "true",
            pinaka_mode=env_map.get("PINAKA_MODE", "mock").strip().lower(),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not self.encryption_at_rest_enabled or not self.kms_key_owner:
            raise ConfigurationError("SEC-13 violation: Encryption at rest and key owner must be configured.")

        if self.tls_min_version not in ("TLSv1.2", "TLSv1.3"):
            raise ConfigurationError(f"SEC-12 violation: Unsupported TLS minimum version '{self.tls_min_version}'.")

        if self.env == "production":
            if self.auth_mode != "oidc":
                raise ConfigurationError("SEC-03/SEC-39 violation: Production requires ASTRA_AUTH_MODE='oidc'.")
            if not (
                self.oidc_issuer_url.startswith("https://")
                and self.oidc_audience
                and self.oidc_jwks_url.startswith("https://")
            ):
                raise ConfigurationError(
                    "SEC-03/SEC-12 violation: Production requires HTTPS OIDC_ISSUER_URL, OIDC_AUDIENCE, and OIDC_JWKS_URL."
                )
            if (
                "dev_only" in self.session_secret_key
                or "replace_with" in self.session_secret_key
                or len(self.session_secret_key) < 32
            ):
                raise ConfigurationError("SEC-14/SEC-39 violation: Production rejects default or short SESSION_SECRET_KEY.")
            if not self.require_https_ingress:
                raise ConfigurationError("SEC-12 violation: Production requires HTTPS ingress.")
            if self.banner_mode == "DEMO":
                raise ConfigurationError("SEC-39 violation: Production cannot run with ASTRA_BANNER_MODE='DEMO'.")

    def verify_egress_url(self, url: str) -> str:
        """SEC-15: Denied-by-default egress filter blocking IMDS and unallowlisted destinations."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise PermissionError(f"SEC-15 violation: Unsupported URL scheme '{parsed.scheme}'.")
        if parsed.username or parsed.password:
            raise PermissionError("SEC-15 violation: Embedded URL credentials are forbidden.")
        host = (parsed.hostname or "").lower()
        if not host:
            raise PermissionError(f"SEC-15 violation: Invalid egress URL '{url}'.")
        if host in BLOCKED_METADATA_HOSTS or host.startswith("169.254."):
            raise PermissionError(f"SEC-15 violation: Cloud metadata endpoint '{host}' is strictly blocked.")
        try:
            ip_obj = ipaddress.ip_address(host)
            mapped = getattr(ip_obj, "ipv4_mapped", None) or ip_obj
            if mapped.is_link_local or str(mapped) in BLOCKED_METADATA_HOSTS:
                raise PermissionError(f"SEC-15 violation: Link-local or metadata IP '{host}' is strictly blocked.")
        except ValueError:
            pass
        if self.execution_policy == "local-no-egress" and host not in ("localhost", "127.0.0.1"):
            raise PermissionError(
                f"SEC-15 violation: Host '{host}' blocked under ASTRA_EXECUTION_POLICY='local-no-egress'."
            )
        if host not in self.allowed_egress_hosts:
            raise PermissionError(f"SEC-15 violation: Egress host '{host}' is not in allowlist {self.allowed_egress_hosts}.")
        if self.env == "production" and parsed.scheme != "https":
            raise PermissionError(f"SEC-12 violation: Production outbound calls require https:// ('{url}').")
        return url

    def display_hostname(self, raw_host: str) -> str:
        """Masks infrastructure hostnames during demo video capture so no AWS/cloud hostname appears on screen."""
        if self.demo_capture_mode:
            return "astra.pinaka.local"
        return raw_host
