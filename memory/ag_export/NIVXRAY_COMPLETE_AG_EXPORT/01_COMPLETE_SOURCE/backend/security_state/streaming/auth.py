"""Cryptographic Transport Authentication and Tenant Context Derivation.

Guarantees the strict invariant:
transport credential -> authenticated principal -> tenant context -> adapter -> canonical evidence
and NEVER:
payload.tenant_id -> tenant context.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..contracts import canonical_json, sha256_digest


class AuthenticationFailureError(Exception):
    """Raised when transport credentials fail cryptographic verification."""
    pass


class TenantMismatchSecurityError(Exception):
    """Raised when untrusted payload attempts to spoof or mismatch authenticated tenant."""
    pass


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Cryptographically verified identity derived from transport layer (mTLS / JWT / Token)."""
    principal_id: str                   # e.g., "sensor-edr-corp-01", "operator-john"
    tenant_id: str                      # Cryptographically verified tenant ID
    transport_mechanism: str            # "mTLS", "JWT_BEARER", "SECURE_INGEST_KEY"
    issuer: str = "NivXRay-PKI"
    authenticated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    roles: Tuple[str, ...] = ("telemetry.ingest",)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "transport_mechanism": self.transport_mechanism,
            "issuer": self.issuer,
            "authenticated_at": self.authenticated_at,
            "roles": list(self.roles),
        }


class TransportAuthenticator:
    """Authoritative boundary authenticating transport credentials and deriving tenant context."""

    def __init__(self, hmac_secret: str = "nivxray-transport-root-secret-2026") -> None:
        self._hmac_secret = hmac_secret.encode("utf-8")
        # Registered ingest keys for sensors: ingest_key -> (principal_id, tenant_id)
        self._known_keys: Dict[str, Tuple[str, str]] = {
            "key-tenant-corp-sensor-01": ("sensor-01", "tenant-corp"),
            "key-tenant-finance-sensor-02": ("sensor-02", "tenant-finance"),
            "key-tenant-replay-default": ("replay-source", "tenant-default"),
        }

    def register_ingest_key(self, key: str, principal_id: str, tenant_id: str) -> None:
        """Register authenticated ingest key (tenant registry)."""
        self._known_keys[key] = (principal_id, tenant_id)

    def authenticate_mtls_cert(
        self,
        subject_dn: str,
        san_dns: Optional[str] = None,
    ) -> AuthenticatedPrincipal:
        """Authenticate mTLS client certificate and derive tenant context.

        Subject format: 'CN=<sensor_id>,OU=<tenant_id>,O=EnterpriseCorp'
        """
        if not subject_dn:
            raise AuthenticationFailureError("Missing mTLS client certificate Subject DN")

        parts = dict(part.strip().split("=", 1) for part in subject_dn.split(",") if "=" in part)
        principal_id = parts.get("CN")
        tenant_id = parts.get("OU")

        if not principal_id or not tenant_id:
            raise AuthenticationFailureError(
                f"mTLS certificate missing CN or OU tenant mapping: {subject_dn}"
            )

        return AuthenticatedPrincipal(
            principal_id=principal_id,
            tenant_id=tenant_id,
            transport_mechanism="mTLS",
            issuer="NivXRay-Internal-CA",
        )

    def authenticate_jwt_bearer(self, token: str) -> AuthenticatedPrincipal:
        """Verify signed JWT bearer token and derive tenant context."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Malformed JWT structure")
            header_b64, payload_b64, sig_b64 = parts

            # Verify HMAC-SHA256 signature
            expected_sig = hmac.new(
                self._hmac_secret,
                f"{header_b64}.{payload_b64}".encode("utf-8"),
                hashlib.sha256,
            ).digest()
            provided_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
            if not hmac.compare_digest(expected_sig, provided_sig):
                raise AuthenticationFailureError("Invalid JWT cryptographic signature")

            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
            payload = json.loads(payload_json.decode("utf-8"))

            # Validate expiration
            if payload.get("exp", 0) < time.time():
                raise AuthenticationFailureError("JWT token expired")

            principal_id = str(payload.get("sub", ""))
            tenant_id = str(payload.get("tid") or payload.get("tenant_id", ""))

            if not principal_id or not tenant_id:
                raise AuthenticationFailureError("JWT missing 'sub' or 'tid' claim")

            return AuthenticatedPrincipal(
                principal_id=principal_id,
                tenant_id=tenant_id,
                transport_mechanism="JWT_BEARER",
                issuer=payload.get("iss", "NivXRay-Auth"),
            )
        except Exception as e:
            if isinstance(e, AuthenticationFailureError):
                raise e
            raise AuthenticationFailureError(f"JWT verification failed: {e}")

    def authenticate_ingest_key(self, api_key: str) -> AuthenticatedPrincipal:
        """Authenticate sensor API key against authoritative tenant mapping."""
        if not api_key or api_key not in self._known_keys:
            raise AuthenticationFailureError("Invalid or unregistered telemetry ingest key")

        principal_id, tenant_id = self._known_keys[api_key]
        return AuthenticatedPrincipal(
            principal_id=principal_id,
            tenant_id=tenant_id,
            transport_mechanism="SECURE_INGEST_KEY",
        )

    def issue_test_jwt(self, principal_id: str, tenant_id: str, ttl_sec: int = 3600) -> str:
        """Helper to generate signed test tokens for verification."""
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")).decode("utf-8").rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": principal_id,
            "tid": tenant_id,
            "iss": "NivXRay-Auth",
            "iat": int(time.time()),
            "exp": int(time.time()) + ttl_sec,
        }).encode("utf-8")).decode("utf-8").rstrip("=")
        sig = base64.urlsafe_b64encode(
            hmac.new(self._hmac_secret, f"{header}.{payload}".encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8").rstrip("=")
        return f"{header}.{payload}.{sig}"
