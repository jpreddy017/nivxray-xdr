"""OAuth2 client-credentials token provider (Phase 1b).

Added to the EXISTING collector framework because the Microsoft Office 365
Management Activity API accepts nothing else for unattended collection: the
poller's bearer/basic/api-key modes cannot obtain an Entra-issued token.

Discipline:

* the token is cached until shortly before its own stated expiry — the
  provider never guesses a lifetime, and a response without `expires_in` is
  treated as immediately stale rather than valid forever;
* a credential failure is reported as AUTHENTICATION_FAILED and never
  retried in a tight loop;
* secret material is held only in memory, is never logged, and is never
  echoed back by `describe()`;
* certificate credentials are recognised as a distinct mode. Phase 1
  implements the abstraction and says plainly that it is not wired, instead
  of pretending a certificate flow exists.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

import httpx

#: Refresh this many seconds before the token's stated expiry.
_SKEW_SECONDS = 120


class TokenError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        self.code = code
        self.message = message
        self.retryable = retryable
        super().__init__(f"{code}: {message}")


class ClientCredentialsTokenProvider:
    """One provider per connector instance. Caches a single token."""

    def __init__(self, *, authority: str, tenant_id: str, scope: str,
                 credentials: Dict[str, Any], timeout: float = 30.0):
        self.authority = (authority or "").rstrip("/")
        self.tenant_id = tenant_id or ""
        self.scope = scope or ""
        self._creds = credentials or {}
        self.timeout = timeout
        self._token: Optional[str] = None
        self._expires_at: float = 0.0
        self.last_error: Optional[str] = None
        self.acquisitions: int = 0

    # ── credential shape ─────────────────────────────────────────
    def mode(self) -> str:
        if self._creds.get("client_secret"):
            return "client_secret"
        if self._creds.get("certificate_private_key_pem") or \
                self._creds.get("certificate_thumbprint"):
            return "certificate"
        return "none"

    def token_url(self) -> str:
        return f"{self.authority}/{self.tenant_id}/oauth2/v2.0/token"

    def describe(self) -> Dict[str, Any]:
        """Never returns secret material — only whether it is present."""
        return {
            "mode": self.mode(),
            "client_id_set": bool(self._creds.get("client_id")),
            "secret_set": bool(self._creds.get("client_secret")),
            "certificate_set": bool(
                self._creds.get("certificate_private_key_pem")),
            "authority": self.authority,
            "scope": self.scope,
            "token_cached": bool(self._token),
            "token_expires_in": max(0, int(self._expires_at - time.time()))
            if self._token else 0,
            "acquisitions": self.acquisitions,
            "last_error": self.last_error,
        }

    def invalidate(self) -> None:
        self._token = None
        self._expires_at = 0.0

    # ── acquisition ──────────────────────────────────────────────
    async def token(self) -> str:
        if self._token and time.time() < self._expires_at:
            return self._token
        mode = self.mode()
        if mode == "none":
            raise TokenError(
                "CREDENTIALS_MISSING",
                "no client_secret and no certificate were configured for "
                "this connector; app-only collection cannot authenticate")
        if mode == "certificate":
            raise TokenError(
                "CERTIFICATE_AUTH_NOT_IMPLEMENTED",
                "certificate (private_key_jwt) client authentication is the "
                "preferred production mode but is NOT implemented in Phase "
                "1b; configure a client secret or wait for the certificate "
                "flow rather than treating this as a transport failure")
        if not self._creds.get("client_id") or not self.tenant_id:
            raise TokenError("CREDENTIALS_INCOMPLETE",
                             "client_id and the Microsoft tenant id are both "
                             "required for the client-credentials flow")
        data = {
            "grant_type": "client_credentials",
            "client_id": self._creds["client_id"],
            "client_secret": self._creds["client_secret"],
            "scope": self.scope,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.token_url(), data=data)
        except (httpx.TimeoutException, httpx.TransportError) as e:
            self.last_error = f"{type(e).__name__}: {e}"
            raise TokenError("TOKEN_ENDPOINT_UNREACHABLE", self.last_error,
                             retryable=True) from e
        if resp.status_code == 429 or resp.status_code >= 500:
            self.last_error = f"HTTP {resp.status_code}"
            raise TokenError("TOKEN_ENDPOINT_THROTTLED_OR_DOWN",
                             self.last_error, retryable=True)
        if resp.status_code >= 400:
            body = resp.json() if "json" in (
                resp.headers.get("content-type") or "") else {}
            # Microsoft's own error code travels through untouched.
            self.last_error = (f"HTTP {resp.status_code} "
                               f"{body.get('error') or ''} "
                               f"{body.get('error_description') or ''}"
                               ).strip()[:300]
            raise TokenError("CREDENTIAL_REJECTED", self.last_error)
        payload = resp.json()
        token = payload.get("access_token")
        expires_in = payload.get("expires_in")
        if not token:
            self.last_error = "token response carried no access_token"
            raise TokenError("TOKEN_RESPONSE_INVALID", self.last_error)
        self._token = str(token)
        # No stated lifetime -> treat as already stale. A guessed lifetime
        # would produce silent 401s halfway through a collection window.
        try:
            self._expires_at = time.time() + max(
                0.0, float(expires_in) - _SKEW_SECONDS)
        except (TypeError, ValueError):
            self._expires_at = 0.0
        self.acquisitions += 1
        self.last_error = None
        return self._token
