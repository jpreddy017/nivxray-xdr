"""
Vendor SourcePoller implementations.

Owner rules:
  · No customer credentials in the codebase.  Ever.
  · When a provider is unconfigured, `fetch()` raises
    `UnconfiguredPollerError` — the runner records the state
    honestly and never fabricates data.
  · Real HTTP calls live inside each poller; the runner remains
    ignorant of vendor URLs, auth schemes, and pagination shapes.
"""
from __future__ import annotations

import os
from typing import Any


class UnconfiguredPollerError(RuntimeError):
    """Raised when the environment lacks the credentials to poll
    a provider.  The runner catches this and records
    `state=DEGRADED|FAILED` with an honest, credential-scrubbed
    message.  It NEVER fabricates telemetry."""


class OktaSystemLogPoller:
    """Real Okta System Log poller.  Requires:
       · OKTA_DOMAIN     (e.g. https://acme.okta.com)
       · OKTA_API_TOKEN  (SSWS token, never hardcoded)"""
    def __init__(self):
        self._domain = os.environ.get("OKTA_DOMAIN")
        self._token  = os.environ.get("OKTA_API_TOKEN")

    async def fetch(self, cursor):
        if not (self._domain and self._token):
            raise UnconfiguredPollerError(
                "Okta poller unconfigured — set OKTA_DOMAIN and OKTA_API_TOKEN.")
        # Real HTTP call intentionally omitted from this delivery.
        # Wire an httpx client that GETs
        #   {domain}/api/v1/logs?after={cursor}
        # with `Authorization: SSWS {token}`.  Return
        # (records, next_cursor) where next_cursor is the next
        # `after` param or None when caught up.
        raise NotImplementedError(
            "OktaSystemLogPoller HTTP client wiring is customer-environment work.")


class EntraSignInLogPoller:
    """Requires ENTRA_TENANT_ID + ENTRA_CLIENT_ID + ENTRA_CLIENT_SECRET."""
    def __init__(self):
        self._tenant  = os.environ.get("ENTRA_TENANT_ID")
        self._client  = os.environ.get("ENTRA_CLIENT_ID")
        self._secret  = os.environ.get("ENTRA_CLIENT_SECRET")

    async def fetch(self, cursor):
        if not (self._tenant and self._client and self._secret):
            raise UnconfiguredPollerError(
                "Entra poller unconfigured — set ENTRA_TENANT_ID, "
                "ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET.")
        raise NotImplementedError(
            "EntraSignInLogPoller HTTP client wiring is customer-environment work.")


class AwsCloudTrailPoller:
    """Requires AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (or an
    STS role via the standard boto chain) + AWS_REGION."""
    def __init__(self):
        self._region = os.environ.get("AWS_REGION")
        self._key    = os.environ.get("AWS_ACCESS_KEY_ID")

    async def fetch(self, cursor):
        if not (self._region and self._key):
            raise UnconfiguredPollerError(
                "AWS CloudTrail poller unconfigured — set AWS_REGION and "
                "AWS_ACCESS_KEY_ID (plus AWS_SECRET_ACCESS_KEY).")
        raise NotImplementedError(
            "AwsCloudTrailPoller SDK client wiring is customer-environment work.")


def poller_configuration_status() -> dict[str, Any]:
    """Report per-provider configuration status WITHOUT leaking
    values.  A `configured=True` here means the required env
    variables are present; it does NOT mean the credentials work
    — a subsequent tick will reveal that honestly."""
    return {
        "okta": {
            "configured": bool(os.environ.get("OKTA_DOMAIN")
                                        and os.environ.get("OKTA_API_TOKEN")),
            "requires":   ["OKTA_DOMAIN", "OKTA_API_TOKEN"],
        },
        "entra": {
            "configured": bool(os.environ.get("ENTRA_TENANT_ID")
                                        and os.environ.get("ENTRA_CLIENT_ID")
                                        and os.environ.get("ENTRA_CLIENT_SECRET")),
            "requires":   ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID",
                                    "ENTRA_CLIENT_SECRET"],
        },
        "aws_cloudtrail": {
            "configured": bool(os.environ.get("AWS_REGION")
                                        and os.environ.get("AWS_ACCESS_KEY_ID")),
            "requires":   ["AWS_REGION", "AWS_ACCESS_KEY_ID",
                                    "AWS_SECRET_ACCESS_KEY"],
        },
    }
