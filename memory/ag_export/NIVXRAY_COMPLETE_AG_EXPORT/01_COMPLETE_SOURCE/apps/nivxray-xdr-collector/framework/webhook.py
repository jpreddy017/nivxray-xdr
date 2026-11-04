"""
Webhook receiver connector · Phase B.

Config:
{
  "label":       "Defender graph webhook",
  "secret_id":   "wh-abc123",              # path segment, tenant-mapped
  "credentials": {
     "hmac_secret": "…"                    # optional; verifies X-Signature
  },
  "signature": {
     "header":   "X-Hub-Signature-256",    # default
     "algo":     "sha256",                 # sha256 | sha1
     "prefix":   "sha256="                 # optional
  },
  "event_id_path":  "id",
  "timestamp_path": "ts",
  "records_path":   ""                     # empty = whole body is one record
}

Route: POST /api/xdr/webhooks/{secret_id}
       Body: raw JSON (parsed) or bytes (retained verbatim in envelope.raw)

Security guarantees:
  • constant-time HMAC comparison
  • timestamp replay window enforced when X-Timestamp header sent
  • 401 / 403 on failure — never 500 for a bad signature
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Dict, List, Optional

from framework.base    import Connector, Envelope, Health, Capability
from framework.parsers import get_path, utcnow_iso


REPLAY_WINDOW_SECONDS = 300      # 5 minutes


class WebhookConnector(Connector):
    source_type: str = "webhook"
    label:       str = "Generic Webhook Receiver"
    capabilities = [Capability.DETECTIONS]

    configuration_schema = {
        "type": "object",
        "required": ["secret_id"],
        "properties": {
            "secret_id":      {"type": "string"},
            "credentials":    {"type": "object"},
            "signature":      {"type": "object"},
            "event_id_path":  {"type": "string"},
            "timestamp_path": {"type": "string"},
            "records_path":   {"type": "string"},
        },
    }

    def __init__(self, tenant_id: str, config: Dict[str, Any],
                 identity: Optional[str] = None):
        super().__init__(tenant_id, config)
        if identity:
            self.identity = identity
        self.label = config.get("label") or self.label
        # Webhooks are passively "connected" once configured — they either
        # receive traffic or don't.  Health flips to ERROR on failed HMAC.
        self.health = Health.CONNECTED

    # ── signature verification ───────────────────────────────
    def verify(self, body: bytes, headers: Dict[str, str]) -> Dict[str, Any]:
        """Return {ok, reason?} — never raises on failure."""
        sig_cfg = self.config.get("signature") or {}
        secret  = (self.config.get("credentials") or {}).get("hmac_secret")
        if not secret:
            # No secret configured → accept but flag as unauthenticated.
            return {"ok": True, "authenticated": False,
                     "reason": "no_hmac_secret_configured"}

        header_name = sig_cfg.get("header", "X-Hub-Signature-256")
        algo        = (sig_cfg.get("algo") or "sha256").lower()
        prefix      = sig_cfg.get("prefix", "sha256=")

        provided = headers.get(header_name) or headers.get(header_name.lower())
        if not provided:
            return {"ok": False, "reason": "missing_signature_header",
                     "header": header_name}

        if algo not in ("sha256", "sha1"):
            return {"ok": False, "reason": f"unsupported_algo:{algo}"}

        hasher = hashlib.sha256 if algo == "sha256" else hashlib.sha1
        expected = hmac.new(secret.encode("utf-8"), body, hasher).hexdigest()
        expected_full = f"{prefix}{expected}"

        if not hmac.compare_digest(provided, expected_full) and \
             not hmac.compare_digest(provided, expected):
            return {"ok": False, "reason": "signature_mismatch"}

        # optional replay guard
        ts = headers.get("X-Timestamp") or headers.get("x-timestamp")
        if ts:
            try:
                delta = abs(time.time() - float(ts))
                if delta > REPLAY_WINDOW_SECONDS:
                    return {"ok": False, "reason": "replay_window_exceeded",
                             "delta_seconds": delta}
            except ValueError:
                return {"ok": False, "reason": "malformed_timestamp"}

        return {"ok": True, "authenticated": True}

    # ── event conversion ─────────────────────────────────────
    def envelopes_from(self, body_json: Any) -> List[Envelope]:
        cfg = self.config
        records_path = cfg.get("records_path") or ""
        records = get_path(body_json, records_path, default=[]) if records_path \
                    else (body_json if isinstance(body_json, list) else [body_json])
        if not isinstance(records, list):
            records = [records]

        envs: List[Envelope] = []
        for rec in records:
            eid = get_path(rec, cfg.get("event_id_path") or "", default=None)
            ts  = get_path(rec, cfg.get("timestamp_path") or "", default=None)
            envs.append(Envelope(
                tenant_id            = self.tenant_id,
                source               = self.label,
                source_event_id      = str(eid) if eid is not None else None,
                connector_id         = self.identity,
                collector_id         = "collector-local",
                collection_method    = "webhook",
                parser_version       = "phaseB.webhook.1",
                source_timestamp     = str(ts) if ts else None,
                collection_timestamp = utcnow_iso(),
                event_type           = self.source_type,
                raw                  = rec if isinstance(rec, dict) else {"value": rec},
                canonical            = {},
            ))
        return envs
