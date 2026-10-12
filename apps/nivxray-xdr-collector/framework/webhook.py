"""
Webhook receiver connector · Phase B.

Config:
{
  "label":       "Defender graph webhook",
  "secret_id":   "wh-abc123",              # path segment, tenant-mapped
  "credentials": {
     "hmac_secret": "…"                    # required; verifies timestamp-bound HMAC
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
  • mandatory timestamp window and shared atomic replay claim
  • 401 on authentication failure; 503 when replay protection is unavailable
"""
from __future__ import annotations

import hashlib
import hmac
import time
import json
import math
from framework.webhook_replay import replay_store, ReplayStoreUnavailable
from typing import Any, Dict, List, Optional

from framework.base    import Connector, Envelope, Health, Capability
from framework.parsers import get_path, utcnow_iso
from framework.identity import collector_id


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
        secret = (self.config.get("credentials") or {}).get("hmac_secret")
        if not isinstance(secret, str) or not secret:
            return {"ok": False, "reason": "hmac_secret_not_configured"}
        if not isinstance(sig_cfg, dict):
            return {"ok": False, "reason": "invalid_signature_configuration"}
        header_name = sig_cfg.get("header", "X-Hub-Signature-256")
        algo = sig_cfg.get("algo", "sha256")
        prefix = sig_cfg.get("prefix", "sha256=")
        if not all(isinstance(v, str) for v in (header_name, algo, prefix)):
            return {"ok": False, "reason": "invalid_signature_configuration"}
        algo = algo.lower()
        if algo not in ("sha256", "sha1"):
            return {"ok": False, "reason": "unsupported_signature_algorithm"}
        lowered = {key.lower(): value for key, value in headers.items()}
        provided = lowered.get(header_name.lower())
        if not isinstance(provided, str) or not provided:
            return {"ok": False, "reason": "missing_signature_header"}
        ts = lowered.get("x-timestamp")
        if not isinstance(ts, str) or not ts:
            return {"ok": False, "reason": "missing_timestamp_header"}
        try:
            if len(ts) > 64:
                raise ValueError()
            timestamp = float(ts)
            timestamp_bytes = ts.encode("ascii")
            if not math.isfinite(timestamp):
                raise ValueError()
        except (ValueError, OverflowError, UnicodeError):
            return {"ok": False, "reason": "malformed_timestamp"}
        now = time.time()
        if timestamp < now - REPLAY_WINDOW_SECONDS:
            return {"ok": False, "reason": "expired_timestamp"}
        if timestamp > now + REPLAY_WINDOW_SECONDS:
            return {"ok": False, "reason": "future_timestamp"}
        normalized = provided[len(prefix):] if prefix and provided.startswith(prefix) else provided
        try:
            # Prefix and hexadecimal case are representations, not identities.
            supplied_digest = bytes.fromhex(normalized)
            expected_size = 32 if algo == "sha256" else 20
            if len(normalized) != expected_size * 2 or len(supplied_digest) != expected_size:
                raise ValueError()
        except (ValueError, TypeError):
            return {"ok": False, "reason": "signature_mismatch"}
        signed_payload = timestamp_bytes + b"." + body
        hasher = hashlib.sha256 if algo == "sha256" else hashlib.sha1
        expected = hmac.new(secret.encode("utf-8"), signed_payload, hasher).digest()
        if not hmac.compare_digest(supplied_digest, expected):
            return {"ok": False, "reason": "signature_mismatch"}
        secret_id = self.config.get("secret_id")
        if not self.tenant_id or not isinstance(secret_id, str) or not secret_id:
            return {"ok": False, "reason": "webhook_identity_not_configured"}
        scope = json.dumps([self.tenant_id, secret_id], separators=(",", ":")).encode()
        key = "nivxray:webhook:replay:v1:" + hashlib.sha256(scope + b"\0" + signed_payload).hexdigest()
        try:
            # A timestamp accepted 300 seconds in the future remains valid
            # for another 300 seconds. Cover the entire possible window.
            claimed = replay_store().claim(key, 2 * REPLAY_WINDOW_SECONDS + 1)
        except ReplayStoreUnavailable:
            return {"ok": False, "reason": "replay_store_unavailable"}
        if not claimed:
            return {"ok": False, "reason": "replayed_request"}
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
                collector_id         = collector_id(),
                collection_method    = "webhook",
                parser_version       = "phaseB.webhook.1",
                source_timestamp     = str(ts) if ts else None,
                collection_timestamp = utcnow_iso(),
                event_type           = self.source_type,
                raw                  = rec if isinstance(rec, dict) else {"value": rec},
                canonical            = {},
            ))
        return envs
