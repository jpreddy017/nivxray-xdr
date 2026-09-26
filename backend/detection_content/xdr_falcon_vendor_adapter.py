"""
Round 28.x · CrowdStrike Falcon adapter.
========================================

First REAL second vendor exercising the Round 28 `VendorAdapter`
contract.  All Falcon-specific complexity — OAuth2 client-credential
token minting, cloud-specific FQDNs, detection schema, action IDs,
error taxonomy — terminates in THIS file.

Owner-locked acceptance gate (Round 28.x):
  This file must ship WITHOUT modifying:
    · xdr_vendor_wizard.py
    · xdr_credential_vault.py
    · xdr_cortex_executor.py
    · xdr_capability_service.py
    · xdr_cortex_ingest.py
    · xdr_cortex_promotion.py
    · Response console router
    · Canonical evidence / promotion / provenance model
  A Falcon change that requires touching any of the above is a
  framework leak and must be fixed at the abstraction, not here.

Falcon capabilities mapped:
  * ENDPOINT_ISOLATE  → POST /devices/entities/devices-actions/v2 (action=contain)
  * BLOCK_HASH        → POST /iocs/entities/indicators/v1 (type=sha256, action=prevent)

Not-yet-supported (adapter honestly reports NOT_SUPPORTED):
  * PROCESS_KILL      — Falcon has no direct terminate; runbook required.
  * DISABLE_USER      — Falcon Identity Protection scope not in this build.
  * REVOKE_TOKEN      — same.
"""
from __future__ import annotations

import base64
import json as _json
import logging
from typing import Any, Optional

from .xdr_vendor_adapter  import VendorAdapter
from .xdr_vendor_registry import register_vendor

log = logging.getLogger("nivxray.xdr.falcon")


FALCON_CLOUDS = {
    "us-1":  "https://api.crowdstrike.com",
    "us-2":  "https://api.us-2.crowdstrike.com",
    "eu-1":  "https://api.eu-1.crowdstrike.com",
    "gov-1": "https://api.laggar.gcw.crowdstrike.com",
}


@register_vendor
class FalconVendor(VendorAdapter):
    vendor_key = "falcon"

    # ── Metadata (drives the shared wizard) ────────────────
    @classmethod
    def metadata(cls) -> dict:
        return {
            "vendor_key":     cls.vendor_key,
            "display_name":   "CrowdStrike Falcon",
            "lifecycle":      "PRODUCTION",
            "credential_schema": [
                {"key": "cloud",        "label": "Cloud",
                    "kind": "select",    "required": True,
                    "options": list(FALCON_CLOUDS.keys()),
                    "default": "us-1"},
                {"key": "client_id",    "label": "OAuth2 Client ID",
                    "kind": "text",      "required": True,
                    "placeholder": "abc123..."},
                {"key": "client_secret","label": "OAuth2 Client Secret",
                    "kind": "secret",    "required": True,
                    "note": "Client-credential grant · write-only · redacted on read."},
            ],
            "capability_ids": [
                "edr.isolate_endpoint",
                "edr.block_hash",
                "edr.contain_process",
                "edr.disable_user",
                "edr.revoke_token",
            ],
            "notes": ("First real BYO-EDR vendor after Cortex.  Falcon "
                          "authenticates via OAuth2 client-credentials; the "
                          "token is minted inside connect() and cached only "
                          "for the current adapter instance."),
        }

    # ── Internals ──────────────────────────────────────────
    def _base_url(self) -> Optional[str]:
        cloud = self._credentials.get("cloud") or "us-1"
        return FALCON_CLOUDS.get(cloud)

    async def _call(self, method: str, path: str,
                        headers: dict | None = None,
                        body: Any | None = None) -> dict:
        base = self._base_url()
        if not base:
            return {"ok": False, "reason": "CONNECTION_FAILED",
                        "detail": "unknown Falcon cloud"}
        if not self._connector:
            return {"ok": False, "reason": "NO_LIVE_TENANT",
                        "detail": "no HTTP connector wired"}
        return await self._connector(method, base + path,
                                              headers or {}, body)

    async def _mint_token(self) -> dict:
        client_id = self._credentials.get("client_id")
        client_secret = self._credentials.get("client_secret")
        if not (client_id and client_secret):
            return {"ok": False, "reason": "NO_LIVE_TENANT",
                        "detail": "client_id / client_secret missing"}
        resp = await self._call(
            "POST", "/oauth2/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"client_id={client_id}&client_secret={client_secret}"
                    "&grant_type=client_credentials")
        if not resp.get("ok"):
            return resp
        # Successful token responses expose access_token in the vendor payload.
        payload = resp.get("json") or {}
        token = payload.get("access_token")
        if not token:
            return {"ok": False, "reason": "AUTHENTICATION_FAILED",
                        "detail": "no access_token in Falcon response"}
        return {"ok": True, "reason": "AVAILABLE",
                    "token": token, "detail": "oauth2 token minted",
                    "vendor_reference": resp.get("vendor_reference")}

    # ── VendorAdapter interface ────────────────────────────
    async def connect(self) -> dict:
        tok = await self._mint_token()
        if not tok.get("ok"):
            return {"ok": False, "reason": tok.get("reason") or "VENDOR_ERROR",
                        "detail": tok.get("detail"),
                        "vendor_reference": tok.get("vendor_reference")}
        # Cache the token on the adapter instance for subsequent calls.
        self._token = tok["token"]
        return {"ok": True, "reason": "AVAILABLE",
                    "detail": "falcon oauth2 healthcheck ok",
                    "vendor_reference": tok.get("vendor_reference")}

    async def capabilities(self) -> list[dict]:
        # Static capability map per Falcon build.  Individual actions
        # may still fail at execute time — the state here is the
        # ADAPTER's promise, not a guarantee.
        return [
            {"action_id": "ENDPOINT_ISOLATE",
              "capability_id": "edr.isolate_endpoint",
              "state": "AVAILABLE",
              "detail": "POST /devices/entities/devices-actions/v2 (contain)"},
            {"action_id": "BLOCK_HASH",
              "capability_id": "edr.block_hash",
              "state": "AVAILABLE",
              "detail": "POST /iocs/entities/indicators/v1 (sha256/prevent)"},
            {"action_id": "PROCESS_KILL",
              "capability_id": "edr.contain_process",
              "state": "NOT_SUPPORTED",
              "detail": "Falcon has no direct terminate API"},
            {"action_id": "DISABLE_USER",
              "capability_id": "edr.disable_user",
              "state": "NOT_SUPPORTED",
              "detail": "Identity Protection scope not in this build"},
            {"action_id": "REVOKE_TOKEN",
              "capability_id": "edr.revoke_token",
              "state": "NOT_SUPPORTED",
              "detail": "Identity Protection scope not in this build"},
        ]

    async def ingest_incidents(self, *, since_cursor: Optional[str]) -> dict:
        c = await self.connect()
        if not c.get("ok"):
            return {"events": [], "next_cursor": since_cursor,
                        "error": c.get("detail")}
        # Falcon /detects lists ids first, then summaries.  We keep
        # the vendor's `last_behavior` timestamp as the cursor.
        headers = {"Authorization": f"Bearer {self._token}"}
        filter_str = ""
        if since_cursor:
            filter_str = f"?filter=last_behavior:>='{since_cursor}'"
        q = await self._call("GET", "/detects/queries/detects/v1" + filter_str,
                                    headers=headers)
        if not q.get("ok"):
            return {"events": [], "next_cursor": since_cursor,
                        "error": q.get("detail")}
        ids = (q.get("json") or {}).get("resources") or []
        if not ids:
            return {"events": [], "next_cursor": since_cursor, "error": None}
        s = await self._call("POST", "/detects/entities/summaries/GET/v1",
                                    headers=headers, body=_json.dumps({"ids": ids}))
        if not s.get("ok"):
            return {"events": [], "next_cursor": since_cursor,
                        "error": s.get("detail")}
        resources = (s.get("json") or {}).get("resources") or []
        events = [self._falcon_to_incident(r) for r in resources]
        new_cursor = max(
            (r.get("last_behavior") for r in resources
              if r.get("last_behavior")), default=since_cursor)
        return {"events": events, "next_cursor": new_cursor, "error": None}

    def _falcon_to_incident(self, det: dict) -> dict:
        """Translate a Falcon detection into the vendor-neutral
        incident shape our parser understands.  Cortex-compatible
        keys → the same CortexParser projection reuses without
        knowing this is Falcon."""
        return {
            "incident_id":       det.get("detection_id") or det.get("id"),
            "detection_time":    _iso_to_epoch_ms(det.get("first_behavior")),
            "modification_time": _iso_to_epoch_ms(det.get("last_behavior")),
            "severity":          _falcon_severity(det.get("max_severity_displayname")),
            "status":            det.get("status") or "new",
            "description":       det.get("behaviors", [{}])[0].get("description")
                                        or "Falcon detection",
            "hosts":             [det.get("device", {}).get("hostname")]
                                        if det.get("device") else [],
            "users":             [b.get("user_name") for b in
                                        (det.get("behaviors") or [])
                                        if b.get("user_name")],
            "mitre_tactics_ids_and_names":
                sorted({f"{b.get('tactic_id')} - {b.get('tactic')}"
                            for b in det.get("behaviors") or []
                            if b.get("tactic_id")}),
            "mitre_techniques_ids_and_names":
                sorted({f"{b.get('technique_id')} - {b.get('technique')}"
                            for b in det.get("behaviors") or []
                            if b.get("technique_id")}),
            "alerts": [{
                "alert_id":                b.get("behavior_id") or f"beh-{i}",
                "detection_timestamp":     _iso_to_epoch_ms(b.get("timestamp")),
                "event_type":              b.get("scenario") or "Falcon Behavior",
                "severity":                b.get("severity"),
                "description":             b.get("description"),
                "host_name":               det.get("device", {}).get("hostname"),
                "user_name":               b.get("user_name"),
                "action_process_image_name":       b.get("filename"),
                "action_process_image_command_line": b.get("cmdline"),
                "action_process_image_sha256":     b.get("sha256"),
                "action_file_sha256":              b.get("sha256"),
                "mitre_tactic_id_and_name":
                    f"{b.get('tactic_id')} - {b.get('tactic')}"
                        if b.get("tactic_id") else None,
                "mitre_technique_id_and_name":
                    f"{b.get('technique_id')} - {b.get('technique')}"
                        if b.get("technique_id") else None,
            } for i, b in enumerate(det.get("behaviors") or [])],
            "key_artifacts": [
                {"type": "sha256", "value": b.get("sha256")}
                for b in det.get("behaviors") or [] if b.get("sha256")
            ],
        }

    async def execute_action(self, action_id: str, params: dict) -> dict:
        c = await self.connect()
        if not c.get("ok"):
            return {"ok": False, "vendor_action_id": None,
                        "detail": c.get("detail"), "http_status": None}
        headers = {"Authorization": f"Bearer {self._token}",
                       "Content-Type":  "application/json"}
        target = params.get("target") or {}
        if action_id == "ENDPOINT_ISOLATE":
            device_id = target.get("id") or target.get("value")
            if not device_id:
                return {"ok": False, "vendor_action_id": None,
                            "detail": "no device id supplied", "http_status": 400}
            body = _json.dumps({"action_parameters": [], "ids": [device_id]})
            resp = await self._call(
                "POST",
                "/devices/entities/devices-actions/v2?action_name=contain",
                headers=headers, body=body)
            return _falcon_action_result(resp)
        if action_id == "BLOCK_HASH":
            sha256 = target.get("value")
            if not sha256:
                return {"ok": False, "vendor_action_id": None,
                            "detail": "no sha256 supplied", "http_status": 400}
            body = _json.dumps({"indicators": [{
                "type": "sha256", "value": sha256,
                "action": "prevent",
                "source": "NivXRay",
                "platforms": ["windows", "mac", "linux"],
                "severity": "high"}]})
            resp = await self._call(
                "POST", "/iocs/entities/indicators/v1",
                headers=headers, body=body)
            return _falcon_action_result(resp)
        # Any other action reaches this point ONLY because a caller
        # bypassed capabilities(); return the honest verdict.
        return {"ok": False, "vendor_action_id": None,
                    "detail": f"{action_id} not supported by Falcon adapter",
                    "http_status": None}


# ── helpers (module-level, easy to unit-test) ────────────────
def _iso_to_epoch_ms(iso: Optional[str]) -> Optional[int]:
    import datetime as _dt
    if not iso: return None
    try:
        return int(_dt.datetime.fromisoformat(
            iso.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def _falcon_severity(name: Optional[str]) -> str:
    mapping = {"Critical": "critical", "High": "high", "Medium": "medium",
                   "Low": "low", "Informational": "info"}
    return mapping.get(name or "", "medium")


def _falcon_action_result(resp: dict) -> dict:
    if not resp.get("ok"):
        return {"ok": False, "vendor_action_id": None,
                    "detail": resp.get("detail") or "vendor rejected",
                    "http_status": resp.get("http_status")}
    payload = resp.get("json") or {}
    action_id = None
    resources = payload.get("resources") or []
    if resources:
        action_id = (resources[0].get("id")
                          or resources[0].get("resources_affected")
                          or resources[0].get("action_id"))
    meta = payload.get("meta") or {}
    return {
        "ok":              True,
        "vendor_action_id": action_id or meta.get("trace_id"),
        "detail":          resp.get("detail")
                                or f"HTTP {resp.get('http_status')}",
        "http_status":     resp.get("http_status"),
    }
