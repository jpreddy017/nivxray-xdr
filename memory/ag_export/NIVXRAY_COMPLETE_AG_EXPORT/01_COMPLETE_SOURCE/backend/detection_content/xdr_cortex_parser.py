"""
Round 26 · Cortex XDR → Canonical Evidence parser.
==================================================

Pure function.  Deterministic.  Takes a Cortex incident payload
(as returned by the vendor API or delivered via webhook) and
projects it into a list of ``xdr_canonical_evidence`` records that
NivXRay's IUE / Correlation / MITRE / Attack-Story engines already
consume.

Locked invariants (owner · Round 26):
  · Every canonical record answers "which Cortex object produced
    me?" via ``source_object_type + source_object_id``.
  · ``event_id`` is DETERMINISTIC (sha256 of stable identity) so
    re-ingesting the same payload upserts the same row.
  · Raw vendor object is preserved verbatim under ``raw``.
  · No incident promotion, no correlation, no verdict — pure
    projection.  Round 26.5 handles promotion.

Supported Cortex objects (subset locked for R26):
  · incident   → 1 canonical row per incident
  · alert      → 1 canonical row per alert
  · key_artifact → 1 canonical row per (type, value)
  · host       → 1 canonical row per host_name observed
  · user       → 1 canonical row per user_name observed
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
from typing import Any, Iterable, Optional

VENDOR = "cortex_xdr"


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _iso_from_epoch_ms(ms: Any) -> Optional[str]:
    if ms is None or not isinstance(ms, (int, float)):
        return None
    try:
        return _dt.datetime.fromtimestamp(
            float(ms) / 1000.0, tz=_dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _event_id(integration_id: str, object_type: str,
                  object_key: str) -> str:
    material = f"{integration_id}|{object_type}|{object_key}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
    return f"cev-cortex-{digest}"


def _base_record(*, integration_id: str, object_type: str,
                     object_id: str, xdr_incident_id: Optional[str],
                     observed_at: Optional[str],
                     raw: Any) -> dict:
    return {
        "event_id":              _event_id(integration_id, object_type,
                                                object_id),
        "vendor":                VENDOR,
        "source_integration_id": integration_id,
        "source_object_type":    object_type,
        "source_object_id":      object_id,
        "xdr_incident_id":       xdr_incident_id,
        "observed_at":           observed_at,
        "ingested_at":           _iso_now(),
        "event_type":            f"cortex.{object_type}",
        "source":                "cortex_xdr",
        # `raw` preserves provenance verbatim — never mutated.
        "raw":                   raw,
    }


# ── Parsers ──────────────────────────────────────────────────
def parse_incident(incident: dict, *, integration_id: str) -> list[dict]:
    """Return the canonical rows produced by ONE Cortex incident
    payload.  Order is deterministic: incident → alerts →
    key_artifacts → hosts → users."""
    if not isinstance(incident, dict):
        return []
    inc_id = str(incident.get("incident_id") or "")
    if not inc_id:
        return []

    rows: list[dict] = []

    # ── Incident row (summary evidence) ──────────────────
    incident_row = _base_record(
        integration_id=integration_id,
        object_type="incident",
        object_id=inc_id,
        xdr_incident_id=inc_id,
        observed_at=_iso_from_epoch_ms(incident.get("detection_time"))
                        or _iso_from_epoch_ms(incident.get("creation_time")),
        raw=incident,
    )
    incident_row["fields"] = {
        "severity":       incident.get("severity"),
        "status":         incident.get("status"),
        "description":    incident.get("description"),
        "alert_count":    incident.get("alert_count"),
        "hosts":          incident.get("hosts")   or [],
        "users":          incident.get("users")   or [],
        "mitre_tactics":  _mitre_pairs(incident.get("mitre_tactics_ids_and_names")),
        "mitre_techniques": _mitre_pairs(incident.get("mitre_techniques_ids_and_names")),
        "manual_severity": incident.get("manual_severity"),
        "assigned_user_mail": incident.get("assigned_user_mail"),
    }
    rows.append(incident_row)

    # ── Alerts ───────────────────────────────────────────
    for alert in incident.get("alerts") or []:
        if not isinstance(alert, dict):
            continue
        aid = str(alert.get("alert_id") or alert.get("event_id") or "")
        if not aid:
            continue
        row = _base_record(
            integration_id=integration_id,
            object_type="alert",
            object_id=aid,
            xdr_incident_id=inc_id,
            observed_at=_iso_from_epoch_ms(alert.get("detection_timestamp"))
                             or _iso_from_epoch_ms(alert.get("source_insert_ts")),
            raw=alert,
        )
        row["fields"] = {
            "event_type":       alert.get("event_type"),
            "severity":         alert.get("severity"),
            "description":      alert.get("description"),
            "action":           alert.get("action_pretty"),
            "host_name":        alert.get("host_name"),
            "host_ip":          alert.get("host_ip"),
            "user_name":        alert.get("user_name"),
            "process_name":     alert.get("action_process_image_name"),
            "process_cmdline":  alert.get("action_process_image_command_line"),
            "process_sha256":   alert.get("action_process_image_sha256"),
            "file_path":        alert.get("action_file_path"),
            "file_sha256":      alert.get("action_file_sha256"),
            "remote_ip":        alert.get("action_remote_ip"),
            "remote_port":      alert.get("action_remote_port"),
            "mitre_tactic":     _pair(alert.get("mitre_tactic_id_and_name")),
            "mitre_technique":  _pair(alert.get("mitre_technique_id_and_name")),
            "caused_by_rule":   alert.get("caused_by_rule")
                                    or alert.get("alert_source"),
        }
        rows.append(row)

    # ── Key artifacts (hash / ip / file / domain / user) ─
    for kart in incident.get("key_artifacts") or []:
        if not isinstance(kart, dict):
            continue
        kt = kart.get("type") or "artifact"
        kv = kart.get("value")
        if not kv:
            continue
        row = _base_record(
            integration_id=integration_id,
            object_type="key_artifact",
            object_id=f"{kt}:{kv}",
            xdr_incident_id=inc_id,
            observed_at=None,
            raw=kart,
        )
        row["fields"] = {"artifact_type": kt, "value": kv,
                             "vendor_score": kart.get("vendor_score")}
        rows.append(row)

    # ── Hosts ────────────────────────────────────────────
    for host in _uniq_strings(incident.get("hosts") or []):
        row = _base_record(
            integration_id=integration_id,
            object_type="host",
            object_id=host,
            xdr_incident_id=inc_id,
            observed_at=None,
            raw={"host_name": host},
        )
        row["fields"] = {"host_name": host}
        rows.append(row)

    # ── Users ────────────────────────────────────────────
    for user in _uniq_strings(incident.get("users") or []):
        row = _base_record(
            integration_id=integration_id,
            object_type="user",
            object_id=user,
            xdr_incident_id=inc_id,
            observed_at=None,
            raw={"user_name": user},
        )
        row["fields"] = {"user_name": user}
        rows.append(row)

    return rows


def parse_batch(payload: Any, *, integration_id: str) -> list[dict]:
    """Accept either a single incident, a list of incidents, or the
    verbatim ``{"reply": {"incidents": [...]}}`` envelope Cortex
    returns.  Always returns a flat list of canonical evidence
    rows."""
    if payload is None:
        return []
    if isinstance(payload, dict):
        reply = payload.get("reply") if "reply" in payload else None
        if isinstance(reply, dict) and "incidents" in reply:
            incidents = reply.get("incidents") or []
        elif "incident_id" in payload:
            incidents = [payload]
        elif "incidents" in payload:
            incidents = payload.get("incidents") or []
        else:
            incidents = []
    elif isinstance(payload, list):
        incidents = payload
    else:
        return []
    rows: list[dict] = []
    for inc in incidents:
        rows.extend(parse_incident(inc, integration_id=integration_id))
    return rows


# ── Helpers ──────────────────────────────────────────────────
def _mitre_pairs(seq: Any) -> list[dict]:
    if not isinstance(seq, (list, tuple)):
        return []
    out: list[dict] = []
    for entry in seq:
        pair = _pair(entry)
        if pair:
            out.append(pair)
    return out


def _pair(entry: Any) -> Optional[dict]:
    """Cortex encodes MITRE as strings like `TA0002 - Execution` or
    a dict.  Preserve both id and name deterministically."""
    if entry is None:
        return None
    if isinstance(entry, dict):
        return {"id":   entry.get("id")   or entry.get("tactic_id")
                            or entry.get("technique_id"),
                    "name": entry.get("name") or entry.get("tactic_name")
                            or entry.get("technique_name")}
    if isinstance(entry, str):
        if " - " in entry:
            i, n = entry.split(" - ", 1)
            return {"id": i.strip(), "name": n.strip()}
        return {"id": entry.strip(), "name": None}
    return None


def _uniq_strings(seq: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in seq:
        if isinstance(v, str) and v not in seen:
            seen.add(v)
            out.append(v)
    return out
