#!/usr/bin/env python3
"""P0-F.13.2 — read-only probe of BOTH device-trajectory implementations.

Audit instrument only. It calls the two live APIs and reports what each
substrate actually returns, so the audit states facts instead of
impressions. It writes nothing and mutates nothing.
"""
import json
import os
import sys
from collections import Counter

import requests

BASE = os.environ.get("AUDIT_BASE_URL") or ""
if not BASE:
    with open("/app/apps/nivxray-xdr/.env") as fh:
        for line in fh:
            if line.startswith("REACT_APP_NIVXRAY_API_URL"):
                BASE = line.split("=", 1)[1].strip()
EMAIL = "admin@nivxray.com"
PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"
DEVICE = sys.argv[1] if len(sys.argv) > 1 else "dev_42e8c6dc74b9"

s = requests.Session()
tok = s.post(f"{BASE}/api/auth/login",
             json={"email": EMAIL, "password": PASSWORD},
             timeout=60).json()
s.headers["Authorization"] = f"Bearer {tok['access_token']}"

out = {"base_url": BASE, "device": DEVICE}

# ── Implementation C — canonical endpoint projection (AMP renderer) ──
amp = s.get(f"{BASE}/api/edr/endpoints/{DEVICE}/trajectory",
            params={"lane_start": 0, "lane_end": 600, "limit": 4000},
            timeout=300).json()
axis = amp.get("lane_axis") or {}
lanes = axis.get("lanes") or []
events = amp.get("events") or []
out["implementation_c_amp"] = {
    "endpoint": "/api/edr/endpoints/{id}/trajectory",
    "engine_id": amp.get("engine_id"),
    "total_lanes": axis.get("total_lanes"),
    "group_counts": axis.get("group_counts"),
    "lane_axis_version": axis.get("lane_axis_version"),
    "axis_scope": axis.get("axis_scope"),
    "observations_all_time": amp.get("observations_all_time"),
    "events_returned": len(events),
    "lane_end_state": dict(Counter(l.get("end_state") for l in lanes)),
    "lane_parent_state": dict(Counter(l.get("parent_state") for l in lanes)),
    "event_kinds": dict(Counter(e.get("kind") for e in events)),
    "event_lane_groups": dict(Counter(e.get("lane_group") for e in events)),
    "dispositions": dict(Counter(e.get("disposition") for e in events)),
    "lanes_with_real_parent": sum(
        1 for l in lanes if l.get("parent_iid")),
    "lanes_with_parent_lane_index": sum(
        1 for l in lanes if l.get("parent_lane_index") is not None),
    "file_lane_examples": [l.get("label") for l in lanes
                           if l.get("group") == "FILE"][:8],
    "network_lane_examples": [l.get("label") for l in lanes
                              if l.get("group") == "NETWORK"][:8],
    "computer_not_collected": sorted(
        k for k, v in (amp.get("computer") or {}).items()
        if isinstance(v, dict) and v.get("state") == "NOT_COLLECTED"),
    "epistemic_state": (amp.get("epistemic_state") or {}).get("state"),
}

# ── Implementation A — XDR case/incident device aggregation ─────────
try:
    xdr = s.get(f"{BASE}/api/edr/device-trajectory",
                params={"device": DEVICE, "all_time": "true"},
                timeout=300).json()
    xev = xdr.get("events") or []
    out["implementation_a_xdr"] = {
        "endpoint": "/api/edr/device-trajectory",
        "http": 200,
        "keys": sorted(xdr.keys()),
        "identity": xdr.get("identity") or xdr.get("device"),
        "events_returned": len(xev),
        "event_kinds": dict(Counter(e.get("kind") for e in xev)),
        "lanes": xdr.get("lane_counts") or xdr.get("lanes"),
        "incidents": len(xdr.get("incidents") or []),
        "has_process_iid": sum(1 for e in xev if e.get("process_iid")),
        "has_parent_iid": sum(1 for e in xev if e.get("parent_iid")),
    }
except Exception as exc:                                    # noqa: BLE001
    out["implementation_a_xdr"] = {"error": repr(exc)}

print(json.dumps(out, indent=1, default=str))
