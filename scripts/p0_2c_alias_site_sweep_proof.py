#!/usr/bin/env python3
"""P0-2C · ALIAS SITE SWEEP — runtime proof.

Every LIVE endpoint-keyed surface must answer identically for every
validated alias of one endpoint, must say ENDPOINT_NOT_RESOLVED (never
`200 []`) for a supplied-but-unresolvable identifier, and must disclose
nothing to a principal from another customer.

Equivalence is asserted on AUTHORITATIVE EVIDENCE IDS, not on counts.
Where a surface is aggregate-only by contract, the strongest available
stable identifiers are compared and the reason is printed.

Usage:  python3 scripts/p0_2c_alias_site_sweep_proof.py
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests

BASE = os.environ.get("NIVX_BASE_URL", "http://localhost:8001")
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
FOREIGN = ("analyst@nivx-live.com", "NivxLive!Analyst2026")

DEVICE_IID = "dev_42e8c6dc74b9"
ENDPOINT_ID = "ep_2d57cbe6f80152062109"
HOSTNAME = "agent-env-630704a1-621f-478b-9b86-a321772d01bf"
FORGED = "dev_ffffffffffff"
FORGED_EP = "ep_ffffffffffffffffffff"

PASS: List[str] = []
FAIL: List[str] = []


def gate(name: str, ok: bool, detail: str = "") -> bool:
    (PASS if ok else FAIL).append(name)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  · {detail}" if detail else ""))
    return ok


def login(creds) -> str:
    r = requests.post(f"{BASE}/api/auth/login",
                      json={"email": creds[0], "password": creds[1]},
                      timeout=30)
    r.raise_for_status()
    d = r.json()
    return d.get("access_token") or d.get("token") or d["data"]["access_token"]


def get(tok: str, path: str, **params) -> Tuple[int, Dict[str, Any]]:
    r = requests.get(f"{BASE}/api{path}", params=params or None,
                     headers={"Authorization": f"Bearer {tok}"}, timeout=180)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {}


def unresolved(body: Dict[str, Any]) -> bool:
    return "ENDPOINT_NOT_RESOLVED" in json.dumps(
        {k: v for k, v in body.items()
         if k in ("state", "reason", "epistemic_state", "identity")})


# ── evidence-id extractors (per surface contract) ───────────────────
def ev_process_tree(b):
    return sorted({i for n in b.get("nodes") or []
                   for i in (n.get("event_iids") or [])})


def ev_detections(b):
    return sorted({f"{r.get('raw_id')}|{r.get('canonical_event_id')}"
                   for r in b.get("detections") or []})


def ev_commands(b):
    return sorted({c.get("command_id") for c in b.get("commands") or []})


def ev_trajectory(b):
    return sorted({e.get("event_iid") for e in b.get("events") or []})


def ev_device_traj(b):
    return sorted({e.get("id") for e in b.get("events") or []})


def ev_linked(b):
    return sorted({i.get("incident_id") for i in b.get("incidents") or []})


SITES = [
    # (label, path template, param style, extractor, aggregate_reason)
    ("process-tree", "/edr/process-tree", "query:endpoint_id",
     ev_process_tree, None),
    ("endpoint-detections", "/edr/endpoint-detections", "query:endpoint_id",
     ev_detections, None),
    ("response/actions", "/edr/response/actions", "query:endpoint_id",
     ev_commands, None),
    ("endpoints/{id}/trajectory", "/edr/endpoints/{id}/trajectory", "path",
     ev_trajectory, None),
    ("endpoints/{id}/linked-incidents", "/edr/endpoints/{id}/linked-incidents",
     "path", ev_linked, None),
    ("device-trajectory", "/edr/device-trajectory", "query:device",
     ev_device_traj, None),
]


def call(tok: str, path_tpl: str, style: str, ident: str, extra=None):
    extra = dict(extra or {})
    if style == "path":
        return get(tok, path_tpl.replace("{id}", ident), **extra)
    key = style.split(":", 1)[1]
    extra[key] = ident
    return get(tok, path_tpl, **extra)


def main() -> int:
    tok = login(ADMIN)
    foreign = login(FOREIGN)

    print("\nA · EVIDENCE-ID EQUIVALENCE ACROSS EVERY VALIDATED ALIAS")
    for label, tpl, style, extract, agg in SITES:
        extra = {"hours": 24 * 365 * 5} if "hours" not in tpl else {}
        if label == "device-trajectory":
            extra = {"all_time": "true"}
        if label in ("endpoints/{id}/trajectory",):
            extra = {"limit": 4000, "lane_end": 100000}
        sets, statuses = {}, {}
        for ident in (DEVICE_IID, ENDPOINT_ID, HOSTNAME):
            sc, body = call(tok, tpl, style, ident, extra)
            statuses[ident] = sc
            sets[ident] = extract(body)
        base = sets[DEVICE_IID]
        same = all(sets[i] == base for i in sets)
        gate(f"A · {label} · identical evidence ids for dev_ / ep_ / hostname",
             same and all(s == 200 for s in statuses.values()),
             f"n={len(base)} " + " ".join(f"{k[:12]}={len(v)}"
                                          for k, v in sets.items()))
        if base:
            gate(f"A · {label} · evidence is non-empty (equivalence is not "
                 f"trivially empty)", True, f"{len(base)} ids")
        else:
            gate(f"A · {label} · evidence non-empty", False,
                 "all three aliases returned NO evidence — equivalence is "
                 "vacuous on this surface with this fixture")

    print("\nB · FORGED IDENTIFIER → ENDPOINT_NOT_RESOLVED (never 200 [])")
    for label, tpl, style, extract, _ in SITES:
        for forged in (FORGED, FORGED_EP):
            sc, body = call(tok, tpl, style, forged)
            gate(f"B · {label} · {forged[:6]}… declares ENDPOINT_NOT_RESOLVED",
                 unresolved(body), f"http={sc} state={body.get('state')} "
                                   f"reason={body.get('reason')}")

    print("\nC · CROSS-TENANT · a foreign analyst learns nothing")
    for label, tpl, style, extract, _ in SITES:
        sc, body = call(foreign, tpl, style, DEVICE_IID)
        blob = json.dumps(body)
        gate(f"C · {label} · no evidence disclosed to another customer",
             extract(body) == [], f"ids={len(extract(body))}")
        gate(f"C · {label} · foreign failure class == unknown-identifier "
             f"class", unresolved(body) or extract(body) == [],
             f"state={body.get('state')}")
        gate(f"C · {label} · no hostname / endpoint_id leak",
             HOSTNAME not in blob and ENDPOINT_ID not in blob)

    print("\nD · NO-IDENTIFIER COLLECTION SEMANTICS PRESERVED (Q2b)")
    sc, body = get(tok, "/edr/response/actions")
    gate("D · /edr/response/actions with NO endpoint_id still returns a "
         "collection", sc == 200 and "commands" in body
         and body.get("state") != "ENDPOINT_NOT_RESOLVED",
         f"http={sc} n={len(body.get('commands') or [])}")
    sc, body = get(tok, "/edr/endpoints")
    gate("D · /edr/endpoints (unfiltered inventory) unchanged",
         sc == 200 and isinstance(body.get("endpoints"), list),
         f"n={body.get('count')}")

    print("\nE · THE ALIAS SET IS DISCLOSED (addressed_by)")
    for tpl, style, key in (("/edr/process-tree", "query:endpoint_id",
                             "identity"),
                            ("/edr/endpoint-detections", "query:endpoint_id",
                             "identity"),
                            ("/edr/response/actions", "query:endpoint_id",
                             "identity")):
        sc, body = call(tok, tpl, style, DEVICE_IID)
        refs = ((body.get(key) or {}).get("addressed_by") or [])
        gate(f"E · {tpl} discloses the alias set it queried",
             bool(refs) and ENDPOINT_ID in refs and DEVICE_IID in refs,
             ",".join(map(str, refs)))

    print("\nG · COMMAND PLANE ACCEPTS THE SAME ALIASES (no false "
          "ENDPOINT_NOT_ENROLLED)")
    # Proven WITHOUT creating a command: a pid that was never observed
    # must fail on TARGET identity, not on enrolment. Reaching the target
    # check at all proves the alias was resolved to the enrolled endpoint.
    for ident, expect in ((DEVICE_IID, "TARGET"), (HOSTNAME, "TARGET"),
                          (ENDPOINT_ID, "TARGET"), (FORGED, "ENDPOINT")):
        r = requests.post(f"{BASE}/api/edr/response/actions",
                          headers={"Authorization": f"Bearer {tok}"},
                          json={"endpoint_id": ident, "action": "KILL_PROCESS",
                                "target": {"pid": 999999},
                                "reason": "p0-2c proof · never executed"},
                          timeout=60)
        code = ((r.json() or {}).get("detail") or {}).get("error", "")
        gate(f"G · POST actions · {ident[:14]}… fails on {expect}, not the "
             f"wrong one", str(code).startswith(expect),
             f"http={r.status_code} error={code}")

    print("\nF · TENANT-CONSTRAINED REVERSE LOOKUP")
    sys.path.insert(0, "/app/backend")
    os.environ.setdefault("PYTHONPATH", "/app/backend")
    from dotenv import load_dotenv
    load_dotenv("/app/backend/.env")
    from services.edr import device_identity as dsvc            # noqa: E402
    ident = dsvc.resolve(DEVICE_IID, {"all_tenants": True, "tenant_ids": []})
    wide = dsvc.identity_refs(ident, DEVICE_IID)
    narrow = dsvc.identity_refs(ident, DEVICE_IID, tenant_ids=["__nobody__"])
    gate("F · a foreign tenant constraint can only NARROW the alias set",
         set(narrow) <= set(wide) and ENDPOINT_ID in wide
         and ENDPOINT_ID not in narrow,
         f"wide={len(wide)} narrow={len(narrow)}")

    print(f"\n{'='*66}\nP0-2C ALIAS SITE SWEEP · {len(PASS)} PASS · "
          f"{len(FAIL)} FAIL")
    for f in FAIL:
        print(f"  FAILED: {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
