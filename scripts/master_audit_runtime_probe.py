#!/usr/bin/env python3
"""MASTER AUDIT · read-only runtime probe.

Establishes WIRING TRUTH (not code existence) for every XDR/EDR/SHARED
capability surface: router registered + app running + HTTP reachable +
does it return real data or an honest empty/absent state.

READ-ONLY. GET requests only. No POST/PUT/PATCH/DELETE.
"""
from __future__ import annotations

import json
import os
import sys

import requests

BASE = os.environ.get("AUDIT_BASE") or "https://greeting-app-5782.preview.emergentagent.com"
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")

ENDPOINT = "dev_42e8c6dc74b9"
INCIDENT = "inc_2305c71cd8f54dc38e55"

# (group, path) — GET only.
PROBES: list[tuple[str, str]] = [
    # ── XDR · incidents / investigation / correlation ──────────────
    ("xdr.incidents",        "/api/incidents?limit=3"),
    ("xdr.incidents",        f"/api/incidents/{INCIDENT}"),
    ("xdr.incidents",        f"/api/incidents/{INCIDENT}/attack-story"),
    ("xdr.incidents",        f"/api/incidents/{INCIDENT}/attack-graph"),
    ("xdr.incidents",        f"/api/incidents/{INCIDENT}/threat-model"),
    ("xdr.incidents",        f"/api/incidents/{INCIDENT}/investigation"),
    ("xdr.incidents",        f"/api/incidents/{INCIDENT}/summary"),
    ("xdr.mss",              "/api/xdr/mss/kpis"),
    ("xdr.mss",              "/api/xdr/mss/soc-queue"),
    ("xdr.mss",              "/api/xdr/mss/detection-overview"),
    ("xdr.mss",              "/api/xdr/mss/analyst-workload"),
    ("xdr.mss",              "/api/xdr/mss/customer-operations"),
    ("xdr.mss",              "/api/xdr/mss/auto-investigation"),
    ("xdr.mss",              "/api/xdr/mss/recent-activity"),
    ("xdr.mss",              "/api/xdr/mss/state-distribution"),
    ("xdr.dashboard",        "/api/xdr/dashboard/tiles"),
    ("xdr.search",           "/api/xdr/search?q=dev_42e8c6dc74b9"),
    ("xdr.search",           "/api/xdr/search/capabilities"),
    ("xdr.correlation",      "/api/xdr/correlation/status"),
    ("xdr.correlation",      "/api/xdr/correlation/rules"),
    ("xdr.correlation",      "/api/xdr/correlation/matches"),
    ("xdr.correlations",     "/api/correlations?limit=3"),
    ("xdr.scenarios",        "/api/xdr/scenarios"),
    ("xdr.saved_views",      "/api/xdr/saved-views"),

    # ── XDR · detection content / rule studio ─────────────────────
    ("xdr.detection",        "/api/xdr/detection/status"),
    ("xdr.detection",        "/api/xdr/detection/inventory"),
    ("xdr.detection",        "/api/xdr/detection/rules?limit=3"),
    ("xdr.detection",        "/api/xdr/detection/versions"),
    ("xdr.detection",        "/api/xdr/detection/policy"),
    ("xdr.rule_studio",      "/api/xdr/rule-studio/status"),
    ("xdr.rule_studio",      "/api/xdr/rule-studio/lanes"),
    ("xdr.rule_studio",      "/api/xdr/rule-studio/rules"),

    # ── XDR · collector / data sources / ingest ───────────────────
    ("xdr.collector_landed", "/api/xdr/collector/landing"),
    ("xdr.collector_landed", "/api/xdr/collector/connectors"),
    ("xdr.collector_landed", "/api/xdr/collector/collectors"),
    ("xdr.collector_landed", "/api/xdr/collector/data-sources"),
    ("xdr.collector_landed", "/api/xdr/collector/source-types"),
    ("xdr.collector_landed", "/api/xdr/collector/outbox"),
    ("xdr.collector_landed", "/api/xdr/collector/outbox/health"),
    ("xdr.collector_landed", "/api/xdr/collector/telemetry-health"),
    ("xdr.collectors_admin", "/api/xdr/collectors"),
    ("xdr.collectors_admin", "/api/xdr/collectors/catalog"),
    ("xdr.collectors_admin", "/api/xdr/collectors/protocols/catalog"),
    ("xdr.data_sources",     "/api/xdr/data-sources"),
    ("xdr.data_sources",     "/api/xdr/data-sources/kinds/catalog"),

    # ── XDR · response plane ──────────────────────────────────────
    ("xdr.response",         f"/api/xdr/incidents/{INCIDENT}/response-executions"),
    ("xdr.response",         "/api/response/actions"),
    ("xdr.response_orphan",  "/api/playbooks"),
    ("xdr.response_orphan",  "/api/automation-rules"),
    ("xdr.response_orphan",  "/api/respond/execute"),
    ("xdr.response_orphan",  "/api/xdr/extensions"),
    ("xdr.response_orphan",  "/api/xdr/health/outbox"),

    # ── XDR · governance / platform ───────────────────────────────
    ("xdr.rbac",             "/api/xdr/rbac/session-context"),
    ("xdr.rbac",             "/api/xdr/rbac/roles"),
    ("xdr.rbac",             "/api/xdr/rbac/users"),
    ("xdr.rbac",             "/api/xdr/rbac/permissions"),
    ("xdr.api_keys",         "/api/xdr/api-keys"),
    ("xdr.webhooks",         "/api/xdr/webhooks"),
    ("xdr.secrets",          "/api/xdr/secrets"),
    ("xdr.audit_log",        "/api/xdr/audit-log?limit=3"),
    ("xdr.audit_log",        "/api/xdr/audit-log/verify/chain"),
    ("xdr.spread",           "/api/xdr/spread"),
    ("xdr.spread",           "/api/xdr/spread/policy"),
    ("xdr.spread",           "/api/xdr/spread/signals"),
    ("xdr.cve",              "/api/xdr/cve/status"),
    ("xdr.cve",              "/api/xdr/cve/exposures"),
    ("xdr.cve",              "/api/xdr/cve/list?limit=3"),
    ("xdr.lolbas",           "/api/xdr/lolbas/status"),
    ("xdr.lolbas",           "/api/xdr/lolbas/coverage"),
    ("xdr.lolbas",           "/api/xdr/lolbas/entries?limit=3"),
    ("xdr.vendor",           "/api/xdr/vendor/_catalog"),
    ("xdr.vendor",           "/api/xdr/vendor/cortex/connections"),
    ("xdr.vendor",           "/api/xdr/vendor/cortex/actions"),
    ("xdr.platform",         "/api/platform/metrics"),
    ("xdr.mitre",            "/api/mitre/catalogue/coverage"),
    ("xdr.intel",            "/api/threat-intel/status"),
    ("xdr.intel",            "/api/ioc/lookup?value=1.1.1.1"),
    ("xdr.kb",               "/api/kb/stats"),
    ("xdr.docs",             "/api/docs/stats"),

    # ── EDR ───────────────────────────────────────────────────────
    ("edr.inventory",        "/api/edr/endpoints"),
    ("edr.context",          f"/api/edr/context?incident_id={INCIDENT}"),
    ("edr.trajectory",       f"/api/edr/device-trajectory?device={ENDPOINT}"),
    ("edr.trajectory",       f"/api/edr/endpoints/{ENDPOINT}/trajectory"),
    ("edr.trajectory",       f"/api/edr/endpoints/{ENDPOINT}/trajectory/focus"),
    ("edr.linked_incidents", f"/api/edr/endpoints/{ENDPOINT}/linked-incidents"),
    ("edr.detections",       "/api/edr/detections"),
    ("edr.detections",       "/api/edr/endpoint-detections"),
    ("edr.process_tree",     f"/api/edr/process-tree?endpoint_id={ENDPOINT}"),
    ("edr.campaign_story",   f"/api/edr/campaign-story?incident_id={INCIDENT}"),
    ("edr.file_traj",        f"/api/edr/file-trajectory?device={ENDPOINT}"),
    ("edr.fleet_spread",     "/api/edr/fleet-spread-index"),
    ("edr.narrative",        "/api/edr/observation-narrative"),
    ("edr.response",         "/api/edr/response/actions"),
    ("edr.response",         "/api/edr/response/isolation-policy"),
    ("edr.enrollment",       "/api/edr/enrollment/endpoints"),
    ("edr.enrollment",       "/api/edr/enrollment/tokens"),
    ("edr.enrollment",       "/api/edr/enrollment/rejections"),
    ("edr.wave0",            "/api/edr/wave0/capabilities/summary"),
    ("edr.wave0",            "/api/edr/wave0/sensors"),
    ("edr.wave0",            "/api/edr/wave0/contracts"),
    ("edr.wave0",            "/api/edr/wave0/detection-rule-bindings"),
    ("edr.wave0",            "/api/edr/wave0/raw-events/stats"),
    ("edr.wave0",            "/api/edr/wave0/filter-taxonomy"),

    # ── SHARED fabric (v2 / cases / investigation) ────────────────
    ("shared.v2_cases",      "/api/v2/cases?limit=3"),
    ("shared.cases",         "/api/cases?limit=3"),
    ("shared.investigation", "/api/investigations?limit=3"),
    ("shared.activity",      "/api/activity/inventory"),
    ("shared.observation",   "/api/observation/inventory"),
    ("shared.truth",         "/api/admin/truth-inventory"),
    ("shared.health",        "/api/health"),

    # ── LEGACY lineage (module-level sample only) ─────────────────
    ("legacy.lab",           "/api/lab/status"),
    ("legacy.rc5",           "/api/rc5/diag/status"),
    ("legacy.die",           "/api/die/"),
    ("legacy.iedde",         "/api/iedde/analyze"),
    ("legacy.corpus",        "/api/corpus/validate/example"),
    ("legacy.nivxforge_pkg", "/api/nivxforge/health"),
    ("legacy.nivxforge_pkg", "/api/nivxforge/preview/framework-status"),
]


def classify(status: int, body: str) -> str:
    if status == 200:
        try:
            j = json.loads(body)
        except Exception:
            return "REACHABLE_200_NON_JSON"
        # empty-ness heuristics, honest reporting only
        if isinstance(j, list):
            return "REACHABLE_200_DATA" if j else "REACHABLE_200_EMPTY"
        if isinstance(j, dict):
            for k in ("items", "results", "incidents", "endpoints", "rules",
                      "events", "connectors", "collectors", "data_sources",
                      "cases", "detections", "tiles", "entries"):
                v = j.get(k)
                if isinstance(v, list):
                    return "REACHABLE_200_DATA" if v else "REACHABLE_200_EMPTY"
            return "REACHABLE_200_DATA" if j else "REACHABLE_200_EMPTY"
    if status in (401, 403):
        return f"AUTHZ_{status}"
    if status == 404:
        return "NOT_ROUTED_404"
    if status == 405:
        return "ROUTED_METHOD_MISMATCH_405"
    if status == 422:
        return "ROUTED_NEEDS_PARAMS_422"
    if status == 501:
        return "NOT_IMPLEMENTED_501"
    if status >= 500:
        return f"SERVER_ERROR_{status}"
    return f"HTTP_{status}"


def main() -> int:
    s = requests.Session()
    r = s.post(f"{BASE}/api/auth/login",
               json={"email": ADMIN[0], "password": ADMIN[1]}, timeout=30)
    if r.status_code != 200:
        print(f"LOGIN FAILED {r.status_code} {r.text[:200]}")
        return 2
    tok = r.json().get("access_token") or r.json().get("token")
    s.headers["Authorization"] = f"Bearer {tok}"
    print(f"LOGIN OK · admin · token {str(tok)[:12]}…\n")

    rows = []
    for group, path in PROBES:
        try:
            resp = s.get(f"{BASE}{path}", timeout=45)
            verdict = classify(resp.status_code, resp.text)
            size = len(resp.content)
        except Exception as exc:                     # noqa: BLE001
            verdict, size, resp = f"PROBE_ERROR:{type(exc).__name__}", 0, None
        rows.append({"group": group, "path": path, "verdict": verdict,
                     "status": getattr(resp, "status_code", None), "bytes": size})
        print(f"{verdict:28} {size:>9}B  {path}")

    out = "/app/memory/master_audit_runtime_probe.json"
    with open(out, "w") as fh:
        json.dump({"base": BASE, "probes": rows}, fh, indent=2)
    print(f"\nwrote {out} · {len(rows)} probes")

    from collections import Counter
    print("\n== verdict summary ==")
    for k, v in sorted(Counter(r["verdict"] for r in rows).items()):
        print(f"{v:4}  {k}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
