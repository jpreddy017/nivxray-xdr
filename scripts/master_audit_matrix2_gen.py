#!/usr/bin/env python3
"""MASTER AUDIT · Matrix 2 route-table generator.

Emits the route-level ownership + wiring table from THREE evidence
sources only — never from filename or folder name:

  1. the LIVE OpenAPI of the running backend  (registration truth)
  2. the read-only runtime probe results       (reachability truth)
  3. the frontend→backend reconciliation       (product-surface truth)

Legacy malware-analysis / decoder-lab lineage is emitted at lineage
level (owner decision 2A), never endpoint-by-endpoint.
"""
from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict

OPENAPI = "/tmp/openapi.json"
PROBE = "/app/memory/master_audit_runtime_probe.json"
SRC = "/app/apps/nivxray-xdr/src"
OUT = "/app/memory/_matrix2_routes.md"

# ── Ownership rules, prefix → (owner, capability) ──────────────────
# XDR   = NivXRay XDR product surface
# EDR   = NivXForge EDR product surface
# SHARED= authoritative fabric both products project from
# LEGACY= earlier malware-analysis/decoder-lab lineage (lineage-level)
OWNER_RULES: list[tuple[str, str, str]] = [
    ("/api/edr/agent/",                "SHARED", "sensor transport + telemetry auth"),
    ("/api/edr/enrollment",            "EDR",    "endpoint enrolment + credential lifecycle"),
    ("/api/edr/wave0",                 "EDR",    "capability-truth registry"),
    ("/api/edr/response",              "EDR",    "endpoint response lifecycle"),
    ("/api/edr/",                      "EDR",    "endpoint evidence projection"),
    ("/api/xdr/collector",             "XDR",    "collection + transport plane"),
    ("/api/xdr/data-sources",          "XDR",    "data-source control plane"),
    ("/api/xdr/ingest",                "SHARED", "authoritative ingest boundary"),
    ("/api/xdr/detection",             "SHARED", "detection content plane"),
    ("/api/xdr/rule-studio",           "XDR",    "rule authoring"),
    ("/api/xdr/correlation",           "SHARED", "correlation engine"),
    ("/api/xdr/mss",                   "XDR",    "MSS / control-center projection"),
    ("/api/xdr/dashboard",             "XDR",    "control-center tiles"),
    ("/api/xdr/search",                "XDR",    "global search"),
    ("/api/xdr/incidents",             "XDR",    "incident queue operations"),
    ("/api/xdr/investigation",         "XDR",    "investigation scenario match"),
    ("/api/xdr/response-evidence",     "SHARED", "response evidence sink"),
    ("/api/xdr/spread",                "SHARED", "indicator spread / sightings"),
    ("/api/xdr/cve",                   "XDR",    "vulnerability exposure"),
    ("/api/xdr/lolbas",                "SHARED", "LOLBAS content pack"),
    ("/api/xdr/scenarios",             "XDR",    "investigation corpus"),
    ("/api/xdr/saved-views",           "XDR",    "queue saved views"),
    ("/api/xdr/vendor",                "XDR",    "vendor integration plane"),
    ("/api/xdr/rbac",                  "SHARED", "RBAC / authorisation"),
    ("/api/xdr/api-keys",              "SHARED", "programmatic access"),
    ("/api/xdr/webhooks",              "SHARED", "outbound webhooks"),
    ("/api/xdr/secrets",               "SHARED", "secrets store"),
    ("/api/xdr/audit-log",             "SHARED", "tamper-evident audit"),
    ("/api/auth",                      "SHARED", "one auth engine, two products"),
    ("/api/incidents",                 "SHARED", "authoritative incident record"),
    ("/api/cases",                     "SHARED", "case store"),
    ("/api/investigations",            "SHARED", "investigation records"),
    ("/api/investigation/",            "SHARED", "investigation projections"),
    ("/api/correlations",              "SHARED", "correlation records"),
    ("/api/v2/",                       "SHARED", "v2 authoritative fabric"),
    ("/api/iue/",                      "SHARED", "IUE understanding lanes"),
    ("/api/verdict/",                  "SHARED", "verdict engine"),
    ("/api/process-tree",              "SHARED", "process ancestry"),
    ("/api/timeline",                  "SHARED", "timeline"),
    ("/api/threat-intel",              "SHARED", "threat intelligence"),
    ("/api/ioc",                       "SHARED", "IOC intelligence"),
    ("/api/enrichment",                "SHARED", "enrichment"),
    ("/api/mitre",                     "SHARED", "MITRE catalogue"),
    ("/api/behaviors",                 "SHARED", "behaviour registry"),
    ("/api/behavior",                  "SHARED", "behaviour provenance"),
    ("/api/response",                  "SHARED", "response fabric alias"),
    ("/api/platform",                  "SHARED", "platform metrics"),
    ("/api/health",                    "SHARED", "liveness"),
    ("/api/kb",                        "SHARED", "knowledge base"),
    ("/api/docs",                      "SHARED", "product documentation"),
    ("/api/schemas",                   "SHARED", "public CIO schema"),
    ("/api/telemetry",                 "SHARED", "telemetry adapters"),
    ("/api/admin/content-supply-chain", "SHARED", "content supply chain"),
    ("/api/admin/",                    "SHARED", "administration"),
    ("/api/narration",                 "SHARED", "narrative composition"),
    ("/api/report",                    "SHARED", "reporting"),
    ("/api/activity",                  "SHARED", "activity inventory"),
    ("/api/observation",               "SHARED", "observation projections"),
    ("/api/sessions",                  "SHARED", "session records"),
    ("/api/session",                   "SHARED", "session records"),
    ("/api/uaie",                      "SHARED", "UAIE catalogue"),
    ("/api/uil",                       "SHARED", "UIL classification"),
    ("/api/ssot",                      "SHARED", "SSOT"),
    ("/api/nivxforge/",                "LEGACY", "older investigation/CIO lineage (name collision: NOT the EDR backend)"),
]

# lineage-level legacy prefixes — emitted as ONE row each (decision 2A)
LEGACY_LINEAGE = {
    "/api/die":            "IEDDE / decoder-intelligence lab",
    "/api/iedde":          "IEDDE analyser",
    "/api/decode":         "decoder guidance + mitigations lab",
    "/api/decoded":        "decoded-artifact lab",
    "/api/analyze":        "single-payload analysis lab",
    "/api/rc5":            "RC5 semantic-engine sprint",
    "/api/lab":            "gamified decoder lab",
    "/api/corpus":         "corpus validation lab",
    "/api/finetune":       "LLM fine-tuning lab",
    "/api/learner":        "learner lab",
    "/api/learning":       "learning lab",
    "/api/learning-engine": "learning engine lab",
    "/api/training":       "training lab",
    "/api/batch":          "batch payload test harness",
    "/api/benchmark":      "benchmark harness",
    "/api/regression":     "regression harness",
    "/api/corrections":    "analyst-correction lab",
    "/api/moe":            "mixture-of-experts panel",
    "/api/planner":        "planner lab",
    "/api/deck":           "pitch-deck download",
    "/api/documents":      "document workspace lab",
    "/api/files":          "file upload lab",
    "/api/artifacts":      "artifact lab",
    "/api/examples":       "sample library",
    "/api/recipe":         "recipe lab",
    "/api/understand":     "understanding lab",
    "/api/upload":         "upload lab",
    "/api/share":          "share lab",
    "/api/emit":           "emit lab",
    "/api/osint":          "OSINT lab",
    "/api/troubleshoot":   "troubleshoot engine",
    "/api/multilayer":     "multilayer battery",
    "/api/taxii":          "TAXII export lab",
    "/api/lolbas":         "LOLBAS export lab",
    "/api/threat-model":   "threat-model lab",
    "/api/chain":          "chain analyser lab",
    "/api/history":        "run history lab",
    "/api/coverage":       "coverage metrics lab",
    "/api/privacy":        "privacy lab",
    "/api/public":         "public feeds lab",
    "/api/system":         "system lab",
    "/api/metrics":        "metrics lab",
    "/api/operations":     "operations lab",
    "/api/mitigations":    "mitigation lab",
    "/api/ai":             "AI assistant lab",
    "/api/convergence":    "convergence lab",
    "/api/behavioral":     "behavioural sysmon lab",
    "/api/attack":         "attack lab",
    "/api/intelligence":   "intelligence overlay lab",
    "/api/incident_summary": "incident summary lab",
    "/api/reports":        "report lab",
    "/api/audit":          "audit download lab",
    "/api/nivxforge":      "older investigation/CIO lineage (name collision: NOT the EDR backend)",
}


def owner_of(path: str) -> tuple[str, str]:
    for pre, owner, cap in OWNER_RULES:
        if path.startswith(pre):
            return owner, cap
    for pre, note in LEGACY_LINEAGE.items():
        if path.startswith(pre):
            return "LEGACY", note
    return "UNCLASSIFIED", "—"


def lineage_of(path: str) -> str | None:
    for pre in sorted(LEGACY_LINEAGE, key=len, reverse=True):
        if path.startswith(pre):
            return pre
    return None


def frontend_consumers() -> dict[str, list[str]]:
    """path-literal → call sites, from the running product source."""
    out = subprocess.run(
        ["grep", "-rnoE", r"/api/[A-Za-z0-9_./{}$:-]+",
         "--include=*.jsx", "--include=*.js", SRC],
        capture_output=True, text=True, check=False)
    m = defaultdict(list)
    for ln in out.stdout.splitlines():
        try:
            f, _no, hit = ln.split(":", 2)
        except ValueError:
            continue
        m[hit].append(f.replace(SRC + "/", ""))
    # also the axios clients that strip the /api prefix
    out2 = subprocess.run(
        ["grep", "-rnoE", r"api\.(get|post|put|patch|delete)\(\s*[\"'`]/[A-Za-z0-9_./{}$:-]+",
         "--include=*.jsx", "--include=*.js", SRC],
        capture_output=True, text=True, check=False)
    for ln in out2.stdout.splitlines():
        try:
            f, _no, hit = ln.split(":", 2)
        except ValueError:
            continue
        rel = re.search(r"[\"'`](/[A-Za-z0-9_./{}$:-]+)", hit)
        if rel:
            m["/api" + rel.group(1)].append(f.replace(SRC + "/", ""))
    return m


def norm(p: str) -> str:
    p = p.split("?")[0].rstrip(".,)`'\"")
    p = re.sub(r"\$\{[^}]*\}", "X", p)
    p = re.sub(r"\{[^}]*\}", "X", p)
    p = re.sub(r"/:[A-Za-z0-9_]+", "/X", p)
    return re.sub(r"/+$", "", p) or "/"


def main() -> None:
    spec = json.load(open(OPENAPI))
    routes = sorted(spec["paths"])
    probes = {p["path"].split("?")[0]: p for p in json.load(open(PROBE))["probes"]}

    fe = frontend_consumers()
    fe_norm: dict[str, list[str]] = defaultdict(list)
    for lit, files in fe.items():
        fe_norm[norm(lit)].extend(files)

    def consumer(route: str) -> str:
        rx = re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", re.escape(route)
                                     .replace(r"\{", "{").replace(r"\}", "}")) + "$")
        hits: list[str] = []
        for n, files in fe_norm.items():
            if rx.match(n):
                hits.extend(files)
        # base-prefix consumers (client concatenates the tail at runtime)
        for n, files in fe_norm.items():
            if route.startswith(n + "/") and n.count("/") >= 3:
                hits.extend(files)
        uniq = sorted(set(hits))
        return ", ".join(f"`{h}`" for h in uniq[:2]) + ("" if len(uniq) <= 2 else f" +{len(uniq)-2}") if uniq else "—"

    def verdict(route: str) -> str:
        rx = re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", re.escape(route)
                                     .replace(r"\{", "{").replace(r"\}", "}")) + "$")
        for p, row in probes.items():
            if rx.match(p):
                return row["verdict"]
        return "NOT_PROBED"

    grouped: dict[str, list[str]] = defaultdict(list)
    legacy_seen: dict[str, int] = defaultdict(int)
    adopted: list[str] = []

    for r in routes:
        owner, cap = owner_of(r)
        methods = ",".join(sorted(m.upper() for m in spec["paths"][r]
                                  if m in ("get", "post", "put", "patch", "delete")))
        cons = consumer(r)
        if owner == "LEGACY":
            # Owner rule 2: a lineage route that a CURRENT product surface
            # actually calls is NOT legacy — it is adopted-in-product and
            # must be classified by its real role.
            if cons != "—":
                adopted.append(
                    f"| `{r}` | {methods} | "
                    f"{LEGACY_LINEAGE.get(lineage_of(r) or '', '—')} "
                    f"| {cons} | {verdict(r)} |")
            else:
                legacy_seen[lineage_of(r) or "?"] += 1
            continue
        grouped[f"{owner} · {cap}"].append(
            f"| `{r}` | {methods} | {cons} | {verdict(r)} |")

    with open(OUT, "w") as fh:
        fh.write("### 2.A · ROUTE-LEVEL TABLE — XDR / EDR / SHARED\n\n")
        fh.write("Columns: **Route · Methods · Product-surface consumer (running "
                 "frontend source) · Runtime probe verdict**. "
                 "`—` in the consumer column means *no product surface calls this "
                 "route* → orphan candidate. `NOT_PROBED` means the route was not "
                 "in the read-only probe set (registration + consumer evidence only).\n")
        for key in sorted(grouped):
            fh.write(f"\n#### {key}  ({len(grouped[key])} routes)\n\n")
            fh.write("| Route | Methods | Product-surface consumer | Runtime verdict |\n")
            fh.write("|---|---|---|---|\n")
            fh.write("\n".join(sorted(grouped[key])) + "\n")

        fh.write("\n### 2.B · ADOPTED FROM THE EARLIER LINEAGE — "
                 "reclassified, NOT legacy (owner rule 2)\n\n")
        fh.write("These routes belong to the earlier malware-analysis / "
                 "decoder-laboratory lineage **but a current product surface "
                 "actually calls them**, so per the owner's rule they are "
                 "classified by their real role — `SHARED · adopted-in-product` "
                 "— and must NOT be treated as legacy or removed.\n\n")
        fh.write("| Route | Methods | Lineage of origin | Product-surface consumer | Runtime verdict |\n")
        fh.write("|---|---|---|---|---|\n")
        fh.write("\n".join(sorted(adopted)) + "\n")
        fh.write(f"\n**{len(adopted)} adopted routes.** The dominant consumers are "
                 "`xdr/pages/XdrRuleTuningPage.jsx` (regression · batch · corpus "
                 "harness), `xdr/adopt/baseCapabilities.js` + "
                 "`xdr/adopt/enginePanels.jsx` (the adopt-before-invent panels), "
                 "`xdr/intel/XdrRecommendationsPanel.jsx` "
                 "(`/api/decode/mitigations/evidence_driven`) and "
                 "`xdr/components/IntelligenceControlPanel.jsx` "
                 "(`/api/intelligence/policy/*`).\n")

        fh.write("\n### 2.C · LEGACY LINEAGE — module/lineage level "
                 "(owner decision 2A, NOT endpoint-by-endpoint)\n\n")
        fh.write("Every route below has **no** product-surface consumer in "
                 "either shell.\n\n")
        fh.write("| Lineage prefix | Routes | Lineage | Owner | Action |\n|---|---|---|---|---|\n")
        total = 0
        for pre, n in sorted(legacy_seen.items(), key=lambda kv: -kv[1]):
            total += n
            fh.write(f"| `{pre}/*` | {n} | {LEGACY_LINEAGE.get(pre, '—')} | "
                     f"LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |\n")
        fh.write(f"\n**Legacy lineage total: {total} routes** across "
                 f"{len(legacy_seen)} lineages, of "
                 f"{len(routes)} registered routes.\n")

    print(f"wrote {OUT}")
    print(f"routes total {len(routes)} · product routes "
          f"{sum(len(v) for v in grouped.values())} · legacy {total}")
    for key in sorted(grouped):
        print(f"  {len(grouped[key]):>4}  {key}")


if __name__ == "__main__":
    main()
