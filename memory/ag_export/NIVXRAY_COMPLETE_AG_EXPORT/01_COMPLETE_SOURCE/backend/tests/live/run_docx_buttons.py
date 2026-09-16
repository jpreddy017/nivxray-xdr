#!/usr/bin/env python3
"""Live test of every WORKSPACE button against every payload in Testing_new.docx.
Produces a compact PASS/FAIL matrix + saves per-sample JSON in
/app/test_reports/docx_buttons/."""
import json, os, time, requests, docx
from pathlib import Path

API   = "http://localhost:8001"
# Credentials come from env (backend/.env exports ADMIN_EMAIL / ADMIN_PASSWORD).
_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if not _PASSWORD:
    raise SystemExit("ADMIN_PASSWORD env var required (source backend/.env first)")
CREDS = {"email": os.environ.get("ADMIN_EMAIL", "admin@nivxray.com"), "password": _PASSWORD}
OUTDIR = Path("/app/test_reports/docx_buttons"); OUTDIR.mkdir(parents=True, exist_ok=True)

# ── Extract 4 distinct payloads from the doc ────────────────────────────
d = docx.Document("/app/backend/tests/live/testing_new.docx")
p = [x.text for x in d.paragraphs if x.text.strip()]
SAMPLES = [
    ("S1_base32_blob",           p[0]),                          # base32 blob
    ("S2_ps_frombase64_shellcode", p[1]),                        # [Byte[]]$var_code = FromBase64String(...)
    ("S3_cmd_caret_ps_xor",      p[2] + " " + p[3] + " " + p[4] + " " + p[5]),  # cmd caret ps -e | XOR
    ("S4_iex_binary_download",   p[6] + " " + p[7]),             # Invoke-Expression binary-encoded IEX
]
for sid, pl in SAMPLES: print(f"  · {sid:<30s} len={len(pl):>5} head={pl[:60]!r}")
print()

# ── Login ────────────────────────────────────────────────────────────────
tok = requests.post(f"{API}/api/auth/login", json=CREDS, timeout=15).json()["access_token"]
H = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

# ── Buttons under test ───────────────────────────────────────────────────
def _smart(payload):
    r = requests.post(f"{API}/api/decode/smart", headers=H, json={"input": payload}, timeout=60)
    return r.status_code, r.json() if r.status_code == 200 else {"error": r.text[:200]}

def _magic(payload):
    r = requests.post(f"{API}/api/decode/magic", headers=H, json={"input": payload}, timeout=60)
    return r.status_code, r.json() if r.status_code == 200 else {"error": r.text[:200]}

def _ai_decode(payload):
    r = requests.post(f"{API}/api/ai/auto-decode", headers=H, json={"input": payload}, timeout=90)
    return r.status_code, r.json() if r.status_code == 200 else {"error": r.text[:200]}

def _analyze(payload, decoded):
    r = requests.post(f"{API}/api/analyze", headers=H, timeout=90,
                      json={"input": payload, "output": decoded,
                            "enrich_osint": True, "use_ai_verdict": True, "describe": True})
    return r.status_code, r.json() if r.status_code == 200 else {"error": r.text[:200]}

def _predict_tree(raw, decoded):
    r = requests.post(f"{API}/api/analyze/process-tree", headers=H, timeout=75,
                      json={"raw": raw, "decoded": decoded})
    return r.status_code, r.json() if r.status_code == 200 else {"error": r.text[:200]}

# ── Run ──────────────────────────────────────────────────────────────────
rows = []
for sid, payload in SAMPLES:
    print(f"═══ {sid} ═══")
    row = {"sample": sid, "len": len(payload)}
    t0 = time.time(); sc, d1 = _smart(payload)
    row["smart"] = {"code": sc, "ms": int((time.time()-t0)*1000),
                    "chain": len(d1.get("trace") or []),
                    "output": (d1.get("output") or "")[:120],
                    "verdict": (d1.get("verdict_card") or {}).get("label")}
    print(f"  SMART   HTTP {sc} · {row['smart']['ms']}ms · chain={row['smart']['chain']} · out={row['smart']['output'][:60]!r}")

    t0 = time.time(); sc, d2 = _magic(payload)
    row["magic"] = {"code": sc, "ms": int((time.time()-t0)*1000),
                    "output": (d2.get("output") or "")[:120]}
    print(f"  MAGIC   HTTP {sc} · {row['magic']['ms']}ms · out={row['magic']['output'][:60]!r}")

    t0 = time.time(); sc, d3 = _ai_decode(payload)
    row["ai_decode"] = {"code": sc, "ms": int((time.time()-t0)*1000),
                        "engine": d3.get("winner_engine"),
                        "confidence": d3.get("confidence"),
                        "cache_hit": d3.get("cache_hit"),
                        "output": (d3.get("output") or "")[:120],
                        "stopped_gracefully": d3.get("stopped_gracefully")}
    print(f"  AI-DEC  HTTP {sc} · {row['ai_decode']['ms']}ms · engine={row['ai_decode']['engine']} · conf={row['ai_decode']['confidence']} · out={row['ai_decode']['output'][:60]!r}")

    decoded = d1.get("output") or ""
    t0 = time.time(); sc, d4 = _analyze(payload, decoded)
    row["analyze"] = {"code": sc, "ms": int((time.time()-t0)*1000),
                      "verdict": (d4.get("ai_verdict") or {}).get("verdict") if isinstance(d4.get("ai_verdict"),dict) else "?",
                      "iocs": sum(len(v) for v in (d4.get("iocs") or {}).values()) if isinstance(d4.get("iocs"),dict) else 0,
                      "mitre": len(d4.get("mitre") or []),
                      "ai_err": (d4.get("description") or {}).get("error") if isinstance(d4.get("description"),dict) else None,
                      "osint_err": (d4.get("osint") or {}).get("error") if isinstance(d4.get("osint"),dict) else None}
    print(f"  ANALYZE HTTP {sc} · {row['analyze']['ms']}ms · verdict={row['analyze']['verdict']} · iocs={row['analyze']['iocs']} · mitre={row['analyze']['mitre']}")
    if row["analyze"]["ai_err"]: print(f"          ⚠ AI leg   : {row['analyze']['ai_err']}")
    if row["analyze"]["osint_err"]: print(f"          ⚠ OSINT leg: {row['analyze']['osint_err']}")

    t0 = time.time(); sc, d5 = _predict_tree(payload, decoded)
    root = (d5.get("predicted_process_tree") or {}).get("root") or {}
    row["predict_tree"] = {"code": sc, "ms": int((time.time()-t0)*1000),
                           "evidence_source": (d5.get("predicted_process_tree") or {}).get("evidence_source"),
                           "root_process": root.get("process"),
                           "children_count": len(root.get("children") or [])}
    print(f"  TREE    HTTP {sc} · {row['predict_tree']['ms']}ms · src={row['predict_tree']['evidence_source']!r} · root={root.get('process')!r} · kids={len(root.get('children') or [])}")

    # dump full per-sample json
    with open(OUTDIR / f"{sid}.json", "w") as f:
        json.dump({"sample": sid, "payload": payload,
                   "smart": d1, "magic": d2, "ai_decode": d3,
                   "analyze": d4, "predict_tree": d5}, f, indent=2, default=str)
    rows.append(row); print()

# ── Summary Markdown table ───────────────────────────────────────────────
md = ["# WORKSPACE Buttons × 4 Payloads — Live Regression Matrix", ""]
md += ["| Sample | SMART | MAGIC | AI DECODE | ANALYZE | PREDICT TREE |",
       "|---|---|---|---|---|---|"]
for r in rows:
    def _cell(x, ok_key="code"):
        return f"HTTP {x['code']} · {x['ms']}ms" if x.get("code") == 200 else f"❌ {x.get('code')}"
    md.append(f"| `{r['sample']}` | {_cell(r['smart'])} · chain {r['smart']['chain']} "
              f"| {_cell(r['magic'])} "
              f"| {_cell(r['ai_decode'])} · engine {r['ai_decode']['engine']} · conf {r['ai_decode']['confidence']}"
              + (" · **cache**" if r["ai_decode"]["cache_hit"] else "")
              + f" | {_cell(r['analyze'])} · verdict {r['analyze']['verdict']} · IOCs {r['analyze']['iocs']} · MITRE {r['analyze']['mitre']} "
              + (" · ⚠AI" if r["analyze"]["ai_err"] else "")
              + f" | {_cell(r['predict_tree'])} · src {r['predict_tree']['evidence_source']!r} · root {r['predict_tree']['root_process']!r} |")
with open(OUTDIR / "MATRIX.md", "w") as f: f.write("\n".join(md))
print("═══ SUMMARY ═══")
for line in md[2:]: print(line)
print(f"\n✓ Per-sample JSON:  {OUTDIR}/S*.json")
print(f"✓ Matrix report:    {OUTDIR}/MATRIX.md")
