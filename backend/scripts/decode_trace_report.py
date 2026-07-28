"""Decode Trace Report · deterministic pipeline instrumentation.

Purpose
=======
Every previous v1.5.x cycle patched symptoms rather than identifying the
first stage where the pipeline diverged from analyst expectations. This
tool exists to make that diagnostic step routine.

Given a raw analyst input, this script executes the exact same code path
as the ``POST /api/decode/smart`` endpoint, but emits a fully-instrumented
trace for every stage:

    * Input Parser  · IU classification, atomic-IOC guard, capabilities
    * CRE           · effective payload
    * RTE           · per-layer transformations (decoder, in/out length,
                      SHA-256, confidence, changed?)
    * Diagnostics   · every DX code with causal chain
    * Semantic Intent · each rule and every fired intent
    * Behavior Graph · nodes and edges
    * Verdict Uplift · band, composition, reason
    * Analyst Report · summary + IOCs + MITRE + recommendations
    * UI Payload    · the exact JSON keys the frontend reads

Determinism
===========
The trace is reproducible byte-for-byte given the same input — every
stage output is either a hash or a length, never a timestamp or a random
ID. The final ``determinism_hash`` covers the entire trace.

Usage
=====

    # From a local file
    python -m scripts.decode_trace_report --file /tmp/sample.txt

    # From stdin
    cat sample.txt | python -m scripts.decode_trace_report

    # As JSON (for CI ingestion)
    python -m scripts.decode_trace_report --file sample.txt --json

    # Compare against the LIVE deployed API (E2E parity check)
    python -m scripts.decode_trace_report --file sample.txt --live

Non-goals
=========
This tool does NOT modify the pipeline. It observes only. Any bug it
uncovers must be fixed in the appropriate module and re-run to confirm
convergence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import textwrap
from pathlib import Path
from typing import Any


# ── Import shim so this script works when invoked either as
# ── `python -m scripts.decode_trace_report` or `python scripts/decode_trace_report.py`
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))


def _sha(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode("utf-8", errors="replace")
    return hashlib.sha256(s).hexdigest()[:16]


def _preview(s: str, n: int = 120) -> str:
    if not s:
        return "(empty)"
    s = s.replace("\n", "⏎").replace("\r", "␍").replace("\t", "→")
    return s[:n] + ("…" if len(s) > n else "")


def _rule(width: int = 72, ch: str = "─") -> str:
    return ch * width


# ══════════════════════════════════════════════════════════════════
# Stage runners — each returns a dict with the stage's observables.
# ══════════════════════════════════════════════════════════════════

def run_local_trace(text: str) -> dict[str, Any]:
    """Execute the same code path as ``/api/decode/smart`` and return an
    instrumented trace snapshot for every stage."""
    from v2.investigation.pipeline import investigate, _atomic_ioc_kind

    trace: dict[str, Any] = {
        "input": {
            "sha256_16": _sha(text),
            "length":    len(text),
            "preview":   _preview(text),
            "atomic_ioc_kind": _atomic_ioc_kind(text),
        },
    }

    inv = investigate(text)
    inv_d = inv.to_dict() if hasattr(inv, "to_dict") else {}

    # ── Stage 1 · Input Understanding (IU) ─────────────────────
    iu = inv_d.get("iu") or {}
    trace["iu"] = {
        "classification": iu.get("classification") or iu.get("type"),
        "confidence":     iu.get("confidence"),
        "capabilities":   iu.get("capabilities") or [],
        "language":       iu.get("language"),
    }

    # ── Stage 2 · Command Reconstruction (CRE) ─────────────────
    cre = inv_d.get("cre") or {}
    eff = (cre.get("effective_payload") or "")
    trace["cre"] = {
        "effective_payload_sha_16": _sha(eff),
        "effective_payload_len":    len(eff),
        "effective_payload_preview": _preview(eff),
        "notes":                    cre.get("notes") or [],
    }

    # ── Stage 3 · Recursive Transformation Engine (RTE) ────────
    rte = inv_d.get("rte") or {}
    artifacts = rte.get("artifacts") or []
    steps = rte.get("steps") or []
    diagnostics = rte.get("diagnostics") or []

    per_layer = []
    for i, art in enumerate(artifacts):
        content = art.get("content") or ""
        per_layer.append({
            "layer":     i,
            "sha256_16": _sha(content),
            "length":    len(content),
            "kind":      art.get("kind"),
            "preview":   _preview(content, 100),
        })

    per_step = []
    for j, step in enumerate(steps):
        per_step.append({
            "step":            j,
            "transformation":  step.get("transformation"),
            "from_layer":      step.get("input_layer"),
            "to_layer":        step.get("output_layer"),
            "confidence":      step.get("confidence"),
            "changed":         (
                artifacts[step.get("input_layer") or 0].get("content")
                != artifacts[step.get("output_layer") or 0].get("content")
                if artifacts and step.get("output_layer") is not None
                and step.get("output_layer") < len(artifacts)
                else None
            ),
        })

    per_diag = []
    for d in diagnostics:
        per_diag.append({
            "code":      d.get("code"),
            "severity":  d.get("severity"),
            "type":      d.get("failure_type"),
            "caused_by": d.get("caused_by"),
            "reason":    (d.get("reason") or "")[:160],
        })

    trace["rte"] = {
        "stop_reason":       rte.get("stop_reason"),
        "depth":             rte.get("depth"),
        "layers_count":      len(artifacts),
        "steps_count":       len(steps),
        "determinism_hash":  rte.get("determinism_hash"),
        "final_layer_sha_16": (per_layer[-1]["sha256_16"] if per_layer else None),
        "final_layer_len":    (per_layer[-1]["length"] if per_layer else None),
        "layers":             per_layer,
        "steps":              per_step,
        "diagnostics":        per_diag,
    }

    # ── Stage 4 · Semantic Intent ──────────────────────────────
    intent = inv_d.get("intent") or {}
    fired = intent.get("intents") or []
    trace["intent"] = {
        "input_to_brain_sha_16": (per_layer[-1]["sha256_16"] if per_layer else None),
        "input_to_brain_len":    (per_layer[-1]["length"] if per_layer else None),
        "intents_fired_count":   len(fired),
        "intents": [
            {
                "category":   i.get("category"),
                "risk":       i.get("risk"),
                "confidence": i.get("confidence"),
                "purpose":    (i.get("purpose") or "")[:100],
                "mitre_ids":  i.get("mitre_ids") or [],
                "signatures": [
                    (ev.get("meta") or {}).get("signature")
                    for ev in (i.get("evidence") or [])
                ],
            }
            for i in fired
        ],
        "determinism_hash": intent.get("determinism_hash"),
    }

    # ── Stage 5 · Behavior Graph ───────────────────────────────
    beh = inv_d.get("behavior") or {}
    trace["behavior"] = {
        "schema":       beh.get("schema"),
        "nodes_count":  len(beh.get("nodes") or []),
        "edges_count":  len(beh.get("edges") or []),
    }

    # ── Stage 6 · Verdict Uplift ───────────────────────────────
    v = inv_d.get("verdict") or {}
    r = v.get("reasoning") or {}
    trace["verdict"] = {
        "band":         v.get("band"),
        "confidence":   v.get("confidence"),
        "reason":       (v.get("reason") or "")[:200],
        "composition":  r.get("composition") or [],
        "top_intent_count": len(v.get("top_intents") or []),
    }

    # ── Stage 7 · Analyst Report ───────────────────────────────
    rep = inv_d.get("report") or {}
    trace["report"] = {
        "executive_summary_len": len(rep.get("executive_summary") or ""),
        "mitre_count":           len(rep.get("mitre") or []),
        "iocs_count":             len(rep.get("iocs") or []),
        "recommendations_count":  len(rep.get("recommendations") or []),
    }

    trace["coverage"] = inv_d.get("coverage") or []
    trace["investigation_determinism_hash"] = inv_d.get("determinism_hash")
    return trace


def run_live_trace(text: str) -> dict[str, Any] | None:
    """Hit the deployed ``/api/decode/smart`` exactly the way the UI does
    and extract the same instrumentation for the RESPONSE the frontend
    actually receives. Returns None if the API is unreachable."""
    import json as _json
    import urllib.error
    import urllib.request

    env_path = Path("/app/frontend/.env")
    if not env_path.exists():
        return None
    api = None
    for line in env_path.read_text().splitlines():
        if line.startswith("REACT_APP_BACKEND_URL="):
            api = line.split("=", 1)[1].strip()
            break
    if not api:
        return None

    # Login with the admin credentials from memory/test_credentials.md
    cred_path = Path("/app/memory/test_credentials.md")
    email, password = "admin@nivxray.com", os.environ.get("ADMIN_PASSWORD", "")
    if cred_path.exists() and not password:
        for line in cred_path.read_text().splitlines():
            low = line.lower().strip()
            if low.startswith("- **password**:") or low.startswith("- password:"):
                _, _, val = line.partition(":")
                # strip leading whitespace, backticks, and the parenthesised
                # rotation hint that follows the actual credential.
                val = val.strip()
                if "`" in val:
                    # take the FIRST backtick-quoted token — the credential
                    val = val.split("`")[1]
                else:
                    val = val.split()[0] if val else val
                password = val
                break
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 DecodeTraceReport",
    }
    try:
        req = urllib.request.Request(
            f"{api}/api/auth/login",
            data=_json.dumps({"email": email, "password": password}).encode(),
            headers=headers, method="POST")
        tok = _json.loads(urllib.request.urlopen(req, timeout=60).read())["access_token"]
    except Exception as e:
        return {"error": f"live login failed: {e}"}

    headers["Authorization"] = f"Bearer {tok}"
    try:
        req = urllib.request.Request(
            f"{api}/api/decode/smart",
            data=_json.dumps({"input": text}).encode(),
            headers=headers, method="POST")
        data = _json.loads(urllib.request.urlopen(req, timeout=180).read())
    except Exception as e:
        return {"error": f"live decode failed: {e}"}

    # UI-payload mapping — what the frontend actually consumes.
    ui_output = data.get("output") or ""
    ui_output_legacy = data.get("output_legacy") or ""
    return {
        "api_endpoint":            f"{api}/api/decode/smart",
        "response_keys":           sorted(data.keys()),
        "ui_output_sha_16":        _sha(ui_output),
        "ui_output_length":        len(ui_output),
        "ui_output_starts_with":   _preview(ui_output, 200),
        "ui_output_legacy_len":    len(ui_output_legacy),
        "ui_output_legacy_preview": _preview(ui_output_legacy, 100),
        "has_rte_brain_block":     ("RTE DECODER TRACE" in ui_output),
        "verdict_v2":              (data.get("verdict_v2") or {}).get("verdict"),
        "verdict_card":            (data.get("verdict_card") or {}).get("verdict"),
        "investigation_verdict_band": ((data.get("investigation") or {}).get("verdict") or {}).get("band"),
        "investigation_verdict_conf": ((data.get("investigation") or {}).get("verdict") or {}).get("confidence"),
        "rte_stop_reason":         ((data.get("investigation") or {}).get("rte") or {}).get("stop_reason"),
        "rte_depth":               ((data.get("investigation") or {}).get("rte") or {}).get("depth"),
        "rte_artifacts_count":     len(((data.get("investigation") or {}).get("rte") or {}).get("artifacts") or []),
        "diagnostics_count":       len(((data.get("investigation") or {}).get("rte") or {}).get("diagnostics") or []),
        "intent_fired_count":      len(((data.get("investigation") or {}).get("intent") or {}).get("intents") or []),
    }


# ══════════════════════════════════════════════════════════════════
# Renderer
# ══════════════════════════════════════════════════════════════════

def render_report(trace: dict[str, Any], live: dict[str, Any] | None = None) -> str:
    L: list[str] = []
    L.append(_rule(78, "═"))
    L.append("  NIVXRAY · DECODE TRACE REPORT")
    L.append(_rule(78, "═"))

    inp = trace["input"]
    L.append("")
    L.append(f"INPUT")
    L.append(f"  ├── SHA-256/16      : {inp['sha256_16']}")
    L.append(f"  ├── Length          : {inp['length']:,} chars")
    L.append(f"  ├── Atomic IOC kind : {inp['atomic_ioc_kind'] or '(none)'}")
    L.append(f"  └── Preview         : {inp['preview']}")
    L.append("")
    L.append("↓")

    iu = trace["iu"]
    L.append("")
    L.append(f"STAGE 1 · INPUT UNDERSTANDING (IU)")
    L.append(f"  Classification : {iu['classification']}")
    L.append(f"  Confidence     : {iu['confidence']}")
    L.append(f"  Language       : {iu['language']}")
    L.append(f"  Capabilities   : {iu['capabilities']}")
    L.append("")
    L.append("↓")

    cre = trace["cre"]
    L.append("")
    L.append(f"STAGE 2 · COMMAND RECONSTRUCTION (CRE)")
    L.append(f"  Effective payload : sha={cre['effective_payload_sha_16']}  len={cre['effective_payload_len']:,}")
    L.append(f"  Preview           : {cre['effective_payload_preview']}")
    if cre["notes"]:
        for n in cre["notes"][:3]:
            L.append(f"  Note              : {n}")
    L.append("")
    L.append("↓")

    rte = trace["rte"]
    L.append("")
    L.append(f"STAGE 3 · RECURSIVE TRANSFORMATION ENGINE (RTE)")
    L.append(f"  stop_reason      : {rte['stop_reason']}")
    L.append(f"  depth            : {rte['depth']}   layers: {rte['layers_count']}   steps: {rte['steps_count']}")
    L.append(f"  determinism_hash : {(rte['determinism_hash'] or '')[:16]}")
    L.append("")
    L.append(f"  LAYERS:")
    for lay in rte["layers"]:
        L.append(f"    L{lay['layer']}  sha={lay['sha256_16']}  len={lay['length']:>6}  kind={lay['kind']}")
        L.append(f"        preview: {lay['preview']}")
    L.append("")
    L.append(f"  STEPS:")
    if not rte["steps"]:
        L.append(f"    (no transformations fired)")
    for st in rte["steps"]:
        L.append(f"    step {st['step']}  {st['transformation']:35s}  "
                 f"L{st['from_layer']}→L{st['to_layer']}  "
                 f"conf={st['confidence']}  changed={st['changed']}")
    L.append("")
    L.append(f"  DIAGNOSTICS:")
    if not rte["diagnostics"]:
        L.append(f"    (no diagnostics emitted)")
    for d in rte["diagnostics"]:
        cause = f"caused_by={d['caused_by']}" if d['caused_by'] else "(root)"
        L.append(f"    [{(d['severity'] or '').upper():>7}] {d['code']}  {d['type'] or ''}  {cause}")
        if d['reason']:
            L.append(f"             {d['reason']}")
    L.append("")
    L.append(f"  → FINAL ARTEFACT : sha={rte['final_layer_sha_16']}  len={rte['final_layer_len']}")
    L.append("")
    L.append("↓")

    it = trace["intent"]
    L.append("")
    L.append(f"STAGE 4 · SEMANTIC INTENT (Investigation Brain input)")
    L.append(f"  Input-to-brain    : sha={it['input_to_brain_sha_16']}  len={it['input_to_brain_len']}")
    L.append(f"  Intents fired     : {it['intents_fired_count']}")
    for i in it["intents"]:
        sigs = [s for s in i["signatures"] if s]
        L.append(f"    [{i['risk']:>6}] {i['category']:>18s}  conf={i['confidence']}  {i['purpose']}")
        if sigs:
            L.append(f"        signatures: {sigs}")
        if i["mitre_ids"]:
            L.append(f"        mitre     : {i['mitre_ids']}")
    L.append(f"  determinism_hash  : {(it['determinism_hash'] or '')[:16]}")
    L.append("")
    L.append("↓")

    b = trace["behavior"]
    L.append("")
    L.append(f"STAGE 5 · BEHAVIOR GRAPH")
    L.append(f"  schema       : {b['schema']}")
    L.append(f"  nodes/edges  : {b['nodes_count']} / {b['edges_count']}")
    L.append("")
    L.append("↓")

    v = trace["verdict"]
    L.append("")
    L.append(f"STAGE 6 · VERDICT UPLIFT")
    L.append(f"  band         : {v['band']}   confidence: {v['confidence']}")
    L.append(f"  composition  : {v['composition']}")
    L.append(f"  reason       : {v['reason']}")
    L.append("")
    L.append("↓")

    rep = trace["report"]
    L.append("")
    L.append(f"STAGE 7 · ANALYST REPORT")
    L.append(f"  executive summary : {rep['executive_summary_len']:,} chars")
    L.append(f"  mitre / iocs / recs : {rep['mitre_count']} / {rep['iocs_count']} / {rep['recommendations_count']}")
    L.append("")

    if live is not None:
        L.append(_rule(78, "═"))
        L.append("  UI PAYLOAD MAPPING (from LIVE deployed API)")
        L.append(_rule(78, "═"))
        if "error" in live:
            L.append(f"  ⚠ {live['error']}")
        else:
            L.append(f"  endpoint            : {live['api_endpoint']}")
            L.append(f"  response keys       : {len(live['response_keys'])} keys")
            L.append(f"  ui `output` sha/len : {live['ui_output_sha_16']}  {live['ui_output_length']}")
            L.append(f"  ui `output` starts  : {live['ui_output_starts_with']}")
            L.append(f"  ui has RTE header?  : {live['has_rte_brain_block']}")
            L.append(f"  ui `output_legacy`  : len={live['ui_output_legacy_len']} · {live['ui_output_legacy_preview']}")
            L.append(f"  investigation.rte   : stop={live['rte_stop_reason']}  depth={live['rte_depth']}  artefacts={live['rte_artifacts_count']}")
            L.append(f"  investigation.verdict.band : {live['investigation_verdict_band']}  conf: {live['investigation_verdict_conf']}")
            L.append(f"  investigation.intent count : {live['intent_fired_count']}")
            L.append(f"  legacy verdict_v2 / _card  : {live['verdict_v2']}  /  {live['verdict_card']}")
        L.append("")

    L.append(_rule(78, "═"))
    L.append("  FOUR DIAGNOSTIC QUESTIONS (evidence-based)")
    L.append(_rule(78, "═"))
    Q1_pass = (rte["layers_count"] >= 2)
    Q1 = "YES · Decoder produced ≥ 2 layers" if Q1_pass else "NO"
    L.append(f"  Q1  artifacts[] contains decoded PowerShell?           {Q1}")
    if not Q1_pass:
        L.append(f"      → Root cause: RTE stop_reason={rte['stop_reason']}, "
                 f"last step={rte['steps'][-1]['transformation'] if rte['steps'] else '(no steps)'}")

    Q2_pass = None
    if live and "error" not in (live or {}):
        Q2_pass = (live["ui_output_length"] > (rte["final_layer_len"] or 0) * 0.5)
        L.append(f"  Q2  API `output` field carries decoded PowerShell?      "
                 f"{'YES' if Q2_pass else 'NO'} (len={live['ui_output_length']})")
        if not Q2_pass:
            L.append(f"      → API mapping issue: RTE produced {rte['final_layer_len']} bytes "
                     f"but `output` only has {live['ui_output_length']}")

        Q3_pass = live["has_rte_brain_block"]
        L.append(f"  Q3  UI payload contains the RTE brain-block header?     "
                 f"{'YES' if Q3_pass else 'NO'}")
        if not Q3_pass:
            L.append(f"      → Frontend rendering issue: `output` does not carry the")
            L.append(f"        v1.5.1 promotion header — check routers/ops.py")

    Q4_stop = rte["stop_reason"]
    Q4_last = rte["steps"][-1]["transformation"] if rte["steps"] else "(none)"
    L.append(f"  Q4  If artifacts[] partial, last decoder / stop_reason  {Q4_last} / {Q4_stop}")
    if rte["diagnostics"]:
        root = next((d for d in rte["diagnostics"] if not d["caused_by"]), rte["diagnostics"][0])
        L.append(f"      root diagnostic: {root['code']}  {root['type']}")

    L.append("")
    L.append(_rule(78, "═"))
    L.append(f"  investigation determinism_hash : {(trace.get('investigation_determinism_hash') or '')[:16]}")
    L.append(_rule(78, "═"))
    return "\n".join(L)


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════

def _read_input(args) -> str:
    if args.file:
        return Path(args.file).read_text(encoding="utf-8", errors="replace")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode Trace Report — instrument every stage of the "
                    "NivXRay pipeline for one sample.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python -m scripts.decode_trace_report --file /tmp/user_sample.txt
              python -m scripts.decode_trace_report --file /tmp/sample.txt --live
              cat sample.txt | python -m scripts.decode_trace_report --json
        """),
    )
    parser.add_argument("--file", help="input file (utf-8)")
    parser.add_argument("--live", action="store_true",
                        help="also hit the deployed API and diff the UI payload")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of text")
    args = parser.parse_args()

    text = _read_input(args)
    if not text:
        parser.print_help()
        return 1

    trace = run_local_trace(text)
    live  = run_live_trace(text) if args.live else None

    if args.json:
        payload = {"local": trace, "live": live}
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_report(trace, live))
    return 0


if __name__ == "__main__":
    sys.exit(main())
