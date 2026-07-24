"""NivXRay Investigation — Timeline Builder.

Deterministic chronological event fusion from the Investigation Model.
The timeline is the analyst's mental scaffold — every downstream stage
(Attack Story, Executive Summary, Technical Summary) consumes THIS output.

Every timeline entry has:
    ts          — ISO timestamp when known, empty otherwise
    ts_display  — human-friendly rendering
    actor       — subject (host / user / process / detector)
    action      — verb (detected, executed, created, contacted, …)
    target      — object (file / URL / registry key)
    evidence    — one-line supporting evidence
    provenance  — Observed | Decoded | Historical | Derived
    kind        — detection | process | file | network | registry | auth | ti
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any


_TS_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")


def _parse_ts(ts: str) -> float:
    """Return an epoch sort key. Unknown timestamps sort to +inf."""
    if not ts:
        return float("inf")
    s = ts.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s.replace(" ", "T")[:32]).timestamp()
    except Exception:
        pass
    # Try loose "YYYY-MM-DD HH:MM:SS.ffffff+ZZ:ZZ" variants
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return float("inf")


def _fmt(ts: str) -> str:
    return ts if _TS_ISO.match(ts or "") else (ts or "unknown time")


def build(im: dict) -> list[dict]:
    """Fuse every event bucket from the Investigation Model into one
    chronologically sorted timeline. Deterministic."""
    if not im:
        return []
    tl: list[dict] = []
    incident = im.get("incident") or {}
    assets   = im.get("assets") or {}

    # ── Raw MDR events (highest fidelity — detection-level records) ─
    for e in im.get("raw_events") or []:
        ts = e.get("ts_raw") or ""
        host = e.get("hostname") or ""
        user = e.get("user") or ""
        det = e.get("detection_name") or ""
        src = e.get("source") or "endpoint"
        proc = e.get("process") or ""
        parent = e.get("parent_process") or ""
        cmd = (e.get("command_line") or "").strip()
        threat = e.get("threat_name") or ""
        action = (e.get("action") or "").lower()
        path = e.get("path") or ""

        if det:
            tl.append({
                "ts": ts, "ts_display": _fmt(ts),
                "actor": src, "action": "detected",
                "target": det + (f" on {host}" if host else ""),
                "evidence": (
                    (f"Threat name: {threat}. " if threat else "")
                    + (f"Path: {path}. " if path else "")
                    + (f"User: {user}. " if user else "")
                ).strip() or "Detection recorded by endpoint.",
                "provenance": "Observed", "kind": "detection",
            })

        if proc or cmd:
            tl.append({
                "ts": ts, "ts_display": _fmt(ts),
                "actor": (parent or "process chain"),
                "action": "spawned" if parent else "executed",
                "target": proc or "<unknown process>",
                "evidence": (
                    (f"User: {user}. " if user else "")
                    + (f"Command: `{cmd[:180]}`" if cmd else "")
                ).strip() or "Process activity recorded.",
                "provenance": "Observed", "kind": "process",
            })

        if path and action in ("quarantined", "blocked", "deleted", "created",
                                "executed", "downloaded", "moved", "modified"):
            tl.append({
                "ts": ts, "ts_display": _fmt(ts),
                "actor": src, "action": action,
                "target": path,
                "evidence": (f"SHA256: {e.get('sha256','')[:16]}…"
                             if e.get("sha256") else "File action recorded."),
                "provenance": "Observed", "kind": "file",
            })

    # ── Network activity from URL classification ───────────────────
    for n in im.get("network") or []:
        if n.get("classification") not in ("attacker", "unknown", "suspect"):
            continue
        url = n.get("url") or n.get("domain") or n.get("dst")
        if not url:
            continue
        tl.append({
            "ts": n.get("ts") or "", "ts_display": _fmt(n.get("ts") or ""),
            "actor": "host", "action": "contacted",
            "target": url,
            "evidence": (f"Protocol: {n.get('protocol') or 'unknown'} · "
                         f"classification: {n.get('classification')}"),
            "provenance": "Observed", "kind": "network",
        })

    # ── Registry persistence ───────────────────────────────────────
    for r in im.get("registry") or []:
        tl.append({
            "ts": r.get("ts") or "", "ts_display": _fmt(r.get("ts") or ""),
            "actor": r.get("hostname") or "host",
            "action": r.get("action") or "modified",
            "target": r.get("path") or "<registry>",
            "evidence": ("Persistence key" if r.get("is_persistence")
                         else "Registry change"),
            "provenance": "Observed", "kind": "registry",
        })

    # ── Authentication ────────────────────────────────────────────
    for a in im.get("auth") or []:
        tl.append({
            "ts": a.get("ts") or "", "ts_display": _fmt(a.get("ts") or ""),
            "actor": a.get("user") or "user",
            "action": a.get("kind") or "authenticated",
            "target": a.get("dst_host") or a.get("src_host") or "",
            "evidence": f"Result: {a.get('result') or 'unknown'}",
            "provenance": "Observed", "kind": "auth",
        })

    # ── TI matches (correlated evidence, not detection-level) ──────
    for ti in im.get("ti") or []:
        if not ti.get("value"):
            continue
        tl.append({
            "ts": "", "ts_display": "correlated",
            "actor": ti.get("source") or "threat intel",
            "action": "matched",
            "target": ti.get("value"),
            "evidence": (f"Verdict: {ti.get('verdict') or 'n/a'}"
                         + (f" · family: {ti.get('family')}" if ti.get("family") else "")),
            "provenance": "ThreatIntelligence", "kind": "ti",
        })

    # ── Historical pivots (already derived by the model builder) ──
    for h in im.get("history") or []:
        tl.append({
            "ts": h.get("ts") or "", "ts_display": _fmt(h.get("ts") or "correlated"),
            "actor": "correlation engine",
            "action": "correlated",
            "target": h.get("kind") or "prior activity",
            "evidence": h.get("description") or "",
            "provenance": "Historical", "kind": "history",
        })

    # ── Dedup consecutive identical rows and sort ─────────────────
    tl.sort(key=lambda r: (_parse_ts(r["ts"]), r["kind"]))
    deduped: list[dict] = []
    seen_keys: set[tuple] = set()
    for row in tl:
        key = (row["ts"], row["actor"], row["action"], row["target"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(row)
    return deduped
