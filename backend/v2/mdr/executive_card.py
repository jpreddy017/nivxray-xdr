"""NivXRay AUTO INVESTIGATE — Executive Investigation Card.

Analyst-facing top-of-page summary that answers the five questions a
Tier-2 analyst asks in the first 15 seconds:

  1. What happened?
  2. Why did NivXRay reach this verdict?
  3. What evidence supports it?
  4. What is still unknown?
  5. What should the analyst do next?

Also emits:
  • Investigation Status  — checklist of stages the engine completed
  • Analysis Pipeline     — checklist of analytical passes that ran
  • Investigation Completeness — progress bar with per-dimension state

Deterministic. Reads from the fully-composed pipeline result — never
guesses, never uses an LLM. Every ✓ / ✗ / partial state maps to a
concrete evidence bucket from the pipeline.
"""
from __future__ import annotations

from typing import Any


def _dominant_semantic(chains: list[dict]) -> dict | None:
    """Pick the semantic block with the highest risk_score."""
    best = None
    for c in chains or []:
        sem = c.get("semantic")
        if sem and sem.get("detected"):
            if best is None or (sem.get("risk_score") or 0) > (best.get("risk_score") or 0):
                best = sem
    return best


def _verdict_pretty(v: str) -> str:
    return {
        "malicious":     "Malicious",
        "suspicious":    "Suspicious",
        "needs_review":  "Needs Review",
        "informational": "Informational",
        "unknown":       "Unknown",
    }.get((v or "").lower(), (v or "unknown").title())


def build(result: dict) -> dict:
    """Compose the Executive Investigation Card from a completed pipeline
    result. Returns a dict the frontend can render directly."""
    fis   = (result or {}).get("final_incident_summary") or {}
    mdr   = (result or {}).get("mdr_investigation") or {}
    dp    = (result or {}).get("decode_pipeline") or {}
    chains = dp.get("chains") or []
    sem    = _dominant_semantic(chains)
    osint  = (fis.get("ioc_reputation") or {}).get("summary") or {}

    verdict = (sem or {}).get("verdict") or fis.get("verdict") or "unknown"
    confidence = (sem or {}).get("confidence") or (fis.get("confidence") or {}).get("score") or 0

    # ── 1) What happened? (Primary Finding + Recovered Behavior) ──
    what_happened: dict = {}
    if sem and sem.get("recovered_script"):
        what_happened["primary_finding"] = "PowerShell executed with Base64-encoded command."
        what_happened["recovered_behavior"] = _recovered_behavior_line(sem)
    elif mdr.get("events"):
        first = mdr["events"][0]
        what_happened["primary_finding"] = (
            f"{first.get('source') or 'Endpoint telemetry'} raised "
            f"'{first.get('detection_name') or 'a detection'}'"
            + (f" on `{first.get('hostname')}`" if first.get("hostname") else "")
            + "."
        )
        what_happened["recovered_behavior"] = mdr.get("executive_summary", "").split("\n\n", 1)[0]
    else:
        what_happened["primary_finding"] = (
            "No structured telemetry was supplied. NivXRay ran its "
            "lexical decoders only — output is informational."
        )
        what_happened["recovered_behavior"] = fis.get("executive_summary", "")

    # ── 3) What evidence supports it? (positive + negative) ──────
    positive = _positive_evidence(fis, mdr, sem, chains)
    negative = _negative_evidence(sem)

    # ── 2) Why this verdict? (Because bullets) ────────────────────
    because = _because_bullets(fis, mdr, sem, verdict, positive, negative)

    # ── 4) What is still unknown? ─────────────────────────────────
    unknowns = _unknowns(fis, mdr, sem)

    # ── 5) What should the analyst do next? ───────────────────────
    next_actions = _next_actions(mdr, sem, verdict)

    # ── Investigation Status (stages completed) ───────────────────
    status = _investigation_status(result)

    # ── Analysis Pipeline (passes that ran) ───────────────────────
    pipeline = _analysis_pipeline(result, chains, sem, osint)

    # ── Investigation Completeness ────────────────────────────────
    completeness = _completeness(result, mdr, sem, osint, chains)

    return {
        "verdict":              verdict,
        "verdict_pretty":       _verdict_pretty(verdict),
        "confidence":           int(confidence or 0),
        "what_happened":        what_happened,
        "because":              because,
        "evidence": {
            "positive": positive,
            "negative": negative,
        },
        "unknowns":             unknowns,
        "next_actions":         next_actions,
        "investigation_status": status,
        "analysis_pipeline":    pipeline,
        "completeness":         completeness,
    }


# ── Individual composers ──────────────────────────────────────────
def _recovered_behavior_line(sem: dict) -> str:
    arts = sem.get("artifacts") or []
    ext  = [a for a in arts if a.get("kind") == "url" and a.get("classification") == "external"]
    loop = [a for a in arts if a.get("kind") == "url" and a.get("classification") == "loopback"]
    if loop and not ext:
        return f"Decoded command launches a local HTTP endpoint ({loop[0]['value']})."
    if ext:
        return f"Decoded command references external endpoint ({ext[0]['value']})."
    if sem.get("ast"):
        first = sem["ast"][0]
        return f"Decoded command invokes `{first.get('cmdlet')}`."
    return "Decoded content did not surface a recognisable action."


def _positive_evidence(fis, mdr, sem, chains) -> list[str]:
    ev: list[str] = []
    if sem and sem.get("detected"):
        ev.append("Encoded PowerShell")
        if sem.get("decode_outcome") == "fully_decoded":
            ev.append("Decoded successfully")
    if any(c.get("layer_count", 0) > 0 for c in chains):
        ev.append(f"Recursive decode completed ({sum(c.get('layer_count',0) for c in chains)} layers)")
    iocs = fis.get("iocs") or {}
    if iocs.get("urls"):
        ev.append(f"{len(iocs['urls'])} URL(s) extracted")
    if iocs.get("ips"):
        ev.append(f"{len(iocs['ips'])} IP(s) extracted")
    if iocs.get("sha256"):
        ev.append(f"{len(iocs['sha256'])} SHA256 hash(es) extracted")
    if sem:
        for a in sem.get("artifacts") or []:
            if a.get("kind") == "url" and a.get("classification") == "loopback":
                host = a["value"].split("://")[-1].split(":")[0].split("/")[0]
                ev.append(f"Localhost ({host})")
                break
    if (mdr.get("events") or []):
        ev.append(f"Structured telemetry parsed ({len(mdr['events'])} event(s))")
    return list(dict.fromkeys(ev))


def _negative_evidence(sem) -> list[str]:
    # Mirrors ps_semantic.negative_evidence — surfaces what did NOT happen.
    if not sem:
        return []
    from v2.semantic.ps_semantic import negative_evidence
    return [f"No {ne['category'].lower()} observed"
            for ne in negative_evidence(sem.get("recovered_script") or "")
            if not ne["observed"]]


def _because_bullets(fis, mdr, sem, verdict, positive, negative) -> list[str]:
    out: list[str] = []
    if sem and sem.get("detected"):
        out.append("Encoded PowerShell observed")
        arts = sem.get("artifacts") or []
        if any(a.get("classification") == "loopback" for a in arts if a.get("kind") == "url"):
            out.append("Local HTTP endpoint referenced")
    if verdict == "suspicious":
        out.extend(neg for neg in negative[:3])
        out.append("Additional telemetry required")
    elif verdict == "malicious":
        for p in positive:
            if any(k in p.lower() for k in ("external", "download", "injection", "credential", "persistence")):
                out.append(p)
    elif verdict == "informational":
        out.append("No high-signal behaviours observed")
        out.extend(neg for neg in negative[:2])
    if not out:
        out.append("Insufficient evidence — verdict based on lexical extraction only")
    return list(dict.fromkeys(out))[:8]


def _unknowns(fis, mdr, sem) -> list[str]:
    unknowns: list[str] = []
    if not (mdr.get("events") or []):
        unknowns.append("Structured XDR telemetry (host, user, process chain, action) not supplied")
    if sem and sem.get("detected"):
        arts = sem.get("artifacts") or []
        if not any(a.get("classification") == "external" for a in arts):
            unknowns.append("No external network destination confirmed — cannot rule in C2")
    if not fis.get("evidence_counts", {}).get("processes"):
        unknowns.append("Parent / child process context not observed")
    if not any((c.get("verdict") == "malicious") for c in (fis.get("findings") or [])):
        unknowns.append("Whether the decoded command actually executed on the endpoint")
    return unknowns[:6]


def _next_actions(mdr, sem, verdict) -> list[dict]:
    if mdr.get("recommendations"):
        return mdr["recommendations"][:6]
    if verdict == "suspicious" and sem:
        return [{
            "severity": "medium",
            "title": "Review parent process and WinRM activity",
            "why": ("Encoded PowerShell in isolation is suspicious. Confirm the parent "
                    "process, WinRM state, child processes and outbound network telemetry "
                    "before deciding on escalation.")
        }]
    if verdict == "malicious":
        return [{"severity": "critical",
                 "title": "Escalate to Tier-2 & isolate host",
                 "why": "Malicious behaviour observed — contain the endpoint immediately."}]
    return [{"severity": "informational",
             "title": "Retain for correlation",
             "why": "No high-signal behaviour — keep the incident for future pivoting."}]


def _investigation_status(result: dict) -> list[dict]:
    """Which stages did the ENGINE complete?"""
    fis    = result.get("final_incident_summary") or {}
    mdr    = result.get("mdr_investigation") or {}
    dp     = result.get("decode_pipeline") or {}
    chains = dp.get("chains") or []
    return [
        {"label": "Incident Parsed",       "done": bool(fis)},
        {"label": "Timeline Built",        "done": bool(mdr.get("timeline"))},
        {"label": "Commands Analysed",     "done": bool(chains)},
        {"label": "Decode Complete",       "done": any(c.get("status") in ("complete","cache_hit") for c in chains)},
        {"label": "Threat Intel Correlated","done": bool((fis.get("ioc_reputation") or {}).get("summary", {}).get("total_lookups"))},
        {"label": "MITRE Mapped",          "done": bool(fis.get("mitre_attack"))},
        {"label": "Report Generated",      "done": bool(mdr.get("executive_summary") or fis.get("executive_summary"))},
    ]


def _analysis_pipeline(result, chains, sem, osint) -> list[dict]:
    """Which analytical PASSES ran (regardless of whether the engine
    surfaced a finding)?"""
    mdr = result.get("mdr_investigation") or {}
    return [
        {"label": "Evidence Extraction",     "done": True},
        {"label": "Command Recovery",        "done": bool(result.get("detected", {}).get("commands"))},
        {"label": "Recursive Decode",        "done": any(c.get("layer_count", 0) > 0 for c in chains)},
        {"label": "Semantic Analysis",       "done": bool(sem and sem.get("detected"))},
        {"label": "Behavior Classification", "done": bool(sem and sem.get("behaviors"))},
        {"label": "Threat Intelligence",     "done": bool(osint.get("total_lookups"))},
        {"label": "MITRE Mapping",           "done": bool((result.get("final_incident_summary") or {}).get("mitre_attack"))},
        {"label": "URL Classification",      "done": bool(mdr.get("url_classification"))},
        {"label": "Confidence Scoring",      "done": bool(sem or mdr)},
    ]


def _completeness(result, mdr, sem, osint, chains) -> dict:
    """Analyst-facing investigation-health card."""
    def _st(done: bool | None, partial: bool = False) -> str:
        if done:    return "complete"
        if partial: return "partial"
        return "unavailable"
    fis = result.get("final_incident_summary") or {}
    dims = [
        {"label": "Timeline",              "state": _st(bool(mdr.get("timeline")))},
        {"label": "Command Analysis",      "state": _st(bool(chains))},
        {"label": "Threat Intelligence",   "state": _st(bool(osint.get("matches")), partial=bool(osint.get("total_lookups")))},
        {"label": "File Reputation",       "state": _st(bool(osint.get("matches")), partial=bool(fis.get("iocs", {}).get("sha256")))},
        {"label": "Root Cause",            "state": _st(bool(mdr.get("recommendations") and mdr.get("events")), partial=bool(sem))},
        {"label": "Behavior Correlation",  "state": _st(False, partial=bool(sem and sem.get("behaviors")))},
        {"label": "Execution Confirmation","state": _st(any((c.get("verdict") == "malicious") for c in (fis.get("findings") or [])),
                                                        partial=bool(sem))},
    ]
    scored = 0
    for d in dims:
        if d["state"] == "complete": scored += 2
        elif d["state"] == "partial": scored += 1
    percent = int(round(100 * scored / (2 * len(dims))))
    # Recommendation confidence band
    if percent >= 80:   rec_conf = "High"
    elif percent >= 50: rec_conf = "Medium"
    else:               rec_conf = "Low"
    return {
        "percent":                percent,
        "dimensions":             dims,
        "recommendation_confidence": rec_conf,
    }
