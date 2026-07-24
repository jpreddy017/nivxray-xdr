"""NivXRay Investigation — MDR Report Composer.

The single, canonical composer for the Investigation Workspace report.
Consumes ONLY the Investigation Model + the deterministic classifiers /
timeline. NEVER reads raw JSON, regex output, decoder output or entity
lists directly.

Produces the spec-mandated section order:

    1. Executive Summary        — 2 paragraphs · analyst prose
    2. Investigation Summary    — chronological reconstruction
    3. Timeline                 — machine-readable rows for the UI
    4. Attack Story             — attacker-progression beats
    5. Technical Summary        — process, file, network breakdown
    6. Recommendations          — evidence-linked actions
    7. Observed Evidence        — provenance-tagged artifact catalogue
    8. Observed IOCs            — filtered, attacker-only IOCs
    9. Threat Intelligence      — correlation only (not detection)
   10. Limitations              — explicit unknowns

Deterministic. Same input → byte-identical output.
"""
from __future__ import annotations

from typing import Any

from .classifiers import (
    classify_entities, classify_file, classify_processes,
    PROV_OBSERVED, PROV_DECODED,
)
from .timeline import build as _build_timeline
from .narrative import (
    _describe_process, _family_of, _guess_kill_chain, _escalation_triggers,
)


# ── Executive summary (2 paragraphs, analyst prose) ──────────────
def _executive_summary(im: dict, tl: list[dict], entcls: dict, files: list[dict]) -> list[str]:
    incident = im.get("incident") or {}
    assets   = im.get("assets") or {}
    events   = im.get("raw_events") or []
    detections = incident.get("alert_names") or []
    hosts = assets.get("hosts") or []
    users = assets.get("users") or []
    sources = incident.get("detection_sources") or []
    ti = im.get("ti") or []

    if not events and not detections:
        return [
            ("The supplied telemetry did not contain enough structured "
             "detection data to reconstruct an incident. NivXRay ran its "
             "deterministic decoders and reference-URL filter over the "
             "raw text but no correlation-grade activity was surfaced. "
             "This assessment is informational only."),
            ("Additional telemetry — endpoint alert JSON, XDR case export, "
             "or the underlying process/file/network events — is required "
             "before a defensible verdict can be issued."),
        ]

    ts = ""
    for e in events:
        if e.get("ts_raw"):
            ts = e.get("ts_raw"); break
    source = sources[0] if sources else "the endpoint sensor"
    host_str = (f"host `{hosts[0]}`" if hosts else "the affected endpoint")
    user_str = (f"user `{users[0]}`" if users else "")

    p1_bits: list[str] = []
    if ts:
        p1_bits.append(f"At {ts} UTC")
    p1_bits.append(f"{source} raised **{', '.join(detections[:2]) or 'an endpoint detection'}**")
    p1_bits.append(f"on {host_str}")
    if user_str:
        p1_bits.append(f"under {user_str}")
    p1 = ", ".join(p1_bits[:-1]) + " " + p1_bits[-1] + "." if p1_bits else ""

    # Executed / quarantined / no-execution telemetry?
    executed_files = [f for f in files if f.get("classification") == "Executed"]
    quarantined = [f for f in files if f.get("classification") == "Quarantined"]
    ioc_urls = (entcls.get("iocs") or {}).get("urls") or []

    tail_bits: list[str] = []
    if executed_files:
        tail_bits.append(
            f"Execution telemetry confirms `{executed_files[0].get('name')}` "
            f"ran on the endpoint.")
    elif quarantined:
        tail_bits.append(
            f"The associated payload was **quarantined** by the endpoint sensor; "
            f"no post-execution activity was observed.")
    else:
        tail_bits.append(
            "No execution telemetry associated with the detected artifact was "
            "observed during the investigation window.")

    if ioc_urls:
        tail_bits.append(
            f"{len(ioc_urls)} external URL(s) surfaced as attacker-controlled "
            f"candidates after vendor / console references were filtered.")
    if ti:
        fams = sorted({_family_of(t.get("value") or t.get("family") or "")
                       for t in ti} - {""})
        if fams:
            tail_bits.append(
                f"Threat-intelligence enrichment aligned the observed tooling "
                f"with { ' and '.join(fams[:2]) }.")

    p1 = p1 + " " + " ".join(tail_bits[:2])
    p1 = p1.strip()

    # Paragraph 2 — assessment + next step
    kill = _guess_kill_chain(im)
    triggers = _escalation_triggers(im)
    p2_bits: list[str] = [
        f"The observed sequence is consistent with **{kill}**."
    ]
    if executed_files:
        p2_bits.append(
            "Execution was confirmed, so post-execution containment and forensic "
            "review are warranted.")
    elif quarantined:
        p2_bits.append(
            "Because the endpoint quarantined the file before execution, the "
            "immediate risk is contained; however host-side visibility (Orbital "
            "or equivalent) should be reviewed to confirm no residual activity.")
    else:
        p2_bits.append(
            "Execution could not be confirmed from the supplied telemetry; "
            "further host-side artifacts are required to determine whether the "
            "payload ran.")
    if triggers:
        p2_bits.append(
            f"The combination of { ', '.join(triggers) } warrants escalation "
            f"for customer review.")
    p2 = " ".join(p2_bits)

    return [p1, p2]


# ── Investigation summary (analyst-prose chronological story) ────
def _investigation_summary(im: dict, tl: list[dict]) -> list[str]:
    """Chronological reconstruction. Each paragraph opens with a timestamp
    and reads like an MDR analyst note."""
    if not tl:
        return []
    paras: list[str] = []
    # Paragraph 1 — initial detection
    first_det = next((r for r in tl if r["kind"] == "detection"), None)
    if first_det:
        paras.append(
            f"At {first_det['ts_display']} UTC, {first_det['actor']} "
            f"detected {first_det['target']}. {first_det['evidence']}".strip()
        )
    # Paragraph 2 — process chain
    proc_rows = [r for r in tl if r["kind"] == "process"][:3]
    if proc_rows:
        parts = []
        for r in proc_rows:
            parts.append(f"`{r['actor']}` {r['action']} `{r['target']}`")
        parts_text = "; then ".join(parts)
        paras.append(
            f"Process telemetry shows {parts_text}. "
            + (proc_rows[0]["evidence"] if proc_rows[0]["evidence"] else "")
        )
    # Paragraph 3 — file behaviour
    file_rows = [r for r in tl if r["kind"] == "file"][:3]
    if file_rows:
        parts = []
        for r in file_rows:
            parts.append(f"`{r['target']}` was {r['action']}")
        parts_text = ", ".join(parts)
        paras.append(f"File-level telemetry records {parts_text}. "
                     + (file_rows[0]["evidence"] if file_rows[0]["evidence"] else ""))
    else:
        paras.append(
            "No execution or child-process activity associated with the "
            "detected file(s) was observed during the investigation window."
        )
    # Paragraph 4 — network / TI correlation
    net_rows = [r for r in tl if r["kind"] == "network"]
    ti_rows = [r for r in tl if r["kind"] == "ti"]
    if net_rows or ti_rows:
        n_parts = []
        if net_rows:
            n_parts.append(
                f"outbound network activity to "
                + ", ".join(f"`{r['target']}`" for r in net_rows[:2])
            )
        if ti_rows:
            n_parts.append(
                f"threat-intelligence correlations on "
                + ", ".join(f"`{r['target']}`" for r in ti_rows[:2])
            )
        paras.append(
            "Correlation across enrichment sources identified "
            + " and ".join(n_parts) + "."
        )
    # Paragraph 5 — historical
    hist_rows = [r for r in tl if r["kind"] == "history"]
    if hist_rows:
        paras.append(
            "Historical pivoting identified "
            + " ".join(r["evidence"].lower() for r in hist_rows[:2])
            + "."
        )
    return paras


# ── Attack Story (attacker progression beats) ────────────────────
def _attack_story(im: dict, tl: list[dict]) -> list[dict]:
    """Attacker-progression beats: each beat is a tactic + narrative sentence."""
    beats: list[dict] = []
    events = im.get("raw_events") or []
    proc_names = [(e.get("process") or "").lower() for e in events]
    txt = " ".join(proc_names + [
        (e.get("threat_name") or "").lower() for e in events
    ])

    # Initial detection
    first_det = next((r for r in tl if r["kind"] == "detection"), None)
    if first_det:
        beats.append({
            "tactic": "Initial Detection",
            "beat":   f"The endpoint sensor raised {first_det['target']} at "
                       f"{first_det['ts_display']} UTC.",
            "evidence": [first_det["evidence"]] if first_det["evidence"] else [],
        })

    # Execution
    exec_events = [e for e in events if (e.get("action") or "").lower() == "executed"]
    if exec_events:
        e = exec_events[0]
        beats.append({
            "tactic": "Execution",
            "beat": (f"The payload `{e.get('process') or '<unknown>'}` executed "
                     f"under user `{e.get('user') or '<unknown>'}`."),
            "evidence": [f"Command: `{(e.get('command_line') or '')[:200]}`"],
        })

    # Credential access — SharpHound / Mimikatz
    if "sharphound" in txt or "sh.exe" in txt:
        beats.append({
            "tactic": "Discovery / Credential Access",
            "beat":   "SharpHound-style Active-Directory enumeration was observed, "
                       "commonly used to build attack paths for BloodHound.",
            "evidence": [],
        })
    if "mimikatz" in txt:
        beats.append({
            "tactic": "Credential Access",
            "beat":   "Mimikatz execution was observed — credential material may "
                       "have been extracted from LSASS.",
            "evidence": [],
        })

    # Lateral movement — WinRM / PsExec
    if "wsmprov" in txt or "winrm" in txt:
        beats.append({
            "tactic": "Lateral Movement",
            "beat":   "Windows Remote Management (WinRM) activity was observed — "
                       "the activity originated from a remote PowerShell session.",
            "evidence": [],
        })

    # Impact — ransomware / encryption
    if "ransom" in txt or "encrypt" in txt or "lockbit" in txt or "akira" in txt:
        beats.append({
            "tactic": "Impact",
            "beat":   "Behaviours consistent with pre-encryption / ransomware "
                       "activity were observed.",
            "evidence": [],
        })

    # If we only have detection + no follow-through, add a "contained" beat
    if len(beats) == 1:
        beats.append({
            "tactic": "Containment",
            "beat":   "No follow-through activity (execution, lateral movement, "
                       "credential access, impact) was observed. The detection "
                       "appears to have been contained at the initial trigger.",
            "evidence": [],
        })
    return beats


# ── Technical summary ────────────────────────────────────────────
def _technical_summary(im: dict, entcls: dict,
                       files: list[dict], processes: list[dict]) -> dict:
    incident = im.get("incident") or {}
    return {
        "incident":       incident,
        "hosts":          (im.get("assets") or {}).get("hosts") or [],
        "users":          (im.get("assets") or {}).get("users") or [],
        "processes":      processes,
        "files":          files,
        "network": {
            "ioc_urls":      entcls["iocs"]["urls"],
            "ioc_domains":   entcls["iocs"]["domains"],
            "ioc_ips":       entcls["iocs"]["ips"],
            "reference_urls":   entcls["references"]["urls"],
            "reference_domains":entcls["references"]["domains"],
            "reference_ips":    entcls["references"]["ips"],
        },
        "counts":         entcls["counts"],
    }


# ── Recommendations (evidence-linked) ────────────────────────────
def _recommendations(im: dict, tl: list[dict], files: list[dict]) -> list[dict]:
    recs: list[dict] = []
    events = im.get("raw_events") or []
    hosts = (im.get("assets") or {}).get("hosts") or []
    users = (im.get("assets") or {}).get("users") or []
    executed = [f for f in files if f.get("classification") == "Executed"]
    quarantined = [f for f in files if f.get("classification") == "Quarantined"]
    ti = im.get("ti") or []

    # Immediate
    if executed:
        recs.append({
            "priority": "Immediate",
            "action":   (f"Isolate host `{hosts[0]}`" if hosts else "Isolate affected endpoint"),
            "why":      "Execution telemetry confirms payload ran on the endpoint.",
            "evidence": f"file `{executed[0].get('name')}` classified as Executed",
        })
    elif quarantined:
        recs.append({
            "priority": "Immediate",
            "action":   "Confirm quarantine integrity and hunt for residual persistence",
            "why":      "Endpoint quarantined the file but persistence, credential access "
                        "or lateral movement may have preceded quarantine.",
            "evidence": f"file `{quarantined[0].get('name')}` classified as Quarantined",
        })

    # Short-term
    if users:
        recs.append({
            "priority": "Short-Term",
            "action":   f"Reset credentials for `{users[0]}` and audit their recent activity",
            "why":      "Credentials associated with the detection should be treated as suspect "
                        "until evidence of misuse is ruled out.",
            "evidence": "user observed as detection principal",
        })

    if ti:
        recs.append({
            "priority": "Short-Term",
            "action":   "Ingest matched IOCs into perimeter blocklists and EDR-hunt across the fleet",
            "why":      "Threat-intelligence enrichment produced correlations; broad-hunt reduces "
                        "the risk of re-infection or spread.",
            "evidence": f"{len(ti)} TI correlation(s) identified",
        })

    # Long-term
    recs.append({
        "priority": "Long-Term",
        "action":   "Baseline PowerShell / LOLBIN usage in the environment",
        "why":      "Deterministic detection quality improves when normal script activity is "
                    "characterised — reduces false-positive noise on future incidents.",
        "evidence": "spec-mandated hygiene item, not derived from this incident",
    })
    return recs


# ── Observed Evidence ─────────────────────────────────────────────
def _observed_evidence(entcls: dict, files: list[dict], processes: list[dict]) -> dict:
    return {
        "processes":     processes,
        "files":         files,
        "urls":          entcls.get("urls") or [],
        "domains":       entcls.get("domains") or [],
        "ips":           entcls.get("ips") or [],
    }


def _limitations(im: dict, files: list[dict]) -> list[str]:
    lims: list[str] = []
    if not (im.get("raw_events") or []):
        lims.append("No structured XDR/EDR telemetry was supplied — analysis is limited to "
                    "the raw text provided.")
    if not any(f.get("classification") == "Executed" for f in files):
        lims.append("No execution telemetry (child processes, module loads, memory allocations) "
                    "was observed for the detected file(s); execution cannot be confirmed.")
    if not im.get("network"):
        lims.append("No outbound network activity was surfaced; C2 attribution cannot be made.")
    if not im.get("registry"):
        lims.append("No registry activity was surfaced; persistence status cannot be confirmed.")
    if not im.get("auth"):
        lims.append("No authentication events were provided; lateral-movement attempts cannot "
                    "be assessed.")
    return lims


# ── Public entry point ───────────────────────────────────────────
def compose_report(im: dict) -> dict:
    """Return the full spec-mandated report structure."""
    if not im:
        return {
            "executive_summary":    [],
            "investigation_summary": [],
            "timeline":             [],
            "attack_story":         [],
            "technical_summary":    {},
            "recommendations":      [],
            "observed_evidence":    {},
            "observed_iocs":        {},
            "threat_intelligence":  [],
            "limitations":          [],
            "empty":                True,
        }

    # Reuse classifiers/timeline to keep every stage on the same model.
    entities = {
        "urls":    [n.get("url") for n in (im.get("network") or []) if n.get("url")],
        "domains": list({n.get("domain") for n in (im.get("network") or []) if n.get("domain")}
                        | set((im.get("assets") or {}).get("domains") or [])),
        "ips":     list({n.get("dst") for n in (im.get("network") or []) if n.get("dst")}),
    }
    entcls    = classify_entities(entities)
    files     = [classify_file(f) for f in (im.get("files") or [])]
    processes = classify_processes(im.get("processes") or [])
    tl        = _build_timeline(im)

    return {
        "executive_summary":    _executive_summary(im, tl, entcls, files),
        "investigation_summary":_investigation_summary(im, tl),
        "timeline":             tl,
        "attack_story":         _attack_story(im, tl),
        "technical_summary":    _technical_summary(im, entcls, files, processes),
        "recommendations":      _recommendations(im, tl, files),
        "observed_evidence":    _observed_evidence(entcls, files, processes),
        "observed_iocs":        entcls.get("iocs") or {},
        "threat_intelligence":  im.get("ti") or [],
        "limitations":          _limitations(im, files),
        "empty":                False,
    }
