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

import re as _re
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
    detections = [d for d in (incident.get("alert_names") or []) if d]
    hosts = assets.get("hosts") or []
    users = assets.get("users") or []
    sources = incident.get("detection_sources") or []
    ti = im.get("ti") or []

    if not events and not detections:
        return [
            ("The supplied telemetry did not contain enough structured detection "
             "data to reconstruct an incident. NivXRay applied its deterministic "
             "decoders and reference-URL filter over the raw text but no "
             "correlation-grade activity surfaced. This assessment is informational only."),
            ("Additional telemetry — endpoint alert JSON, XDR case export, or the "
             "underlying process / file / network events — is required before a "
             "defensible verdict can be issued."),
        ]

    # First event with useful metadata
    e0 = next((e for e in events
               if e.get("ts_raw") or e.get("detection_name") or e.get("process")),
              events[0])
    ts = e0.get("ts_raw") or ""
    source = e0.get("source") or (sources[0] if sources else "the endpoint sensor")
    detection = (e0.get("detection_name") or "").strip() or (detections[0] if detections else "")
    host = (e0.get("hostname") or (hosts[0] if hosts else "")).strip()
    user = (e0.get("user") or (users[0] if users else "")).strip()
    parent = (e0.get("parent_process") or "").strip()
    process = (e0.get("process") or "").strip()
    threat = (e0.get("threat_name") or "").strip()

    # ── Paragraph 1 — What happened, on which host, what did the endpoint do?
    p1_bits: list[str] = []
    lead = f"At {ts} UTC, " if ts else ""
    subject = f"{source} detected"
    obj = f"**{detection}**" if detection else "an endpoint detection"
    where = f" on host `{host}`" if host else ""
    who = f" under user account `{user}`" if user else ""
    p1_bits.append(f"{lead}{subject} {obj}{where}{who}.")

    # Process-chain sentence — only if we have a real chain (parent != process)
    if process and parent and _basename(parent) != _basename(process):
        chain_desc = _process_chain_desc(parent, process, e0.get("child_process") or "")
        p1_bits.append(f"Process telemetry shows {chain_desc}.")
    elif process:
        p1_bits.append(f"The activity involved `{process}`"
                       + (f", executed under `{user}`" if user else "") + ".")

    # File action sentence
    executed_files = [f for f in files if f.get("classification") == "Executed"]
    quarantined = [f for f in files if f.get("classification") == "Quarantined"]
    if executed_files:
        p1_bits.append(
            f"Execution telemetry confirms `{executed_files[0].get('name')}` ran on the endpoint.")
    elif quarantined:
        p1_bits.append(
            f"The associated file was **quarantined** by the endpoint agent; "
            f"no post-execution activity was observed during the investigation window.")
    else:
        p1_bits.append(
            "No execution telemetry associated with the detected artifact was observed "
            "during the investigation window.")

    p1 = " ".join(p1_bits)

    # ── Paragraph 2 — Assessment, containment, next step ──────────
    p2_bits: list[str] = []
    ioc_urls = (entcls.get("iocs") or {}).get("urls") or []
    kill = _guess_kill_chain(im)
    p2_bits.append(f"The observed sequence is consistent with **{kill}**.")

    if executed_files:
        p2_bits.append(
            "Because execution was confirmed, post-execution containment and forensic "
            "review of the endpoint are warranted.")
    elif quarantined:
        p2_bits.append(
            "Because the endpoint quarantined the file before execution, the immediate "
            "risk is contained; deeper host-side visibility should still confirm no "
            "residual persistence, credential access, or outbound C2 activity preceded "
            "quarantine.")
    else:
        p2_bits.append(
            "Execution could not be confirmed from the supplied telemetry; further "
            "host-side artefacts are required before ruling execution in or out.")

    if ioc_urls:
        p2_bits.append(
            f"{len(ioc_urls)} external URL{'s' if len(ioc_urls) != 1 else ''} "
            f"surfaced as attacker-controlled candidate{'s' if len(ioc_urls) != 1 else ''} "
            f"after vendor and console references were filtered out.")

    triggers = _escalation_triggers(im)
    if triggers:
        p2_bits.append(
            f"The combination of {_join_natural(triggers)} warrants escalation for "
            f"customer review and validation of the affected account's recent activity.")

    p2 = " ".join(p2_bits)
    return [p1, p2]


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rstrip("/").split("/")[-1].lower().split()[0]


def _process_chain_desc(parent: str, process: str, child: str) -> str:
    pn, cn, dn = _basename(parent), _basename(process), _basename(child)
    chain_desc = f"`{parent}` spawned `{process}`"
    if child and dn != cn:
        chain_desc += f", which in turn launched `{child}`"
    # Add semantic hint for the parent when it's a well-known process
    if pn == "wsmprovhost.exe":
        chain_desc += (" — `wsmprovhost.exe` is the Windows Remote Management (WinRM) "
                       "host process, indicating the activity originated from a remote "
                       "PowerShell session")
    elif pn in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"):
        chain_desc += (f" — {pn.split('.')[0].title()} spawning a scripting engine is the "
                       "canonical phishing → payload pattern")
    return chain_desc


def _join_natural(items: list[str]) -> str:
    items = [i for i in items if i]
    if not items:  return ""
    if len(items) == 1: return items[0]
    if len(items) == 2: return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


# ── Investigation summary (analyst-prose chronological story) ────
def _investigation_summary(im: dict, tl: list[dict], entcls: dict, files: list[dict]) -> list[str]:
    """Chronological reconstruction. Written in Cisco-MDR analyst voice:
    each paragraph opens with a timestamp when known, states what was
    observed before drawing any conclusion, explains WHY where a well-known
    process is involved, and never repeats a value that has already been
    stated in the same paragraph."""
    events = im.get("raw_events") or []
    if not events:
        return []
    paras: list[str] = []
    e0 = events[0]

    # ── Paragraph 1 — Detection sentence + why the alert fired ─────
    ts = e0.get("ts_raw") or ""
    source = e0.get("source") or "the endpoint sensor"
    detection = (e0.get("detection_name") or "").strip()
    host = (e0.get("hostname") or "").strip()
    user = (e0.get("user") or "").strip()
    # Cisco-MDR style opener: name the sensor + subject before the object.
    p1 = (f"Following an ongoing investigation of {source} telemetry, at "
          f"{ts} UTC " if ts else f"{source} telemetry indicates that ")
    if ts:
        p1 += f"{source} identified"
    else:
        p1 = f"{source} identified"
    p1 += f" **{detection}**" if detection else " suspicious endpoint behaviour"
    if host: p1 += f" on host `{host}`"
    if user: p1 += f" running under user account `{user}`"
    p1 += "."
    if e0.get("threat_name"):
        why_desc = _describe_process(e0.get("process") or "")
        p1 += (f" The detection triggered on the observed artefact "
               f"**{e0['threat_name']}**")
        if why_desc:
            p1 += f", which was launched through {why_desc}"
        p1 += ". This context is consistent with post-exploitation tooling activity."
    paras.append(p1)

    # ── Paragraph 2 — Process chain, execution semantics ───────────
    parent = (e0.get("parent_process") or "").strip()
    process = (e0.get("process") or "").strip()
    child = (e0.get("child_process") or "").strip()
    cmd = (e0.get("command_line") or "").strip()
    if parent and process and _basename(parent) != _basename(process):
        pn, prn = _basename(parent), _basename(process)
        why_par = _describe_process(parent)
        why_p = _describe_process(process)
        p2 = ("Process telemetry indicates that the observed activity originated "
              f"from `{parent}`")
        if why_par:
            p2 += f" — {why_par}"
        p2 += f", which launched `{process}`"
        if user:
            p2 += f" under the `{user}` account"
        p2 += "."
        if why_p and "PowerShell" in why_p:
            p2 += (" This execution chain is commonly associated with remote "
                   "administrative activity and provides the context for the "
                   "subsequent detection.")
        elif why_p:
            p2 += f" The child process `{prn}` is {why_p}."
        if child:
            p2 += f" A downstream child process `{child}` was also observed."
        if cmd:
            cmd_display = cmd[:200] + ("…" if len(cmd) > 200 else "")
            p2 += (" The associated command line was recorded as "
                   f"`{cmd_display}`, which corresponds to standard PowerShell "
                   "invocation syntax.") if "powershell" in cmd.lower() else (
                   f" The associated command line was recorded as `{cmd_display}`.")
        paras.append(p2)
    elif process:
        p2 = (f"The activity involved `{process}`" +
              (f", executed under user account `{user}`" if user else "") + ".")
        if cmd:
            p2 += f" Command line: `{cmd[:200]}{'…' if len(cmd) > 200 else ''}`."
        paras.append(p2)

    # ── Paragraph 3 — File behaviour ───────────────────────────────
    executed = [f for f in files if f.get("classification") == "Executed"]
    quarantined = [f for f in files if f.get("classification") == "Quarantined"]
    other = [f for f in files if f.get("classification") not in ("Executed", "Quarantined")]
    if executed:
        f = executed[0]
        paras.append(
            f"Execution telemetry confirms that `{f.get('path') or f.get('name')}` "
            f"ran on the endpoint"
            + (f" (SHA256 `{f['sha256'][:16]}…`)" if f.get("sha256") else "")
            + "."
        )
    elif quarantined:
        f = quarantined[0]
        paras.append(
            f"The endpoint agent **quarantined** `{f.get('path') or f.get('name')}` "
            f"before execution completed"
            + (f" (SHA256 `{f['sha256'][:16]}…`)" if f.get("sha256") else "")
            + ". No execution or child-process activity associated with the file "
            f"was observed during the investigation window."
        )
    elif other:
        f = other[0]
        paras.append(
            f"File-level telemetry records that `{f.get('path') or f.get('name')}` "
            f"was {f.get('classification','observed').lower()} on the endpoint. "
            f"No execution telemetry was observed for the file(s) referenced in the alert."
        )
    else:
        paras.append(
            "No file activity (creation, execution, quarantine, or modification) "
            "was surfaced for the detected artefact during the investigation window."
        )

    # ── Paragraph 4 — Attacker-controlled network + TI correlation ─
    ioc_urls = (entcls.get("iocs") or {}).get("urls") or []
    ioc_ips  = (entcls.get("iocs") or {}).get("ips") or []
    ti = im.get("ti") or []
    net_bits: list[str] = []
    if ioc_urls:
        vals = ", ".join(f"`{u['value']}`" for u in ioc_urls[:2])
        more = "" if len(ioc_urls) <= 2 else f" and {len(ioc_urls) - 2} additional URL(s)"
        net_bits.append(f"outbound activity to attacker-controlled infrastructure {vals}{more}")
    if ioc_ips and not ioc_urls:
        ips = ", ".join(f"`{i['value']}`" for i in ioc_ips[:2])
        net_bits.append(f"outbound activity to external IP address(es) {ips}")
    if ti:
        fams = sorted({_family_of(t.get('value') or t.get('family') or '')
                       for t in ti} - {''})
        if fams:
            net_bits.append(f"threat-intelligence alignment with {_join_natural(fams[:2])}")
    if net_bits:
        paras.append(
            "Correlation across enrichment sources identified " +
            _join_natural(net_bits) + "."
        )

    # ── Paragraph 5 — Historical / repeat activity ────────────────
    hist = im.get("history") or []
    if hist:
        hist_descs = [h.get('description') for h in hist if h.get('description')]
        if hist_descs:
            # Use the raw description prose, not a python-list dump
            paras.append("Historical pivoting identified that "
                          + " ".join(d[0].lower() + d[1:] for d in hist_descs) + "")

    # ── Paragraph 6 — Analyst assessment (short) ──────────────────
    kill = _guess_kill_chain(im)
    triggers = _escalation_triggers(im)
    tail = f"Based on the reconstructed timeline, the observed sequence is consistent with {kill}."
    if not executed and quarantined:
        tail += (" Because the file was quarantined before execution, the immediate "
                 "risk is contained; the investigation continues to verify that no "
                 "credentials, persistence artefacts, or lateral movement preceded quarantine.")
    if triggers:
        tail += (f" The combination of {_join_natural(triggers)} justifies escalation "
                 f"to the customer for validation of the affected account's recent activity.")
    paras.append(tail)
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


# ── Recommendations (evidence-linked, priority-grouped) ─────────
def _recommendations(im: dict, tl: list[dict], files: list[dict]) -> dict:
    imm: list[dict] = []
    short: list[dict] = []
    long_: list[dict] = []
    events = im.get("raw_events") or []
    hosts = (im.get("assets") or {}).get("hosts") or []
    users = (im.get("assets") or {}).get("users") or []
    executed = [f for f in files if f.get("classification") == "Executed"]
    quarantined = [f for f in files if f.get("classification") == "Quarantined"]
    ti = im.get("ti") or []
    txt = " ".join((e.get("process","") + " " + e.get("parent_process","") + " "
                    + e.get("child_process","")).lower() for e in events)
    winrm = "wsmprov" in txt or "winrm" in txt

    # ── Immediate ────────────────────────────────────────────────
    if executed:
        imm.append({
            "action": (f"Isolate host `{hosts[0]}`" if hosts else "Isolate the affected endpoint"),
            "why":    "Execution telemetry confirms the payload ran on the endpoint.",
            "evidence": f"file `{executed[0].get('name')}` classified as Executed",
        })
    elif quarantined:
        imm.append({
            "action": "Verify the quarantine record was successful and the file has not returned",
            "why":    ("The endpoint agent quarantined the file, but analyst review is "
                       "required to confirm the record was applied to disk and no copies "
                       "remain on the host."),
            "evidence": f"file `{quarantined[0].get('name')}` classified as Quarantined",
        })
    if winrm:
        imm.append({
            "action": ("Validate whether the observed WinRM session was authorised and, "
                       "if not, terminate the session on the endpoint"),
            "why":    "WinRM is commonly abused for stealthy remote administration.",
            "evidence": "`wsmprovhost.exe` observed as ancestor of the detected process",
        })

    # ── Short-Term ───────────────────────────────────────────────
    if users:
        short.append({
            "action": f"Reset credentials for `{users[0]}` and audit their recent activity",
            "why":    ("Credentials associated with the detection should be treated as "
                       "suspect until misuse is explicitly ruled out."),
            "evidence": "user observed as detection principal",
        })
    if "sharphound" in txt or "sh.exe" in txt:
        short.append({
            "action": ("Review Active Directory access and enumeration logs for the "
                       "affected account across the last 7 days"),
            "why":    ("SharpHound-style tooling enumerates AD to build attack paths; "
                       "residual enumeration data may still be accessible to the attacker."),
            "evidence": "SharpHound-associated detection observed",
        })
    if ti:
        short.append({
            "action": ("Ingest matched IOCs into perimeter blocklists and EDR-hunt "
                       "across the fleet"),
            "why":    ("Threat-intelligence correlations produced hits; a broad hunt "
                       "reduces the risk of re-infection or spread to adjacent hosts."),
            "evidence": f"{len(ti)} TI correlation(s) identified",
        })
    short.append({
        "action": ("Search for related detections on the same host, user, and hash "
                   "across the last 30 days"),
        "why":    ("Endpoint detections rarely arrive in isolation; earlier alerts "
                   "on the same principals may reveal the original access vector."),
        "evidence": "spec-mandated correlation sweep",
    })

    # ── Long-Term ────────────────────────────────────────────────
    if winrm:
        long_.append({
            "action": ("Restrict WinRM access to explicit administrative subnets and "
                       "require multi-factor authentication for remote PowerShell"),
            "why":    ("The current alert would have been prevented by network-scoping "
                       "WinRM to a hardened jump host."),
            "evidence": "WinRM was reachable from a non-hardened source",
        })
    long_.append({
        "action": "Baseline PowerShell / LOLBIN usage across the environment",
        "why":    ("Deterministic detection quality improves when normal script "
                   "activity is characterised — reduces false-positive noise on "
                   "future incidents."),
        "evidence": "hygiene item, not derived from this incident",
    })
    long_.append({
        "action": ("Enable PowerShell script-block logging (Event ID 4104) and "
                   "module logging on all Windows endpoints"),
        "why":    ("Without these logs, encoded-command payloads cannot be reconstructed "
                   "post-incident."),
        "evidence": "hygiene item, not derived from this incident",
    })

    return {"immediate": imm, "short_term": short, "long_term": long_}


# ── Observed Evidence ─────────────────────────────────────────────
def _observed_evidence(entcls: dict, files: list[dict], processes: list[dict]) -> dict:
    return {
        "processes":     processes,
        "files":         files,
        "urls":          entcls.get("urls") or [],
        "domains":       entcls.get("domains") or [],
        "ips":           entcls.get("ips") or [],
    }


def _mitre_by_tactic(im: dict) -> dict:
    """Group observed MITRE technique IDs by tactic. Deterministic —
    reads the raw_events' `mitre` field only."""
    # ATT&CK technique → tactic mapping for the techniques the parser sees
    # most often. Kept small on purpose; the pipeline shouldn't invent
    # tactics that were never observed.
    T2T = {
        "T1059": "Execution", "T1059.001": "Execution", "T1059.003": "Execution",
        "T1027": "Defense Evasion", "T1140": "Defense Evasion",
        "T1218": "Defense Evasion", "T1218.005": "Defense Evasion",
        "T1055": "Defense Evasion", "T1562": "Defense Evasion",
        "T1105": "Command and Control", "T1071": "Command and Control",
        "T1547": "Persistence", "T1547.001": "Persistence",
        "T1543": "Persistence", "T1053": "Persistence",
        "T1003": "Credential Access", "T1552": "Credential Access",
        "T1082": "Discovery", "T1087": "Discovery", "T1069": "Discovery",
        "T1021": "Lateral Movement", "T1021.006": "Lateral Movement",
        "T1486": "Impact", "T1490": "Impact",
    }
    seen: dict[str, list[str]] = {}
    for e in im.get("raw_events") or []:
        for tid in (e.get("mitre") or []):
            tactic = T2T.get(tid) or T2T.get(tid.split(".")[0]) or "Uncategorised"
            seen.setdefault(tactic, [])
            if tid not in seen[tactic]:
                seen[tactic].append(tid)
    return {tactic: sorted(ids) for tactic, ids in seen.items()}


def _supporting_evidence(im: dict, tl: list[dict], entcls: dict,
                         files: list[dict], processes: list[dict]) -> list[dict]:
    """Emit evidence CARDS the analyst can reference by number.

    Each card = `{id, title, kind, source, observation, provenance,
    confidence, related_timeline}` and appears in the same order the
    Investigation Summary references it. The cards are the audit trail
    that justifies every sentence in the narrative.
    """
    cards: list[dict] = []
    cid = 0

    # Detection cards — one per real detection
    for e in (im.get("raw_events") or [])[:5]:
        det = (e.get("detection_name") or e.get("threat_name") or "").strip()
        if not det:
            continue
        cid += 1
        cards.append({
            "id":               f"E{cid}",
            "title":            det,
            "kind":             "Detection",
            "source":           e.get("source") or "endpoint sensor",
            "observation":      (f"Detected on `{e.get('hostname','')}` at "
                                 f"{e.get('ts_raw') or 'unknown time'}"
                                 + (f" under user `{e['user']}`" if e.get("user") else "")),
            "provenance":       "Observed",
            "confidence":       100,
            "related_timeline": e.get("ts_raw") or "",
        })

    # Command-line cards
    for e in (im.get("raw_events") or [])[:3]:
        cmd = (e.get("command_line") or "").strip()
        if not cmd:
            continue
        cid += 1
        cards.append({
            "id":               f"E{cid}",
            "title":            f"Command Line · {_basename(e.get('process',''))}",
            "kind":             "Process",
            "source":           e.get("source") or "endpoint sensor",
            "observation":      cmd[:400] + ("…" if len(cmd) > 400 else ""),
            "provenance":       "Observed",
            "confidence":       100,
            "related_timeline": e.get("ts_raw") or "",
        })

    # File cards
    for f in files[:5]:
        cid += 1
        cards.append({
            "id":               f"E{cid}",
            "title":            (f.get("path") or f.get("name") or "unnamed file"),
            "kind":             f"File · {f.get('classification','Observed')}",
            "source":           "endpoint sensor",
            "observation":      f.get("reason") or "",
            "provenance":       f.get("provenance", "Observed"),
            "confidence":       100 if f.get("classification") in
                                 ("Executed", "Quarantined", "Blocked") else 90,
            "related_timeline": f.get("ts") or "",
            "sha256":           f.get("sha256", ""),
        })

    # Attacker-controlled network cards
    for u in (entcls.get("iocs", {}).get("urls") or [])[:5]:
        cid += 1
        cards.append({
            "id":               f"E{cid}",
            "title":            u.get("value") or "",
            "kind":             "Network · attacker-controlled",
            "source":           "url classifier",
            "observation":      u.get("reason") or "external URL — no reference match",
            "provenance":       "Observed",
            "confidence":       80,
            "related_timeline": "",
        })

    # Threat-intel cards
    for t in (im.get("ti") or [])[:5]:
        cid += 1
        cards.append({
            "id":               f"E{cid}",
            "title":            t.get("value") or "",
            "kind":             f"Threat Intelligence · {t.get('kind','match')}",
            "source":           t.get("source") or "local_ti",
            "observation":      (t.get("family") + " — " if t.get("family") else "") +
                                 f"verdict: {t.get('verdict') or 'unknown'}",
            "provenance":       "ThreatIntelligence",
            "confidence":       80,
            "related_timeline": "",
        })

    return cards


# ── MITRE ATT&CK with technique names + why-it-fired ─────────────
# Small deterministic catalogue — only techniques the parser sees.
_MITRE_CATALOG = {
    "T1059":     ("Command and Scripting Interpreter",
                  "The alert involved script-interpreter execution — a common execution "
                  "vector for both benign automation and post-exploitation tooling."),
    "T1059.001": ("PowerShell",
                  "PowerShell was observed running in a context that matches the ATT&CK "
                  "PowerShell sub-technique."),
    "T1059.003": ("Windows Command Shell",
                  "cmd.exe was observed executing a command sequence in the process chain."),
    "T1027":     ("Obfuscated Files or Information",
                  "Encoded or otherwise obfuscated content was surfaced — commonly used "
                  "to hide payload intent from casual review."),
    "T1140":     ("Deobfuscate/Decode Files or Information",
                  "The pipeline decoded content that had been obfuscated in the incident."),
    "T1218":     ("System Binary Proxy Execution (LOLBIN)",
                  "A signed Windows binary was observed executing attacker-supplied code."),
    "T1218.005": ("Mshta",
                  "mshta.exe was observed executing a scriptlet."),
    "T1055":     ("Process Injection",
                  "Behaviour consistent with in-memory code injection was observed."),
    "T1562":     ("Impair Defenses",
                  "Behaviour consistent with disabling or bypassing endpoint defences was observed."),
    "T1105":     ("Ingress Tool Transfer",
                  "Outbound download activity to attacker-controlled infrastructure was observed."),
    "T1071":     ("Application Layer Protocol",
                  "Outbound HTTP/HTTPS activity to attacker-controlled infrastructure was observed."),
    "T1547":     ("Boot or Logon Autostart Execution",
                  "Registry or startup-folder writes consistent with persistence were observed."),
    "T1547.001": ("Registry Run Keys / Startup Folder",
                  "A Run/RunOnce key or Startup folder write consistent with persistence was observed."),
    "T1543":     ("Create or Modify System Process",
                  "Service creation or modification consistent with persistence was observed."),
    "T1053":     ("Scheduled Task/Job",
                  "Scheduled-task creation consistent with persistence was observed."),
    "T1003":     ("OS Credential Dumping",
                  "Behaviour consistent with LSASS access / credential extraction was observed."),
    "T1552":     ("Unsecured Credentials",
                  "Access to plaintext credential material was observed."),
    "T1082":     ("System Information Discovery",
                  "Reconnaissance of the host operating system and configuration was observed."),
    "T1087":     ("Account Discovery",
                  "Active-Directory account enumeration was observed — typically driven by "
                  "SharpHound / BloodHound-style tooling."),
    "T1069":     ("Permission Groups Discovery",
                  "Enumeration of AD groups was observed."),
    "T1021":     ("Remote Services",
                  "Remote-service usage (WinRM / RDP / SMB) was observed in the chain."),
    "T1021.006": ("Windows Remote Management",
                  "WinRM (`wsmprovhost.exe`) was observed as ancestor of the detected process."),
    "T1486":     ("Data Encrypted for Impact",
                  "Behaviour consistent with pre-encryption / ransomware activity was observed."),
    "T1490":     ("Inhibit System Recovery",
                  "Backup destruction / shadow-copy deletion behaviour was observed."),
}


def _mitre_with_reasons(im: dict, mitre_by_tactic: dict) -> list[dict]:
    """Flatten mitre_by_tactic into rich rows the UI can render as cards."""
    rows: list[dict] = []
    for tactic, ids in (mitre_by_tactic or {}).items():
        for tid in ids:
            name, reason = _MITRE_CATALOG.get(tid) or _MITRE_CATALOG.get(tid.split(".")[0]) \
                          or ("(technique)", "Observed in the incident telemetry.")
            rows.append({
                "id": tid, "tactic": tactic, "name": name, "reason": reason,
            })
    return rows


# ── Negative findings (Cisco-MDR staple) ─────────────────────────
def _negative_findings(im: dict, files: list[dict], entcls: dict) -> list[dict]:
    """Explicitly enumerate categories that were NOT observed. This is the
    signal analysts trust most: 'the report considered X and did not find it'."""
    events = im.get("raw_events") or []
    txt = " ".join((e.get("process","") + " " + e.get("child_process","") + " " +
                    e.get("command_line","") + " " + e.get("detection_name","")).lower()
                   for e in events)

    def _neg(category, observed, ctx=""):
        return {"category": category, "observed": bool(observed), "context": ctx}

    return [
        _neg("Persistence mechanisms",
             bool(im.get("registry")) or ("run\\" in txt) or ("runonce" in txt),
             "No Run/RunOnce registry writes, Startup-folder drops, or persistence primitives observed."),
        _neg("Scheduled tasks / service creation",
             any(kw in txt for kw in ["schtasks", "sc.exe", "sc create", "at.exe"]),
             "No new scheduled tasks or service creations were surfaced in the telemetry."),
        _neg("Autorun / registry modifications",
             bool(im.get("registry")),
             "No registry modifications were observed for standard autorun locations."),
        _neg("Credential access",
             any(kw in txt for kw in ["mimikatz", "lsass", "sekurlsa", "hashdump", "credmgr"]),
             "No LSASS access, credential-dumping tooling, or hash extraction behaviours were observed."),
        _neg("Lateral movement",
             any(kw in txt for kw in ["psexec", "wmic /node", "sc.exe \\\\", "at \\\\", "smbexec"]),
             "No PsExec, remote-service execution, or SMB-based lateral movement was observed."),
        _neg("Data exfiltration",
             any(kw in txt for kw in ["exfil", "rclone", "7z ", "zip -r", "curl -T"]),
             "No archive-and-upload behaviours or known exfiltration tools were observed."),
        _neg("Ransomware / impact",
             any(kw in txt for kw in ["ransom", "encrypt", "vssadmin", "wbadmin delete",
                                       "bcdedit /set", "cipher /w"]),
             "No shadow-copy deletion, backup-destruction, or mass-encryption behaviour was observed."),
    ]


# ── Probable initial access (paragraph — NOT a separate engine) ──
def _probable_initial_access(im: dict) -> dict:
    """One evidence-linked paragraph. Explicitly admits when evidence is
    insufficient rather than overclaiming."""
    events = im.get("raw_events") or []
    if not events:
        return {
            "paragraph": ("Available telemetry is insufficient to determine the initial "
                          "access vector for this incident. Authentication logs (Windows "
                          "Event IDs 4624 / 4625 / 4776), remote-management session records, "
                          "and email-security telemetry would be required to make a defensible "
                          "assessment."),
            "confidence": "None",
            "evidence":   [],
            "vector":     "Insufficient evidence",
            "ruled_out":  [],
        }
    txt = " ".join((e.get("process","") + " " + e.get("parent_process","") + " " +
                    e.get("command_line","")).lower() for e in events)
    ev: list[str] = []
    if "wsmprov" in txt or "winrm" in txt:
        ev.append("`wsmprovhost.exe` (WinRM host) observed as ancestor process")
        if "powershell" in txt:
            ev.append("PowerShell child process launched in the same session")
        conf = "Medium"
        para = ("Probable Initial Access: Based on the available telemetry, the activity "
                "appears to have originated from a remote Windows Remote Management (WinRM) "
                "administrative session. However, the available evidence is insufficient to "
                "determine how the session was established or whether it was authorised. "
                "Additional authentication events (Windows Event IDs 4624 / 4625 / 4776), "
                "WinRM operational logs, and firewall records for the affected endpoint "
                "are required to confirm the initial access vector.")
        return {"paragraph": para, "confidence": conf, "evidence": ev,
                "vector": "Remote WinRM / PowerShell Remoting", "ruled_out": []}
    if any(o in txt for o in ("winword", "excel", "outlook", "powerpnt")):
        ev.append("Office application observed as ancestor process")
        return {"paragraph": (
            "Probable Initial Access: The presence of an Office application as ancestor "
            "process, followed by scripting-engine or LOLBIN execution, is consistent with "
            "phishing / macro-enabled document delivery. Confirmation requires the original "
            "email artefact, the document itself, and the user's browsing history around the "
            "detection timestamp."),
                "confidence": "Medium", "evidence": ev,
                "vector": "Phishing / macro-enabled document", "ruled_out": []}
    if "msiexec" in txt:
        ev.append("`msiexec.exe` observed running with a remote package URL")
        return {"paragraph": (
            "Probable Initial Access: The observed `msiexec` invocation referencing a "
            "remote package is consistent with a software-installation vector. Additional "
            "context — whether the installation was initiated by the user, a management tool, "
            "or an attacker-supplied link — is required to confirm."),
                "confidence": "Medium", "evidence": ev,
                "vector": "Remote MSI installation", "ruled_out": []}
    return {"paragraph": (
        "Probable Initial Access: The available telemetry does not surface a single "
        "high-confidence initial-access candidate. Additional evidence from authentication "
        "logs, browser history, and email-security telemetry is required before an "
        "initial-access vector can be attributed."),
            "confidence": "Low", "evidence": [], "vector": "Initial access cannot be determined",
            "ruled_out": []}


def _investigation_verdict(im: dict, files: list[dict], entcls: dict,
                            ia: dict, conf: dict, neg: list[dict]) -> dict:
    """5-second answer card. Every field is a short label — no prose."""
    events = im.get("raw_events") or []
    executed    = any(f.get("classification") == "Executed"    for f in files)
    quarantined = any(f.get("classification") == "Quarantined" for f in files)
    blocked     = any(f.get("classification") == "Blocked"     for f in files)
    txt = " ".join((e.get("process","") + " " + e.get("child_process","") + " " +
                    e.get("command_line","")).lower() for e in events)

    def _flag(observed: bool) -> str:
        return "Observed" if observed else "Not Observed"

    persistence = any(kw in txt for kw in ("run\\", "runonce", "schtasks", "sc create")) \
                  or bool(im.get("registry"))
    cred_access = any(kw in txt for kw in ("mimikatz", "lsass", "sekurlsa"))
    lateral     = any(kw in txt for kw in ("psexec", "wmic /node", "smbexec")) \
                  or bool(im.get("auth"))
    net_out     = bool((entcls.get("iocs") or {}).get("urls")) \
                  or bool((entcls.get("iocs") or {}).get("ips"))

    if executed:
        status = "Active — post-execution containment required"
    elif quarantined:
        status = "Contained — quarantined at source"
    elif blocked:
        status = "Contained — blocked at source"
    elif not events:
        status = "Insufficient telemetry"
    else:
        status = "Under investigation"

    classification = "Suspicious endpoint activity"
    if events and events[0].get("detection_name"):
        classification = events[0]["detection_name"]

    return {
        "classification":         classification,
        "current_status":         status,
        "execution":              _flag(executed),
        "persistence":            _flag(persistence),
        "credential_access":      _flag(cred_access),
        "lateral_movement":       _flag(lateral),
        "network_communication":  _flag(net_out),
        "containment":            "Yes" if (quarantined or blocked) else
                                   ("No — active" if executed else "Pending"),
        "customer_action_required": "Yes" if (executed or ia.get("confidence") in
                                                ("High", "Medium")) else "Recommended",
        "confidence":             conf.get("overall", "Low"),
    }


def _threat_intel_summary(im: dict) -> dict:
    """Collapse per-vendor TI records into one unified summary card so the
    report doesn't dump raw vendor output."""
    ti = im.get("ti") or []
    if not ti:
        return {"empty": True}
    indicators = sorted({t.get("value") for t in ti if t.get("value")})
    sources = sorted({t.get("source") for t in ti if t.get("source")})
    verdicts = [t.get("verdict") for t in ti if t.get("verdict")]
    families = sorted({t.get("family") for t in ti if t.get("family")})
    categories = sorted({t.get("kind") for t in ti if t.get("kind")})
    # Overall reputation — worst-of the verdicts, capped
    order = ["clean", "unknown", "suspicious", "malicious"]
    v_scores = [order.index(v.lower()) if v and v.lower() in order else 1
                for v in verdicts]
    worst = max(v_scores) if v_scores else 1
    overall_reputation = order[worst].title() if v_scores else "Unknown"
    confidence = "High" if worst >= 3 else "Medium" if worst >= 2 else "Low"
    return {
        "empty":              False,
        "indicators":         indicators,
        "overall_reputation": overall_reputation,
        "confidence":         confidence,
        "families":           families,
        "categories":         categories,
        "sources":            sources,
        "hit_count":          len(ti),
    }


# ── Citations: link narrative paragraphs → Supporting-Evidence card IDs
def _cite(evidence_cards: list[dict], want: list[str]) -> list[str]:
    """Return the subset of card IDs whose `kind` starts with any prefix in
    `want`. Deterministic — order matches the card list."""
    out: list[str] = []
    for c in evidence_cards or []:
        k = (c.get("kind") or "").lower()
        for w in want:
            if k.startswith(w.lower()):
                out.append(c.get("id"))
                break
    return out


def _citations_for_summary(evidence_cards: list[dict]) -> dict:
    """Return `{para_index: [E-ids]}` so the UI can print a citation
    strip under each Executive/Investigation Summary paragraph."""
    return {
        "executive_p1":     _cite(evidence_cards, ["Detection", "Process", "File"]),
        "executive_p2":     _cite(evidence_cards, ["Network", "Threat", "Historical"]),
        "investigation_p1": _cite(evidence_cards, ["Detection"]),
        "investigation_p2": _cite(evidence_cards, ["Process"]),
        "investigation_p3": _cite(evidence_cards, ["File"]),
        "investigation_p4": _cite(evidence_cards, ["Network", "Threat"]),
        "investigation_p5": _cite(evidence_cards, ["Historical"]),
    }


# ── Known vs Unknown (Cisco MDR staple) ──────────────────────────
def _known_vs_unknown(im: dict, files: list[dict], entcls: dict, ia: dict) -> dict:
    events = im.get("raw_events") or []
    known: list[str] = []
    unknown: list[str] = []
    if events and events[0].get("detection_name"):
        known.append(
            f"{events[0].get('source') or 'Endpoint sensor'} detection "
            f"`{events[0]['detection_name']}` raised at "
            f"{events[0].get('ts_raw') or 'unknown time'}")
    if any(f.get("classification") == "Executed" for f in files):
        known.append("Execution telemetry present — payload ran on the endpoint")
    if any(f.get("classification") == "Quarantined" for f in files):
        known.append("Endpoint agent quarantined the file before execution")
    for e in events[:1]:
        if e.get("parent_process") and e.get("process"):
            known.append(f"Process chain observed: `{e['parent_process']}` → `{e['process']}`")
    if (entcls.get("iocs") or {}).get("urls"):
        known.append(f"{len(entcls['iocs'].get('urls', []))} attacker-controlled URL(s) surfaced")
    if im.get("ti"):
        known.append(f"{len(im['ti'])} threat-intelligence correlation(s) identified")

    if not any(f.get("classification") == "Executed" for f in files):
        unknown.append("Whether the detected payload actually executed on the endpoint")
    if ia.get("confidence") in ("Low", "Medium", "None"):
        unknown.append(
            f"How the initial access was obtained "
            f"(current attribution confidence: {ia.get('confidence')})")
    if not im.get("auth"):
        unknown.append("Whether the associated user credentials were compromised or misused")
    if not im.get("network") or not any(
            n.get("classification") in ("attacker", "unknown")
            for n in (im.get("network") or [])):
        unknown.append("Whether additional payloads were downloaded from attacker infrastructure")
    if not any(e.get("user") for e in events):
        unknown.append("Which user account initiated the observed activity")
    unknown.append("Whether the observed administrative activity was authorised by the customer")
    return {"known": known, "unknown": unknown}


# ── Investigation Conclusion ──────────────────────────────────────
def _investigation_conclusion(im: dict, files: list[dict], entcls: dict,
                              recs: dict, neg: list[dict]) -> str:
    events = im.get("raw_events") or []
    if not events:
        return ("Available telemetry was insufficient to reconstruct a coherent activity "
                "chain. This assessment reflects only what the supplied evidence supports. "
                "Additional endpoint telemetry is required before a defensible verdict can "
                "be issued.")
    executed = [f for f in files if f.get("classification") == "Executed"]
    quarantined = [f for f in files if f.get("classification") == "Quarantined"]
    hosts = (im.get("assets") or {}).get("hosts") or []
    kill = _guess_kill_chain(im)
    parts: list[str] = []
    parts.append(
        f"Available telemetry indicates that {hosts[0] if hosts else 'the affected endpoint'} "
        f"experienced activity consistent with {kill}"
    )
    if quarantined and not executed:
        parts.append(", and that the detected executable was **quarantined** before "
                     "execution completed")
    elif executed:
        parts.append(", with **execution telemetry confirming** the payload ran on the endpoint")
    parts.append(".")
    # Negative-finding summary — Cisco style
    unobs = [n["category"].lower() for n in neg if not n["observed"]]
    if unobs:
        parts.append(" No evidence of "
                     + _join_natural(unobs[:4])
                     + " was identified within the available telemetry, which reduces the "
                       "estimated post-exploitation impact of the observed activity.")
    hist = im.get("history") or []
    if hist:
        parts.append(" Historical detections on the same endpoint increase the investigative "
                     "priority; however, the immediate threat appears contained.")
    parts.append(" Additional validation with the customer is recommended to confirm whether "
                 "the observed administrative activity was authorised and to review any "
                 "downstream activity on the affected accounts.")
    return "".join(parts)


# ── Investigation Confidence card ─────────────────────────────────
def _investigation_confidence(im: dict, files: list[dict], entcls: dict,
                              recs: dict) -> dict:
    events = im.get("raw_events") or []
    coverage = im.get("coverage") or {}
    have = sum(1 for v in coverage.values() if v)
    total = max(1, len(coverage))
    evidence_completeness = int(round(100 * have / total))
    # Timeline completeness = fraction of events with a real timestamp
    ts_present = sum(1 for e in events if e.get("ts_raw"))
    timeline_completeness = (int(round(100 * ts_present / max(1, len(events))))
                             if events else 0)
    executed = any(f.get("classification") == "Executed" for f in files)
    quarantined = any(f.get("classification") == "Quarantined" for f in files)
    execution_conf = ("High" if executed
                      else ("High" if quarantined else "Low"))
    # Root-cause confidence — driven by whether a probable IA vector was found
    ia = _probable_initial_access(im)
    root_cause_conf = ia.get("confidence") or "Low"
    # Overall — worst-of the sub-scores, but not below evidence_completeness bracket
    def _band(n):
        return "High" if n >= 80 else "Medium" if n >= 50 else "Low"
    scores = [_band(evidence_completeness), _band(timeline_completeness),
              execution_conf, root_cause_conf]
    order = {"None": 0, "Low": 1, "Medium": 2, "High": 3}
    overall = min(scores, key=lambda b: order.get(b, 0))
    return {
        "overall":                 overall,
        "evidence_completeness":   evidence_completeness,
        "timeline_completeness":   timeline_completeness,
        "execution_confidence":    execution_conf,
        "root_cause_confidence":   root_cause_conf,
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
            "confidence":             {},
            "verdict":                {},
            "ti_summary":             {"empty": True},
            "citations":              {},
            "executive_summary":      [],
            "known_vs_unknown":       {"known": [], "unknown": []},
            "probable_initial_access": {"paragraph": "", "confidence": "None", "evidence": [], "vector": "", "ruled_out": []},
            "investigation_summary":  [],
            "timeline":               [],
            "attack_story":           [],
            "technical_summary":      {},
            "mitre_by_tactic":        {},
            "mitre_techniques":       [],
            "negative_findings":      [],
            "recommendations":        {"immediate": [], "short_term": [], "long_term": []},
            "supporting_evidence":    [],
            "observed_evidence":      {},
            "observed_iocs":          {},
            "threat_intelligence":    [],
            "limitations":            [],
            "investigation_conclusion": "",
            "empty":                  True,
        }

    # Reuse classifiers/timeline to keep every stage on the same model.
    # Harvest URLs / IPs / domains from BOTH the pre-classified network
    # bucket (populated by the FIS/OSINT pipeline) AND directly from
    # event command lines / paths, so the report is self-sufficient from
    # the model — no external enrichment layer required for the URL bucket
    # to be populated.  This makes the regression corpus and any offline
    # replay produce the same output as the live pipeline.
    _URL_RE  = _re.compile(r"https?://[^\s\"'<>)]+", _re.I)
    _IP_RE   = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _HOST_RE = _re.compile(r"\b([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+)\b", _re.I)

    from_events_text: list[str] = []
    for e in im.get("raw_events") or []:
        for k in ("command_line", "path", "message"):
            v = e.get(k)
            if v:
                from_events_text.append(str(v))
    # Also scan the ORIGINAL incident text — URLs / IPs that arrive as
    # free-standing reference lines ("Attacker URL: https://…") aren't
    # captured by any adapter field, but the report should still surface
    # them (correctly classified) in the Observed Evidence bucket.
    if im.get("raw_text"):
        from_events_text.append(im["raw_text"])
    joined_events_text = " ".join(from_events_text)

    urls_bucket = list({n.get("url") for n in (im.get("network") or []) if n.get("url")})
    urls_bucket += [m.group(0).rstrip('.,;)"\'')
                    for m in _URL_RE.finditer(joined_events_text)]
    urls_bucket = sorted(set(u for u in urls_bucket if u))

    doms_from_urls = set()
    for u in urls_bucket:
        try:
            from urllib.parse import urlparse
            h = (urlparse(u).hostname or "").lower()
            if h: doms_from_urls.add(h)
        except Exception:
            pass
    domains_bucket = sorted(
        {n.get("domain") for n in (im.get("network") or []) if n.get("domain")}
        | set((im.get("assets") or {}).get("domains") or [])
        | doms_from_urls
        | {h.lower() for h in _HOST_RE.findall(joined_events_text)
           if "." in h and not any(h.lower().endswith("." + x) for x in
                                    ("exe", "dll", "ps1", "sct", "msi",
                                     "docm", "sys", "vbs", "js", "hta"))}
    )
    ips_bucket = sorted(
        {n.get("dst") for n in (im.get("network") or []) if n.get("dst")}
        | set(_IP_RE.findall(joined_events_text))
    )
    entities = {
        "urls":    urls_bucket,
        "domains": domains_bucket,
        "ips":     [ip for ip in ips_bucket if ip],
    }
    entcls    = classify_entities(entities)
    files     = [classify_file(f) for f in (im.get("files") or [])]
    processes = classify_processes(im.get("processes") or [])
    tl        = _build_timeline(im)
    mitre_bt  = _mitre_by_tactic(im)
    recs      = _recommendations(im, tl, files)
    neg       = _negative_findings(im, files, entcls)
    ia        = _probable_initial_access(im)
    kvu       = _known_vs_unknown(im, files, entcls, ia)
    conclusion = _investigation_conclusion(im, files, entcls, recs, neg)
    conf      = _investigation_confidence(im, files, entcls, recs)
    verdict   = _investigation_verdict(im, files, entcls, ia, conf, neg)
    ti_summary = _threat_intel_summary(im)

    supporting_cards = _supporting_evidence(im, tl, entcls, files, processes)
    citations = _citations_for_summary(supporting_cards)

    # 2026-08-01 operator directive · graph-only Incident Narrative
    # override. When the caller stashed the ORIGINAL raw input in
    # `im["_raw_input"]` we run the Phase 1 pipeline over it and
    # replace `executive_summary` + `investigation_summary` with the
    # analyst-style narrative so this report surface reads like an
    # incident investigation, not a canonical event dump.
    _exec = _executive_summary(im, tl, entcls, files)
    _inv = _investigation_summary(im, tl, entcls, files)
    try:
        raw_in = im.get("_raw_input")
        if raw_in:
            from nivxforge.investigation.pipeline.orchestrator import run_phase1
            from nivxforge.investigation.pipeline.narrative_engine import (
                compose_incident_narrative,
            )
            _state = run_phase1(raw_in)
            _narr = compose_incident_narrative(_state)
            if _narr and _narr.paragraphs:
                _exec = [_narr.executive_summary or _narr.paragraphs[0]]
                _inv = list(_narr.paragraphs)
    except Exception:  # noqa: BLE001
        # Fall through to legacy composition on any failure.
        pass

    return {
        "verdict":              verdict,
        "confidence":           conf,
        "executive_summary":    _exec,
        "citations":            citations,
        "known_vs_unknown":     kvu,
        "probable_initial_access": ia,
        "investigation_summary": _inv,
        "timeline":             tl,
        "attack_story":         _attack_story(im, tl),
        "technical_summary":    _technical_summary(im, entcls, files, processes),
        "mitre_by_tactic":      mitre_bt,
        "mitre_techniques":     _mitre_with_reasons(im, mitre_bt),
        "negative_findings":    neg,
        "recommendations":      recs,
        "supporting_evidence":  supporting_cards,
        "observed_evidence":    _observed_evidence(entcls, files, processes),
        "observed_iocs":        entcls.get("iocs") or {},
        "threat_intelligence":  im.get("ti") or [],
        "ti_summary":           ti_summary,
        "limitations":          _limitations(im, files),
        "investigation_conclusion": conclusion,
        "empty":                False,
    }
