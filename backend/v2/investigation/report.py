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

    # ── Paragraph 2 — Assessment, correlation, next step
    p2_bits: list[str] = []
    ioc_urls = (entcls.get("iocs") or {}).get("urls") or []
    if threat:
        fam = _family_of(threat)
        p2_bits.append(
            f"Threat intelligence classified the observed activity as **{threat}**"
            + (f" ({fam})" if fam else "") + ".")
    elif ti:
        fams = sorted({_family_of(t.get("value") or t.get("family") or "")
                       for t in ti} - {""})
        if fams:
            p2_bits.append(
                f"Threat-intelligence enrichment aligned the observed tooling with "
                f"{' and '.join(fams[:2])}.")

    kill = _guess_kill_chain(im)
    p2_bits.append(f"The observed sequence is consistent with **{kill}**.")

    if executed_files:
        p2_bits.append(
            "Because execution was confirmed, post-execution containment and forensic "
            "review of the endpoint are warranted.")
    elif quarantined:
        p2_bits.append(
            "Because the endpoint quarantined the file before execution, the immediate "
            "risk is contained; deeper host-side visibility (Orbital or equivalent) "
            "should still confirm no residual persistence, credential access, or "
            "outbound C2 activity preceded quarantine.")
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
    p1 = (f"At {ts} UTC, " if ts else "") + f"{source} detected"
    p1 += f" **{detection}**" if detection else " suspicious endpoint activity"
    if host: p1 += f" on host `{host}`"
    if user: p1 += f" under user account `{user}`"
    p1 += "."
    # Why did it fire? Threat name + technical context.
    if e0.get("threat_name"):
        p1 += f" The alert was raised on the observed artefact **{e0['threat_name']}**"
        why_desc = _describe_process(e0.get("process") or "")
        if why_desc:
            p1 += f", which is associated with {why_desc}"
        p1 += "."
    paras.append(p1)

    # ── Paragraph 2 — Process chain, execution semantics ───────────
    parent = (e0.get("parent_process") or "").strip()
    process = (e0.get("process") or "").strip()
    child = (e0.get("child_process") or "").strip()
    cmd = (e0.get("command_line") or "").strip()
    if parent and process and _basename(parent) != _basename(process):
        p2 = f"Process telemetry shows {_process_chain_desc(parent, process, child)}."
        if cmd:
            # Show the command line — but if it's an EncodedCommand blob,
            # truncate to keep the paragraph readable.
            cmd_display = cmd[:180] + ("…" if len(cmd) > 180 else "")
            p2 += f" The observed command line was `{cmd_display}`."
        why_p = _describe_process(process)
        if why_p:
            p2 += (f" `{_basename(process)}` is {why_p}.")
        paras.append(p2)
    elif process:
        p2 = (f"The activity involved `{process}`" +
              (f", executed under user account `{user}`" if user else "") + ".")
        if cmd:
            p2 += f" Command line: `{cmd[:180]}{'…' if len(cmd) > 180 else ''}`."
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
            "mitre_by_tactic":      {},
            "recommendations":      [],
            "supporting_evidence":  [],
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
        "investigation_summary":_investigation_summary(im, tl, entcls, files),
        "timeline":             tl,
        "attack_story":         _attack_story(im, tl),
        "technical_summary":    _technical_summary(im, entcls, files, processes),
        "mitre_by_tactic":      _mitre_by_tactic(im),
        "recommendations":      _recommendations(im, tl, files),
        "supporting_evidence":  _supporting_evidence(im, tl, entcls, files, processes),
        "observed_evidence":    _observed_evidence(entcls, files, processes),
        "observed_iocs":        entcls.get("iocs") or {},
        "threat_intelligence":  im.get("ti") or [],
        "limitations":          _limitations(im, files),
        "empty":                False,
    }
