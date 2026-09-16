"""v2/investigation/attack_story.py · Deterministic Attack Story generator.

Traverses the Investigation Knowledge Graph (IKG) — parent→child spawn
edges, verdict rollups, MITRE technique mappings — and emits an ordered
list of sentences describing the attack. Every sentence links to the
IKG evidence nodes / events that back it up.

No LLM. No paraphrasing. Same IKG → same story, byte-for-byte.

Public API:
    story = build_attack_story(inv_frames, ikg, verdicts)
    story  # list[Sentence]

Sentence shape:
    {
      "idx":         0,                   # 0-indexed rank
      "text":        "…",                 # analyst-facing sentence
      "tactic":      "initial_access",    # MITRE tactic bucket
      "severity":    "high",              # low | medium | high | critical
      "frame_iids":  ["f_abc", "f_def"],  # events that back the sentence
      "process_iids":["ent_process_..."], # processes referenced
      "signals":     ["SUSPICIOUS_PARENT"],
      "evidence_ref":"suspicious_parent · office → lolbin",
    }
"""
from __future__ import annotations
from typing import Any


# ── Deterministic phrase templates ──────────────────────────────────

_OFFICE_LOLBIN = {
    "rundll32.exe":  "loaded a DLL via rundll32",
    "regsvr32.exe":  "abused regsvr32 to run remote scriptlets",
    "certutil.exe":  "downloaded a payload via certutil",
    "msiexec.exe":   "executed an MSI installer",
    "wmic.exe":      "abused WMIC for command execution",
    "bitsadmin.exe": "downloaded a payload via bitsadmin",
    "mshta.exe":     "executed an HTA file",
    "powershell.exe":"launched PowerShell",
    "cmd.exe":       "launched a command shell",
    "cscript.exe":   "ran a WSH script",
    "wscript.exe":   "ran a WSH script",
}


def _fmt_ts(ts: str) -> str:
    return (ts or "").replace("T", " ").replace("Z", " UTC").strip()


def _bin_of(node: dict) -> str:
    return (node.get("label") or "").lower()


def _frames_by_process(frames: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in frames:
        pid = ((f.get("entity") or {}).get("iid")
               if (f.get("entity") or {}).get("type") == "process"
               else (f.get("parent") or {}).get("iid"))
        if not pid:
            continue
        out.setdefault(pid, []).append(f)
    return out


def _severity_of(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 30: return "medium"
    return "low"


def build_attack_story(frames: list[dict], ikg_dict: dict,
                       corr_dict: dict) -> list[dict]:
    """Return a deterministic, ordered list of story sentences.

    Uses the IKG + correlation output that the builder has already produced.
    Never re-scores or re-classifies — read-only projection.
    """
    if not frames:
        return []

    nodes: list[dict] = ikg_dict.get("nodes", [])
    edges: list[dict] = ikg_dict.get("edges", [])
    node_by_id: dict[str, dict] = {n["id"]: n for n in nodes}
    spawned: list[dict] = [e for e in edges if e["type"] == "spawned"]

    # Frame lookup indexes.
    frame_by_id: dict[str, dict] = {
        (f.get("frame_iid") or f.get("id") or ""): f for f in frames
    }
    fbp = _frames_by_process(frames)

    # Fired signals by process — pulled straight from the correlation output.
    proc_verdicts: dict[str, dict] = corr_dict.get("processes", {})

    story: list[dict] = []
    used_signals: set[tuple[str, str]] = set()   # (process_iid, signal)

    def _emit(text: str, tactic: str, severity: str, *,
              frame_iids: list[str] | None = None,
              process_iids: list[str] | None = None,
              signals: list[str] | None = None,
              evidence_ref: str = "") -> None:
        story.append({
            "idx":          len(story),
            "text":         text,
            "tactic":       tactic,
            "severity":     severity,
            "frame_iids":   list(dict.fromkeys(frame_iids or [])),
            "process_iids": list(dict.fromkeys(process_iids or [])),
            "signals":      list(dict.fromkeys(signals or [])),
            "evidence_ref": evidence_ref,
        })

    # ═ Sentence 1 · Initial spawn — Office/Browser parent → LOLBin/shell ═
    #   Detection priority:
    #     1. An IKG `spawned` edge from an Office/Browser parent to a LOLBin.
    #     2. A process aggregate that fired SUSPICIOUS_PARENT (parses the
    #        reason string to recover the parent/child binaries).
    _emitted_initial = False
    for edge in spawned:
        parent = node_by_id.get(edge["source"])
        child  = node_by_id.get(edge["target"])
        if not parent or not child:
            continue
        pb = _bin_of(parent)
        cb = _bin_of(child)
        is_office  = pb in {"winword.exe", "excel.exe", "powerpnt.exe",
                            "outlook.exe", "onenote.exe", "wordpad.exe"}
        is_browser = pb in {"chrome.exe", "firefox.exe", "msedge.exe",
                            "iexplore.exe", "brave.exe"}
        if (is_office or is_browser) and cb in _OFFICE_LOLBIN:
            phrase   = _OFFICE_LOLBIN[cb]
            parent_pretty = parent.get("label") or pb
            frame_hits = [
                f.get("frame_iid") for f in fbp.get(child["id"], [])
                if f.get("frame_iid")
            ]
            _emit(
                text=f"{parent_pretty} spawned {cb} which {phrase}.",
                tactic="initial_access",
                severity="high",
                frame_iids=frame_hits[:3],
                process_iids=[parent["id"], child["id"]],
                signals=["SUSPICIOUS_PARENT"],
                evidence_ref=f"suspicious parent · {pb} → {cb}",
            )
            used_signals.add((child["id"], "SUSPICIOUS_PARENT"))
            _emitted_initial = True
            break

    if not _emitted_initial:
        # Fallback — a process aggregate that fired SUSPICIOUS_PARENT tells
        # us the same story even if the IKG parent-of edge wasn't stitched
        # (e.g. missing explicit parent link in the raw telemetry).
        import re as _re
        for pid, pv in proc_verdicts.items():
            if "SUSPICIOUS_PARENT" not in pv.get("signals", []):
                continue
            # Pull the reason string from evidence_breakdown.
            reason = ""
            for e in pv.get("evidence_breakdown", []):
                if e.get("signal") == "SUSPICIOUS_PARENT":
                    reason = e.get("reason", ""); break
            m = _re.search(r"parent\s+(\S+)\s+spawned\s+(?:shell|LOLBin)\s+(\S+)", reason)
            pb = (m.group(1) if m else "unknown")
            cb = (m.group(2) if m else (node_by_id.get(pid, {}).get("label") or ""))
            phrase = _OFFICE_LOLBIN.get(cb, "executed a suspicious binary")
            frame_hits = [f.get("frame_iid") for f in fbp.get(pid, [])
                          if f.get("frame_iid")]
            _emit(
                text=f"{pb} spawned {cb} which {phrase}.",
                tactic="initial_access",
                severity=_severity_of(pv.get("score", 0)),
                frame_iids=frame_hits[:3],
                process_iids=[pid],
                signals=["SUSPICIOUS_PARENT"],
                evidence_ref=f"suspicious parent · {pb} → {cb}",
            )
            used_signals.add((pid, "SUSPICIOUS_PARENT"))
            break

    # ═ Sentence · Encoded / obfuscated command execution ═
    for pid, pv in proc_verdicts.items():
        sigs = set(pv.get("signals", []))
        if "ENCODED_POWERSHELL" in sigs and (pid, "ENCODED_POWERSHELL") not in used_signals:
            label = node_by_id.get(pid, {}).get("label", pid)
            frame_hits = [f.get("frame_iid") for f in fbp.get(pid, [])
                          if f.get("frame_iid")]
            _emit(
                text=f"{label} executed a base64-encoded PowerShell payload.",
                tactic="execution",
                severity=_severity_of(pv.get("score", 0)),
                frame_iids=frame_hits[:3],
                process_iids=[pid],
                signals=["ENCODED_POWERSHELL"],
                evidence_ref="obfuscation · encoded PowerShell",
            )
            used_signals.add((pid, "ENCODED_POWERSHELL"))
            break

    # ═ Sentence · Download cradle ═
    for pid, pv in proc_verdicts.items():
        sigs = set(pv.get("signals", []))
        if ("DOWNLOAD_CRADLE" in sigs or "LOLBAS_ABUSE" in sigs) \
                and (pid, "DOWNLOAD_CRADLE") not in used_signals:
            label = node_by_id.get(pid, {}).get("label", pid)
            frame_hits = [f.get("frame_iid") for f in fbp.get(pid, [])
                          if f.get("frame_iid")]
            _emit(
                text=f"{label} contacted an external URL to fetch a payload.",
                tactic="command_and_control",
                severity=_severity_of(pv.get("score", 0)),
                frame_iids=frame_hits[:3],
                process_iids=[pid],
                signals=[s for s in sigs if s in ("DOWNLOAD_CRADLE", "LOLBAS_ABUSE")],
                evidence_ref="download cradle",
            )
            used_signals.add((pid, "DOWNLOAD_CRADLE"))
            break

    # ═ Sentence · Persistence established ═
    persistence_hits = []
    for pid, pv in proc_verdicts.items():
        for s in ("REGISTRY_PERSISTENCE", "SCHEDULED_TASK_CREATE",
                  "WMI_PERSISTENCE", "SERVICE_INSTALL"):
            if s in pv.get("signals", []):
                persistence_hits.append((pid, s))
    if persistence_hits:
        pid, sig = persistence_hits[0]
        pv = proc_verdicts.get(pid, {})
        label = node_by_id.get(pid, {}).get("label", pid)
        verb  = {
            "REGISTRY_PERSISTENCE":  "wrote a Run key",
            "SCHEDULED_TASK_CREATE": "created a scheduled task",
            "WMI_PERSISTENCE":       "installed a WMI event consumer",
            "SERVICE_INSTALL":       "installed a service",
        }[sig]
        frame_hits = [f.get("frame_iid") for f in fbp.get(pid, [])
                      if f.get("frame_iid")]
        _emit(
            text=f"{label} {verb} to survive reboots.",
            tactic="persistence",
            severity=_severity_of(pv.get("score", 0)),
            frame_iids=frame_hits[:3],
            process_iids=[pid],
            signals=[sig],
            evidence_ref=f"persistence · {sig.lower()}",
        )

    # ═ Sentence · Credential access ═
    for pid, pv in proc_verdicts.items():
        sigs = set(pv.get("signals", []))
        if sigs & {"CREDENTIAL_DUMPING", "LSASS_ACCESS", "SAM_ACCESS"}:
            label = node_by_id.get(pid, {}).get("label", pid)
            frame_hits = [f.get("frame_iid") for f in fbp.get(pid, [])
                          if f.get("frame_iid")]
            _emit(
                text=f"{label} accessed credential material (LSASS / SAM / NTDS).",
                tactic="credential_access",
                severity=_severity_of(pv.get("score", 0)),
                frame_iids=frame_hits[:3],
                process_iids=[pid],
                signals=list(sigs & {"CREDENTIAL_DUMPING", "LSASS_ACCESS", "SAM_ACCESS"}),
                evidence_ref="credential access",
            )
            break

    # ═ Sentence · Defense evasion ═
    for pid, pv in proc_verdicts.items():
        sigs = set(pv.get("signals", []))
        evasion = sigs & {"AMSI_BYPASS", "DEFENDER_TAMPERING",
                          "PROCESS_INJECTION", "OBFUSCATION"}
        if evasion:
            label = node_by_id.get(pid, {}).get("label", pid)
            frame_hits = [f.get("frame_iid") for f in fbp.get(pid, [])
                          if f.get("frame_iid")]
            _emit(
                text=f"{label} attempted to evade defenses ({', '.join(sorted(evasion)).lower()}).",
                tactic="defense_evasion",
                severity=_severity_of(pv.get("score", 0)),
                frame_iids=frame_hits[:3],
                process_iids=[pid],
                signals=list(evasion),
                evidence_ref="defense evasion",
            )
            break

    # ═ Sentence · Beacon / C2 ═
    for pid, pv in proc_verdicts.items():
        sigs = set(pv.get("signals", []))
        c2 = sigs & {"EXTERNAL_C2", "NETWORK_BEACONING"}
        if c2:
            label = node_by_id.get(pid, {}).get("label", pid)
            frame_hits = [f.get("frame_iid") for f in fbp.get(pid, [])
                          if f.get("frame_iid")]
            _emit(
                text=f"{label} established a command-and-control channel.",
                tactic="command_and_control",
                severity=_severity_of(pv.get("score", 0)),
                frame_iids=frame_hits[:3],
                process_iids=[pid],
                signals=list(c2),
                evidence_ref="command-and-control",
            )
            break

    # ═ Sentence · Impact / ransomware ═
    for pid, pv in proc_verdicts.items():
        sigs = set(pv.get("signals", []))
        impact = sigs & {"BACKUP_DESTRUCTION", "SHADOW_COPY_DELETE",
                         "MASS_FILE_ENCRYPTION", "RANSOM_NOTE_CREATION"}
        if impact:
            label = node_by_id.get(pid, {}).get("label", pid)
            frame_hits = [f.get("frame_iid") for f in fbp.get(pid, [])
                          if f.get("frame_iid")]
            phrases = []
            if "BACKUP_DESTRUCTION"  in impact: phrases.append("destroyed backups")
            if "SHADOW_COPY_DELETE"  in impact: phrases.append("deleted shadow copies")
            if "MASS_FILE_ENCRYPTION"in impact: phrases.append("encrypted files at scale")
            if "RANSOM_NOTE_CREATION"in impact: phrases.append("dropped a ransom note")
            _emit(
                text=f"{label} caused impact — { ', '.join(phrases) }.",
                tactic="impact",
                severity="critical",
                frame_iids=frame_hits[:3],
                process_iids=[pid],
                signals=list(impact),
                evidence_ref="impact",
            )
            break

    # Fallback — no explicit signals matched, but device is non-benign.
    dev = corr_dict.get("device") or {}
    if not story and dev and dev.get("score", 0) > 0:
        _emit(
            text=f"Suspicious activity observed on the device — {dev.get('explanation', '')}.",
            tactic="execution",
            severity=_severity_of(dev.get("score", 0)),
            frame_iids=[], process_iids=[], signals=[],
            evidence_ref="device rollup",
        )

    # Renumber idx for safety after fallback insertion.
    for i, s in enumerate(story):
        s["idx"] = i
    return story
