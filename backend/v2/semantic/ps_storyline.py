"""NivXRay PowerShell Behavior Storyline (2026-07-27).

Deterministic, evidence-driven narrative generator. Consumes the SemanticResult
(recovered_script, behaviors_v2, artifacts, deobfuscation, ast_tree,
verdict_breakdown) and produces:

    {
      "executive_summary": str,          # 1-2 sentence Tier-1 answer
      "sections": [ {key,title,observed,narrative,mitre,evidence[]}, ... ],
      "attack_narrative": str,           # multi-line technical story
      "mitre_techniques": [ {id, sections[]} ],
    }

Contract (locked with SOC user 2026-07-27):
    • NO LLM. NO hallucination. NO guesswork. All statements are backed by
      concrete evidence (behavior IDs, artifacts, decoded script snippets).
    • Every section explicitly declares whether behavior was observed. When
      no evidence exists, we say so — never invent content.
    • Storyline is generated FROM the fully decoded payload, never from the
      raw obfuscated input.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Iterable


# ── Section → behavior-id mapping ──────────────────────────────────────
# The mapping is deterministic and exhaustive. Any behavior ID that appears
# in the taxonomy MUST route to at least one section, otherwise it will be
# silently dropped from the narrative.
SECTION_MAP: list[tuple[str, str, list[str]]] = [
    ("initial_execution", "Initial Execution", [
        "encoded_command", "invoke_expression", "memory_execution",
        "fileless_execution", "execution_policy_bypass", "hidden_window",
        "no_profile",
    ]),
    ("process_behavior", "Process Behavior", [
        "process_spawn", "lolbin_abuse", "process_injection",
    ]),
    ("network_behavior", "Network Behavior", [
        "webclient_downloadstring", "webclient_downloadfile",
        "invoke_webrequest", "invoke_restmethod", "bits_download",
        "remote_script_download", "network_beaconing", "c2_communication",
        "external_network", "local_network_only", "lateral_movement",
    ]),
    ("file_activity", "File Activity", []),           # artifact-driven
    ("registry_activity", "Registry Activity", [
        "registry_modification",
    ]),                                                # artifacts also contribute
    ("persistence", "Persistence", [
        "scheduled_task", "service_creation", "registry_run_key",
        "persistence",
    ]),
    ("credential_access", "Credential Access", [
        "credential_access",
    ]),
    ("defense_evasion", "Defense Evasion", [
        "amsi_bypass", "defender_tamper", "reflection", "defense_evasion",
        "payload_decode", "payload_decompression", "string_reconstruction",
        "char_array_join", "privilege_escalation",
    ]),
]


# Cmdlets that indicate file activity when present in the decoded script.
_FILE_CMDLETS = re.compile(
    r"\b(out-file|set-content|add-content|new-item|remove-item|"
    r"copy-item|move-item|get-content|test-path|start-bitstransfer)\b",
    re.IGNORECASE,
)


def _behaviors_by_id(behaviors: list[dict]) -> dict[str, dict]:
    """Index a `behaviors_v2` list by id (last wins for duplicates)."""
    return {b.get("id"): b for b in (behaviors or []) if b.get("id")}


def _artifacts_of(artifacts: list[dict], kind: str) -> list[dict]:
    return [a for a in (artifacts or []) if a.get("kind") == kind]


# ── Section builders ───────────────────────────────────────────────────
def _fmt_behaviors(bs: list[dict]) -> str:
    """Analyst-facing comma-separated list of behavior names."""
    parts = []
    for b in bs:
        name = b.get("name") or b.get("id") or "unknown"
        conf = b.get("confidence")
        if isinstance(conf, int):
            parts.append(f"{name} (conf {conf})")
        else:
            parts.append(name)
    return ", ".join(parts)


def _section_narrative(section_key: str, matched: list[dict],
                        artifacts: list[dict], script: str) -> str:
    """Build the analyst-facing narrative for a given section."""
    if section_key == "initial_execution":
        if not matched:
            return ("No explicit execution-flag behavior was observed. The "
                    "recovered script does not use `-EncodedCommand`, "
                    "`Invoke-Expression`, or a hidden window flag.")
        pieces = [f"The payload initiates execution via {_fmt_behaviors(matched)}."]
        if any(b["id"] == "encoded_command" for b in matched):
            pieces.append("A `-EncodedCommand` wrapper was used to hide the "
                          "true script from surface-level inspection.")
        if any(b["id"] in ("invoke_expression", "memory_execution",
                             "fileless_execution") for b in matched):
            pieces.append("The recovered script relies on in-memory execution — "
                          "the code never touches disk before running.")
        return " ".join(pieces)

    if section_key == "process_behavior":
        if not matched:
            return "No process spawn, LOLBIN abuse, or injection primitives were observed."
        return (f"Process-level activity: {_fmt_behaviors(matched)}. "
                "Each entry above is backed by a cmdlet or process node in the AST.")

    if section_key == "network_behavior":
        ext_urls = _artifacts_of(artifacts, "url")
        ext_urls = [a for a in ext_urls if a.get("classification") == "external"]
        ext_ips = [a for a in _artifacts_of(artifacts, "ip")
                    if a.get("classification") == "external"]
        if not matched and not ext_urls and not ext_ips:
            return "No outbound network activity was observed in the decoded payload."
        pieces = []
        if matched:
            pieces.append(f"Network behaviors: {_fmt_behaviors(matched)}.")
        if ext_urls:
            urls = ", ".join(a.get("value", "") for a in ext_urls[:5])
            pieces.append(f"External URLs referenced ({len(ext_urls)}): {urls}.")
        if ext_ips:
            ips = ", ".join(a.get("value", "") for a in ext_ips[:5])
            pieces.append(f"External IPs referenced ({len(ext_ips)}): {ips}.")
        return " ".join(pieces)

    if section_key == "file_activity":
        files = _artifacts_of(artifacts, "file")
        cmdlet_hits = _FILE_CMDLETS.findall(script or "")
        if not files and not cmdlet_hits:
            return "No file-system activity was observed."
        pieces = []
        if files:
            paths = ", ".join(a.get("value", "") for a in files[:5])
            pieces.append(f"File paths referenced ({len(files)}): {paths}.")
        if cmdlet_hits:
            uniq = sorted({c.lower() for c in cmdlet_hits})
            pieces.append(f"File cmdlets invoked: {', '.join(uniq)}.")
        return " ".join(pieces)

    if section_key == "registry_activity":
        regs = _artifacts_of(artifacts, "registry")
        if not matched and not regs:
            return "No registry access or modification was observed."
        pieces = []
        if matched:
            pieces.append(f"Registry behaviors: {_fmt_behaviors(matched)}.")
        if regs:
            keys = ", ".join(a.get("value", "") for a in regs[:5])
            pieces.append(f"Registry keys referenced ({len(regs)}): {keys}.")
        return " ".join(pieces)

    if section_key == "persistence":
        if not matched:
            return ("No persistence primitives (scheduled task, service, "
                    "or Run-key registration) were observed.")
        return (f"Persistence tactics: {_fmt_behaviors(matched)}. "
                "The payload attempts to survive reboots or user sign-out.")

    if section_key == "credential_access":
        if not matched:
            return "No credential-access behavior was observed in the decoded payload."
        return (f"Credential-access primitives: {_fmt_behaviors(matched)}. "
                "The payload targets credential material or authentication artifacts.")

    if section_key == "defense_evasion":
        if not matched:
            return "No defense-evasion behavior was observed."
        return (f"Defense-evasion tactics: {_fmt_behaviors(matched)}. "
                "These behaviors are designed to bypass or blind security controls "
                "before or during execution.")

    return "No evidence observed."


# ── Executive & attack-narrative ───────────────────────────────────────
def _executive_summary(verdict_breakdown: dict, behaviors: list[dict],
                        deob: dict, artifacts: list[dict]) -> str:
    verdict = (verdict_breakdown or {}).get("verdict") or "inconclusive"
    risk = (verdict_breakdown or {}).get("risk_score")
    stages_count = len((deob or {}).get("stages") or [])
    boundary = (deob or {}).get("boundary_op") or ""
    top = sorted(behaviors, key=lambda b: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            .get(b.get("severity", "info"), 4),
        -(b.get("confidence") or 0),
    ))[:3]
    top_names = ", ".join(b.get("name", "?") for b in top) or "no observable behaviors"

    ext_urls = [a for a in _artifacts_of(artifacts, "url")
                 if a.get("classification") == "external"]
    net_bit = ""
    if ext_urls:
        net_bit = f" It reaches out to {len(ext_urls)} external URL(s)."

    parts = [f"Verdict: **{verdict.upper()}**"]
    if isinstance(risk, int):
        parts[0] += f" · risk {risk}/100."
    else:
        parts[0] += "."
    parts.append(f"Top observable behaviors: {top_names}.")
    if stages_count:
        parts.append(f"Recovered from {stages_count} deterministic "
                     f"deobfuscation stage(s)"
                     + (f", halted at execution boundary `{boundary}`." if boundary
                         else "."))
    if net_bit:
        parts.append(net_bit.strip())
    return " ".join(parts)


def _attack_narrative(sections: list[dict], deob: dict,
                       script: str) -> str:
    lines: list[str] = []
    observed = [s for s in sections if s["observed"]]
    if not observed:
        return ("No offensive behavior was observed in the decoded payload. "
                "The recovered script is benign or exercises only informational "
                "cmdlets.")

    lines.append("Reconstructed attack flow (deterministic, evidence-driven):")
    stages_count = len((deob or {}).get("stages") or [])
    if stages_count:
        boundary = (deob or {}).get("boundary_op") or ""
        lines.append(f"1. The raw command was recursively deobfuscated over "
                     f"{stages_count} deterministic stage(s)"
                     + (f", halting at execution boundary `{boundary}`." if boundary
                         else "."))
    else:
        lines.append("1. No obfuscation was applied — the raw command was "
                     "analyzed directly.")

    step = 2
    for sec in observed:
        # Skip the "final decoded script" pseudo-sections here — they are
        # rendered as separate blocks in the UI.
        if sec["key"] in ("deobfuscation_chain", "final_decoded_script"):
            continue
        lines.append(f"{step}. **{sec['title']}** — {sec['narrative']}")
        step += 1

    return "\n".join(lines)


# ── Public entrypoint ──────────────────────────────────────────────────
def build_storyline(*, recovered_script: str,
                     behaviors_v2: list[dict],
                     artifacts: list[dict],
                     deobfuscation: dict,
                     verdict_breakdown: dict) -> dict:
    """Return a fully deterministic storyline dict — see module docstring."""
    behaviors_v2 = behaviors_v2 or []
    artifacts = artifacts or []
    deobfuscation = deobfuscation or {}
    verdict_breakdown = verdict_breakdown or {}
    script = recovered_script or ""

    idx = _behaviors_by_id(behaviors_v2)

    # Deob-chain summary section
    stages = deobfuscation.get("stages") or []
    if stages:
        techniques = sorted({(s.get("technique") or "?") for s in stages})
        deob_narrative = (
            f"Applied {len(stages)} deterministic transformation(s): "
            f"{', '.join(techniques)}. "
            f"Stopped: {deobfuscation.get('stopped_reason', 'fixed_point')}."
        )
        if deobfuscation.get("boundary_op"):
            deob_narrative += (f" Execution boundary reached: "
                               f"`{deobfuscation['boundary_op']}` — no dynamic "
                               f"evaluation performed.")
        deob_observed = True
    else:
        deob_narrative = ("No deterministic deobfuscation was applicable — the "
                          "payload was already in a decodable form.")
        deob_observed = False

    # Final decoded script
    final_script = (deobfuscation.get("final") or script or "").strip()

    # Build categorized sections
    sections: list[dict] = []
    sections.append({
        "key": "deobfuscation_chain",
        "title": "Deobfuscation Chain Summary",
        "observed": deob_observed,
        "narrative": deob_narrative,
        "mitre": [],
        "evidence": [{"kind": "deobfuscation", "count": len(stages)}]
                     if stages else [],
    })
    sections.append({
        "key": "final_decoded_script",
        "title": "Final Decoded Script",
        "observed": bool(final_script),
        "narrative": (final_script[:2000] if final_script
                      else "No decoded script content was recovered."),
        "mitre": [],
        "evidence": [{"kind": "script_length", "value": len(final_script)}],
    })

    for key, title, ids in SECTION_MAP:
        matched = [b for bid in ids if (b := idx.get(bid))]
        mitre = sorted({m for b in matched for m in (b.get("mitre") or [])})
        # Section-specific evidence hooks (artifacts, cmdlets)
        evidence: list[dict] = [{"kind": "behavior", "id": b["id"],
                                  "name": b.get("name"),
                                  "confidence": b.get("confidence"),
                                  "severity": b.get("severity")}
                                 for b in matched]
        if key == "network_behavior":
            for a in artifacts:
                if a.get("kind") in ("url", "ip") \
                        and a.get("classification") == "external":
                    evidence.append({"kind": a["kind"], "value": a["value"],
                                     "classification": a.get("classification")})
        if key == "file_activity":
            for a in artifacts:
                if a.get("kind") == "file":
                    evidence.append({"kind": "file", "value": a["value"]})
            for hit in sorted(set(m.lower()
                                   for m in _FILE_CMDLETS.findall(script))):
                evidence.append({"kind": "cmdlet", "value": hit})
        if key == "registry_activity":
            for a in artifacts:
                if a.get("kind") == "registry":
                    evidence.append({"kind": "registry", "value": a["value"]})

        observed = bool(matched) or bool(
            [e for e in evidence if e.get("kind") not in ("behavior",)])
        narrative = _section_narrative(key, matched, artifacts, script)
        sections.append({
            "key": key,
            "title": title,
            "observed": observed,
            "narrative": narrative,
            "mitre": mitre,
            "evidence": evidence,
        })

    # MITRE roll-up — group techniques by contributing section
    mitre_map: dict[str, list[str]] = {}
    for sec in sections:
        for m in sec.get("mitre") or []:
            mitre_map.setdefault(m, []).append(sec["key"])
    mitre_out = [{"id": m, "sections": secs}
                 for m, secs in sorted(mitre_map.items())]

    exec_summary = _executive_summary(verdict_breakdown, behaviors_v2,
                                       deobfuscation, artifacts)
    attack_story = _attack_narrative(sections, deobfuscation, script)

    return {
        "executive_summary": exec_summary,
        "sections":          sections,
        "mitre_techniques":  mitre_out,
        "attack_narrative":  attack_story,
    }
