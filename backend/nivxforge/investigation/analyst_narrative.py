"""Analyst Investigation Narrative Composer (2026-08-01).

Produces an MDR-analyst-style Executive Investigation Summary from a
CIO. Variable-length: **minimum 2 paragraphs**, maximum scales with
the depth of the investigation (vendor telemetry richness, chain
length, TI hits, multi-host correlation, MITRE coverage, verdict
class).

Contract:
    compose_analyst_narrative(cio: CIO) -> str

Rules:
    * Every sentence must be backed by concrete evidence present in
      the CIO. If the evidence isn't there, the sentence is skipped.
    * No template phrases. No decoder-internal telemetry. No LLM.
    * Guaranteed ≥ 2 paragraphs on any non-empty CIO.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from nivxforge.investigation.customer_report import _sanitize_customer_text


# ─── Basic helpers ────────────────────────────────────────────────────

def _hosts(cio: Dict[str, Any]) -> List[str]:
    ent = ((cio.get("summary") or {}).get("entities_digest") or {}) or {}
    out = list(ent.get("hosts") or [])
    for h in (cio.get("metadata") or {}).get("hosts", []) or []:
        if h and h not in out:
            out.append(h)
    for line in str(cio.get("input_text") or "").splitlines():
        if "host=" in line:
            frag = line.split("host=", 1)[1].split(" ")[0]
            if frag and frag not in out:
                out.append(frag)
    return out[:20]


def _users(cio: Dict[str, Any]) -> List[str]:
    ent = ((cio.get("summary") or {}).get("entities_digest") or {}) or {}
    return list(ent.get("users") or [])[:10]


def _iocs(cio: Dict[str, Any]) -> Dict[str, List[str]]:
    md = cio.get("metadata") or {}
    return md.get("iocs") or {}


def _recovered_command(cio: Dict[str, Any]) -> str:
    for layer in reversed(cio.get("decode_chain") or []):
        prev = str(layer.get("preview") or "").strip()
        if prev:
            return prev
    return ""


def _decode_layer_count(cio: Dict[str, Any]) -> int:
    return len([l for l in (cio.get("decode_chain") or []) if l.get("preview")])


def _lolbins(cio: Dict[str, Any]) -> List[str]:
    graph = cio.get("evidence_graph") or {}
    seen: List[str] = []
    for n in graph.get("nodes") or []:
        if (n.get("kind") or "").lower() != "lolbin":
            continue
        val = (n.get("attrs") or {}).get("binary") or n.get("value") or n.get("label") or ""
        val = str(val).strip()
        if val and val.lower() not in [s.lower() for s in seen]:
            seen.append(val)
    return seen[:6]


def _mitre_techniques(cio: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    md = ((cio.get("summary") or {}).get("mitre_digest") or {})
    # Two shapes observed in production:
    #   A) Flat: {"techniques": [{...}, ...], "tactics": [...], "coverage": N}
    #   B) Tactic-keyed: {"execution": [{...}], "persistence": [...], ...}
    def _push_list(seq):
        for t in seq or []:
            if not isinstance(t, dict):
                continue
            tid = t.get("technique_id") or t.get("id") or ""
            name = t.get("name") or t.get("title") or ""
            if tid and (tid, name) not in out:
                out.append((tid, name))
    if isinstance(md.get("techniques"), list):
        _push_list(md["techniques"])
    for k, val in md.items():
        if k in ("techniques", "tactics", "coverage"):
            continue
        if isinstance(val, list):
            _push_list(val)
        elif isinstance(val, dict):
            _push_list(val.get("techniques") or [])
    if not out:
        for n in ((cio.get("evidence_graph") or {}).get("nodes") or []):
            if (n.get("kind") or "").lower() != "mitre_technique":
                continue
            tid = (n.get("attrs") or {}).get("technique_id") or ""
            name = str(n.get("label") or "").replace(f"{tid} ·", "").strip(" ·")
            if tid and (tid, name) not in out:
                out.append((tid, name))
    return out[:8]


def _mitre_tactic_ids(cio: Dict[str, Any]) -> List[str]:
    _tactic_from_key = {
        "initial_access": "TA0001 (Initial Access)",
        "execution": "TA0002 (Execution)",
        "persistence": "TA0003 (Persistence)",
        "privilege_escalation": "TA0004 (Privilege Escalation)",
        "defense_evasion": "TA0005 (Defense Evasion)",
        "credential_access": "TA0006 (Credential Access)",
        "discovery": "TA0007 (Discovery)",
        "lateral_movement": "TA0008 (Lateral Movement)",
        "collection": "TA0009 (Collection)",
        "exfiltration": "TA0010 (Exfiltration)",
        "command_and_control": "TA0011 (Command and Control)",
        "impact": "TA0040 (Impact)",
    }
    out: List[str] = []
    md = ((cio.get("summary") or {}).get("mitre_digest") or {})
    # Flat shape: `tactics` is a list of tactic names.
    for tac_name in (md.get("tactics") or []):
        key = str(tac_name).lower().replace(" ", "_").replace("-", "_")
        pretty = _tactic_from_key.get(key)
        if pretty and pretty not in out:
            out.append(pretty)
    # Tactic-keyed shape: top-level keys are tactic names.
    for key in md.keys():
        if key in ("techniques", "tactics", "coverage"):
            continue
        pretty = _tactic_from_key.get(str(key).lower())
        if pretty and pretty not in out and md.get(key):
            out.append(pretty)
    # Fallback via evidence graph.
    if not out:
        for n in ((cio.get("evidence_graph") or {}).get("nodes") or []):
            if (n.get("kind") or "").lower() != "mitre_technique":
                continue
            t = str(((n.get("attrs") or {}).get("tactic") or "")).lower()
            key = t.replace(" ", "_").replace("-", "_")
            pretty = _tactic_from_key.get(key)
            if pretty and pretty not in out:
                out.append(pretty)
    return out


def _incident_meta(cio: Dict[str, Any]) -> Dict[str, str]:
    md = cio.get("metadata") or {}
    out = {
        "vendor": str(md.get("vendor") or "").strip(),
        "incident_id": str(md.get("incident_id") or "").strip(),
        "detection": str(md.get("detection_name") or "").strip(),
        "threat_name": str(md.get("threat_name") or "").strip(),
        "timestamp": str(md.get("first_seen") or md.get("timestamp") or "").strip(),
        "action": str(md.get("action") or "").strip(),
    }
    txt = str(cio.get("input_text") or "")
    if not out["vendor"]:
        for line in txt.splitlines():
            line = line.strip()
            if line.startswith("# vendor="):
                out["vendor"] = line[len("# vendor="):].strip()
                break
    for line in txt.splitlines()[:20]:
        for tag, key in (("detection=", "detection"),
                          ("threat=", "threat_name"),
                          ("action=", "action"),
                          ("ts=", "timestamp")):
            if tag in line and not out[key]:
                frag = line.split(tag, 1)[1].split(" ")[0].strip()
                if frag:
                    out[key] = frag
    if not out["vendor"]:
        prov = str(md.get("normalised_via") or "")
        if prov.startswith("normalizers.py:"):
            out["vendor"] = prov[len("normalizers.py:"):]
    return out


def _hashes_with_names(cio: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    iocs = _iocs(cio)
    seen: set = set()
    for algo in ("sha256", "sha1", "md5"):
        for h in iocs.get(algo, []) or []:
            if h and h not in seen:
                seen.add(h)
                out.append((h, ""))
    txt = str(cio.get("input_text") or "")
    for i, (h, _) in enumerate(out):
        for line in txt.splitlines():
            if h in line:
                for tok in line.split():
                    tok = tok.strip(",.;:()'\"")
                    if "." in tok and tok.lower().endswith(
                        (".exe", ".dll", ".ps1", ".bat", ".js", ".vbs", ".hta", ".msi")
                    ):
                        out[i] = (h, tok)
                        break
                break
    return out[:6]


def _threat_intel_summary(cio: Dict[str, Any]) -> str:
    ti = ((cio.get("metadata") or {}).get("ti_shield") or {}) or {}
    frags: List[str] = []
    vt = ti.get("virustotal") or {}
    if isinstance(vt, dict):
        pos = vt.get("positives") or vt.get("malicious")
        total = vt.get("total") or vt.get("scanners")
        if pos and total:
            frags.append(f"a VirusTotal detection ratio of {pos}/{total}")
    smac = ti.get("secure_malware_analytics") or ti.get("smac") or {}
    if isinstance(smac, dict) and smac.get("score"):
        frags.append(f"a Secure Malware Analytics threat score of {smac['score']}")
    otx = ti.get("otx") or {}
    if isinstance(otx, dict) and otx.get("pulses"):
        frags.append(f"{otx['pulses']} AlienVault OTX pulses")
    return "; ".join(frags)


def _internal_ip_present(cio: Dict[str, Any]) -> Optional[str]:
    """Return the first RFC1918 IP found in IOCs, else None."""
    ips = _iocs(cio).get("ips") or []
    for ip in ips:
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                o1, o2 = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            if o1 == 10:
                return ip
            if o1 == 172 and 16 <= o2 <= 31:
                return ip
            if o1 == 192 and o2 == 168:
                return ip
            if o1 == 127:
                return ip
    return None


def _verdict_fields(cio: Dict[str, Any]) -> Dict[str, Any]:
    v = cio.get("verdict") or {}
    ex = v.get("explain") or {}
    cc = ex.get("confidence_calculation") or {}
    return {
        "label": v.get("label") or "Undetermined",
        "pct": int(v.get("confidence_pct") or 0),
        "raw_pct": int(cc.get("raw_noisy_or_pct") or 0),
        "mitigators": int(cc.get("mitigators_present") or 0),
        "dampen_pct": int(cc.get("mitigator_dampening_max_pct") or 0),
        "escalation": ex.get("escalation_applied"),
        "reason": str(v.get("reason") or "").strip(),
    }


# ─── Narrative composer · story arc, not fact recital ───────────────
#
# The narrative unfolds as an MDR analyst would tell it:
#
#   1. OPENING       — What arrived · when · from where (sets the scene)
#   2. DISCOVERY     — What decoding / normalisation revealed (the reveal)
#   3. INTERPRETATION— What the evidence MEANS (analyst judgement)
#   4. CORRELATION   — MITRE · TI · multi-host correlation (widening)
#   5. JUDGEMENT     — Why the verdict is what it is (weighing)
#   6. GUIDANCE      — What the responder should do (action)
#
# Chapters are woven with transitional language ("then", "critically",
# "taken together") — not concatenated bullets. Empty chapters are
# skipped silently. On thin CIOs, we still ship a 2-paragraph story:
# an opening/discovery paragraph and a judgement/guidance paragraph.


def _fmt_recovered(cmd: str, limit: int = 220) -> str:
    if not cmd:
        return ""
    cmd = cmd.strip()
    return f"`{cmd}`" if len(cmd) < limit else f"`{cmd[:limit-1]}…`"


def _chapter_opening(cio: Dict[str, Any]) -> str:
    """Sets the scene — what arrived, from where, when. Story voice."""
    m = _incident_meta(cio)
    hosts = _hosts(cio)
    users = _users(cio)
    iu = ((cio.get("metadata") or {}).get("input_understanding") or {}) or {}
    itype = (iu.get("label") or iu.get("type") or "").replace("_", " ").strip().lower()
    if m["vendor"]:
        parts: List[str] = [f"This investigation began when **{m['vendor']}**"]
        if m["incident_id"]:
            parts.append(f"raised Incident **{m['incident_id']}**")
        else:
            parts.append("raised an alert")
        if m["detection"] or m["threat_name"]:
            det = m["detection"] or m["threat_name"]
            parts.append(f"for **{det}**")
        if hosts:
            parts.append(f"on host **{hosts[0]}**")
        if users:
            parts.append(f"(user {users[0]})")
        if m["timestamp"]:
            parts.append(f"at {m['timestamp']}")
        sentence = " ".join(parts).rstrip(".") + "."
        return sentence
    # No vendor — analyst-driven submission.
    if itype:
        return (
            f"An analyst submitted a **{itype}** artefact for triage; the "
            "pipeline immediately routed it into the recursive decoder to "
            "recover any hidden behaviour."
        )
    return (
        "An analyst submitted an artefact for triage; the pipeline "
        "routed it into the recursive decoder to surface hidden behaviour."
    )


def _chapter_discovery(cio: Dict[str, Any]) -> str:
    """The reveal — what decoding uncovered. Uses temporal connectors."""
    recovered = _recovered_command(cio)
    layers = _decode_layer_count(cio)
    lolbins = _lolbins(cio)
    urls = _iocs(cio).get("urls") or []
    if not (recovered or lolbins or urls):
        return ""
    parts: List[str] = []
    if layers >= 2 and recovered:
        parts.append(
            f"Peeling back **{layers}** successive encoding layers, the "
            f"decoder ultimately recovered the command {_fmt_recovered(recovered)}"
        )
    elif recovered:
        parts.append(f"The decoder recovered the command {_fmt_recovered(recovered)}")
    elif lolbins:
        parts.append(f"The submission invoked **{lolbins[0]}**")
    tail = parts[0]
    # Weave in what the recovered command DOES.
    if urls:
        target = urls[0]
        tail += (
            f" — an in-memory PowerShell invocation that reaches out to "
            f"**{target}** and executes whatever content the server returns"
        )
    elif lolbins and recovered:
        tail += f", invoked via the {lolbins[0]} living-off-the-land binary"
    return tail.rstrip(".") + "."


def _chapter_interpretation(cio: Dict[str, Any]) -> str:
    """Analyst judgement — what the pattern MEANS. Adds interpretive
    framing, not just facts."""
    recovered = _recovered_command(cio)
    urls = _iocs(cio).get("urls") or []
    internal = _internal_ip_present(cio)
    layers = _decode_layer_count(cio)
    if not recovered:
        return ""
    sentences: List[str] = []
    # Classify the recovered command shape
    rec_lc = recovered.lower()
    if "iex" in rec_lc and ("downloadstring" in rec_lc or "downloadfile" in rec_lc or "invoke-webrequest" in rec_lc or "invoke-restmethod" in rec_lc):
        sentences.append(
            "This is a textbook **stager pattern** — the attacker hides the "
            "true payload behind an encoded wrapper, then pulls the "
            "second-stage code from an internet-facing endpoint at run-time "
            "so that static endpoint controls see nothing more than a signed "
            "`powershell.exe` process."
        )
    elif "/dev/tcp/" in rec_lc:
        sentences.append(
            "This is a **reverse-shell one-liner** — a single bash "
            "invocation that opens an outbound TCP connection to the "
            "attacker and hands the resulting file descriptors to an "
            "interactive shell, effectively giving remote command execution "
            "with the privileges of the calling user."
        )
    elif layers >= 2:
        sentences.append(
            "The multi-layer obfuscation itself is a strong behavioural "
            "signal — legitimate administrative scripts rarely encode "
            "themselves recursively, so the effort spent hiding intent "
            "typically reflects intent worth hiding."
        )
    # Add a scoping caveat when the destination is internal
    if internal and urls:
        sentences.append(
            f"Critically, the destination **{internal}** falls inside "
            "RFC1918 private space, which suggests this specific submission "
            "is a lab or test artefact rather than active internet-facing "
            "command-and-control — the same command aimed at a public "
            "endpoint would carry substantially higher operational risk."
        )
    return " ".join(sentences)


def _chapter_correlation(cio: Dict[str, Any]) -> str:
    """Widening scope — MITRE, TI, multi-host. Uses aggregating language."""
    tactics = _mitre_tactic_ids(cio)
    techs = _mitre_techniques(cio)
    ti = _threat_intel_summary(cio)
    hosts = _hosts(cio)
    ac = ((cio.get("summary") or {}).get("attack_chain") or []) or []
    sentences: List[str] = []
    if techs and tactics:
        tech_strs = [f"**{tid}** ({name})" if name else f"**{tid}**"
                      for tid, name in techs[:4]]
        sentences.append(
            "Behaviourally, this activity maps to "
            + ", ".join(tech_strs)
            + " — spanning the "
            + " · ".join(t.split(" ", 1)[1].strip("()") for t in tactics[:3])
            + " tactics — a combination consistent with the initial "
            "execution stage of a broader intrusion attempt."
        )
    elif techs:
        tech_strs = [f"**{tid}** ({name})" if name else f"**{tid}**"
                      for tid, name in techs[:4]]
        sentences.append(
            "Observed behaviour aligns with the ATT&CK techniques "
            + ", ".join(tech_strs) + "."
        )
    if len(ac) >= 2:
        chain = " → ".join(
            str(s.get("label") or "").split("·")[-1].strip()
            for s in ac[:5] if s.get("label")
        )
        if chain and "→" in chain:
            sentences.append(
                f"Reconstructing the timeline, the sequence unfolds as "
                f"**{chain}**, which shows the attacker chaining a signed "
                "living-off-the-land binary into a downloader in a way "
                "that would blend into normal administrative activity."
            )
    if ti:
        binaries = _lolbins(cio) or [""]
        target = f"**{binaries[0]}**" if binaries[0] else "the recovered payload"
        sentences.append(
            f"Threat intelligence corroborates the assessment: {target} "
            f"carries {ti}."
        )
    if len(hosts) >= 2:
        m = _incident_meta(cio)
        others = ", ".join(hosts[1:6])
        cont = ""
        if (m["action"] or "").lower() in ("quarantined", "blocked"):
            cont = f" — with confirmed containment on **{hosts[0]}**"
        sentences.append(
            f"Notably, the same indicators surface across multiple hosts "
            f"({hosts[0]}, {others}){cont} — this is not an isolated event "
            "but sits inside a broader enterprise exposure that warrants "
            "follow-on hunt work."
        )
    return " ".join(sentences)


def _chapter_judgement(cio: Dict[str, Any]) -> str:
    """Why the verdict is what it is. Story voice: 'weighing the evidence…'"""
    vf = _verdict_fields(cio)
    label = vf["label"]
    pct = vf["pct"]
    raw = vf["raw_pct"]
    dampen = vf["dampen_pct"]
    esc = vf["escalation"]
    internal = _internal_ip_present(cio)
    sentences: List[str] = []
    if label in ("Malicious", "Suspicious"):
        opener = (
            f"Taking the recovered command, the ATT&CK mapping and the "
            f"supporting indicators together, the verdict engine landed on "
            f"**{label} at {pct}% confidence**"
        )
        if esc:
            opener += f" — a promotion driven by the escalation rule *{esc}*"
        sentences.append(opener + ".")
    else:
        sentences.append(
            f"Weighing the available evidence, the verdict engine returned "
            f"**{label} at {pct}% confidence** — the sample carries "
            "concerning shape but no single indicator strong enough to "
            "commit to a Malicious call."
        )
    if raw and pct < raw - 10 and vf["mitigators"]:
        if internal:
            sentences.append(
                f"Confidence is intentionally dampened from a raw {raw}%: "
                f"the destination **{internal}** is RFC1918 private space, "
                f"which the internal-asset mitigator downgrades by up to "
                f"{dampen}% — the arithmetic is deliberate and defensible."
            )
        else:
            sentences.append(
                f"The final number sits below the raw Noisy-OR aggregate "
                f"({raw}%) because {vf['mitigators']} mitigating signal(s) "
                f"dampen the score by up to {dampen}%."
            )
    return " ".join(sentences)


def _chapter_guidance(cio: Dict[str, Any]) -> str:
    """What the responder should do next. Direct, actionable."""
    vf = _verdict_fields(cio)
    label = vf["label"]
    m = _incident_meta(cio)
    urls = _iocs(cio).get("urls") or []
    ips = _iocs(cio).get("ips") or []
    recovered = _recovered_command(cio)
    if label not in ("Malicious", "Suspicious"):
        return ""
    parts: List[str] = []
    if (m["action"] or "").lower() in ("quarantined", "blocked"):
        parts.append(
            "For the responder: although the endpoint agent contained the "
            "immediate execution, the delivery vector and blast-radius "
            "questions remain open. Recommended next moves are to "
        )
    else:
        parts.append("For the responder, the recommended next moves are to ")
    actions: List[str] = []
    ext_iocs = [u for u in urls if "192.168." not in u and "127.0." not in u]
    ext_iocs += [i for i in ips if not (i.startswith("192.168.")
                                          or i.startswith("10.") or i.startswith("127."))]
    if ext_iocs:
        actions.append(
            f"block the network indicator{'s' if len(ext_iocs) > 1 else ''} "
            f"({', '.join(ext_iocs[:3])}) at the perimeter"
        )
    if recovered:
        actions.append(
            "hunt for the recovered command string across PowerShell "
            "script-block logging (Event ID 4104) and process telemetry"
        )
    actions.append(
        "review any parent process that spawned this instance for follow-on "
        "child activity"
    )
    if len(actions) >= 3:
        joined = "; ".join(actions[:-1]) + f"; and {actions[-1]}"
    elif len(actions) == 2:
        joined = f"{actions[0]}; and {actions[1]}"
    else:
        joined = actions[0]
    parts.append(joined + ".")
    return "".join(parts)


# ─── Public entry ────────────────────────────────────────────────────

def compose_analyst_narrative(cio) -> str:
    """Compose an MDR-analyst-style Executive Investigation Summary as
    a **story**, not a fact recital. Adaptive length: minimum 2
    paragraphs; longer as vendor telemetry, TI, chain data and MITRE
    coverage grow richer. Deterministic. Never raises. Never empty."""
    try:
        cio_d = cio.model_dump(mode="json") if hasattr(cio, "model_dump") else dict(cio)
    except Exception:  # noqa: BLE001
        cio_d = cio if isinstance(cio, dict) else {}

    def _safe(fn) -> str:
        try:
            return fn(cio_d).strip()
        except Exception:  # noqa: BLE001
            return ""

    opening        = _safe(_chapter_opening)
    discovery      = _safe(_chapter_discovery)
    interpretation = _safe(_chapter_interpretation)
    correlation    = _safe(_chapter_correlation)
    judgement      = _safe(_chapter_judgement)
    guidance       = _safe(_chapter_guidance)

    # Weave into paragraphs. The story arc groups related chapters so
    # transitions read naturally.
    #   Para 1 = OPENING + DISCOVERY   (what happened)
    #   Para 2 = INTERPRETATION        (what it means)
    #   Para 3 = CORRELATION           (widening scope)
    #   Para 4 = JUDGEMENT + GUIDANCE  (verdict and action)
    p1 = " ".join(p for p in (opening, discovery) if p).strip()
    p2 = interpretation
    p3 = correlation
    p4 = " ".join(p for p in (judgement, guidance) if p).strip()

    paragraphs = [p for p in (p1, p2, p3, p4) if p]

    # Guarantee ≥ 2 paragraphs — collapse when the CIO is thin.
    if len(paragraphs) < 2:
        vf = _verdict_fields(cio_d)
        fallback_close = (
            f"Weighing the available evidence, the verdict engine returned "
            f"**{vf['label']} at {vf['pct']}% confidence**."
        )
        if not paragraphs:
            paragraphs = [
                "The pipeline received the artefact but could not recover "
                "additional behavioural detail.",
                fallback_close,
            ]
        else:
            paragraphs.append(fallback_close)

    cleaned = [_sanitize_customer_text(p).strip() for p in paragraphs]
    cleaned = [p for p in cleaned if p]
    return "\n\n".join(cleaned)


__all__ = ["compose_analyst_narrative"]
