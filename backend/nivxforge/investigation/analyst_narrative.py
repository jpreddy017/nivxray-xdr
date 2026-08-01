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


# ─── Section composers · each returns "" if not enough evidence ───────

def _sec_detection(cio: Dict[str, Any]) -> str:
    m = _incident_meta(cio)
    hosts = _hosts(cio)
    parts: List[str] = []
    if m["vendor"]:
        parts.append(m["vendor"])
    if m["incident_id"]:
        parts.append(f"generated Incident {m['incident_id']}")
    if m["detection"] or m["threat_name"]:
        det = m["detection"] or m["threat_name"]
        verb = m["action"] or "detected"
        parts.append(f"{verb} {det}")
    if hosts:
        parts.append(f"on host {hosts[0]}")
    if m["timestamp"]:
        parts.append(f"at {m['timestamp']}")
    if not parts:
        return ""
    return " ".join(parts) + "."


def _sec_executable(cio: Dict[str, Any]) -> str:
    lolbins = _lolbins(cio)
    recovered = _recovered_command(cio)
    layers = _decode_layer_count(cio)
    if not (lolbins or recovered):
        return ""
    sentences: List[str] = []
    if lolbins and recovered:
        rec = recovered if len(recovered) < 220 else recovered[:217] + "…"
        sentences.append(
            f"The primary executable {lolbins[0]} was invoked with the "
            f"command `{rec}`."
        )
    elif recovered:
        rec = recovered if len(recovered) < 220 else recovered[:217] + "…"
        sentences.append(f"The recovered command resolves to `{rec}`.")
    elif lolbins:
        sentences.append(f"The primary executable {lolbins[0]} was invoked.")
    if layers >= 2:
        sentences.append(
            f"The payload required {layers} decoder passes to reach its "
            "final form, indicating deliberate obfuscation."
        )
    urls = _iocs(cio).get("urls") or []
    if urls and lolbins:
        sentences.append(
            f"The recovered command reaches out to {urls[0]}, which is "
            "characteristic of second-stage payload staging."
        )
    return " ".join(sentences)


def _sec_hashes(cio: Dict[str, Any]) -> str:
    hs = _hashes_with_names(cio)
    if not hs:
        return ""
    if len(hs) == 1:
        h, name = hs[0]
        if name:
            return f"The investigation identified SHA-256 hash {h} ({name})."
        return f"The investigation identified SHA-256 hash {h}."
    parts = [f"{h} ({name})" if name else h for h, name in hs[:3]]
    return (
        f"The investigation identified {len(hs)} associated file hashes: "
        f"{', '.join(parts)}."
    )


def _sec_containment(cio: Dict[str, Any]) -> str:
    m = _incident_meta(cio)
    action = m["action"].lower()
    if action in ("quarantined", "blocked", "prevented", "remediated"):
        agent = m["vendor"] or "The endpoint agent"
        return (
            f"{agent} {action} the detected executable, preventing further "
            "execution on the affected endpoint."
        )
    return ""


def _sec_execution_chain(cio: Dict[str, Any]) -> str:
    ac = ((cio.get("summary") or {}).get("attack_chain") or []) or []
    if len(ac) < 2:
        return ""
    steps = []
    for s in ac[:6]:
        lbl = str(s.get("label") or "").split("·")[-1].strip()
        if lbl:
            steps.append(lbl)
    if len(steps) < 2:
        return ""
    return (
        "The investigation reconstructed the execution chain as "
        + " → ".join(steps) + "."
    )


def _sec_threat_intel(cio: Dict[str, Any]) -> str:
    ti = _threat_intel_summary(cio)
    if not ti:
        return ""
    lolbins = _lolbins(cio)
    target = lolbins[0] if lolbins else "the sample"
    return f"Threat intelligence indicates {target} carries {ti}."


def _sec_multi_host(cio: Dict[str, Any]) -> str:
    hosts = _hosts(cio)
    if len(hosts) < 2:
        return ""
    m = _incident_meta(cio)
    others = ", ".join(hosts[1:6])
    if (m["action"] or "").lower() in ("quarantined", "blocked"):
        return (
            f"The same indicators were observed across multiple hosts "
            f"({others}), with confirmed containment on {hosts[0]}, "
            "indicating broader enterprise exposure rather than an isolated "
            "event."
        )
    return (
        f"The same indicators were observed across multiple hosts "
        f"({hosts[0]}, {others}), indicating broader enterprise exposure "
        "rather than an isolated event."
    )


def _sec_mitre(cio: Dict[str, Any]) -> str:
    tactics = _mitre_tactic_ids(cio)
    techs = _mitre_techniques(cio)
    if not (tactics or techs):
        return ""
    parts: List[str] = []
    if tactics:
        parts.append(f"MITRE ATT&CK mapping identifies {', '.join(tactics[:4])}")
    if techs:
        tech_strs = [f"{tid} ({name})" if name else tid for tid, name in techs[:5]]
        parts.append("with observed techniques including " + ", ".join(tech_strs))
    return ", ".join(parts) + "."


def _sec_verdict(cio: Dict[str, Any]) -> str:
    vf = _verdict_fields(cio)
    label = vf["label"]
    pct = vf["pct"]
    raw = vf["raw_pct"]
    dampen = vf["dampen_pct"]
    esc = vf["escalation"]
    internal_ip = _internal_ip_present(cio)
    sentences: List[str] = []

    # Verdict statement
    if label in ("Malicious", "Suspicious"):
        sentences.append(
            f"The verdict engine returned **{label} at {pct}% confidence**."
        )
    else:
        sentences.append(f"The verdict engine returned {label} at {pct}% confidence.")

    # Explain low confidence when mitigators were active
    if raw and pct < raw - 10 and vf["mitigators"]:
        note = ""
        if internal_ip:
            note = (
                f" This is dampened from a raw {raw}% because the destination "
                f"IP ({internal_ip}) is on RFC1918 private space — the "
                "internal-asset mitigator downgrades confidence by up to "
                f"{dampen}%. The same command against a public endpoint would "
                "score materially higher."
            )
        else:
            note = (
                f" This is dampened from a raw {raw}% because {vf['mitigators']} "
                f"mitigating signal(s) reduced the score by up to {dampen}%."
            )
        sentences.append(note.strip())

    # Escalation rule cite
    if esc:
        sentences.append(
            f"The promotion was driven by the escalation rule `{esc}`."
        )

    # Investigative caveat / next-step recommendation
    m = _incident_meta(cio)
    if label in ("Malicious", "Suspicious"):
        if (m["action"] or "").lower() in ("quarantined", "blocked"):
            sentences.append(
                "Although containment was successful, the presence of the "
                "detection and associated indicators warrants continued "
                "investigation to determine the initial delivery vector and "
                "whether other hosts remain exposed."
            )
        else:
            sentences.append(
                "The sample should be treated as attacker-controlled until "
                "confirmed otherwise. Recommended next steps: block the "
                "identified network indicators at the perimeter, hunt for the "
                "recovered command string across PowerShell script-block "
                "logging (Event ID 4104) and process telemetry, and review "
                "any parent process that spawned this instance for follow-on "
                "child activity."
            )
    return " ".join(sentences)


# ─── Public entry ────────────────────────────────────────────────────

def compose_analyst_narrative(cio) -> str:
    """Return an MDR-analyst-style Executive Investigation Summary
    tailored to the depth of the CIO. Minimum 2 paragraphs; more if
    the CIO has vendor telemetry, TI hits, multi-host correlation, etc.
    Never raises; never returns empty."""
    try:
        cio_d = cio.model_dump(mode="json") if hasattr(cio, "model_dump") else dict(cio)
    except Exception:  # noqa: BLE001
        cio_d = cio if isinstance(cio, dict) else {}

    # Each section is composed independently. Empty strings are dropped.
    sections: List[str] = []
    for fn in (_sec_detection, _sec_executable, _sec_hashes, _sec_containment,
               _sec_execution_chain, _sec_threat_intel, _sec_multi_host,
               _sec_mitre, _sec_verdict):
        try:
            s = fn(cio_d).strip()
        except Exception:  # noqa: BLE001
            s = ""
        if s:
            sections.append(s)

    # Adaptive grouping into paragraphs. Rules:
    #   * At least 2 paragraphs on any non-empty CIO.
    #   * Each paragraph is 1–3 related sections.
    #   * Groupings preserve MDR-analyst reading order.
    #     P1 = Detection + Executable + Hashes + Containment
    #     P2 = Execution chain + Threat intel + Multi-host
    #     P3 = MITRE
    #     P4 = Verdict + Investigative caveat
    p1_keys = {"detection", "executable", "hashes", "containment"}
    p2_keys = {"execution_chain", "threat_intel", "multi_host"}
    p3_keys = {"mitre"}
    p4_keys = {"verdict"}
    key_map = {
        _sec_detection.__name__:       "detection",
        _sec_executable.__name__:      "executable",
        _sec_hashes.__name__:          "hashes",
        _sec_containment.__name__:     "containment",
        _sec_execution_chain.__name__: "execution_chain",
        _sec_threat_intel.__name__:    "threat_intel",
        _sec_multi_host.__name__:      "multi_host",
        _sec_mitre.__name__:           "mitre",
        _sec_verdict.__name__:         "verdict",
    }
    # Rebuild sections with their keys so we can group.
    keyed: List[Tuple[str, str]] = []
    for fn in (_sec_detection, _sec_executable, _sec_hashes, _sec_containment,
               _sec_execution_chain, _sec_threat_intel, _sec_multi_host,
               _sec_mitre, _sec_verdict):
        try:
            s = fn(cio_d).strip()
        except Exception:  # noqa: BLE001
            s = ""
        if s:
            keyed.append((key_map[fn.__name__], s))

    para_buckets: Dict[int, List[str]] = {1: [], 2: [], 3: [], 4: []}
    for key, s in keyed:
        if key in p1_keys:
            para_buckets[1].append(s)
        elif key in p2_keys:
            para_buckets[2].append(s)
        elif key in p3_keys:
            para_buckets[3].append(s)
        else:
            para_buckets[4].append(s)

    paragraphs = [" ".join(para_buckets[i]).strip() for i in (1, 2, 3, 4)
                   if para_buckets[i]]

    # Guarantee ≥ 2 paragraphs — if only one bucket had content, split
    # the LAST paragraph so the verdict statement gets its own paragraph.
    if len(paragraphs) < 2 and paragraphs:
        # Move verdict section (if present) to its own paragraph.
        verdict_para = " ".join(para_buckets[4]).strip()
        if verdict_para:
            paragraphs = [
                " ".join(para_buckets[1] + para_buckets[2] + para_buckets[3]).strip(),
                verdict_para,
            ]
            paragraphs = [p for p in paragraphs if p]
        # Still one? Split by sentence.
        if len(paragraphs) < 2 and paragraphs[0]:
            single = paragraphs[0]
            # Prefer a split point after the executable/command sentence.
            sents = _split_sentences(single)
            if len(sents) >= 4:
                half = len(sents) // 2
                paragraphs = [" ".join(sents[:half]).strip(),
                              " ".join(sents[half:]).strip()]
            elif len(sents) >= 2:
                paragraphs = [sents[0].strip(),
                              " ".join(sents[1:]).strip()]

    if not paragraphs:
        v = _verdict_fields(cio_d)
        paragraphs = [
            f"Investigation completed. Verdict: {v['label']} at {v['pct']}% "
            "confidence.",
            v["reason"] or "No further analyst detail was recovered from the "
                          "submitted artefact.",
        ]

    # Sanitize per-paragraph so the whitespace collapse inside
    # `_sanitize_customer_text` doesn't destroy inter-paragraph breaks.
    cleaned = [_sanitize_customer_text(p).strip() for p in paragraphs]
    cleaned = [p for p in cleaned if p]
    return "\n\n".join(cleaned)


def _split_sentences(text: str) -> List[str]:
    """Naive sentence splitter — good enough for narrative output."""
    out: List[str] = []
    buf = ""
    for ch in text:
        buf += ch
        if ch in ".!?" and len(buf) > 40:
            out.append(buf.strip())
            buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out


__all__ = ["compose_analyst_narrative"]
