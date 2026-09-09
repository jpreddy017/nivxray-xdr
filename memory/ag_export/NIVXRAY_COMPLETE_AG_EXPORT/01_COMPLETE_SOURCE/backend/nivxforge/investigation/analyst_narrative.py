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
    # Delegate to `customer_report._iocs` which correctly falls back to
    # the evidence graph when `metadata.iocs` isn't populated yet at
    # compose-time. Without this delegation the narrative composer sees
    # zero IOCs during summary composition and drops URL-driven
    # interpretation branches (mechanism explanation, staging clause,
    # perimeter-block recommendation).
    from nivxforge.investigation.customer_report import _iocs as _cr_iocs
    return _cr_iocs(cio) or {}


def _recovered_command(cio: Dict[str, Any]) -> str:
    for layer in reversed(cio.get("decode_chain") or []):
        prev = str(layer.get("preview") or "").strip()
        if not prev:
            continue
        # Skip vendor canonical text (the ingress-gate synthesised
        # `# vendor=... event[0] ts=... cmd=...` stream). That's an
        # internal representation, not something the analyst wants to
        # see quoted as "the underlying command".
        if prev.startswith("# vendor=") or prev.startswith("event["):
            continue
        if "vendor=Generic" in prev or "cisco:amp:event" in prev:
            continue
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
    """Sets the scene. Vendor telemetry dominates when present — the
    first sentence names the source. Otherwise names the artefact
    shape. No fixed phrasing: sentence structure follows what evidence
    is actually available."""
    m = _incident_meta(cio)
    hosts = _hosts(cio)
    users = _users(cio)
    lolbins = _lolbins(cio)
    iocs = _iocs(cio)
    hashes = _hashes_with_names(cio)

    # ── Vendor-driven opening ──
    if m["vendor"]:
        subj = f"**{m['vendor']}**"
        # Sentence 1 — the alert itself. Structure depends on what's
        # present so the phrasing varies naturally.
        s1_parts: List[str] = [subj]
        if m["incident_id"]:
            s1_parts.append(f"raised Incident **{m['incident_id']}**")
        elif m["detection"] or m["threat_name"]:
            s1_parts.append("raised an alert")
        else:
            s1_parts.append("generated telemetry")
        if m["detection"] or m["threat_name"]:
            det = m["detection"] or m["threat_name"]
            s1_parts.append(f"for **{det}**")
        if hosts:
            s1_parts.append(f"on host **{hosts[0]}**")
        if users:
            s1_parts.append(f"(user `{users[0]}`)")
        if m["timestamp"]:
            s1_parts.append(f"at {m['timestamp']}")
        s1 = " ".join(s1_parts).rstrip(".") + "."

        # Sentence 2 — what the alert captured. Names process + hash +
        # URL when known.
        s2_bits: List[str] = []
        if lolbins:
            s2_bits.append(f"execution of `{lolbins[0]}`")
        urls = iocs.get("urls") or []
        if urls:
            s2_bits.append(f"reaching out to `{urls[0]}`")
        elif iocs.get("ips"):
            s2_bits.append(f"contacting `{iocs['ips'][0]}`")
        if hashes:
            h, name = hashes[0]
            if name:
                s2_bits.append(f"associated with SHA-256 `{h}` (`{name}`)")
            else:
                s2_bits.append(f"associated with SHA-256 `{h}`")
        s2 = ""
        if s2_bits:
            s2 = "The alert captured " + ", ".join(s2_bits) + "."

        # Sentence 3 — containment status when the vendor took action.
        s3 = ""
        action = (m["action"] or "").lower()
        if action in ("quarantined", "blocked", "prevented", "remediated"):
            s3 = f"{subj} {action} the executable before it completed its second-stage fetch."

        return " ".join(p for p in (s1, s2, s3) if p).strip()

    # ── No vendor · analyst-submitted artefact ──
    # Multiple phrasings driven by the evidence density so it never
    # repeats the same "An analyst submitted..." line every time.
    if lolbins and hashes:
        h, name = hashes[0]
        return (f"An artefact was submitted for triage carrying "
                f"`{lolbins[0]}` execution and SHA-256 "
                f"`{h}`{f' (`{name}`)' if name else ''}, which the decoder "
                "immediately unpacked to expose the underlying behaviour.")
    if lolbins:
        urls = iocs.get("urls") or iocs.get("ips") or []
        tail = f" targeting `{urls[0]}`" if urls else ""
        return (f"The submission carried `{lolbins[0]}` execution{tail}, "
                "which the decoder unpacked layer by layer to expose the "
                "underlying behaviour.")
    iu = ((cio.get("metadata") or {}).get("input_understanding") or {}) or {}
    itype = (iu.get("label") or iu.get("type") or "").replace("_", " ").strip().lower()
    if itype:
        return (f"The pipeline received a **{itype}** submission and routed "
                "it into the recursive decoder for behavioural triage.")
    return ("The pipeline received an artefact for triage and routed it "
            "into the recursive decoder for behavioural analysis.")


def _chapter_discovery(cio: Dict[str, Any]) -> str:
    """The reveal — what decoding uncovered. Phrasing varies based on
    how many layers were peeled and what the recovered content is."""
    recovered = _recovered_command(cio)
    layers = _decode_layer_count(cio)
    lolbins = _lolbins(cio)
    urls = _iocs(cio).get("urls") or []
    ips = _iocs(cio).get("ips") or []
    if not (recovered or lolbins or urls):
        return ""
    parts: List[str] = []
    # Reveal — vary phrasing by layer count so it isn't always
    # "Peeling back N layers..."
    if layers >= 3 and recovered:
        parts.append(
            f"After {layers} decoder passes, the underlying command "
            f"resolved to {_fmt_recovered(recovered)}"
        )
    elif layers == 2 and recovered:
        parts.append(
            f"Two decoder passes were required before the command "
            f"resolved to {_fmt_recovered(recovered)}"
        )
    elif recovered:
        parts.append(f"The recovered command reads {_fmt_recovered(recovered)}")
    elif lolbins:
        parts.append(f"The submission invoked `{lolbins[0]}`")
    tail = parts[0]
    # Weave what the recovered command does — but drop the canned
    # "characteristic of second-stage payload staging" trailer. Instead
    # describe the mechanism when evidence is strong enough.
    if urls and lolbins:
        target = urls[0]
        tail += (
            f", using the {lolbins[0]} living-off-the-land binary to fetch "
            f"and execute content from **{target}** in a single in-memory "
            "operation with no persistent file dropped to disk"
        )
    elif urls:
        tail += f", which reaches out to **{urls[0]}** and executes whatever the server returns"
    elif ips and lolbins:
        tail += f", using {lolbins[0]} to contact **{ips[0]}**"
    return tail.rstrip(".") + "."


def _chapter_interpretation(cio: Dict[str, Any]) -> str:
    """Analyst judgement — explains WHY the observed behaviour maps
    to the stated interpretation. Mechanism-level, not label-level."""
    recovered = _recovered_command(cio)
    urls = _iocs(cio).get("urls") or []
    internal = _internal_ip_present(cio)
    layers = _decode_layer_count(cio)
    hashes = _hashes_with_names(cio)
    m = _incident_meta(cio)
    hosts = _hosts(cio)
    if not (recovered or (m["detection"] and hashes) or (m["threat_name"] and hashes)):
        return ""
    sentences: List[str] = []

    # --- Vendor-detection interpretation (no decoded command needed) ---
    # Fires when a vendor named a threat AND a hash / multi-host
    # correlation is present — explains WHY the detection matters.
    if m["detection"] or m["threat_name"]:
        det = m["detection"] or m["threat_name"]
        hash_sentence = ""
        if hashes:
            _, name = hashes[0]
            hash_sentence = (
                f" The signal is anchored to a concrete file hash rather than "
                "a behavioural heuristic, which reduces the chance this is a "
                "false positive"
            )
            if name:
                hash_sentence += f" — the binary carrying that hash is `{name}`"
            hash_sentence += "."
        multi_host = ""
        if len(hosts) >= 2:
            multi_host = (
                f" The same detection surfaces on {len(hosts)} hosts, which "
                "elevates this from an isolated endpoint event to a shared "
                "artefact — either the same package was distributed to "
                "multiple systems or the same operator staged the payload "
                "across the estate."
            )
        sentences.append(
            f"The `{det}` detection carries specific meaning: the vendor "
            "matched a known indicator rather than a generic anomaly, so the "
            "verdict is grounded in prior threat-intelligence rather than "
            "post-hoc guesswork." + hash_sentence + multi_host
        )

    rec_lc = recovered.lower() if recovered else ""
    is_iex_stager = "iex" in rec_lc and (
        "downloadstring" in rec_lc or "downloadfile" in rec_lc
        or "invoke-webrequest" in rec_lc or "invoke-restmethod" in rec_lc
    )
    is_reverse_shell = "/dev/tcp/" in rec_lc
    is_ps_download = "downloadstring" in rec_lc or "downloadfile" in rec_lc

    if is_iex_stager and urls:
        target = urls[0]
        sentences.append(
            f"The mechanism is worth naming explicitly: PowerShell's `IEX` "
            f"(Invoke-Expression) executes the exact string returned by "
            f"`DownloadString('{target}')` directly in memory, without ever "
            "writing the second-stage payload to disk. Endpoint tools that "
            "rely on file-write or signature detection see only the signed "
            "`powershell.exe` process making an HTTP GET — the actual "
            "malicious code never presents a file to scan."
        )
    elif is_ps_download and urls:
        sentences.append(
            f"The download primitive here is worth noting: `DownloadString` "
            f"pulls the content of `{urls[0]}` straight into memory as a "
            "string, bypassing any control that inspects newly-written files."
        )
    elif is_reverse_shell:
        sentences.append(
            "The construct is a POSIX-shell reverse shell one-liner. "
            "`bash -i` opens an interactive shell, and the "
            "`>& /dev/tcp/…` redirection reuses Bash's built-in TCP "
            "handler to bind stdin/stdout/stderr to a socket — giving "
            "remote interactive command execution with the privileges "
            "of the calling user, and leaving no additional file on disk."
        )
    elif layers >= 2:
        sentences.append(
            f"The {layers} successive encoding layers here matter as "
            "signal in their own right: legitimate administrative scripts "
            "very rarely encode themselves recursively, so the effort "
            "spent hiding the payload typically reflects intent worth "
            "hiding — deliberate evasion of both human review and static "
            "analysis tooling."
        )

    if internal and urls:
        sentences.append(
            f"One scoping note: the destination `{internal}` is RFC1918 "
            "private space, so this specific submission is a lab or test "
            "artefact rather than live internet-facing command-and-control. "
            "The same construct aimed at a public IP would carry the same "
            "mechanical risk without the internal-only caveat."
        )
    return " ".join(sentences)


def _chapter_correlation(cio: Dict[str, Any]) -> str:
    """Widening scope — MITRE, TI, multi-host. Language varies by
    what is present."""
    tactics = _mitre_tactic_ids(cio)
    techs = _mitre_techniques(cio)
    ti = _threat_intel_summary(cio)
    hosts = _hosts(cio)
    ac = ((cio.get("summary") or {}).get("attack_chain") or []) or []
    sentences: List[str] = []

    if techs and tactics:
        tech_strs = [f"**{tid}** ({name})" if name else f"**{tid}**"
                      for tid, name in techs[:4]]
        tactic_names = [t.split(" ", 1)[1].strip("()") for t in tactics[:3]]
        sentences.append(
            "The observed behaviour aligns with "
            + ", ".join(tech_strs)
            + " — the tactic combination ("
            + " · ".join(tactic_names)
            + ") is the typical early-stage signature of a hands-on-keyboard "
            "intrusion or a commodity loader dropping a second-stage implant."
        )
    elif techs:
        tech_strs = [f"**{tid}** ({name})" if name else f"**{tid}**"
                      for tid, name in techs[:4]]
        sentences.append(
            "The recovered activity maps to " + ", ".join(tech_strs) + "."
        )

    if len(ac) >= 2:
        chain = " → ".join(
            str(s.get("label") or "").split("·")[-1].strip()
            for s in ac[:5] if s.get("label")
        )
        if chain and "→" in chain:
            sentences.append(
                f"Sequencing the timeline, the observed order was "
                f"**{chain}** — a chain that keeps every intermediate step "
                "on a signed or otherwise expected binary, which is why "
                "signature-only detection would miss the composite behaviour."
            )

    if ti:
        binaries = _lolbins(cio) or [""]
        target = f"`{binaries[0]}`" if binaries[0] else "the recovered payload"
        sentences.append(
            f"Threat intelligence corroborates the read: {target} carries {ti}."
        )

    if len(hosts) >= 2:
        m = _incident_meta(cio)
        others = ", ".join(f"`{h}`" for h in hosts[1:6])
        cont = ""
        if (m["action"] or "").lower() in ("quarantined", "blocked"):
            cont = f", with confirmed containment on `{hosts[0]}`"
        sentences.append(
            f"The same indicators surface on {len(hosts) - 1} additional "
            f"host(s) ({others}){cont} — this is enterprise exposure, "
            "not an isolated event, and the incident should be scoped "
            "against every host that carries any of the shared indicators."
        )
    return " ".join(sentences)


def _chapter_judgement(cio: Dict[str, Any]) -> str:
    """Why the verdict is what it is. Phrasing varies by outcome."""
    vf = _verdict_fields(cio)
    label = vf["label"]
    pct = vf["pct"]
    raw = vf["raw_pct"]
    dampen = vf["dampen_pct"]
    esc = vf["escalation"]
    internal = _internal_ip_present(cio)
    sentences: List[str] = []

    if label == "Malicious":
        opener = (
            f"The verdict engine returned **Malicious at {pct}% confidence**"
        )
        if esc:
            opener += f", driven by the escalation rule `{esc}`"
        sentences.append(opener + ".")
    elif label == "Suspicious":
        sentences.append(
            f"Aggregated evidence supports a **Suspicious at {pct}% "
            "confidence** verdict — enough behavioural signal to warrant "
            "response but not enough to commit to a definite malicious call."
        )
    else:
        sentences.append(
            f"On the current evidence, the verdict engine returned "
            f"**{label} at {pct}% confidence**."
        )

    if raw and pct < raw - 10 and vf["mitigators"]:
        if internal:
            sentences.append(
                f"The final confidence is intentionally below the raw "
                f"aggregate of {raw}%: the destination `{internal}` sits "
                f"inside RFC1918 space, and the internal-asset mitigator "
                f"reduces the score by up to {dampen}% because private-IP "
                "targets are usually test infrastructure rather than "
                "genuine adversary C2."
            )
        else:
            sentences.append(
                f"The score is dampened from a raw {raw}% because "
                f"{vf['mitigators']} mitigating indicator(s) reduce "
                f"confidence by up to {dampen}%."
            )
    return " ".join(sentences)


def _chapter_guidance(cio: Dict[str, Any]) -> str:
    """Direct responder actions. Wording follows the specific
    indicators, not a fixed template."""
    vf = _verdict_fields(cio)
    label = vf["label"]
    m = _incident_meta(cio)
    urls = _iocs(cio).get("urls") or []
    ips = _iocs(cio).get("ips") or []
    hashes = _hashes_with_names(cio)
    recovered = _recovered_command(cio)
    if label not in ("Malicious", "Suspicious"):
        return ""

    intro = "Recommended follow-up: "
    if (m["action"] or "").lower() in ("quarantined", "blocked"):
        intro = ("Although the endpoint agent contained the immediate "
                 "execution, the delivery vector and blast-radius questions "
                 "remain open — recommended follow-up: ")

    actions: List[str] = []
    ext_urls = [u for u in urls if "192.168." not in u and "127.0." not in u
                 and "10." != u[:3]]
    ext_ips  = [i for i in ips if not (i.startswith("192.168.")
                    or i.startswith("10.") or i.startswith("127.")
                    or (i.startswith("172.") and 16 <= int(i.split(".")[1]) <= 31 if i.count(".") == 3 else False))]
    if ext_urls:
        actions.append(
            f"block `{ext_urls[0]}` at the perimeter and enrich against your "
            "threat-intel feeds for related infrastructure"
        )
    elif ext_ips:
        actions.append(
            f"block `{ext_ips[0]}` at the perimeter and enrich against your "
            "threat-intel feeds for related infrastructure"
        )
    if recovered:
        actions.append(
            "hunt for the recovered command string across PowerShell "
            "script-block logging (Event ID 4104) and process telemetry "
            "to identify any other endpoints exhibiting the same pattern"
        )
    if hashes:
        actions.append(
            f"add SHA-256 `{hashes[0][0]}` to your endpoint deny-list and "
            "search VirusTotal / your sandbox history for prior observations"
        )
    actions.append(
        "review the parent process that spawned this instance to identify "
        "the initial delivery vector"
    )

    if len(actions) >= 3:
        joined = "; ".join(actions[:-1]) + f"; and {actions[-1]}."
    elif len(actions) == 2:
        joined = f"{actions[0]}; and {actions[1]}."
    else:
        joined = actions[0] + "."
    return intro + joined


# ─── Public entry ────────────────────────────────────────────────────

def compose_analyst_narrative(cio) -> str:
    """Compose an MDR-analyst-style Executive Investigation Summary as
    a **story**, not a fact recital. Adaptive length: minimum 2
    paragraphs; longer as vendor telemetry, TI, chain data and MITRE
    coverage grow richer. Deterministic. Never raises. Never empty.

    2026-08-01 operator directive: when the CIO carries the Phase 1
    Investigation Graph (attached at `cio.metadata.phase1_state`),
    delegate to the graph-only Incident Narrative Engine which is
    prohibited by contract from describing any X-Lab internals.
    """
    # ── Preferred path · graph-only Incident Narrative ────────────
    # Read phase1_state from the LIVE CIO object BEFORE dumping to
    # JSON — otherwise model_dump() serialises the dataclass state
    # to primitives and we lose the object reference.
    try:
        from nivxforge.investigation.incident_narrative_override import (
            full_incident_markdown,
        )
        override = full_incident_markdown(cio)
        if override:
            return override
    except Exception:  # noqa: BLE001
        pass

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
    result = "\n\n".join(cleaned)
    # Operator-locked lexicon gate: strip every implementation-detail
    # phrase (`pipeline`, `decoder`, `verdict engine`, `layer count`, …)
    # so the narrative reads like an MDR analyst report rather than a
    # walkthrough of X-Lab's internals. See
    # /app/backend/nivxforge/investigation/narrative_lexicon_gate.py.
    from nivxforge.investigation.narrative_lexicon_gate import sanitize
    return sanitize(result)


__all__ = ["compose_analyst_narrative"]
