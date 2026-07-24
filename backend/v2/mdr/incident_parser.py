"""NivXRay MDR — Structured Incident Parser.

Parses telemetry text from Cisco Secure Endpoint / Umbrella / XDR,
CrowdStrike Falcon, Microsoft Defender, SentinelOne, etc. into a
list of `IncidentEvent` records. Each event mirrors what a Tier-2
analyst would extract when reading the incident by hand:

  { ts, source, detection_name, threat_name, hostname, user,
    parent_process, process, child_process, command_line,
    sha256, md5, path, mitre[], action, message, raw_offset }

Deterministic — regex only, no LLM. Callers should apply this BEFORE
running the recursive decoder / semantic passes so downstream stages
have real evidence to reason over.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict


@dataclass
class IncidentEvent:
    ts: str = ""                  # ISO-8601 if we can normalise
    ts_raw: str = ""              # original timestamp string
    source: str = ""              # "Cisco Secure Endpoint" / "CrowdStrike" / …
    detection_name: str = ""      # "PowerShell Exploitation Framework Commandlets"
    threat_name: str = ""         # "Hacktool/SharpHound", "Banker Trojan", …
    hostname: str = ""
    user: str = ""
    parent_process: str = ""
    process: str = ""
    child_process: str = ""
    command_line: str = ""
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    path: str = ""
    mitre: list[str] = field(default_factory=list)
    action: str = ""              # "Quarantined" / "Blocked" / "Moved" / "Detected only"
    message: str = ""             # short human-readable summary line
    raw_offset: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


# ── Regex library ────────────────────────────────────────────────
_TS_RE = re.compile(
    r"\b(20\d{2}[-/]\d{1,2}[-/]\d{1,2})[T ](\d{1,2}:\d{2}(?::\d{2})?)(?:\.\d+)?(?:\s*UTC|\s*Z|[+\-]\d{2}:?\d{2})?",
    re.I,
)
_HOST_RE = re.compile(r"\b(?:host(?:name)?|endpoint|computer|device)\s*[:=]\s*([A-Za-z0-9._\-]+)", re.I)
_USER_RE = re.compile(r"\b(?:user|username|account)\s*[:=]\s*([A-Za-z0-9._\-@\\]+)", re.I)
_DETECT_RE = re.compile(r"\b(?:detection|alert|rule|threat)\s*(?:name)?\s*[:=]\s*([^\r\n]{4,180})", re.I)
_THREAT_RE = re.compile(r"\b(?:threat\s+name|threat|malware\s*family|family)\s*[:=]\s*([^\r\n]{3,80})", re.I)
_PARENT_RE = re.compile(r"\b(?:parent(?:\s*process)?|ppid)\s*[:=]\s*([A-Za-z0-9._\-\\/:() ]{2,200})", re.I)
_PROC_RE   = re.compile(r"\b(?:process|image|executable)\s*[:=]\s*([A-Za-z0-9._\-\\/:() ]{2,200})", re.I)
_CHILD_RE  = re.compile(r"\b(?:child(?:\s*process)?)\s*[:=]\s*([A-Za-z0-9._\-\\/:() ]{2,200})", re.I)
_CMD_RE    = re.compile(r"\b(?:command\s*line|cmdline|command)\s*[:=]\s*([^\r\n]{3,4096})", re.I)
_SHA256_RE = re.compile(r"\b(?:sha ?256|hash|filehash)\s*[:=]\s*([a-fA-F0-9]{64})\b", re.I)
_SHA1_RE   = re.compile(r"\b(?:sha ?1)\s*[:=]\s*([a-fA-F0-9]{40})\b", re.I)
_MD5_RE    = re.compile(r"\b(?:md ?5)\s*[:=]\s*([a-fA-F0-9]{32})\b", re.I)
_PATH_RE   = re.compile(r"\b(?:path|file(?:\s*path)?|location)\s*[:=]\s*([A-Za-z]:\\[^\r\n]{3,300}|/[A-Za-z0-9._/\-]{3,300})", re.I)
_ACTION_RE = re.compile(r"\b(quarantined|blocked|moved|deleted|contained|remediated|isolated|detected\s+only|cleaned)\b", re.I)
_MITRE_RE  = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SRC_HINTS = {
    "cisco":         "Cisco Secure Endpoint",
    "amp for endpoints": "Cisco Secure Endpoint",
    "umbrella":      "Cisco Umbrella",
    "xdr":           "Cisco XDR",
    "crowdstrike":   "CrowdStrike Falcon",
    "falcon":        "CrowdStrike Falcon",
    "defender":      "Microsoft Defender",
    "sentinelone":   "SentinelOne",
    "carbon black":  "Carbon Black",
    "sysmon":        "Sysmon",
    "splunk":        "Splunk",
}


def _detect_source(chunk: str) -> str:
    low = chunk.lower()
    for key, canonical in _SRC_HINTS.items():
        if key in low:
            return canonical
    return ""


def _split_events(text: str) -> list[tuple[str, int]]:
    """Split incident text into event-shaped chunks. Two strategies:
    1. Blank-line separators.  2. Timestamp anchors.  If neither yields
    multiple events we return the whole text as one event.
    """
    chunks: list[tuple[str, int]] = []
    # Anchor at timestamps — every timestamp starts a new event chunk.
    ts_positions = [m.start() for m in _TS_RE.finditer(text)]
    if len(ts_positions) >= 2:
        ts_positions.append(len(text))
        for i in range(len(ts_positions) - 1):
            s, e = ts_positions[i], ts_positions[i + 1]
            chunks.append((text[s:e], s))
        return chunks
    # Fallback — blank-line separated blocks.
    offset = 0
    for block in re.split(r"\n\s*\n", text):
        b = block.strip()
        if len(b) >= 20:
            chunks.append((b, offset))
        offset += len(block) + 2
    if not chunks:
        chunks.append((text, 0))
    return chunks


def _first_group(rgx: re.Pattern, text: str) -> str:
    m = rgx.search(text)
    return (m.group(1).strip() if m else "").strip("'\" ")


def parse_events(text: str) -> list[IncidentEvent]:
    """Return zero-or-more `IncidentEvent` records extracted from `text`."""
    events: list[IncidentEvent] = []
    for chunk, off in _split_events(text):
        ts_m = _TS_RE.search(chunk)
        ts_raw = f"{ts_m.group(1)} {ts_m.group(2)}" if ts_m else ""
        ev = IncidentEvent(
            ts_raw=ts_raw,
            ts=ts_raw.replace("/", "-").replace(" ", "T") if ts_raw else "",
            source=_detect_source(chunk),
            detection_name=_first_group(_DETECT_RE, chunk),
            threat_name=_first_group(_THREAT_RE, chunk),
            hostname=_first_group(_HOST_RE, chunk),
            user=_first_group(_USER_RE, chunk),
            parent_process=_first_group(_PARENT_RE, chunk),
            process=_first_group(_PROC_RE, chunk),
            child_process=_first_group(_CHILD_RE, chunk),
            command_line=_first_group(_CMD_RE, chunk),
            sha256=_first_group(_SHA256_RE, chunk).lower(),
            sha1=_first_group(_SHA1_RE, chunk).lower(),
            md5=_first_group(_MD5_RE, chunk).lower(),
            path=_first_group(_PATH_RE, chunk),
            mitre=sorted(set(_MITRE_RE.findall(chunk))),
            action=(_ACTION_RE.search(chunk).group(1).lower() if _ACTION_RE.search(chunk) else ""),
            message=chunk.strip().split("\n", 1)[0][:200],
            raw_offset=off,
        )
        # Skip empty shells — an event must have SOMETHING beyond a timestamp.
        if any([ev.detection_name, ev.threat_name, ev.process, ev.command_line,
                ev.sha256, ev.hostname]):
            events.append(ev)
    return events


def build_timeline(events: list[IncidentEvent]) -> list[dict]:
    """Chronologically ordered, deduplicated timeline. Each item includes a
    short one-line summary suitable for the Executive Summary."""
    def _key(e: IncidentEvent):
        return (e.ts_raw or "", e.raw_offset)
    ordered = sorted(events, key=_key)
    out: list[dict] = []
    for e in ordered:
        summary_parts = []
        if e.source:         summary_parts.append(e.source)
        if e.detection_name: summary_parts.append(f"detected **{e.detection_name}**")
        elif e.threat_name:  summary_parts.append(f"observed **{e.threat_name}**")
        if e.hostname:       summary_parts.append(f"on `{e.hostname}`")
        if e.user:           summary_parts.append(f"as `{e.user}`")
        chain = " → ".join(x for x in (e.parent_process, e.process, e.child_process) if x)
        if chain:            summary_parts.append(f"({chain})")
        if e.action:         summary_parts.append(f"— **{e.action}**")
        out.append({
            "ts": e.ts_raw or "unknown",
            "source": e.source,
            "summary": " ".join(summary_parts) or e.message,
            "event": e.to_dict(),
        })
    return out


def compose_executive_summary(events: list[IncidentEvent],
                              verdict: str, escalate: bool) -> str:
    """Narrative Executive Summary — reads like a Tier-2 analyst wrote it."""
    if not events:
        return ("The incident text did not contain structured detection "
                "telemetry (no timestamps, detection names, processes or "
                "hashes). NivXRay ran only its lexical decoders — treat "
                "this output as informational until real XDR telemetry is "
                "supplied.")
    hosts = sorted({e.hostname for e in events if e.hostname})
    users = sorted({e.user for e in events if e.user})
    sources = sorted({e.source for e in events if e.source})
    threats = sorted({e.threat_name for e in events if e.threat_name})
    quarantined = [e for e in events if e.action in ("quarantined", "blocked", "contained", "isolated")]
    lines: list[str] = []
    first = events[0]
    if first.ts_raw and first.source and first.detection_name:
        lines.append(
            f"On {first.ts_raw} UTC {first.source} detected "
            f"**{first.detection_name}**"
            + (f" on host `{hosts[0]}`" if hosts else "")
            + (f" under user `{users[0]}`" if users else "")
            + ".")
    elif first.detection_name:
        lines.append(f"{first.source or 'Endpoint telemetry'} raised "
                     f"**{first.detection_name}**"
                     + (f" on `{hosts[0]}`" if hosts else "") + ".")
    # Process-chain narrative — most impactful single sentence.
    chained = [e for e in events if e.parent_process and e.process]
    if chained:
        e = chained[0]
        chain = " launched ".join(x for x in (e.parent_process, e.process, e.child_process) if x)
        lines.append(
            f"The activity involved `{chain}`"
            + (f" under `{e.user}`" if e.user else "")
            + ", indicating a possible " + _guess_technique(e) + ".")
    # Subsequent events (threat detonations).
    for e in events[1:]:
        if e.threat_name:
            l = (f"At {e.ts_raw} UTC {e.source or 'the endpoint'} observed "
                 f"**{e.threat_name}**")
            if e.process:  l += f" ({e.process})"
            if e.action:   l += f" — {e.action}"
            lines.append(l + ".")
    if quarantined:
        n = len(quarantined)
        lines.append(f"{n} file{'s' if n>1 else ''} were {quarantined[0].action} "
                     "by the endpoint agent.")
    if len(events) >= 2 and hosts:
        lines.append(f"All observed events pivot around host `{hosts[0]}`; "
                     "environmental search confirms scope is currently limited "
                     "to this endpoint.")
    if threats and any("banker" in t.lower() or "trojan" in t.lower() for t in threats):
        lines.append("Historical pivoting on the host surfaced prior malware "
                     "(banker/trojan family) — recommend reviewing the earlier "
                     "quarantine record and confirming full cleanup.")
    lines.append("Based on the observed sequence, the activity is consistent with "
                 + _guess_kill_chain(events) + ".")
    if escalate:
        lines.append("**Escalation to customer recommended.**")
    return "\n\n".join(lines)


def _guess_technique(e: IncidentEvent) -> str:
    proc = (e.process + " " + e.child_process + " " + e.command_line).lower()
    if "wsmprovhost" in proc:                return "remote PowerShell / WinRM session"
    if "sharphound" in proc or "sh.exe" in proc: return "Active Directory enumeration (SharpHound)"
    if "mimikatz" in proc:                   return "credential access via Mimikatz"
    if "psexec" in proc:                     return "lateral movement via PsExec"
    if "rundll32" in proc:                   return "living-off-the-land execution via rundll32"
    if "certutil" in proc and ("http" in proc or "-urlcache" in proc):
        return "payload staging via certutil"
    if "powershell" in proc and ("-enc" in proc or "encodedcommand" in proc):
        return "obfuscated PowerShell execution"
    return "endpoint-native tool abuse"


def _guess_kill_chain(events: list[IncidentEvent]) -> str:
    txt = " ".join(
        (e.detection_name + " " + e.threat_name + " " + e.process
         + " " + e.child_process + " " + e.command_line).lower()
        for e in events
    )
    if "sharphound" in txt:  return "credential access and Active Directory enumeration"
    if "kerberoast" in txt:  return "Kerberoasting"
    if "mimikatz" in txt:    return "in-memory credential theft"
    if "wsmprov" in txt or "winrm" in txt:
        return "remote administration abuse (WinRM / PowerShell Remoting)"
    if "banker" in txt or "trojan" in txt:
        return "commodity malware execution"
    return "post-exploitation tooling activity"


def derive_recommendations(events: list[IncidentEvent],
                           url_buckets: dict) -> list[dict]:
    """Evidence-driven recommendations — never generic 'block URLs'."""
    recs: list[dict] = []
    txt = " ".join((e.detection_name + " " + e.threat_name + " " + e.process
                    + " " + e.child_process + " " + e.command_line).lower()
                   for e in events)
    if "sharphound" in txt:
        recs.append({"severity": "high",
                     "title": "Review Active Directory enumeration",
                     "why": "SharpHound execution was observed — check what "
                            "collection methods were used and audit any "
                            "returned attack paths (BloodHound)."})
    if "kerberoast" in txt:
        recs.append({"severity": "critical",
                     "title": "Reset privileged service-account credentials",
                     "why": "Kerberoasting detected. Any exposed SPN / service "
                            "account TGTs must be rotated to invalidate stolen "
                            "hashes."})
    if "wsmprovhost" in txt or "winrm" in txt:
        recs.append({"severity": "high",
                     "title": "Review WinRM logs and endpoint listener state",
                     "why": "wsmprovhost.exe under a user context suggests a "
                            "remote PowerShell session. Correlate WinRM logs "
                            "with the originating host."})
    for e in events:
        if e.action in ("quarantined", "blocked"):
            recs.append({"severity": "medium",
                         "title": "Verify quarantine and cleanup",
                         "why": f"{e.threat_name or e.detection_name} was "
                                f"{e.action} — confirm no persistence or "
                                "second-stage artefacts remain."})
            break
    if any("banker" in (e.threat_name or "").lower() for e in events):
        recs.append({"severity": "high",
                     "title": "Full malware scan on affected host",
                     "why": "Historical banker/trojan detection on the same "
                            "host — run a full offline scan and audit for "
                            "persistence."})
    if url_buckets.get("attacker"):
        recs.append({"severity": "high",
                     "title": "Block confirmed attacker URLs at egress",
                     "why": "Only URLs classified as `attacker` are worth "
                            "blocking — reference URLs (cisco, virustotal, "
                            "mitre, ...) were correctly excluded."})
    # Isolate on high-severity activity
    hosts = sorted({e.hostname for e in events if e.hostname})
    if hosts and any(r["severity"] in ("high", "critical") for r in recs):
        recs.insert(0, {"severity": "critical",
                        "title": f"Isolate host `{hosts[0]}` from network",
                        "why": "High-severity post-exploitation behaviour "
                               "observed on this endpoint — isolate while "
                               "the investigation continues."})
    if not recs:
        recs.append({"severity": "informational",
                     "title": "Retain incident for future correlation",
                     "why": "No high-signal post-exploitation behaviour was "
                            "reconstructed from the supplied telemetry."})
    return recs


def escalation_decision(events: list[IncidentEvent],
                        url_buckets: dict) -> dict:
    """{'decision': 'escalate'|'monitor'|'close', 'confidence': 0..100, 'reason': str}"""
    triggers = []
    txt = " ".join((e.threat_name + " " + e.detection_name + " " + e.process
                    + " " + e.child_process).lower() for e in events)
    if "sharphound" in txt: triggers.append("SharpHound execution")
    if "mimikatz" in txt:   triggers.append("Mimikatz execution")
    if "kerberoast" in txt: triggers.append("Kerberoasting")
    if "wsmprov" in txt:    triggers.append("suspicious remote PowerShell (WinRM)")
    if url_buckets.get("attacker"):
        triggers.append(f"{len(url_buckets['attacker'])} attacker URL(s)")
    if any(e.threat_name and "trojan" in e.threat_name.lower() for e in events):
        triggers.append("historical trojan on same host")
    if triggers:
        return {"decision": "escalate",
                "confidence": min(95, 60 + 10 * len(triggers)),
                "reason": "Escalate — " + "; ".join(triggers) + "."}
    if events:
        return {"decision": "monitor",
                "confidence": 60,
                "reason": ("Endpoint telemetry present but no high-signal "
                           "post-exploitation indicators — continue monitoring.")}
    return {"decision": "close",
            "confidence": 70,
            "reason": "No structured telemetry — informational only."}
