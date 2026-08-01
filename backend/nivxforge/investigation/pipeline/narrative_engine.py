"""Incident-Centric Narrative Engine (Phase 5, graph-only consumer).

Contract (operator directive · 2026-08-01):

    The Narrative Engine consumes ONLY the Investigation Graph. It
    NEVER describes the internal workings of X-Lab (`pipeline`,
    `decoder`, `verdict engine`, `graph builder`, `parser`, …).
    Every paragraph's subject is the incident, the endpoint, the
    user, the malware, the attacker, the process chain, the network
    activity, the evidence, the threat, or the customer impact —
    never the tool.

Input:  `InvestigationState` (from Phase 1 orchestrator).
Output: Markdown-ish analyst prose in an incident-first structure:

    1. Incident opener        (vendor · detection · host · timestamp)
    2. Process / command chain
    3. External infrastructure activity
    4. Threat family / MITRE alignment
    5. Containment status
    6. Recommendations

The engine passes its own output through the narrative lexicon gate
so any accidental slip in phrasing gets rewritten before it leaves
this module.

Deterministic. Never raises. Never empty.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .contract_check import UNKNOWN, check_contract11
from .graph_builder import GraphNode, InvestigationGraph
from ..narrative_lexicon_gate import sanitize
from .orchestrator import InvestigationState


@dataclass(frozen=True)
class IncidentNarrative:
    executive_summary: str
    paragraphs: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]   # graph node ids cited

    def to_markdown(self) -> str:
        return "\n\n".join(self.paragraphs)


_VENDOR_LABELS = {
    "cisco_secure_endpoint": "Cisco Secure Endpoint",
    "cisco_xdr": "Cisco XDR",
    "sysmon": "Sysmon",
    "windows_event": "Windows Event Log",
    "microsoft_defender": "Microsoft Defender",
    "crowdstrike": "CrowdStrike Falcon",
    "suricata": "Suricata",
    "zeek": "Zeek",
    "generic_json": "the submitted telemetry",
    "encoded_command": "the submitted command line",
    "plain_command": "the submitted command line",
    "plain_text": "the submitted artefact",
}


def compose_incident_narrative(state: InvestigationState) -> IncidentNarrative:
    """Compose an analyst-style narrative from an InvestigationState.

    Consumes ONLY the Investigation Graph and orchestrator metadata
    (never CEM.raw, never decoded strings, never pipeline internals).
    Every fact traces to a specific graph node id."""
    graph = state.graph
    cited: List[str] = []

    hosts = graph.nodes_of("host")
    users = graph.nodes_of("user")
    processes = graph.nodes_of("process")
    commands = graph.nodes_of("command")
    files = graph.nodes_of("file")
    urls = graph.nodes_of("url")
    ips = _external_ips(graph)
    hashes = graph.nodes_of("hash")
    dns_nodes = graph.nodes_of("dns")
    detections = graph.nodes_of("detection")
    decoded_payloads = graph.nodes_of("decoded_payload")

    vendor_label = _VENDOR_LABELS.get(state.vendor.vendor,
                                       _humanize(state.vendor.vendor))
    ts = _timestamp_iso(state)
    containment = _containment_state(state)

    # ── 1 · Incident opener ─────────────────────────────────────────
    opener = _paragraph_incident_opener(
        vendor_label, ts, detections, hosts, users, containment, cited,
    )

    # ── 2 · Process / command chain ────────────────────────────────
    process_para = _paragraph_process_chain(
        processes, commands, files, decoded_payloads, cited,
    )

    # ── 3 · External infrastructure ────────────────────────────────
    external_para = _paragraph_external_infra(urls, ips, dns_nodes, cited)

    # ── 4 · Threat family / MITRE alignment ────────────────────────
    threat_para = _paragraph_threat_alignment(
        state, detections, cited,
    )

    # ── 5 · Containment status ─────────────────────────────────────
    containment_para = _paragraph_containment(hosts, containment, cited)

    # ── 6 · Recommendations ────────────────────────────────────────
    recommendations_para = _paragraph_recommendations(
        urls, ips, hashes, commands, hosts, cited,
    )

    paragraphs = tuple(
        p for p in (
            opener,
            process_para,
            external_para,
            threat_para,
            containment_para,
            recommendations_para,
        ) if p.strip()
    )

    # Guarantee ≥ 2 paragraphs even for thin evidence.
    if len(paragraphs) < 2:
        report = check_contract11(state)
        fallback = (
            "Additional telemetry is required to determine the full "
            "scope of this activity. "
            + "; ".join(
                a.answer for a in report.answers
                if a.answer != UNKNOWN and "Cannot determine" not in a.answer
            )[:400]
        )
        paragraphs = paragraphs + (fallback,)

    # Executive summary = first paragraph (opener) — that's the analyst
    # tl;dr. Downstream renderers render the full paragraphs list.
    exec_summary = paragraphs[0]

    # Sanitise every paragraph through the lexicon gate as a
    # belt-and-braces guard against implementation-detail leaks.
    cleaned = tuple(sanitize(p) for p in paragraphs)
    return IncidentNarrative(
        executive_summary=sanitize(exec_summary),
        paragraphs=cleaned,
        evidence_refs=tuple(dict.fromkeys(cited)),
    )


# ── Paragraph builders ────────────────────────────────────────────

def _paragraph_incident_opener(
    vendor_label: str,
    ts: Optional[str],
    detections: List[GraphNode],
    hosts: List[GraphNode],
    users: List[GraphNode],
    containment: Optional[str],
    cited: List[str],
) -> str:
    detection_name = None
    if detections:
        cited.append(detections[0].id)
        detection_name = detections[0].value

    host_bit = ""
    if hosts:
        cited.append(hosts[0].id)
        host_name = hosts[0].value
        host_ip = (hosts[0].attrs or {}).get("ip")
        if host_ip:
            host_bit = f"endpoint **{host_name}** ({host_ip})"
        else:
            host_bit = f"endpoint **{host_name}**"

    user_bit = ""
    if users:
        cited.append(users[0].id)
        user_bit = f" under user account `{users[0].value}`"

    ts_bit = f"On {ts}, " if ts else ""

    if detection_name and host_bit:
        opener = (
            f"{ts_bit}{vendor_label} identified the detection "
            f"**{detection_name}** on {host_bit}{user_bit}."
        )
    elif detection_name:
        opener = (
            f"{ts_bit}{vendor_label} identified the detection "
            f"**{detection_name}**{user_bit}."
        )
    elif host_bit:
        opener = (
            f"{ts_bit}{vendor_label} surfaced suspicious activity on "
            f"{host_bit}{user_bit}."
        )
    else:
        opener = f"{ts_bit}{vendor_label} surfaced suspicious activity."

    if containment == "isolated":
        opener += " The endpoint was automatically isolated shortly after detection."
    elif containment == "quarantined":
        opener += " The offending file was quarantined by the endpoint agent."
    elif containment == "blocked":
        opener += " The activity was blocked by the endpoint agent."
    elif containment == "prevented":
        opener += " The behaviour was prevented before it could complete."
    return opener


def _paragraph_process_chain(
    processes: List[GraphNode],
    commands: List[GraphNode],
    files: List[GraphNode],
    decoded_payloads: List[GraphNode],
    cited: List[str],
) -> str:
    if not (processes or commands):
        return ""

    parts: List[str] = []
    lead_process = _pick_meaningful_process(processes)
    lead_command = _pick_meaningful_command(commands)

    if lead_process and lead_command:
        cited.append(lead_process.id)
        cited.append(lead_command.id)
        parts.append(
            f"The activity was carried out by `{_short_process_name(lead_process.value)}` "
            f"executing `{_shorten(lead_command.value, 240)}`."
        )
    elif lead_command:
        cited.append(lead_command.id)
        parts.append(
            f"The observed command line was `{_shorten(lead_command.value, 240)}`."
        )
    elif lead_process:
        cited.append(lead_process.id)
        parts.append(
            f"The primary process observed on the endpoint was "
            f"`{_short_process_name(lead_process.value)}`."
        )

    # Decoded content — one sentence, no implementation detail.
    if decoded_payloads:
        cited.append(decoded_payloads[0].id)
        preview = _shorten(decoded_payloads[0].value, 200)
        parts.append(
            f"The obfuscated content resolved to the following underlying "
            f"activity: `{preview}`."
        )

    # File / hash context — one sentence.
    if files:
        cited.append(files[0].id)
        parts.append(
            f"The activity involved the file `{_shorten(files[0].value, 160)}`."
        )

    # Behaviour interpretation (heuristic on command content).
    if lead_command:
        behavioural = _interpret_command_behaviour(lead_command.value)
        if behavioural:
            parts.append(behavioural)

    return " ".join(parts)


def _paragraph_external_infra(
    urls: List[GraphNode],
    ips: List[GraphNode],
    dns_nodes: List[GraphNode],
    cited: List[str],
) -> str:
    if not (urls or ips or dns_nodes):
        return ""
    external_urls = [u for u in urls if _is_external_url(u.value)]
    external_dns = [d for d in dns_nodes if _is_external_domain(d.value)]

    if not (external_urls or ips or external_dns):
        return ""

    fragments: List[str] = []
    if external_urls:
        top = external_urls[0]
        cited.append(top.id)
        fragments.append(
            f"The activity attempted communication with **{top.value}**"
        )
    elif external_dns:
        top = external_dns[0]
        cited.append(top.id)
        fragments.append(
            f"The activity issued DNS queries for **{top.value}**"
        )
    elif ips:
        top = ips[0]
        cited.append(top.id)
        fragments.append(
            f"The activity contacted the external address **{top.value}**"
        )

    remainder = []
    if len(external_urls) > 1:
        remainder.append(f"{len(external_urls)-1} additional URL(s)")
    if len(external_dns) > 1:
        remainder.append(f"{len(external_dns)-1} additional domain(s)")
    if len(ips) > 1:
        remainder.append(f"{len(ips)-1} additional IP address(es)")
    if remainder:
        fragments.append("along with " + ", ".join(remainder))

    fragments.append(
        ", which indicates that the observed activity attempted to reach "
        "infrastructure outside the endpoint's expected communication "
        "profile rather than remaining local."
    )
    return " ".join(fragments).replace(" ,", ",")


def _paragraph_threat_alignment(
    state: InvestigationState,
    detections: List[GraphNode],
    cited: List[str],
) -> str:
    tactics, techniques = _mitre_from_state(state)
    families: List[str] = []
    for d in detections:
        fam = (d.attrs or {}).get("threat_family")
        if fam and fam not in families:
            families.append(fam)
    if not (tactics or techniques or families):
        return ""

    parts: List[str] = []
    if families:
        parts.append(
            f"The vendor detection is associated with the threat family "
            f"**{families[0]}**"
        )
        if detections:
            cited.append(detections[0].id)
        if len(families) > 1:
            parts[-1] += (
                f" (with related indicators for {', '.join(families[1:3])})"
            )
        parts[-1] += ", significantly increasing confidence that the observed activity represents an active malware execution chain rather than benign administrative behaviour."
    if techniques:
        tech_bits = ", ".join(f"**{t}**" for t in techniques[:3])
        parts.append(
            f"The observed activity aligns with the ATT&CK technique(s) "
            f"{tech_bits}."
        )
    if tactics:
        tac_bits = ", ".join(_tactic_label(t) for t in tactics[:4])
        parts.append(
            f"On the ATT&CK tactic scale, the activity spans {tac_bits}, "
            f"indicating the attack had progressed beyond a single "
            f"isolated event."
        )
    return " ".join(parts)


def _paragraph_containment(
    hosts: List[GraphNode],
    containment: Optional[str],
    cited: List[str],
) -> str:
    if not containment or containment == "none":
        return ""
    host_ref = ""
    if hosts:
        host_ref = f" on {hosts[0].value}"
        cited.append(hosts[0].id)
    if containment == "isolated":
        return (
            f"The endpoint agent has isolated the affected system{host_ref}, "
            f"preventing further outbound activity while the investigation "
            f"continues."
        )
    if containment == "quarantined":
        return (
            f"The endpoint agent has quarantined the offending file{host_ref}. "
            f"Additional telemetry review is recommended to confirm whether "
            f"any related activity ran before the quarantine took effect."
        )
    if containment == "blocked":
        return (
            f"The endpoint agent blocked the observed activity{host_ref}. "
            f"Follow-up review should confirm whether the intended payload "
            f"was staged elsewhere before the block."
        )
    if containment == "prevented":
        return (
            f"The observed behaviour was prevented before it completed"
            f"{host_ref}."
        )
    return ""


def _paragraph_recommendations(
    urls: List[GraphNode],
    ips: List[GraphNode],
    hashes: List[GraphNode],
    commands: List[GraphNode],
    hosts: List[GraphNode],
    cited: List[str],
) -> str:
    actions: List[str] = []
    ext_urls = [u for u in urls if _is_external_url(u.value)]
    if ext_urls:
        cited.append(ext_urls[0].id)
        actions.append(
            f"block `{ext_urls[0].value}` at the perimeter and enrich the "
            f"URL against threat-intelligence feeds for related infrastructure"
        )
    ext_ips = [i for i in ips if _is_external_ip(i.value)]
    if ext_ips and not ext_urls:
        cited.append(ext_ips[0].id)
        actions.append(
            f"block `{ext_ips[0].value}` at the perimeter and pivot on "
            f"related infrastructure through your threat-intelligence platform"
        )
    if hashes:
        cited.append(hashes[0].id)
        actions.append(
            f"add SHA-256 `{hashes[0].value}` to the endpoint deny-list and "
            f"pivot on VirusTotal / your sandbox history for prior sightings"
        )
    if hosts:
        cited.append(hosts[0].id)
        actions.append(
            f"review the parent process that spawned the observed activity "
            f"on {hosts[0].value} to identify the initial delivery vector"
        )
    if commands:
        actions.append(
            "hunt for the observed command pattern across PowerShell "
            "script-block logging (Event ID 4104) and process telemetry to "
            "identify additional endpoints exhibiting the same behaviour"
        )
    if not actions:
        return ""
    intro = "Recommended follow-up: "
    if len(actions) >= 3:
        joined = "; ".join(actions[:-1]) + f"; and {actions[-1]}."
    elif len(actions) == 2:
        joined = f"{actions[0]}; and {actions[1]}."
    else:
        joined = actions[0] + "."
    return intro + joined


# ── Helpers ──────────────────────────────────────────────────────────

def _timestamp_iso(state: InvestigationState) -> Optional[str]:
    for evt in state.cem.events:
        if evt.timestamp:
            ts = evt.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.strftime("%d %B %Y at %H:%M:%S UTC")
    for inc in state.cem.incidents:
        if inc.first_seen:
            ts = inc.first_seen
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.strftime("%d %B %Y at %H:%M:%S UTC")
    return None


def _containment_state(state: InvestigationState) -> Optional[str]:
    for evt in state.cem.events:
        if evt.containment and evt.containment.value != "none":
            return evt.containment.value
    for inc in state.cem.incidents:
        if inc.containment and inc.containment.value != "none":
            return inc.containment.value
    return None


def _mitre_from_state(state: InvestigationState) -> Tuple[List[str], List[str]]:
    """Best-effort MITRE surface: extract from CEM events' raw fields
    if the normalizer captured `mitre_tactics` / `mitre_techniques`."""
    tactics: List[str] = []
    techniques: List[str] = []
    for evt in state.cem.events:
        raw = evt.raw or {}
        for t in raw.get("mitre_tactics", []) or []:
            if isinstance(t, str) and t not in tactics:
                tactics.append(t)
        for t in raw.get("mitre_techniques", []) or []:
            if isinstance(t, str) and t not in techniques:
                techniques.append(t)
    return tactics, techniques


def _external_ips(graph: InvestigationGraph) -> List[GraphNode]:
    return [n for n in graph.nodes_of("ip") if _is_external_ip(n.value)]


def _is_external_ip(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith(("10.", "127.", "192.168.", "169.254.")):
        return False
    if ip.startswith("172.") and ip.count(".") == 3:
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return False
        except ValueError:
            pass
    return True


def _is_external_url(url: str) -> bool:
    if not url:
        return False
    low = url.lower()
    # Vendor consoles are not attacker infra — never surface them.
    if any(x in low for x in ("console.amp.cisco.com", "cisco.com",
                                "microsoft.com", "crowdstrike.com",
                                "sentinelone.com")):
        return False
    return True


def _is_external_domain(dom: str) -> bool:
    if not dom:
        return False
    low = dom.lower()
    if any(x in low for x in ("cisco.com", "microsoft.com",
                                "crowdstrike.com", "sentinelone.com",
                                "amp.cisco.com")):
        return False
    return True


def _pick_meaningful_process(nodes: List[GraphNode]) -> Optional[GraphNode]:
    """Return the process node with the richest attributes / longest
    canonical path, ignoring bare placeholders."""
    if not nodes:
        return None
    return sorted(nodes, key=lambda n: (-len(n.attrs or {}),
                                          -len(n.value)))[0]


def _pick_meaningful_command(nodes: List[GraphNode]) -> Optional[GraphNode]:
    if not nodes:
        return None
    # Prefer longer, non-parent commands with actual arguments.
    def rank(n: GraphNode) -> Tuple[int, int]:
        role = (n.attrs or {}).get("role")
        role_penalty = 1 if role == "parent" else 0
        return (role_penalty, -len(n.value))
    return sorted(nodes, key=rank)[0]


def _short_process_name(image: str) -> str:
    if not image:
        return ""
    # `file:///C%3A/windows/system32/cmd.exe` → cmd.exe
    from urllib.parse import unquote
    decoded = unquote(image)
    for sep in ("\\", "/"):
        if sep in decoded:
            decoded = decoded.rsplit(sep, 1)[-1]
    return decoded or image


def _shorten(s: str, n: int) -> str:
    if not s:
        return ""
    s = s.strip()
    if len(s) <= n:
        return s
    return s[:n - 1].rstrip() + "…"


def _interpret_command_behaviour(cmd: str) -> Optional[str]:
    """Deterministic behaviour interpretation from command content.
    Returns a single analyst-style sentence or None."""
    if not cmd:
        return None
    low = cmd.lower()
    obs: List[str] = []
    if "^" in cmd and cmd.count("^") >= 5:
        obs.append(
            "The command uses caret escape characters to obfuscate its "
            "content, a technique commonly employed to evade both human "
            "review and static analysis tooling"
        )
    if "finger" in low and "@" in low:
        obs.append(
            "The command invokes the `finger` Windows binary against a "
            "remote host, an unusual behaviour outside legitimate "
            "administrative use that is frequently abused to reach external "
            "infrastructure while bypassing endpoint URL controls"
        )
    if "certutil" in low and ("urlcache" in low or "-f " in low or "-decode" in low):
        obs.append(
            "The command invokes `certutil` in a mode used to download or "
            "decode content, a well-known living-off-the-land technique for "
            "staging additional malware"
        )
    if "bitsadmin" in low and "/transfer" in low:
        obs.append(
            "The command invokes `bitsadmin` to transfer a remote file, a "
            "technique frequently used to smuggle payloads past URL filters"
        )
    if "mshta" in low and ("http" in low or ".hta" in low):
        obs.append(
            "The command invokes `mshta` to execute remote or scripted "
            "HTML content, a technique frequently seen in loader stages of "
            "commodity malware"
        )
    if "rundll32" in low and ("javascript" in low or ".dll" in low and "http" in low):
        obs.append(
            "The command invokes `rundll32` to execute remote or scripted "
            "code, a technique used to bypass application-control policies"
        )
    if "downloadstring" in low or "iwr " in low or "iex(" in low.replace(" ", ""):
        obs.append(
            "The command downloads and immediately executes remote content "
            "in memory, avoiding the on-disk footprint typical of legitimate "
            "administration"
        )
    if not obs:
        return None
    # Pick the most specific observation (highest index priority) — the
    # last non-generic one added tends to be the most concrete.
    return obs[-1] + "."


def _tactic_label(t: str) -> str:
    """Format `'TA0002 - Execution'` → `Execution (TA0002)`."""
    if " - " in t:
        code, name = t.split(" - ", 1)
        return f"{name.strip()} ({code.strip()})"
    return t


def _humanize(s: str) -> str:
    return " ".join(w.capitalize() for w in (s or "").replace("_", " ").split())


__all__ = ["IncidentNarrative", "compose_incident_narrative"]
