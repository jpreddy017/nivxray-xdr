"""NivXRay-native PowerShell behavior extractor (Phase 9.4).

Consumes an AST produced by `ps_ast.parse()` and emits analyst-facing
behavior tags describing observable actions the recovered script would
perform when executed.

Design contract:
    • NivXRay-native taxonomy — behavior names describe what a Tier-2
      analyst would write on the whiteboard, not the ATT&CK technique.
      MITRE IDs are attached as a **mapping**, never as the name.
    • Each behavior carries: id, name, severity, confidence,
      rationale, evidence (source spans), mitre[], node_ref.
    • Deterministic — no LLM.
    • Extensible — every extractor is a function that appends behaviors
      to a shared list. Adding a new tag = adding a function.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable

from .ps_ast import Node, Script, _all_children, _fold_string


# ── Behavior taxonomy (NivXRay-native, MITRE as mapping) ─────────
# id                             : machine-readable stable identifier
# name                           : analyst-facing observable name
# severity                       : critical | high | medium | low | info
# mitre                          : ATT&CK technique IDs (mapping, not identity)
TAXONOMY: dict[str, dict] = {
    # ── Delivery / Execution flags ────────────────────────────────
    "execution_policy_bypass":  {"name": "Execution Policy Bypass",       "severity": "medium", "mitre": ["T1059.001"]},
    "hidden_window":            {"name": "Hidden Window Execution",       "severity": "medium", "mitre": ["T1564.003"]},
    "no_profile":               {"name": "PowerShell No-Profile Launch",  "severity": "low",    "mitre": ["T1059.001"]},
    "encoded_command":          {"name": "Encoded PowerShell Command",    "severity": "medium", "mitre": ["T1027", "T1059.001"]},
    "invoke_expression":        {"name": "PowerShell Invoke-Expression",  "severity": "high",   "mitre": ["T1059.001"]},
    "memory_execution":         {"name": "In-Memory Script Execution",    "severity": "high",   "mitre": ["T1059.001", "T1620"]},
    "fileless_execution":       {"name": "Fileless Execution",            "severity": "high",   "mitre": ["T1620"]},
    "lolbin_abuse":             {"name": "LOLBIN Abuse",                  "severity": "high",   "mitre": ["T1218"]},
    "process_spawn":            {"name": "Process Spawn",                 "severity": "low",    "mitre": []},

    # ── Download / Delivery ───────────────────────────────────────
    "webclient_downloadstring": {"name": "WebClient DownloadString",      "severity": "high",   "mitre": ["T1105", "T1059.001"]},
    "webclient_downloadfile":   {"name": "WebClient DownloadFile",        "severity": "high",   "mitre": ["T1105"]},
    "invoke_webrequest":        {"name": "Invoke-WebRequest",             "severity": "medium", "mitre": ["T1105"]},
    "invoke_restmethod":        {"name": "Invoke-RestMethod",             "severity": "medium", "mitre": ["T1105"]},
    "bits_download":            {"name": "BITS Download",                 "severity": "medium", "mitre": ["T1197", "T1105"]},
    "remote_script_download":   {"name": "Remote Script Download",        "severity": "high",   "mitre": ["T1105"]},

    # ── Obfuscation / Decoding ────────────────────────────────────
    "payload_decode":           {"name": "Payload Decode",                "severity": "medium", "mitre": ["T1027"]},
    "payload_decompression":    {"name": "Payload Decompression",         "severity": "medium", "mitre": ["T1027"]},
    "string_reconstruction":    {"name": "String Reconstruction (-f/-join)", "severity": "medium", "mitre": ["T1027.010"]},
    "char_array_join":          {"name": "Char-Array Join Obfuscation",   "severity": "medium", "mitre": ["T1027.010"]},

    # ── Defense evasion ───────────────────────────────────────────
    "amsi_bypass":              {"name": "AMSI Bypass",                   "severity": "critical", "mitre": ["T1562.001"]},
    "defender_tamper":          {"name": "Defender Tampering",            "severity": "critical", "mitre": ["T1562.001"]},
    "reflection":               {"name": "Reflection / .NET Load",        "severity": "high",   "mitre": ["T1027.004", "T1055"]},
    "defense_evasion":          {"name": "Defense Evasion",               "severity": "high",   "mitre": ["T1562"]},

    # ── Persistence ───────────────────────────────────────────────
    "scheduled_task":           {"name": "Scheduled Task",                "severity": "high",   "mitre": ["T1053.005"]},
    "service_creation":         {"name": "Service Creation",              "severity": "high",   "mitre": ["T1543.003"]},
    "registry_run_key":         {"name": "Registry Run Key",              "severity": "high",   "mitre": ["T1547.001"]},
    "registry_modification":    {"name": "Registry Modification",         "severity": "medium", "mitre": ["T1112"]},
    "persistence":              {"name": "Persistence",                   "severity": "high",   "mitre": []},

    # ── Access / Privileges ───────────────────────────────────────
    "credential_access":        {"name": "Credential Access",             "severity": "critical", "mitre": ["T1003"]},
    "privilege_escalation":     {"name": "Privilege Escalation",          "severity": "high",   "mitre": []},
    "process_injection":        {"name": "Process Injection",             "severity": "critical", "mitre": ["T1055"]},

    # ── Network / C2 ──────────────────────────────────────────────
    "network_beaconing":        {"name": "Network Beaconing",             "severity": "high",   "mitre": ["T1071.001"]},
    "c2_communication":         {"name": "C2 Communication",              "severity": "critical", "mitre": ["T1071"]},
    "external_network":         {"name": "External Network Communication","severity": "medium", "mitre": ["T1071.001"]},
    "local_network_only":       {"name": "Local Network Only",            "severity": "info",   "mitre": []},
    "lateral_movement":         {"name": "Lateral Movement",              "severity": "high",   "mitre": ["T1021"]},
}


# ── Behavior record ──────────────────────────────────────────────
@dataclass
class Behavior:
    id: str
    name: str
    severity: str
    confidence: int                     # 0-100
    rationale: str                      # analyst-facing WHY
    mitre: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)   # [{span_start, span_end, snippet, source}]
    node_ref: str = ""                  # AST node kind@offset

    def to_dict(self) -> dict:
        return asdict(self)


def _mk(bid: str, *, confidence: int, rationale: str,
        evidence: list[dict] | None = None,
        node_ref: str = "") -> Behavior:
    """Instantiate a Behavior from the taxonomy."""
    tax = TAXONOMY[bid]
    return Behavior(
        id=bid,
        name=tax["name"],
        severity=tax["severity"],
        confidence=confidence,
        rationale=rationale,
        mitre=list(tax["mitre"]),
        evidence=list(evidence or []),
        node_ref=node_ref,
    )


def _span(n: Node, script_src: str, source: str = "ast") -> dict:
    snippet = (script_src[n.start:n.end] if script_src else n.text)[:200]
    return {"span_start": n.start, "span_end": n.end,
            "snippet": snippet, "source": source, "node_kind": n.kind}


# ── Behavior extractors ──────────────────────────────────────────
_URL_RE  = re.compile(r"https?://[^\s\"'<>]{4,300}", re.I)
_IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _extract_from_call(call: Node, script_src: str, vars_: dict[str, str],
                       out: list[Behavior]) -> None:
    """Behaviors keyed off `Verb-Noun` cmdlet invocations."""
    cmdlet = (call.meta.get("cmdlet") or call.text or "").strip()
    low = cmdlet.lower()

    if low in ("iex", "invoke-expression"):
        out.append(_mk("invoke_expression", confidence=95,
                       rationale=("Script invokes `Invoke-Expression` — "
                                  "dynamically evaluates recovered strings, a hallmark of fileless PS."),
                       evidence=[_span(call, script_src)],
                       node_ref=f"Call@{call.start}"))
        out.append(_mk("memory_execution", confidence=85,
                       rationale=("`Invoke-Expression` executes code entirely in-memory — "
                                  "no persistent artefact is written to disk."),
                       evidence=[_span(call, script_src)]))
    if low in ("iwr", "invoke-webrequest", "curl", "wget"):
        out.append(_mk("invoke_webrequest", confidence=90,
                       rationale="Script issues an outbound HTTP request via `Invoke-WebRequest`.",
                       evidence=[_span(call, script_src)],
                       node_ref=f"Call@{call.start}"))
    if low in ("irm", "invoke-restmethod"):
        out.append(_mk("invoke_restmethod", confidence=90,
                       rationale="Script issues an outbound REST call via `Invoke-RestMethod`.",
                       evidence=[_span(call, script_src)]))
    if low in ("start-bitstransfer",):
        out.append(_mk("bits_download", confidence=85,
                       rationale=("Script uses Background Intelligent Transfer Service "
                                  "for download — often abused for stealthy delivery."),
                       evidence=[_span(call, script_src)]))
    if low in ("register-scheduledtask", "new-scheduledtask", "schtasks"):
        out.append(_mk("scheduled_task", confidence=90,
                       rationale="Script registers or manipulates a Windows Scheduled Task.",
                       evidence=[_span(call, script_src)]))
        out.append(_mk("persistence", confidence=80,
                       rationale="Scheduled Task creation is a known persistence primitive.",
                       evidence=[_span(call, script_src)]))
    if low in ("new-service", "sc.exe"):
        out.append(_mk("service_creation", confidence=88,
                       rationale="Script creates or modifies a Windows service — persistence primitive.",
                       evidence=[_span(call, script_src)]))
        out.append(_mk("persistence", confidence=75,
                       rationale="Service creation is a known persistence primitive.",
                       evidence=[_span(call, script_src)]))
    if low in ("set-mppreference",):
        out.append(_mk("defender_tamper", confidence=95,
                       rationale=("Script tunes `Set-MpPreference` — commonly used to "
                                  "disable Defender's real-time protection or add exclusions."),
                       evidence=[_span(call, script_src)]))
    if low in ("add-type",):
        out.append(_mk("reflection", confidence=85,
                       rationale=("`Add-Type` compiles inline .NET code — analysts should "
                                  "check for VirtualAlloc / WriteProcessMemory usage."),
                       evidence=[_span(call, script_src)]))
    if low in ("set-itemproperty", "new-itemproperty"):
        # Determine if it's a Run key (persistence) or ordinary registry mod
        args_text = " ".join(_fold_string(c, vars_) or c.text
                              for c in call.children if c.kind in ("String", "Var", "Ident"))
        if re.search(r"\\Run\\|\\RunOnce\\|CurrentVersion\\Run",
                     args_text, re.I):
            out.append(_mk("registry_run_key", confidence=90,
                           rationale=("Registry write targets a `Run` / `RunOnce` key — "
                                      "well-known auto-start persistence."),
                           evidence=[_span(call, script_src)]))
            out.append(_mk("persistence", confidence=85,
                           rationale="Registry Run key is a known persistence primitive."))
        else:
            out.append(_mk("registry_modification", confidence=70,
                           rationale="Script modifies a registry value.",
                           evidence=[_span(call, script_src)]))
    if low in ("start-process", "start", "saps"):
        out.append(_mk("process_spawn", confidence=60,
                       rationale="Script spawns a child process explicitly via `Start-Process`.",
                       evidence=[_span(call, script_src)]))


def _extract_from_method_call(mc: Node, script_src: str, vars_: dict[str, str],
                              out: list[Behavior]) -> None:
    """Behaviors keyed off `.Method(...)` chains."""
    member = (mc.meta.get("member") or "").strip()
    low = member.lower()
    if low in ("downloadstring",):
        out.append(_mk("webclient_downloadstring", confidence=95,
                       rationale=("`.DownloadString()` fetches a remote string — "
                                  "classic delivery step for staged malware."),
                       evidence=[_span(mc, script_src)],
                       node_ref=f"MethodCall@{mc.start}"))
        out.append(_mk("remote_script_download", confidence=85,
                       rationale="Remote content pulled directly into memory as a string.",
                       evidence=[_span(mc, script_src)]))
    if low in ("downloadfile",):
        out.append(_mk("webclient_downloadfile", confidence=95,
                       rationale="`.DownloadFile()` writes a remote payload to disk.",
                       evidence=[_span(mc, script_src)]))
    if low in ("downloaddata",):
        out.append(_mk("webclient_downloadfile", confidence=85,
                       rationale=("`.DownloadData()` fetches remote bytes into memory — "
                                  "typically decoded and executed."),
                       evidence=[_span(mc, script_src)]))
    if low in ("frombase64string",):
        out.append(_mk("payload_decode", confidence=90,
                       rationale="Script decodes an inline Base64 payload via `Convert::FromBase64String`.",
                       evidence=[_span(mc, script_src)]))
    if low in ("load", "loadfile", "loadwithpartialname", "unsafeloadfrom"):
        # `[Reflection.Assembly]::Load(...)` — reflective assembly load
        out.append(_mk("reflection", confidence=90,
                       rationale=("Reflective assembly load — .NET code executed "
                                  "in-memory without touching disk."),
                       evidence=[_span(mc, script_src)]))
        out.append(_mk("fileless_execution", confidence=85,
                       rationale="Assembly load bypasses disk artefacts entirely."))
    if low in ("virtualalloc", "writeprocessmemory", "createthread", "createremotethread",
               "ntmapviewofsection", "ntcreatethreadex"):
        out.append(_mk("process_injection", confidence=95,
                       rationale=(f"Script calls `{member}` — direct Win32 primitive used for "
                                  "shellcode injection / thread hijacking."),
                       evidence=[_span(mc, script_src)]))


def _extract_from_static_member(sm: Node, script_src: str, out: list[Behavior]) -> None:
    """`[Type]::Member` accesses — Reflection, FromBase64, AmsiUtils, etc."""
    typ = (sm.text or "").strip()
    member = (sm.meta.get("member") or "").strip().lower()
    joined = f"{typ}::{member}".lower()

    if "system.reflection.assembly" in typ.lower() and member in ("load", "loadfile", "loadwithpartialname"):
        out.append(_mk("reflection", confidence=90,
                       rationale="Reflective assembly load via `[Reflection.Assembly]::Load(...)`.",
                       evidence=[_span(sm, script_src)]))
        out.append(_mk("fileless_execution", confidence=80,
                       rationale="In-memory .NET assembly load — no on-disk artefact."))
    if member == "frombase64string" and "convert" in typ.lower():
        out.append(_mk("payload_decode", confidence=90,
                       rationale="Base64 payload decode via `[Convert]::FromBase64String(...)`.",
                       evidence=[_span(sm, script_src)]))
    if "amsi" in joined or member in ("amsiscanbuffer", "amsiinitialize"):
        out.append(_mk("amsi_bypass", confidence=95,
                       rationale=("Script touches AMSI internals — attempting to bypass "
                                  "the Antimalware Scan Interface."),
                       evidence=[_span(sm, script_src)]))
    if "gzipstream" in typ.lower() or "deflatestream" in typ.lower():
        out.append(_mk("payload_decompression", confidence=85,
                       rationale=f"Payload decompressed via `{typ}` — decode-time obfuscation.",
                       evidence=[_span(sm, script_src)]))


def _extract_from_ident_context(script: Script, out: list[Behavior]) -> None:
    """Text-level heuristics that don't need a full AST match — CLI flag
    detection (`-EncodedCommand`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`)."""
    text = script.src
    low = text.lower()
    if re.search(r"-executionpolicy\s+bypass|-ep\s+bypass", low):
        out.append(_mk("execution_policy_bypass", confidence=95,
                       rationale="`-ExecutionPolicy Bypass` disables script-execution restrictions."))
    if re.search(r"-windowstyle\s+hidden|-w(?:indow)?s?\s+hidden|-w\s+h(?:idden)?", low):
        out.append(_mk("hidden_window", confidence=90,
                       rationale="`-WindowStyle Hidden` conceals the PowerShell console from the user."))
    if re.search(r"-noprofile|-nop\b", low):
        out.append(_mk("no_profile", confidence=80,
                       rationale="`-NoProfile` bypasses profile scripts — reduces telemetry surface."))
    if re.search(r"-encodedcommand|-enc\b|-e\s+[A-Za-z0-9+/=]{16,}", low):
        out.append(_mk("encoded_command", confidence=95,
                       rationale="Payload delivered as `-EncodedCommand` Base64 blob — obfuscation."))
    # LOLBIN heuristics
    lolbins = ["rundll32", "regsvr32", "mshta", "certutil", "bitsadmin",
               "wmic", "installutil", "msbuild", "cscript", "wscript"]
    for lb in lolbins:
        if re.search(rf"\b{lb}(?:\.exe)?\b", low):
            out.append(_mk("lolbin_abuse", confidence=85,
                           rationale=f"Script chains through `{lb}` — a well-known Living-Off-the-Land binary."))
            break
    # AMSI text-level signals (bypass tricks that don't hit static method calls)
    if re.search(r"amsiinitfailed|amsiscanbuffer|amsiutils|amsi\.dll|"
                 r"system\.management\.automation\.amsiutils", low):
        out.append(_mk("amsi_bypass", confidence=95,
                       rationale=("Script references AMSI internals "
                                  "(`AmsiUtils` / `amsiInitFailed`) — classic bypass primitive.")))
    # Defender tampering text-level
    if re.search(r"set-mppreference|disablerealtimemonitoring|"
                 r"exclusionpath|preferences\\defender", low):
        out.append(_mk("defender_tamper", confidence=90,
                       rationale="Script disables or excludes paths from Defender scanning."))
    # Credential access text-level
    if re.search(r"mimikatz|sekurlsa|lsass\.dmp|convertto-securestring|"
                 r"get-credential|ntds\.dit|sam\.hive|sharphound|kerberoast", low):
        out.append(_mk("credential_access", confidence=90,
                       rationale="Script references credential-extraction tooling or LSASS artefacts."))


def _extract_url_ip_behaviors(script: Script, out: list[Behavior]) -> None:
    """Classify network endpoints — external → C2/beaconing candidate;
    loopback/private → local-only."""
    urls = _URL_RE.findall(script.src)
    ips  = _IP_RE.findall(script.src)
    ext = 0
    local = 0
    for u in urls:
        host = re.sub(r"^https?://", "", u).split("/", 1)[0].split(":", 1)[0].lower()
        if host in ("localhost", "127.0.0.1", "::1") or host.startswith("127."):
            local += 1
        elif re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", host):
            local += 1
        else:
            ext += 1
    for ip in ips:
        if ip.startswith("127.") or ip in ("0.0.0.0", "255.255.255.255"):
            local += 1
        elif re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", ip):
            local += 1
        else:
            ext += 1
    if ext > 0:
        out.append(_mk("external_network", confidence=85,
                       rationale=f"{ext} external endpoint(s) referenced in recovered script."))
        # A single external endpoint combined with an IEX/DownloadString call
        # deserves C2 / beaconing consideration. That combination is checked
        # by the caller after both extractors have run.
    if local > 0 and ext == 0:
        out.append(_mk("local_network_only", confidence=90,
                       rationale=("All observed network targets resolve to loopback / private "
                                  "address space — no external C2 candidate.")))


def _string_reconstruction_signal(script: Script, out: list[Behavior]) -> None:
    """Detect `-f`, `-join`, char-array, ToCharArray reconstruction — regardless of whether we could fold them."""
    text = script.src
    if re.search(r"\'\s*-f\s*", text, re.I) or re.search(r"\"\s*-f\s*", text, re.I):
        out.append(_mk("string_reconstruction", confidence=80,
                       rationale="Script uses the `-f` format operator to reconstruct strings at runtime."))
    if re.search(r"-join\s*(?:''|\"\"|\(|\$)", text, re.I):
        out.append(_mk("string_reconstruction", confidence=75,
                       rationale="Script uses `-join` to concatenate an array back into a string."))
    if re.search(r"\[char\s*\[\s*\]\s*\]", text, re.I) or re.search(r"tochararray\s*\(", text, re.I):
        out.append(_mk("char_array_join", confidence=80,
                       rationale="Script constructs strings from `[char[]]` array literals."))


def _c2_correlation(behaviors: list[Behavior]) -> None:
    """If both external network + download-and-execute primitives are present,
    escalate to C2 / beaconing candidate."""
    ids = {b.id for b in behaviors}
    delivery = ids & {"webclient_downloadstring", "webclient_downloadfile",
                      "invoke_webrequest", "invoke_restmethod",
                      "remote_script_download", "bits_download"}
    if "external_network" in ids and delivery and "invoke_expression" in ids:
        behaviors.append(_mk("c2_communication", confidence=85,
                             rationale=("External endpoint + delivery primitive + Invoke-Expression → "
                                        "download-and-execute chain typical of C2 stagers.")))


def _dedupe(behaviors: list[Behavior]) -> list[Behavior]:
    """Collapse duplicate behaviors — keep the highest-confidence + union
    of evidence spans."""
    by_id: dict[str, Behavior] = {}
    for b in behaviors:
        if b.id not in by_id:
            by_id[b.id] = b
            continue
        cur = by_id[b.id]
        # Merge evidence, keep highest confidence + first rationale
        seen_spans = {(e.get("span_start"), e.get("span_end")) for e in cur.evidence}
        for e in b.evidence:
            key = (e.get("span_start"), e.get("span_end"))
            if key not in seen_spans:
                cur.evidence.append(e)
                seen_spans.add(key)
        if b.confidence > cur.confidence:
            cur.confidence = b.confidence
    # Sort by severity then confidence
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(by_id.values(), key=lambda x: (order.get(x.severity, 5), -x.confidence))


def extract_behaviors(script: Script) -> list[Behavior]:
    """Main entry point. Walks the AST + text-level context and returns
    a deduplicated, sorted list of Behaviors."""
    out: list[Behavior] = []
    vars_ = script.variables

    for stmt in script.statements:
        for n in _all_children(stmt):
            if n.kind == "Call":
                _extract_from_call(n, script.src, vars_, out)
            elif n.kind == "MethodCall":
                _extract_from_method_call(n, script.src, vars_, out)
            elif n.kind == "StaticCall" or n.kind == "StaticMember":
                _extract_from_static_member(n, script.src, out)

    _extract_from_ident_context(script, out)
    _extract_url_ip_behaviors(script, out)
    _string_reconstruction_signal(script, out)
    # Text-level fallbacks — catch behaviors whose call node the AST
    # parser missed. Locked with SOC user 2026-07-27 during Phase 1
    # naked-script corpus expansion.
    _text_fallback_behaviors(script, out)
    _c2_correlation(out)
    return _dedupe(out)


# ── Text-level fallbacks ─────────────────────────────────────────
_TEXT_INVOKE_EXPR_RE = re.compile(r"\b(?:iex|invoke-expression)\b", re.IGNORECASE)
_TEXT_COMPRESSION_RE = re.compile(
    r"\b(?:gzip|deflate|brotli)stream\b|compressionmode\b|readtoend\(\)",
    re.IGNORECASE,
)


def _text_fallback_behaviors(script: "Script", out: list["Behavior"]) -> None:
    """Emit high-severity behaviors purely from a text-level scan when
    the AST call extractor missed them (common on naked scripts that
    the AST parser can't fully walk, e.g. `Invoke-Expression $s` after
    a semicolon on the same line)."""
    ids_present = {b.id for b in out}
    src = script.src or ""
    if _TEXT_INVOKE_EXPR_RE.search(src) and "invoke_expression" not in ids_present:
        out.append(_mk("invoke_expression", confidence=90,
                        rationale=("Script contains `Invoke-Expression`/`IEX` — "
                                    "dynamically evaluates recovered strings, a "
                                    "hallmark of fileless PS."),
                        evidence=[{"kind": "text_match", "value": "Invoke-Expression"}]))
        if "memory_execution" not in ids_present:
            out.append(_mk("memory_execution", confidence=80,
                            rationale=("`Invoke-Expression` executes code entirely "
                                        "in-memory — no persistent artefact is written."),
                            evidence=[{"kind": "text_match", "value": "Invoke-Expression"}]))
    if _TEXT_COMPRESSION_RE.search(src) and "payload_decompression" not in ids_present:
        out.append(_mk("payload_decompression", confidence=85,
                        rationale=("Script uses a compression stream "
                                    "(`GzipStream` / `DeflateStream` / `BrotliStream`) "
                                    "over a Base64 blob — a common evasion trick to "
                                    "hide a text payload behind another format."),
                        evidence=[{"kind": "text_match", "value": "CompressionStream"}]))


# ── Evidence Graph builder ───────────────────────────────────────
def build_evidence_graph(script: Script, behaviors: list[Behavior],
                         decoder_layers: list[dict] | None = None) -> dict:
    """Construct a node/edge graph the UI can render as Evidence Cards.

    Nodes: script | decoder_layer | behavior | ioc
    Edges: derives_from (decoder chain) | witnesses (behavior ← script) |
           observes (behavior ← ioc)
    """
    nodes: list[dict] = []
    edges: list[dict] = []

    # 1) Root script node
    nodes.append({
        "id": "script:root",
        "kind": "script",
        "label": "Recovered PowerShell",
        "meta": {"length": len(script.src), "statements": len(script.statements)},
    })

    # 2) Decoder layers (upstream provenance)
    prev_id = None
    for i, layer in enumerate(decoder_layers or []):
        nid = f"decoder:{i}"
        nodes.append({
            "id": nid, "kind": "decoder_layer",
            "label": layer.get("decoder") or f"layer_{i}",
            "meta": {
                "confidence": layer.get("confidence"),
                "in_len": layer.get("in_len"),
                "out_len": layer.get("out_len"),
                "why": (layer.get("why") or "")[:200],
                "layer": layer.get("layer"),
            },
        })
        if prev_id:
            edges.append({"src": prev_id, "dst": nid, "kind": "derives_from"})
        prev_id = nid
    if prev_id:
        edges.append({"src": prev_id, "dst": "script:root", "kind": "derives_from"})

    # 3) Behavior nodes + evidence edges
    for b in behaviors:
        bid = f"behavior:{b.id}"
        nodes.append({
            "id": bid, "kind": "behavior",
            "label": b.name,
            "meta": {"severity": b.severity, "confidence": b.confidence,
                     "mitre": b.mitre, "rationale": b.rationale},
        })
        # One `witnesses` edge per evidence span
        for e in b.evidence:
            edges.append({
                "src": bid, "dst": "script:root", "kind": "witnesses",
                "meta": {"span_start": e.get("span_start"),
                         "span_end": e.get("span_end"),
                         "snippet": e.get("snippet")},
            })
        if not b.evidence:
            edges.append({"src": bid, "dst": "script:root", "kind": "inferred"})

    # 4) IOC nodes (from script content)
    urls = sorted(set(_URL_RE.findall(script.src)))
    ips  = sorted(set(_IP_RE.findall(script.src)))
    for u in urls:
        nid = f"ioc:url:{u}"
        nodes.append({"id": nid, "kind": "ioc", "label": u,
                      "meta": {"type": "url"}})
        edges.append({"src": nid, "dst": "script:root", "kind": "observes"})
    for ip in ips:
        nid = f"ioc:ip:{ip}"
        nodes.append({"id": nid, "kind": "ioc", "label": ip,
                      "meta": {"type": "ip"}})
        edges.append({"src": nid, "dst": "script:root", "kind": "observes"})

    return {"nodes": nodes, "edges": edges,
            "stats": {"node_count": len(nodes), "edge_count": len(edges)}}
