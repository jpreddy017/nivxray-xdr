"""
DIE · Input Understanding Engine (IUE)
──────────────────────────────────────
Owner-locked 2026-02-28 · P0 orchestrator.

The IUE is the FIRST thing every Workspace paste passes through.  It
answers the two most important questions before *any* decoder or
analyzer touches the input:

    1. WHAT did the analyst give me?          (Input Type)
    2. WHAT am I going to do with it?          (Investigation Plan)

Then — and only then — the existing engines execute (DIE, DKP,
Chain, Attack Story, Report).  The plan is analyst-visible so the
Workspace stops feeling like a black-box and starts feeling like a
cohesive investigation platform.

Everything below is deterministic — no LLM, no randomness, no
network.  Same paste → same understanding, same plan, same trace.
"""
from __future__ import annotations
import base64
import binascii
import re
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Callable, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════
# 1. Input Type Taxonomy
# ══════════════════════════════════════════════════════════════════
#
# 21 first-class input types.  Ordering below IS the classifier
# priority — higher-fidelity signatures win over lower-fidelity ones.
#
INPUT_TYPES = (
    "powershell_encoded",     # -EncodedCommand / -enc / -ec + b64
    "powershell_naked",       # `powershell.exe` + tail script
    "nested_shell_chain",     # cmd/c "..." / mshta / rundll32 wrapper
    "command_chain",          # ;, &&, ||, & separators
    "single_command",         # one CLI line
    "pe_file",                # MZ...PE header
    "rtf_document",           # {\rtf
    "office_ole",             # OLE / OOXML magic
    "pdf_document",           # %PDF-
    "base64_blob",            # bare b64, no wrapper
    "hex_blob",               # long hex stream
    "gzip_blob",              # \x1f\x8b header
    "registry_export",        # Windows Registry Editor Version 5.00
    "windows_event_log",      # EventID / Provider Name markers
    "sysmon_log",             # Microsoft-Windows-Sysmon markers
    "process_tree",           # tree markers (└─ ├─ pid)
    "vendor_json",            # Talos/Mandiant/CrowdStrike/Defender JSON
    "vendor_report_text",     # mixed prose w/ vendor markers
    "url_only",               # bare URL
    "plain_text",             # analyst notes, no strong indicator
    "unknown",
)


# ══════════════════════════════════════════════════════════════════
# 2. Result models
# ══════════════════════════════════════════════════════════════════
@dataclass
class ContentSummary:
    """Counts of concrete things detected in the paste."""
    commands:        int = 0
    executables:     int = 0
    registry_keys:   int = 0
    file_paths:      int = 0
    urls:            int = 0
    ips:             int = 0
    hashes:          int = 0
    process_edges:   int = 0
    stages:          int = 0
    encoded_layers:  int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


@dataclass
class DecodeLayerPlan:
    """A single layer in the planned decode pipeline."""
    index:      int
    name:       str            # "Base64" · "UTF-16LE" · "GZip" · "PE recover"
    reason:     str            # why we think this layer is needed
    expected_bytes: Optional[int] = None
    confidence: float = 0.9

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlanStep:
    """One row in the analyst-visible checklist."""
    id:     str
    label:  str
    engine: str            # "extractor"|"decoder"|"die"|"dkp"|"attack_story"|"report"|"preprocessor"|"artifact_intel"
    status: str = "planned"   # planned|running|done|failed|skipped
    ms:     Optional[float] = None
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConfidenceMatrix:
    input_classification: float = 0.0
    decode_path:          float = 0.0
    language_detection:   float = 0.0
    estimated_recovery:   float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {k: round(v, 3) for k, v in asdict(self).items()}


@dataclass
class InputUnderstanding:
    input_type:       str
    label:            str        # human-friendly one-liner ("Multi-command Investigation")
    confidence:       float
    reasoning:        List[str]
    contents:         ContentSummary
    decode_required:  bool
    decode_reason:    str
    decode_layers:    List[DecodeLayerPlan]
    next_engine:      str
    next_engine_reason: str
    plan:             List[PlanStep]
    confidence_matrix: ConfidenceMatrix
    execution_trace:  List[PlanStep] = field(default_factory=list)
    engine_version:   str = "iue-1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_type":       self.input_type,
            "label":            self.label,
            "confidence":       round(self.confidence, 3),
            "reasoning":        list(self.reasoning),
            "contents":         self.contents.to_dict(),
            "decode_required":  self.decode_required,
            "decode_reason":    self.decode_reason,
            "decode_layers":    [d.to_dict() for d in self.decode_layers],
            "next_engine":      self.next_engine,
            "next_engine_reason": self.next_engine_reason,
            "plan":             [s.to_dict() for s in self.plan],
            "confidence_matrix": self.confidence_matrix.to_dict(),
            "execution_trace":  [s.to_dict() for s in self.execution_trace],
            "engine_version":   self.engine_version,
        }


# ══════════════════════════════════════════════════════════════════
# 3. Deterministic classifier
# ══════════════════════════════════════════════════════════════════
_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def _looks_like_base64(blob: str, min_len: int = 24) -> bool:
    if not blob or len(blob) < min_len:
        return False
    stripped = re.sub(r"\s+", "", blob)
    if not _B64_RE.match(stripped):
        return False
    if len(stripped) % 4 != 0:
        return False
    try:
        base64.b64decode(stripped, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _hex_ratio(text: str) -> float:
    stripped = re.sub(r"[\s\\x,0]", "", text)
    if not stripped:
        return 0.0
    hexish = sum(1 for c in stripped if c in "0123456789abcdefABCDEF")
    return hexish / max(1, len(stripped))


_PROSE_MARKERS = re.compile(
    r"(?im)^(the |talos |initial access|discovery|lateral movement|"
    r"executive summary|engagement \d|customer |defenders |result|"
    r"outcome|main research question|why (this|logs)|defensive)"
)
_VENDOR_MARKERS = re.compile(
    r"(?i)\b(cisco talos|talos ir|mandiant|crowdstrike|"
    r"microsoft defender|securex|falcon overwatch|"
    r"defender for endpoint|sentinel|palo alto unit 42|"
    r"kaspersky|checkpoint research)\b"
)
_VENDOR_JSON_MARKERS = re.compile(
    r"(?i)\"(?:AlertContext|entityType|serviceSource|creationTimeUtc|"
    r"detectionSource|Investigation|Incident|attack_intent|"
    r"CrowdStrike|Talos|SecureX|falcon_hostname|detection_ids?)\"\s*:"
)


def classify(text: str) -> Tuple[str, str, float, List[str]]:
    """Return (type, label, confidence, reasoning_bullets)."""
    if not text or not text.strip():
        return "unknown", "Empty input", 0.0, ["Nothing to classify."]

    src = text.strip()
    reasoning: List[str] = []

    # ── PE file ───────────────────────────────────────────────────
    if src[:2] == "MZ" or src[:4] == "\\x4d\\x5a":
        reasoning.append("MZ header detected at offset 0.")
        return "pe_file", "Portable Executable (PE)", 0.98, reasoning

    # ── PDF ───────────────────────────────────────────────────────
    if src[:5] == "%PDF-":
        reasoning.append("PDF magic header at offset 0.")
        return "pdf_document", "PDF Document", 0.99, reasoning

    # ── RTF ───────────────────────────────────────────────────────
    if src[:5] == "{\\rtf":
        reasoning.append("RTF magic header at offset 0.")
        return "rtf_document", "Rich Text Format Document", 0.99, reasoning

    # ── GZip ──────────────────────────────────────────────────────
    if src[:2] == "\x1f\x8b" or src[:8] == "1f8b0800":
        reasoning.append("GZip magic bytes detected.")
        return "gzip_blob", "GZip-compressed Blob", 0.97, reasoning

    # ── Windows Registry Export ───────────────────────────────────
    if "Windows Registry Editor Version" in src[:200]:
        reasoning.append("Registry Editor version banner present.")
        return "registry_export", "Windows Registry Export (.reg)", 0.98, reasoning

    # ── Sysmon log ────────────────────────────────────────────────
    if re.search(r"(?i)Microsoft[- ]Windows[- ]Sysmon", src[:5000]):
        reasoning.append("Sysmon provider markers detected.")
        return "sysmon_log", "Sysmon Event Log", 0.9, reasoning

    # ── Windows event log ─────────────────────────────────────────
    if (re.search(r"(?i)EventID[\":\s]+\d+", src[:5000])
        and re.search(r"(?i)Provider(?:Name|Guid)", src[:5000])):
        reasoning.append("Windows Event Log field markers detected.")
        return "windows_event_log", "Windows Event Log", 0.9, reasoning

    # ── Vendor JSON export ────────────────────────────────────────
    if src.lstrip()[:1] in "{[" and _VENDOR_JSON_MARKERS.search(src[:4000]):
        reasoning.append("JSON structure with vendor-specific field names.")
        return "vendor_json", "Vendor JSON Export", 0.9, reasoning

    # ── Mixed vendor / IR prose ───────────────────────────────────
    if len(src) >= 400 and (_VENDOR_MARKERS.search(src) or _PROSE_MARKERS.search(src)):
        lines = src.splitlines()
        non_command_lines = sum(1 for ln in lines if ln.strip() and not re.match(
            r"^\s*(cmd|powershell|pwsh|wmic|reg|sc|schtasks|net|"
            r"vssadmin|bcdedit|certutil|bitsadmin|rundll32|regsvr32|"
            r"mshta|msiexec|whoami|hostname|ipconfig|systeminfo|arp|"
            r"nltest|quser|ping|tracert|netstat|tasklist|taskkill|"
            r"ssh|scp|curl|wget|bash|python|node)\b", ln, re.I))
        if non_command_lines >= 4:
            reasoning.append(
                "Prose-heavy paste (vendor / IR report markers detected).")
            reasoning.append(f"{non_command_lines} narrative lines identified.")
            return "vendor_report_text", "Mixed Investigation (Vendor Report / IR Notes)", 0.9, reasoning

    # ── PowerShell EncodedCommand ─────────────────────────────────
    m = re.search(
        r"(?i)-e(?:nc(?:od(?:ed(?:command)?)?)?)?\s+(?P<b64>[A-Za-z0-9+/=]{24,})",
        src,
    )
    if m and _looks_like_base64(m.group("b64")):
        reasoning.append("Detected `-EncodedCommand` flag on PowerShell invocation.")
        reasoning.append(f"Base64 blob of {len(m.group('b64'))} chars (validated).")
        return "powershell_encoded", "PowerShell -EncodedCommand (base64 · UTF-16LE)", 0.97, reasoning

    # ── Nested shell chain (mshta/rundll32/etc wrapping a payload) ─
    if re.search(
        r"(?i)\b(cmd|powershell|pwsh|bash|sh|python|node|wscript|cscript|mshta|"
        r"rundll32|regsvr32|certutil|bitsadmin|msiexec)"
        r"(?:\.exe)?\b[^\n]*?(?:-c|-command|/c|-e|-EncodedCommand)\s+[\"']",
        src,
    ):
        reasoning.append("Nested shell invocation detected (host + `-c`/`/c` + quoted payload).")
        return "nested_shell_chain", "Nested Shell Chain (LOLBAS host + inline payload)", 0.9, reasoning

    # ── PowerShell (naked) ────────────────────────────────────────
    if re.search(r"(?i)\bpowershell(?:\.exe)?\b|\bpwsh(?:\.exe)?\b", src):
        reasoning.append("PowerShell interpreter reference detected.")
        return "powershell_naked", "PowerShell Command / Script", 0.9, reasoning

    if re.search(r"(?i)invoke-expression|invoke-webrequest|new-object\s+(?:system\.)?net\.|"
                 r"\[system\.\w+]::|frombase64string", src):
        reasoning.append("PowerShell-specific .NET / cmdlet markers detected.")
        return "powershell_naked", "PowerShell (naked script)", 0.85, reasoning

    # ── Command chain ─────────────────────────────────────────────
    hard_sep = sum(src.count(sep) for sep in (";", "&&", "||"))
    lines = [ln for ln in src.splitlines() if ln.strip()]
    if hard_sep >= 1 or len(lines) >= 3:
        reasoning.append(
            f"Multiple command steps detected ({hard_sep} explicit separators, {len(lines)} lines)."
        )
        return "command_chain", "Multi-command Investigation", 0.85, reasoning

    # ── URL only ──────────────────────────────────────────────────
    if re.fullmatch(r"\s*https?://\S+\s*", src):
        reasoning.append("Input is a bare URL.")
        return "url_only", "URL", 0.98, reasoning

    # ── Base64 blob (bare) ────────────────────────────────────────
    if _looks_like_base64(src.strip(), min_len=40):
        reasoning.append(f"Input is a validated base64 blob ({len(src.strip())} chars).")
        return "base64_blob", "Base64 Blob (no wrapper)", 0.9, reasoning

    # ── Hex blob ──────────────────────────────────────────────────
    if _hex_ratio(src) > 0.85 and len(re.sub(r"\s+", "", src)) >= 32:
        reasoning.append("Input is predominantly hex characters.")
        return "hex_blob", "Hex Blob", 0.85, reasoning

    # ── Single command / plain text fallback ──────────────────────
    if re.match(r"^\s*[A-Za-z][\w\-]*(?:\.exe)?\s+", src.splitlines()[0]) and len(lines) == 1:
        reasoning.append("Single CLI-shaped line detected.")
        return "single_command", "Single Command", 0.8, reasoning

    reasoning.append("No strong indicators — treating as plain analyst text.")
    return "plain_text", "Plain Text / Analyst Notes", 0.6, reasoning


# ══════════════════════════════════════════════════════════════════
# 4. Content summarizer (uses preprocessor when appropriate)
# ══════════════════════════════════════════════════════════════════
def _summarize_contents(text: str, input_type: str) -> Tuple[ContentSummary, Any]:
    """Return the counts + the PreprocessResult (or None)."""
    from .preprocessor import preprocess as _pp
    pre = None
    cs = ContentSummary()
    try:
        pre = _pp(text or "")
    except Exception:
        pre = None
    if pre:
        cs.commands = len([a for a in pre.artifacts if a.type == "command"])
        cs.executables = len([a for a in pre.artifacts if a.type in ("executable", "lolbin")])
        cs.registry_keys = len([a for a in pre.artifacts if a.type == "registry"])
        cs.file_paths = len([a for a in pre.artifacts if a.type in ("file_path", "unc_path")])
        cs.urls = len([a for a in pre.artifacts if a.type == "url"])
        cs.ips = len([a for a in pre.artifacts if a.type == "ip"])
        cs.hashes = len([a for a in pre.artifacts if a.type == "hash"])
        cs.process_edges = len(pre.process_edges)
        cs.stages = len(pre.stages)
    # Encoded layer estimation is done separately for encoded inputs.
    return cs, pre


# ══════════════════════════════════════════════════════════════════
# 5. Decode planner
# ══════════════════════════════════════════════════════════════════
def _plan_decode_layers(text: str, input_type: str) -> Tuple[bool, str, List[DecodeLayerPlan]]:
    """Decide whether decoding is required and, if so, plan the layers."""
    if input_type == "powershell_encoded":
        layers = [
            DecodeLayerPlan(1, "Base64",   "Decode the `-EncodedCommand` argument.", confidence=0.98),
            DecodeLayerPlan(2, "UTF-16LE", "PowerShell wire format for encoded commands.", confidence=0.98),
        ]
        # Look for classic secondary layers.
        if re.search(r"(?i)frombase64string|gzip|deflate|xor", text):
            layers.append(DecodeLayerPlan(3, "Inner Base64/GZip",
                          "Cradle strings hint at a second decode inside the recovered script.",
                          confidence=0.7))
        return True, "PowerShell `-EncodedCommand` detected.", layers

    if input_type == "base64_blob":
        layers = [DecodeLayerPlan(1, "Base64", "Bare Base64 payload; try direct decode.", confidence=0.9)]
        return True, "Input is a validated Base64 blob.", layers

    if input_type == "hex_blob":
        layers = [DecodeLayerPlan(1, "Hex", "Predominantly hex characters; try hex→bytes.", confidence=0.85)]
        return True, "Input is a hex-encoded stream.", layers

    if input_type == "gzip_blob":
        return True, "GZip magic bytes detected.", [
            DecodeLayerPlan(1, "GZip", "Inflate the compressed stream.", confidence=0.97),
        ]

    if input_type == "nested_shell_chain":
        return True, ("Wrapper shell (cmd/powershell/mshta/…) hosts an inline payload; "
                     "the CRE will peel one layer at a time."), [
            DecodeLayerPlan(1, "Command Reconstruction (CRE)",
                            "Peel host wrappers until the effective payload is bare.",
                            confidence=0.95),
        ]

    if input_type == "pe_file":
        return True, "PE binary — pass to the static PE analyzer, not the decoder chain.", [
            DecodeLayerPlan(1, "PE static analysis",
                            "Header + section table + imports parsing.", confidence=0.95),
        ]

    # Non-decodable inputs.
    if input_type in ("vendor_report_text", "vendor_json", "plain_text",
                     "windows_event_log", "sysmon_log", "registry_export",
                     "command_chain", "single_command", "powershell_naked",
                     "url_only", "unknown"):
        return False, "No encoded payload detected — proceeding directly to semantic analysis.", []

    return False, "No decode required.", []


# ══════════════════════════════════════════════════════════════════
# 6. Next-engine router
# ══════════════════════════════════════════════════════════════════
def _next_engine(input_type: str) -> Tuple[str, str]:
    return {
        "powershell_encoded":  ("Decoder → DIE (PowerShell)",
                                "Base64/UTF-16LE decode, then PowerShell semantic AST."),
        "powershell_naked":    ("DIE (PowerShell)",
                                "Direct PowerShell semantic AST analysis."),
        "nested_shell_chain":  ("CRE → DIE",
                                "Recursive wrapper peel then dispatch to the correct engine."),
        "command_chain":       ("Chain Analyzer → DIE per step",
                                "Multiple commands present — analyse each independently, then aggregate."),
        "single_command":      ("DIE (single-step)",
                                "One command line — direct DIE dispatch."),
        "pe_file":             ("Artifact Intelligence (PE)",
                                "Binary artifact — static PE analysis, not decoder chain."),
        "rtf_document":        ("Artifact Intelligence (RTF)",
                                "RTF stream extraction pipeline."),
        "office_ole":          ("Artifact Intelligence (Office)",
                                "OLE / OOXML macro analysis pipeline."),
        "pdf_document":        ("Artifact Intelligence (PDF)",
                                "PDF stream extractor pipeline."),
        "base64_blob":         ("Decoder (Base64) → Language classifier → DIE",
                                "Bare Base64 blob — decode first, then classify recovered content."),
        "hex_blob":            ("Decoder (Hex) → classifier → DIE",
                                "Hex payload — decode then classify."),
        "gzip_blob":           ("Decoder (GZip) → classifier",
                                "Inflate then classify."),
        "registry_export":     ("Preprocessor (registry route)",
                                "Registry entries route to the registry analyzer."),
        "windows_event_log":   ("Preprocessor (event-log route)",
                                "Event-log fields route to the event-log analyzer."),
        "sysmon_log":          ("Preprocessor (sysmon route)",
                                "Sysmon fields route to the sysmon analyzer."),
        "process_tree":        ("Preprocessor (process route)",
                                "Process tree → parent/child edges."),
        "vendor_json":         ("Vendor JSON adapter → Preprocessor → DIE",
                                "Vendor payload — normalise and extract stages."),
        "vendor_report_text":  ("Preprocessor → DIE per stage → Attack Story",
                                "Prose IR report — extract structured stages before analysing."),
        "url_only":            ("IOC enrichment (URL)",
                                "Single URL — enrichment only."),
        "plain_text":          ("Preprocessor (IOC-only)",
                                "No strong indicators — extract IOCs only."),
        "unknown":             ("Preprocessor (best-effort)",
                                "Fall back to universal extractor."),
    }.get(input_type, ("Preprocessor", "Default route."))


# ══════════════════════════════════════════════════════════════════
# 7. Plan step generator
# ══════════════════════════════════════════════════════════════════
def _build_plan(input_type: str, decode_required: bool,
                decode_layers: List[DecodeLayerPlan]) -> List[PlanStep]:
    steps: List[PlanStep] = []
    steps.append(PlanStep("classify", "Classify input type", "iue"))
    steps.append(PlanStep("understand", "Summarise input contents", "preprocessor"))

    if decode_required:
        for L in decode_layers:
            steps.append(PlanStep(
                f"decode_{L.index}",
                f"Decode Layer {L.index} — {L.name}",
                "decoder", detail=L.reason,
            ))

    if input_type in ("vendor_report_text", "vendor_json", "command_chain",
                      "registry_export", "sysmon_log", "windows_event_log",
                      "process_tree", "plain_text", "unknown"):
        steps.append(PlanStep("extract", "Extract commands / registry / paths / IOCs", "preprocessor"))
        steps.append(PlanStep("stages",  "Build ordered investigation stages", "preprocessor"))

    if input_type in ("powershell_encoded", "powershell_naked", "nested_shell_chain",
                      "command_chain", "single_command", "vendor_report_text",
                      "vendor_json", "plain_text"):
        steps.append(PlanStep("die",         "Run DIE (semantic AST + MITRE)", "die"))
        steps.append(PlanStep("dkp",         "DKP enrichment (family / tactic / narrative)", "dkp"))

    if input_type in ("pe_file", "rtf_document", "office_ole", "pdf_document"):
        steps.append(PlanStep("artifact_intel", "Run Artifact Intelligence (static analyser)", "artifact_intel"))

    steps.append(PlanStep("intent",      "Classify Attack Intent (ATT&CK tactic mix)", "die"))
    steps.append(PlanStep("story",       "Build Attack Story", "attack_story"))
    steps.append(PlanStep("report",      "Generate deterministic Report", "report"))
    return steps


# ══════════════════════════════════════════════════════════════════
# 8. Executor
# ══════════════════════════════════════════════════════════════════
def _execute_plan(text: str, plan: List[PlanStep], input_type: str,
                  analyze_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
                  ) -> Tuple[List[PlanStep], Dict[str, Any]]:
    """Runs the plan steps against the real engines and records the trace.

    ``analyze_fn`` — the DIE analyze function (injected to avoid a
    module cycle).
    Returns (execution_trace, analyse_envelope).
    """
    from .preprocessor import preprocess as _pp
    if analyze_fn is None:
        # Lazy import to break the cycle.
        from .api import analyze as _real_analyze
        analyze_fn = _real_analyze

    trace: List[PlanStep] = []
    envelope: Dict[str, Any] = {}
    pre = None

    for step in plan:
        s = PlanStep(
            id=step.id, label=step.label, engine=step.engine,
            status="running", detail=step.detail,
        )
        t0 = time.perf_counter()
        try:
            if s.id == "classify":
                s.detail = f"input_type={input_type}"
            elif s.id in ("understand", "extract", "stages"):
                if pre is None:
                    pre = _pp(text or "")
                if s.id == "extract":
                    s.detail = (
                        f"{len(pre.artifacts)} artifacts across "
                        f"{len(pre.stats.get('types', {}))} types"
                    )
                elif s.id == "stages":
                    s.detail = f"{len(pre.stages)} stages · {len(pre.process_edges)} process edges"
                else:
                    s.detail = f"{len(pre.artifacts)} artifacts summarised"
            elif s.id.startswith("decode_"):
                # Decode layers are executed transparently inside DIE
                # today.  We surface the intent + timing here; the
                # actual bytes recovered land on the envelope trace.
                s.detail = s.detail or "handled by DIE / CRE"
            elif s.id == "die":
                if not envelope:
                    envelope = analyze_fn(text) or {}
                lang = envelope.get("language") or "unknown"
                cmdlets = len(envelope.get("cmdlets", []) or [])
                s.detail = f"language={lang} · cmdlets={cmdlets}"
            elif s.id == "dkp":
                if not envelope:
                    envelope = analyze_fn(text) or {}
                dkp_hits = len(envelope.get("dkp_matches", []) or [])
                s.detail = f"{dkp_hits} DKP matches"
            elif s.id == "intent":
                if not envelope:
                    envelope = analyze_fn(text) or {}
                intent = envelope.get("attack_intent") or envelope.get("chain", {}).get("attack_intent") or {}
                primary = intent.get("primary_tactic") or "n/a"
                s.detail = f"primary_tactic={primary}"
            elif s.id == "story":
                if not envelope:
                    envelope = analyze_fn(text) or {}
                chain = envelope.get("chain") or {}
                step_count = chain.get("step_count") or len(envelope.get("cmdlets", []) or [])
                s.detail = f"{step_count} stages"
            elif s.id == "report":
                s.detail = "deterministic template ready"
            elif s.id == "artifact_intel":
                s.detail = "queued (static analyser dispatch)"
            else:
                s.detail = s.detail or "completed"
            s.status = "done"
        except Exception as exc:  # noqa: BLE001 — trace surfaces failures
            s.status = "failed"
            s.detail = f"{type(exc).__name__}: {exc}"
        s.ms = round((time.perf_counter() - t0) * 1000, 2)
        trace.append(s)

    return trace, envelope


# ══════════════════════════════════════════════════════════════════
# 9. Public API
# ══════════════════════════════════════════════════════════════════
def understand(text: str, *, execute: bool = True) -> InputUnderstanding:
    """Understand the input; optionally execute the plan and record
    the trace.  Determinism guaranteed — same text → same result.
    """
    input_type, label, base_conf, reasoning = classify(text)
    contents, pre = _summarize_contents(text, input_type)
    decode_required, decode_reason, decode_layers = _plan_decode_layers(text, input_type)
    contents.encoded_layers = len(decode_layers)
    next_engine, next_reason = _next_engine(input_type)
    plan = _build_plan(input_type, decode_required, decode_layers)

    # ── Confidence matrix (deterministic composition) ────────────
    cm = ConfidenceMatrix(
        input_classification=base_conf,
        decode_path=(
            min(1.0, sum(L.confidence for L in decode_layers) / max(1, len(decode_layers)))
            if decode_layers else (0.98 if not decode_required else 0.5)
        ),
        language_detection=(
            0.98 if input_type in ("powershell_encoded", "powershell_naked",
                                    "nested_shell_chain", "single_command",
                                    "command_chain") else
            0.8 if input_type in ("vendor_report_text", "vendor_json",
                                   "registry_export", "sysmon_log",
                                   "windows_event_log") else
            0.6
        ),
        estimated_recovery=(
            0.95 if input_type == "powershell_encoded" else
            0.9 if input_type in ("nested_shell_chain", "base64_blob", "gzip_blob") else
            0.85 if input_type in ("vendor_report_text", "command_chain") else
            0.75
        ),
    )

    understanding = InputUnderstanding(
        input_type=input_type, label=label,
        confidence=base_conf, reasoning=reasoning,
        contents=contents,
        decode_required=decode_required,
        decode_reason=decode_reason,
        decode_layers=decode_layers,
        next_engine=next_engine,
        next_engine_reason=next_reason,
        plan=plan,
        confidence_matrix=cm,
    )

    if execute:
        trace, _envelope = _execute_plan(text, plan, input_type)
        understanding.execution_trace = trace

    return understanding
