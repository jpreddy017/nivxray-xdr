"""
DIE · Investigation Results Renderer
────────────────────────────────────
Frozen 2026-03-01 as part of IUE v2.0.

The Investigation Results renderer replaces the legacy "OUTPUT" pane.
Whenever the IUE decides that the input does not require decoding
(plain PowerShell, CMD, Bash, vendor report, IOC list, Sigma, …) OR
when decoding has already been performed, the Workspace displays a
deterministic *investigation view* built from:

  · Input Understanding Engine     — input type, encoding, decode
                                     decision, extracted counts
  · Preprocessor                    — per-command stages + families +
                                     tactics + MITRE + commonly-
                                     observed-in
  · DIE analyze envelope           — LOLBAS, IOCs, MITRE
  · DKP (Decoder Knowledge Pack)   — family recognition + confidence
  · Attack Intent                  — deterministic threat objective

Everything below is deterministic — no LLM, no network, no
randomness.  Same paste → same investigation result text.

The renderer emits BOTH:
  · `output` — a plain-text formatted view suitable for the pane
  · `object` — a structured Canonical Investigation Object (SSOT)
              that downstream engines will consume in v2.1.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from .preprocessor import preprocess as preprocess_input
from .input_understanding import understand as understand_input
from .lolbas import lolbas_lookup, LOLBAS_REGISTRY  # noqa: F401
from .ioc_semantic import extract_iocs
from .intent import classify_intent_from_analyze
from .api import analyze


# ── Formatting helpers ────────────────────────────────────────────
_H1_WIDTH = 62
_H1_BORDER = "═" * _H1_WIDTH
_H2_BORDER = "─" * _H1_WIDTH


def _h1(title: str) -> str:
    return f"{_H1_BORDER}\n{title.upper()}\n{_H1_BORDER}"


def _h2(title: str) -> str:
    return f"{_H2_BORDER}\n{title}\n{_H2_BORDER}"


def _kv(label: str, value: Any, indent: int = 0) -> str:
    pad = " " * indent
    return f"{pad}{label:<20} {value}"


def _bullet(text: str, indent: int = 2) -> str:
    return f"{' ' * indent}• {text}"


def _empty(section: str) -> str:
    return f"  (none)"


# ── Renderer ──────────────────────────────────────────────────────
def render(input_text: str) -> Dict[str, Any]:
    """Render the full Investigation Results view for an input paste.

    Returns ``{output: str, object: dict}`` where ``output`` is the
    formatted text destined for the Workspace pane and ``object`` is
    the Canonical Investigation Object (SSOT) for downstream engines.
    """
    src = input_text or ""

    # 1) IUE — classification + plan
    understanding = understand_input(src, execute=False)
    u_dict = understanding.to_dict()

    # 2) Preprocessor — stages + artifacts + relationships
    pre = preprocess_input(src)

    # 3) DIE analyze — LOLBAS, MITRE, IOCs, DKP
    env = analyze(src)

    # 4) Attack intent — deterministic threat objective
    intent = classify_intent_from_analyze(env) or {}

    # 5) Aggregate IOCs — canonical shape
    iocs = env.get("iocs") or extract_iocs(src)
    ioc_by_kind: Dict[str, List[str]] = {}
    for i in iocs:
        k = (i.get("kind") or "unknown").lower()
        v = i.get("value") or i.get("indicator") or ""
        if v:
            ioc_by_kind.setdefault(k, []).append(v)

    # 6) LOLBAS surfaced by the analyze envelope
    lolbins = env.get("lolbins") or []

    # 7) MITRE surfaced by the analyze envelope
    techniques = env.get("techniques") or []

    # 8) DKP matches
    dkp_matches = env.get("dkp_matches") or []

    # ── Build the OUTPUT text ─────────────────────────────────────
    lines: List[str] = []

    # HERO
    lines.append(_h1("Investigation Results"))
    lines.append("")
    lines.append(u_dict.get("hero_sentence") or u_dict.get("label", ""))
    lines.append("")

    # ── INPUT UNDERSTANDING ──
    lines.append(_h1("Input Understanding"))
    lines.append("")
    lines.append(_kv("Input Type",       u_dict.get("label", "?")))
    lines.append(_kv("Classification",   u_dict.get("input_type", "?")))
    lines.append(_kv("Confidence",       f"{int((u_dict.get('confidence') or 0) * 100)}%"))
    lines.append(_kv("Language",         (env.get("language") or "n/a")))
    lines.append(_kv("Decode Required",  "YES" if u_dict.get("decode_required") else "NO"))
    if u_dict.get("decode_reason"):
        lines.append(_kv("Decode Reason",    u_dict["decode_reason"]))
    lines.append(_kv("Next Engine",      u_dict.get("next_engine", "?")))
    lines.append("")

    contents = u_dict.get("contents") or {}
    lines.append("Extracted Contents")
    lines.append(_kv("Commands",       contents.get("commands", 0), indent=2))
    lines.append(_kv("Executables",    contents.get("executables", 0), indent=2))
    lines.append(_kv("Registry Keys",  contents.get("registry_keys", 0), indent=2))
    lines.append(_kv("File Paths",     contents.get("file_paths", 0), indent=2))
    lines.append(_kv("URLs",           contents.get("urls", 0), indent=2))
    lines.append(_kv("IPs",            contents.get("ips", 0), indent=2))
    lines.append(_kv("Hashes",         contents.get("hashes", 0), indent=2))
    lines.append(_kv("Process Edges",  contents.get("process_edges", 0), indent=2))
    lines.append(_kv("Stages",         contents.get("stages", 0), indent=2))
    lines.append("")

    reasoning = u_dict.get("reasoning") or []
    if reasoning:
        lines.append("Reasoning")
        for r in reasoning:
            lines.append(_bullet(r))
        lines.append("")

    # ── COMMAND ANALYSIS ──
    lines.append(_h1("Command Analysis"))
    lines.append("")
    stages = pre.stages
    if not stages:
        lines.append("  (no commands recognised)")
        lines.append("")
    else:
        for i, s in enumerate(stages, start=1):
            title = s.title or (s.normalized_command or "")[:80]
            lines.append(_h2(f"Command {i} · {title}"))
            lines.append("")
            if s.normalized_command and s.normalized_command != title:
                lines.append(_kv("Command",   s.normalized_command[:200]))
            if s.objective:
                lines.append(_kv("Purpose",   s.objective))
            if s.tactic:
                lines.append(_kv("Tactic",    s.tactic))
            if s.mitre:
                lines.append(_kv("MITRE",     ", ".join(s.mitre)))
            if s.command_family:
                lines.append(_kv("Family",    s.command_family))
            if s.commonly_observed_in:
                lines.append(_kv("Commonly Observed In",
                               ", ".join(s.commonly_observed_in[:5])))
            lines.append(_kv("Confidence",  f"{int(s.confidence * 100)}%"))
            risk = _risk_for_tactic(s.tactic)
            if risk:
                lines.append(_kv("Risk",      risk))
            if s.evidence:
                lines.append("")
                lines.append("  Evidence")
                for e in s.evidence[:5]:
                    lines.append(_bullet(e, indent=4))
            lines.append("")

    # ── IOC ANALYSIS ──
    lines.append(_h1("IOC Analysis"))
    lines.append("")
    if not ioc_by_kind:
        lines.append("  (no IOCs extracted)")
        lines.append("")
    else:
        for kind in ("ip", "url", "domain", "hash", "email",
                     "file_path", "registry", "service"):
            values = ioc_by_kind.get(kind) or []
            if not values:
                continue
            label = {
                "ip":         "IPs",
                "url":        "URLs",
                "domain":     "Domains",
                "hash":       "Hashes",
                "email":      "Emails",
                "file_path":  "File Paths",
                "registry":   "Registry Keys",
                "service":    "Services",
            }.get(kind, kind.capitalize())
            lines.append(_h2(label))
            for v in values[:15]:
                lines.append(_bullet(v))
            if len(values) > 15:
                lines.append(_bullet(f"… and {len(values) - 15} more"))
            lines.append("")

    # ── LOLBAS ANALYSIS ──
    lines.append(_h1("LOLBAS Analysis"))
    lines.append("")
    if not lolbins:
        lines.append("  (no LOLBAS binaries observed)")
        lines.append("")
    else:
        seen = set()
        for lb in lolbins:
            binary = (lb.get("binary") or "").lower()
            if binary in seen or not binary:
                continue
            seen.add(binary)
            entry = lolbas_lookup(binary) or {}
            lines.append(_h2(binary))
            legit = entry.get("legit") or entry.get("legitimate") or ""
            abuse = entry.get("abuse")  or entry.get("observed_abuse") or ""
            mitre = entry.get("mitre")  or lb.get("mitre") or []
            detection = entry.get("detection") or entry.get("detection_ideas") or []
            if legit:  lines.append(_kv("Legitimate Purpose", legit))
            if abuse:  lines.append(_kv("Observed Abuse", abuse))
            if mitre:  lines.append(_kv("MITRE", ", ".join(mitre)))
            if detection:
                lines.append("")
                lines.append("  Detection Ideas")
                for d in (detection[:4] if isinstance(detection, list) else [detection]):
                    lines.append(_bullet(d, indent=4))
            lines.append("")

    # ── MITRE COVERAGE ──
    lines.append(_h1("MITRE ATT&CK Coverage"))
    lines.append("")
    if not techniques:
        lines.append("  (no MITRE techniques mapped)")
        lines.append("")
    else:
        by_tactic: Dict[str, List[Dict[str, Any]]] = {}
        for t in techniques:
            tac = t.get("tactic") or t.get("tactic_name") or "Other"
            by_tactic.setdefault(tac, []).append(t)
        for tactic in sorted(by_tactic.keys()):
            lines.append(_h2(tactic))
            for t in by_tactic[tactic][:15]:
                tid = t.get("id") or ""
                name = t.get("name") or ""
                ev = t.get("evidence") or ""
                bullet = f"{tid} — {name}" if name else tid
                lines.append(_bullet(bullet))
                if ev:
                    lines.append(f"      evidence: {ev}")
            lines.append("")

    # ── DKP MATCHES ──
    if dkp_matches:
        lines.append(_h1("Decoder Knowledge Pack (DKP)"))
        lines.append("")
        for m in dkp_matches[:10]:
            name = m.get("name") or m.get("family") or m.get("id") or "?"
            conf = m.get("confidence")
            conf_str = f"{int(conf * 100)}%" if isinstance(conf, (int, float)) else "?"
            lines.append(_h2(f"{name}  ·  {conf_str}"))
            desc = m.get("description") or m.get("summary") or ""
            if desc:
                lines.append(desc)
            observed = m.get("commonly_observed_in") or []
            if observed:
                lines.append("")
                lines.append(_kv("Commonly Observed In",
                               ", ".join(observed[:5])))
            lines.append("")

    # ── SUMMARY ──
    lines.append(_h1("Summary"))
    lines.append("")
    lines.append(_kv("Threat Objective",   intent.get("primary_objective") or intent.get("objective") or "Undetermined"))
    lines.append(_kv("Attack Progress",    f"{intent.get('progress_pct', 0)}%"))
    lines.append(_kv("Confidence",         f"{int((intent.get('confidence') or 0) * 100)}%"))
    lines.append(_kv("Commands Extracted", contents.get("commands", 0)))
    lines.append(_kv("LOLBAS",             len({(lb.get('binary') or '').lower() for lb in lolbins if lb.get('binary')})))
    lines.append(_kv("MITRE Techniques",   len(techniques)))
    lines.append(_kv("IOCs",               sum(len(v) for v in ioc_by_kind.values())))
    lines.append("")

    # Not-attribution disclaimer (WORKSPACE_ARCHITECTURE_RULES.md · R5).
    lines.append("Not attribution — historical prevalence only.")
    lines.append("Every conclusion links back to extracted evidence.")
    lines.append("")

    output = "\n".join(lines)

    # ── Canonical Investigation Object (SSOT) ──
    canonical: Dict[str, Any] = {
        "metadata": {
            "engine_version":  "iue-2.0.0-slice-1",
            "input_bytes":     len(src),
            "language":        env.get("language"),
        },
        "input":               {"raw": src},
        "profiling":           {
            "input_type":      u_dict.get("input_type"),
            "label":           u_dict.get("label"),
            "confidence":      u_dict.get("confidence"),
            "reasoning":       u_dict.get("reasoning"),
            "contents":        contents,
        },
        "understanding":       u_dict,
        "commands":            [_command_to_ssot(s) for s in stages],
        "iocs":                ioc_by_kind,
        "lolbas":              [_lolbas_to_ssot(lb) for lb in lolbins],
        "mitre":               techniques,
        "dkp":                 dkp_matches,
        "preprocessor":        pre.to_dict(),
        "intent":              intent,
        "engines_selected":    u_dict.get("engines_selected", []),
        "engines_skipped":     u_dict.get("engines_skipped", []),
    }

    return {"output": output, "object": canonical}


# ── Helpers ───────────────────────────────────────────────────────
def _risk_for_tactic(tactic: Optional[str]) -> Optional[str]:
    if not tactic:
        return None
    return {
        "Impact":               "Critical",
        "Command and Control":  "High",
        "Exfiltration":         "High",
        "Lateral Movement":     "High",
        "Persistence":          "High",
        "Defense Evasion":      "Medium",
        "Execution":            "Medium",
        "Discovery":            "Medium",
        "Initial Access":       "High",
    }.get(tactic, "Medium")


def _command_to_ssot(stage) -> Dict[str, Any]:
    return {
        "id":                    stage.id,
        "index":                 stage.index,
        "title":                 stage.title,
        "kind":                  stage.kind,
        "objective":             stage.objective,
        "tactic":                stage.tactic,
        "mitre":                 list(stage.mitre or []),
        "family":                stage.command_family,
        "commonly_observed_in":  list(stage.commonly_observed_in or []),
        "normalized_command":    stage.normalized_command,
        "raw_excerpt":           stage.raw_excerpt,
        "line_number":           stage.line_number,
        "confidence":            stage.confidence,
        "risk":                  _risk_for_tactic(stage.tactic),
    }


def _lolbas_to_ssot(lb: Dict[str, Any]) -> Dict[str, Any]:
    binary = (lb.get("binary") or "").lower()
    entry = lolbas_lookup(binary) or {}
    return {
        "binary":            binary,
        "legit":             entry.get("legit") or entry.get("legitimate", ""),
        "abuse":             entry.get("abuse")  or entry.get("observed_abuse", ""),
        "mitre":             entry.get("mitre")  or lb.get("mitre") or [],
        "detection":         entry.get("detection") or entry.get("detection_ideas") or [],
    }
