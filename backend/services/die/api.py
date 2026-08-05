"""
DIE · orchestrator
──────────────────
Single-entry ``analyze(...)`` API used by the FastAPI router and the
internal recursive pipeline.  Dispatches to the right sub-analyzer
based on a lightweight language signal, then merges outputs into a
uniform envelope so callers never have to branch on language.
"""
from __future__ import annotations
import re
from typing import Any, Dict, Optional

from .powershell_ast import parse_powershell
from .cmd_ast        import parse_cmd
from .javascript_ast import parse_javascript
from .vbscript_ast   import parse_vbscript
from .bash_ast       import parse_bash
from .python_ast     import parse_python
from .lolbas import lolbas_lookup
from .ioc_semantic import extract_iocs, summarize_iocs
from .dkp import match as dkp_match
from .chain import analyze_chain, looks_like_chain
from .preprocessor import preprocess as preprocess_input, PreprocessResult

# ── language detector ─────────────────────────────────────────────
_PS_HINTS = re.compile(
    r"(?i)"
    r"(powershell(\.exe)?\s|-encodedcommand|-nop|\biex[\s\(]|invoke-expression|"
    r"invoke-webrequest|new-object\s+(?:system\.)?net\.|invoke-restmethod|"
    r"\$env:|\[system\.\w+]::|frombase64string|\.downloadstring\(|"
    r"\.downloadfile\(|start-bitstransfer)"
)
_CMD_HINTS = re.compile(
    r"(?i)(^|\s|&)(cmd\.exe|\bset\s+[A-Z_]+=|%[A-Z_]+%|!\w+!|\bfor\s+/[a-z]|"
    r"\bcall\s+|\bstart\s+/|\bschtasks\b|\breg\s+add\b|\bwmic\b|"
    r"\bvssadmin\b|\bwbadmin\b|\bbcdedit\b|\bnetsh\b|\btasklist\b|"
    r"\btaskkill\b|\bcertutil\b|\bbitsadmin\b|\brundll32\b|\bregsvr32\b|"
    r"\bmshta\b|\bmsiexec\b|\bcopy\s+\\\\|\bxcopy\s+|"
    # Common bare Windows discovery / system verbs.
    r"^(whoami|hostname|ipconfig|systeminfo|arp|nltest|query|nslookup|"
    r"tracert|ping\b|route\s+print)\b|"
    r"\bnet\s+(user|group|localgroup|view|use|start|stop|share|accounts)\b|"
    r"\bwmic\s+\w+\s+(get|call)\b)"
)
_JS_HINTS = re.compile(
    r"(?i)(new\s+ActiveXObject|WScript\.Shell|createobject\(|eval\(|"
    r"function\s+\w+\s*\(|=>\s*\{|require\(|\.prototype\.|document\.write)"
)
_VBS_HINTS = re.compile(
    r"(?i)(\bDim\s+\w+|Set\s+\w+\s*=\s*Create[Oo]bject|End\s+Sub|End\s+Function|"
    r"On\s+Error\s+Resume|WScript\.CreateObject)"
)
_BASH_HINTS = re.compile(
    r"(?i)(^#!\s*/(bin|usr).*sh|\becho\s+-n\s+|curl\s+-|wget\s+|/bin/sh\b|/bin/bash\b)"
)


_PY_HINTS = re.compile(
    r"(?im)(^\s*(?:from|import)\s+\w|^\s*def\s+\w+\s*\(|^\s*class\s+\w+\s*[\(:]|"
    r"print\(|subprocess\.|__import__|urllib\.request|requests\.(?:get|post))"
)


def detect_language(src: str) -> str:
    """Return one of ``powershell|cmd|javascript|vbscript|bash|unknown``.

    Deterministic priority order: PowerShell dominates when both PS
    and CMD hints exist (the majority of dual-string launchers wrap
    PowerShell). This ordering is stable so repeated runs match.
    """
    if not src:
        return "unknown"
    if _PS_HINTS.search(src):
        return "powershell"
    # VBScript checked before JavaScript because `createobject(` triggers
    # both — but Dim/Set/End Sub is a VBScript-only signature.
    if _VBS_HINTS.search(src):
        return "vbscript"
    # Python check comes before JavaScript because both use eval/exec —
    # but `def x():` / `import x` are Python-only.
    if _PY_HINTS.search(src):
        return "python"
    if _JS_HINTS.search(src):
        return "javascript"
    if _CMD_HINTS.search(src):
        return "cmd"
    if _BASH_HINTS.search(src):
        return "bash"
    return "unknown"


def analyze(src: str, language: Optional[str] = None) -> Dict[str, Any]:
    """Single-entry semantic analysis over any command-line input.

    Cycle A ships PowerShell fully.  Non-PowerShell inputs receive a
    minimal envelope with IOC + LOLBAS + language classification so
    downstream analyzers can still act.  Cycle B replaces the stubs
    with real ASTs.
    """
    if not src:
        return _empty_envelope("unknown")

    # ── Preprocessor gate (P0 · 2026-02-28) ──────────────────────
    # When the caller pasted unstructured / mixed analyst text (blog
    # post, IR report, SOC notes) we route through the deterministic
    # preprocessor FIRST.  It decomposes the paste into structured
    # artifacts + ordered stages, then we hand those stages down as
    # a synthesised chain — the frozen v1.1 core sees a well-formed
    # multi-step chain envelope and never sees the raw prose.
    if language is None and _looks_like_mixed_input(src):
        pre = preprocess_input(src)
        # Only take over when the preprocessor found ≥2 stages — one
        # stage means "regular command", which the existing paths
        # already handle correctly.
        if pre.stage_count() >= 2:
            return _preprocessor_to_envelope(pre, src)

    # Chain fast-path (Phase B.2 · 2026-02-16 pm) — when the input
    # contains a shell chain (`&`, `&&`, `||`, `|`, `;`, newlines) OR
    # a nested-shell payload, run the chain analyzer so analysts see
    # a per-step timeline instead of one flat envelope.  ``language``
    # is only honoured on single-step inputs; explicit language for a
    # chain is nonsensical because each step may differ.
    if language is None and looks_like_chain(src):
        chain_env = analyze_chain(src, analyze_fn=_analyze_single)
        # Only *actually* return the chain envelope when the split
        # produced more than one step.  A single-step "chain" is the
        # original flat input — pass through cleanly.
        if chain_env["step_count"] > 1:
            env = _chain_to_envelope(chain_env)
            _attach_preprocessor(env, src)
            return env

    env = _analyze_single(src, language=language)
    _attach_preprocessor(env, src)
    return env


def _attach_preprocessor(env: Dict[str, Any], src: str) -> None:
    """Additively attach a preprocessor bundle to any analyze envelope.

    This is the single source of truth that guarantees the frontend
    Trajectory Diagram + Inline Attack Story render for EVERY input
    — plain commands, chains, or prose — as long as the preprocessor
    can build at least one deterministic stage.
    """
    if "preprocessor" in env and env.get("preprocessor"):
        return
    try:
        pre = preprocess_input(src or "")
    except Exception:
        return
    if pre.stage_count() >= 1:
        env["preprocessor"] = {
            "artifacts":     [a.to_dict() for a in pre.artifacts],
            "stages":        [s.to_dict() for s in pre.stages],
            "process_edges": [e.to_dict() for e in pre.process_edges],
            "stats":         dict(pre.stats),
        }


def _analyze_single(src: str, language: Optional[str] = None) -> Dict[str, Any]:
    if not src:
        return _empty_envelope("unknown")
    lang = language or detect_language(src)

    if lang == "powershell":
        ast = parse_powershell(src)
        env = {
            "language":  "powershell",
            "ast":       ast,
            "cmdlets":   ast["cmdlets"],
            "lolbins":   ast["lolbins"],
            "techniques": ast["techniques"],
            "iocs":      ast["iocs"],
            "iocs_summary": summarize_iocs(ast["iocs"]),
            "obfuscation_score": ast["complexity"]["obfuscation_score"],
            "_raw_source": src,
        }
        env["dkp_matches"] = [m.to_dict() for m in dkp_match(env)]
        from .intent import classify_intent_from_analyze
        env["attack_intent"] = classify_intent_from_analyze(env)
        env.pop("_raw_source", None)
        return env

    # Cycle B — dispatch to the language-specific AST.  Every parser
    # returns the same-shape envelope so callers don't need to branch.
    if lang == "cmd":
        ast = parse_cmd(src)
    elif lang == "javascript":
        ast = parse_javascript(src)
    elif lang == "vbscript":
        ast = parse_vbscript(src)
    elif lang == "bash":
        ast = parse_bash(src)
    elif lang == "python":
        ast = parse_python(src)
    else:
        env = {
            "language":       lang,
            "ast":            None,
            "cmdlets":        [],
            "lolbins":        _scan_lolbins(src),
            "techniques":     _lolbin_techniques(_scan_lolbins(src)),
            "iocs":           extract_iocs(src),
            "iocs_summary":   summarize_iocs(extract_iocs(src)),
            "obfuscation_score": 0,
            "_raw_source":    src,
        }
        env["dkp_matches"] = [m.to_dict() for m in dkp_match(env)]
        env.pop("_raw_source", None)
        return env

    env = {
        "language":         lang,
        "ast":              ast,
        "cmdlets":          ast.get("commands", []),
        "lolbins":          ast.get("lolbins", []),
        "techniques":       ast.get("techniques", []),
        "iocs":             ast.get("iocs", []),
        "iocs_summary":     ast.get("iocs_summary", {}),
        "obfuscation_score": ast.get("complexity", {}).get("obfuscation_score", 0),
        "_raw_source":      src,
    }
    env["dkp_matches"] = [m.to_dict() for m in dkp_match(env)]
    from .intent import classify_intent_from_analyze
    env["attack_intent"] = classify_intent_from_analyze(env)
    env.pop("_raw_source", None)
    return env


def analyze_powershell(src: str) -> Dict[str, Any]:
    return analyze(src, language="powershell")


def analyze_command(src: str) -> Dict[str, Any]:
    return analyze(src, language=None)


# ── helpers ───────────────────────────────────────────────────────
def _empty_envelope(lang: str) -> Dict[str, Any]:
    return {
        "language": lang, "ast": None, "cmdlets": [], "lolbins": [],
        "techniques": [], "iocs": [], "iocs_summary": {},
        "obfuscation_score": 0,
    }


def _scan_lolbins(src: str):
    seen: Dict[str, Dict[str, Any]] = {}
    for m in re.finditer(r"[A-Za-z][\w\-]*\.exe", src, re.I):
        entry = lolbas_lookup(m.group(0))
        if entry:
            key = m.group(0).lower()
            seen[key] = {"binary": key, **entry}
    return sorted(seen.values(), key=lambda x: x["binary"])


def _lolbin_techniques(lolbins):
    seen: Dict[str, Dict[str, str]] = {}
    for lb in lolbins:
        for t in lb.get("mitre", []) or []:
            seen[t] = {"id": t, "name": "", "evidence": f"LOLBAS: {lb['binary']}"}
    return sorted(seen.values(), key=lambda x: x["id"])


def _chain_to_envelope(chain_env: Dict[str, Any]) -> Dict[str, Any]:
    """Adapt a ``analyze_chain`` result into the top-level ``analyze``
    envelope shape so existing consumers (router · CEM emitter) keep
    working without a branch.  The full per-step detail lives on the
    ``chain`` key; the flat fields are the *aggregate union* across
    every step."""
    agg = chain_env["aggregate"]
    return {
        "language":          chain_env["primary_language"],
        "chain":             chain_env,
        "ast":               None,      # per-step ASTs live inside `chain.steps`
        "cmdlets":           [],
        "lolbins":           agg["lolbins"],
        "techniques":        agg["techniques"],
        "iocs":              agg["iocs"],
        "iocs_summary":      _summarize_agg(agg["iocs"]),
        "dkp_matches":       agg["dkp_matches"],
        "obfuscation_score": max((s.get("obfuscation_score", 0)
                                  for s in chain_env["steps"]), default=0),
    }


def _summarize_agg(iocs):
    from .ioc_semantic import summarize_iocs
    return summarize_iocs(iocs)


# ── Preprocessor bridge (P0 · 2026-02-28) ─────────────────────────
# Heuristic: input is "mixed / unstructured" when it looks more like
# prose than a shell chain.  Deterministic rules — same input, same
# routing decision:
#   1. contains ≥ 6 lines AND
#   2. line-count / hard-separator-count ≥ 3 (i.e. many more lines
#      than `;`, `&&`, `||`, `&`) AND
#   3. at least one line begins with a natural-language capital word
#      (not a shell verb) OR contains prose markers like ": " on a
#      non-command line.
_PROSE_MARKERS = re.compile(
    r"(?im)^(the |talos |initial access|discovery|lateral movement|"
    r"executive summary|engagement \d|customer |defenders |result|"
    r"outcome|main research question|why (this|logs)|defensive)"
)


def _looks_like_mixed_input(src: str) -> bool:
    if not src or len(src) < 200:
        return False
    lines = src.splitlines()
    if len(lines) < 6:
        return False
    hard_seps = sum(src.count(sep) for sep in (";", "&&", "||"))
    if len(lines) < hard_seps * 2:
        return False
    if _PROSE_MARKERS.search(src):
        return True
    # Fallback: lots of lines that don't look like commands.
    non_command_lines = sum(
        1 for ln in lines
        if ln.strip() and not re.match(
            r"^\s*(cmd|powershell|pwsh|wmic|reg|sc|schtasks|net|"
            r"vssadmin|bcdedit|certutil|bitsadmin|rundll32|regsvr32|"
            r"mshta|msiexec|whoami|hostname|ipconfig|systeminfo|arp|"
            r"nltest|quser|ping|tracert|netstat|tasklist|taskkill|"
            r"ssh|scp|curl|wget|bash|python|node)\b", ln, re.I,
        )
    )
    return non_command_lines >= 6


def _preprocessor_to_envelope(pre: "PreprocessResult", src: str) -> Dict[str, Any]:
    """Adapt a PreprocessResult into the top-level ``analyze`` envelope.

    We synthesise a chain-style envelope from the extracted stages so
    every downstream consumer (CEM · verdict · investigation · Attack
    Story) keeps working without a single schema change.
    """
    from copy import deepcopy
    from .intent import classify_intent as _intent

    steps: list = []
    languages_seen: Dict[str, int] = {}
    aggregate_techniques: Dict[str, Dict[str, Any]] = {}
    aggregate_lolbins:    Dict[str, Dict[str, Any]] = {}
    aggregate_iocs:       Dict[str, Dict[str, Any]] = {}
    aggregate_dkp:        Dict[str, Dict[str, Any]] = {}

    for stage in pre.stages:
        # Prefer the normalized command; fall back to a synthetic
        # verb so single-token / prose stages still analyse.
        step_text = stage.normalized_command or stage.raw_excerpt or stage.title
        step_lang = None
        step_env = _analyze_single(step_text, language=step_lang) if step_text else _empty_envelope("unknown")
        step_env = deepcopy(step_env)
        step_env.pop("_raw_source", None)

        tactic = _stage_tactic(stage) or classify_step_intent(step_env, step_text)

        step_record = {
            "index":      stage.index,
            "text":       step_text,
            "parent":     None,
            "language":   step_env.get("language"),
            "intent":     tactic,
            "summary":    _stage_summary(stage, step_env, step_text),
            "techniques": step_env.get("techniques", []),
            "lolbins":    step_env.get("lolbins", []),
            "iocs":       step_env.get("iocs", []),
            "dkp_matches": step_env.get("dkp_matches", []),
            "obfuscation_score": step_env.get("obfuscation_score", 0),
            "ast":        step_env.get("ast"),
            # Preprocessor provenance — new fields, additive:
            "preprocessor_stage": {
                "id":                 stage.id,
                "kind":               stage.kind,
                "title":              stage.title,
                "command_family":     stage.command_family,
                "line_number":        stage.line_number,
                "raw_excerpt":        stage.raw_excerpt,
                "artifact_ids":       list(stage.artifact_ids),
                "confidence":         stage.confidence,
            },
        }
        steps.append(step_record)
        languages_seen[step_env.get("language") or "unknown"] = \
            languages_seen.get(step_env.get("language") or "unknown", 0) + 1
        for t in step_record["techniques"]:
            aggregate_techniques.setdefault(t["id"], t)
        for lb in step_record["lolbins"]:
            aggregate_lolbins.setdefault(lb["binary"], lb)
        for i in step_record["iocs"]:
            aggregate_iocs.setdefault(f"{i['kind']}:{i['value']}", i)
        for m in step_record["dkp_matches"]:
            prev = aggregate_dkp.get(m["id"])
            if prev is None or prev["confidence"] < m["confidence"]:
                aggregate_dkp[m["id"]] = m

    primary = max(languages_seen.items(), key=lambda kv: kv[1])[0] if languages_seen else "unknown"

    bullets = [f"Step {s['index']} — {s['intent']} · {s['summary']}" for s in steps]
    chain_env = {
        "input":            src,
        "chain":            True,
        "step_count":       len(steps),
        "primary_language": primary,
        "languages_seen":   languages_seen,
        "steps":            steps,
        "narrative_bullets": bullets,
        "aggregate": {
            "techniques":  sorted(aggregate_techniques.values(),
                                  key=lambda t: t["id"]),
            "lolbins":     sorted(aggregate_lolbins.values(),
                                  key=lambda l: l["binary"]),
            "iocs":        sorted(aggregate_iocs.values(),
                                  key=lambda i: (i["kind"], i["value"])),
            "dkp_matches": sorted(aggregate_dkp.values(),
                                  key=lambda m: (-m["confidence"], m["id"])),
        },
        "attack_intent":  _intent({
            "steps": steps,
            "aggregate": {
                "techniques":  list(aggregate_techniques.values()),
                "dkp_matches": list(aggregate_dkp.values()),
            },
        }),
        # Preprocessor summary — new key, additive:
        "preprocessor": {
            "artifacts":      [a.to_dict() for a in pre.artifacts],
            "stages":         [s.to_dict() for s in pre.stages],
            "process_edges":  [e.to_dict() for e in pre.process_edges],
            "stats":          dict(pre.stats),
        },
    }

    env = _chain_to_envelope(chain_env)
    env["preprocessor"] = chain_env["preprocessor"]
    return env


def _stage_tactic(stage) -> Optional[str]:
    """Return the ATT&CK tactic bucket implied by the stage family."""
    return {
        "reverse-ssh-tunnel":         "Command and Control",
        "shadow-copy-deletion":       "Impact",
        "ad-discovery":               "Discovery",
        "ad-enumeration":             "Discovery",
        "host-discovery":             "Discovery",
        "session-discovery":          "Discovery",
        "account-discovery":          "Discovery",
        "persistence-scheduled-task": "Persistence",
        "registry-modification":      "Defense Evasion",
        "software-uninstall":         "Defense Evasion",
        "msi-install":                "Execution",
        "sync-rclone-style":          "Exfiltration",
        "data-exfiltration":          "Exfiltration",
        "rmm-remote-access":          "Command and Control",
        "brute-ratel":                "Command and Control",
        "psexec-lateral":             "Lateral Movement",
        "lateral-movement":           "Lateral Movement",
        "uac-disable":                "Defense Evasion",
        "log-clearing":               "Defense Evasion",
        "initial-access-social":      "Initial Access",
    }.get(getattr(stage, "command_family", None))


def _stage_summary(stage, env, step_text: str) -> str:
    """Compact human-friendly summary line for a preprocessor stage."""
    if stage.command_family:
        return f"{stage.title} — `{(stage.normalized_command or step_text)[:100]}`"
    txt = (step_text or stage.title).strip()
    if len(txt) > 120:
        txt = txt[:117] + "…"
    return f"`{txt}`"


def classify_step_intent(env, text):
    from .chain import classify_intent as _ci
    return _ci(env, text)
