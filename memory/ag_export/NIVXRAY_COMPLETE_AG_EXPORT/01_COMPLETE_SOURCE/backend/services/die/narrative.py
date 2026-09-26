"""
DIE · Deterministic Narrative Generator (Phase B.4 · 2026-02-16 evening)
────────────────────────────────────────────────────────────────────────
Owner-locked canonical 12-section report structure (DO NOT reorder):

    1.  Executive Summary
    2.  Overall Assessment
    3.  Behavior Summary
    4.  Attack Story
    5.  Recovered Artifacts
    6.  Technical Findings
    7.  MITRE Coverage
    8.  Attack Intent
    9.  Evidence Summary
    10. Detection Opportunities
    11. Recommendations
    12. Confidence Summary

Every section is populated by pure templates — no LLM.  Same input
→ same paragraph.
"""
from __future__ import annotations
from typing import Any, Dict, List

from .confidence import score_investigation, CONFIDENCE_LEGEND


def generate_report(env: Dict[str, Any], *,
                    case_id: str = "",
                    input_preview: str = "") -> Dict[str, Any]:
    """Produce the canonical 12-section deterministic report."""
    conf = score_investigation(env)
    conf_by = {d["name"]: d["score"] for d in conf["dimensions"]}
    chain   = env.get("chain") or {}
    intent  = env.get("attack_intent") or chain.get("attack_intent") or {}
    tech    = env.get("techniques") or []
    dkp     = env.get("dkp_matches") or []
    lolbins = env.get("lolbins") or []
    iocs    = env.get("iocs") or []
    ast     = env.get("ast") or {}

    sections = [
        _s("Executive Summary",      conf["overall"],            _exec_summary(env, intent, chain)),
        _s("Overall Assessment",     conf["overall"],            _overall(env, intent, conf)),
        _s("Behavior Summary",       conf_by.get("Decoder", 0),  _behavior(env, ast, chain)),
        _s("Attack Story",           conf_by.get("Intent", 0),   _attack_story(chain)),
        _s("Recovered Artifacts",    conf_by.get("Artifacts", 0),_recovered_artifacts(ast, chain)),
        _s("Technical Findings",     conf_by.get("Decoder", 0),  _technical(env, ast)),
        _s("MITRE Coverage",         conf_by.get("MITRE", 0),    _mitre(tech)),
        _s("Attack Intent",          conf_by.get("Intent", 0),   _intent(intent)),
        _s("Evidence Summary",       conf_by.get("DKP", 0),      _evidence(dkp, iocs, lolbins)),
        _s("Detection Opportunities",conf_by.get("DKP", 0),      _detection(dkp)),
        _s("Recommendations",        conf["overall"],            _recommendations(intent, dkp)),
        _s("Confidence Summary",     conf["overall"],            _confidence_summary(conf)),
    ]

    return {
        "case_id":       case_id,
        "input_preview": input_preview,
        "confidence":    conf,
        "legend":        CONFIDENCE_LEGEND,
        "sections":      sections,
    }


# ── section builder ──────────────────────────────────────────────
def _s(title: str, score: int, body: str) -> Dict[str, Any]:
    return {
        "title":      title,
        "confidence": int(score),
        "bucket":     ("High" if score >= 95
                       else "Moderate" if score >= 80
                       else "Requires validation"),
        "body":       body.strip(),
    }


# ── section templates ────────────────────────────────────────────
def _exec_summary(env, intent, chain):
    obj = intent.get("objective") or "Uncategorised"
    lang = env.get("language") or "unknown"
    steps = chain.get("step_count") or 1
    if steps > 1:
        return (
            f"This investigation covers a {steps}-step {lang.upper()} "
            f"command chain. The engine's synthesis classifies the "
            f"primary objective as **{obj}** at {int((intent.get('confidence') or 0)*100)}% "
            f"confidence."
        )
    return (
        f"This investigation covers a single-step {lang.upper()} input. "
        f"The engine's synthesis classifies the primary objective as "
        f"**{obj}**."
    )


def _overall(env, intent, conf):
    return (
        f"Overall investigation confidence: **{conf['overall']}% "
        f"({conf['bucket']})**. Attack progress across the ATT&CK "
        f"tactic set: {int((intent.get('progress') or 0)*100)}%. "
        f"Observed phases: {', '.join(intent.get('observed_phases', [])) or '—'}."
    )


def _behavior(env, ast, chain):
    lang = env.get("language")
    if chain.get("steps"):
        bullets = "\n".join(f"- {b}" for b in (chain.get("narrative_bullets") or [])[:8])
        return f"Behavioural breakdown of the {lang} chain:\n{bullets}"
    if ast.get("flags"):
        flagged = [k for k, v in (ast["flags"] or {}).items() if v]
        return f"{lang.upper()} input flags active: {', '.join(flagged) or '(none)'}"
    return f"{lang.upper()} input analysed; no significant flags fired."


def _attack_story(chain):
    steps = chain.get("steps") or []
    if not steps:
        return "Single-step input — no attack chain reconstructed."
    lines = [f"{s['index']}. **{s['intent']}** — `{(s.get('text') or '')[:120]}`"
             for s in steps]
    return "\n".join(lines)


def _recovered_artifacts(ast, chain):
    canonical = (ast or {}).get("encoded_payloads") or []
    if canonical:
        rows = [f"- Payload {i+1}: encoding={p.get('encoding')}, "
                f"preview=`{(p.get('preview') or '')[:80]}`"
                for i, p in enumerate(canonical[:5])]
        return "Recovered payloads (deterministic decode):\n" + "\n".join(rows)
    return "No embedded artifacts were recovered during decoding."


def _technical(env, ast):
    rows = []
    rows.append(f"- Language: **{env.get('language') or 'unknown'}**")
    rows.append(f"- Obfuscation score: {env.get('obfuscation_score', 0)}/100")
    if ast.get("cmdlets"):
        rows.append(f"- Cmdlets: {len(ast['cmdlets'])}")
    if ast.get("commands"):
        rows.append(f"- Commands: {len(ast['commands'])}")
    lolbins = env.get("lolbins") or []
    if lolbins:
        rows.append(f"- LOLBAS: {', '.join(l['binary'] for l in lolbins[:6])}")
    return "\n".join(rows)


def _mitre(tech):
    if not tech:
        return "No MITRE ATT&CK techniques mapped."
    rows = [f"- **{t['id']}** — {t.get('name') or t.get('evidence') or ''}"
            for t in tech[:20]]
    return "\n".join(rows)


def _intent(intent):
    if not intent:
        return "Attack Intent Engine did not run."
    ev = "\n".join(f"- {e}" for e in (intent.get("evidence") or [])[:6])
    return (
        f"**Primary Objective:** {intent.get('objective')}\n"
        f"**Rule:** `{intent.get('rule')}`\n"
        f"**Confidence:** {int((intent.get('confidence') or 0)*100)}%\n\n"
        f"Evidence:\n{ev or '- (none)'}"
    )


def _evidence(dkp, iocs, lolbins):
    parts = []
    if dkp:
        parts.append("**DKP matches:**\n" + "\n".join(
            f"- {m['name']} ({int(m['confidence']*100)}%) — Commonly observed in: "
            f"{' · '.join((m.get('families') or m.get('malware_uses') or [])[:5]) or '—'}"
            for m in dkp[:8]))
    if iocs:
        parts.append("**IOCs:**\n" + "\n".join(
            f"- `{i['kind']}` · {i['value']}" for i in iocs[:10]))
    if lolbins:
        parts.append(f"**LOLBAS:** {', '.join(l['binary'] for l in lolbins[:8])}")
    return "\n\n".join(parts) or "No structured evidence surfaced."


def _detection(dkp):
    rules = [m for m in dkp if m.get("detection_logic")]
    if not rules:
        return "No detection-logic fragments available for the matched patterns."
    return "\n\n".join(
        f"**{m['name']}**\n```\n{m['detection_logic']}\n```" for m in rules[:6])


def _recommendations(intent, dkp):
    steps = []
    for m in dkp[:4]:
        steps.extend((m.get("investigation") or [])[:2])
    if not steps:
        steps = ["Correlate the case with recent history for shared IOCs.",
                 "Feed recovered artifacts back through DIE for deeper decode."]
    return "\n".join(f"- {s}" for s in steps[:10])


def _confidence_summary(conf):
    rows = [f"- **{d['name']}** — {d['score']}% ({d['bucket']})"
            for d in conf["dimensions"]]
    legend = "\n".join(f"- {l['range']} · {l['label']}" for l in CONFIDENCE_LEGEND)
    return "\n".join(rows) + "\n\n**Legend:**\n" + legend
