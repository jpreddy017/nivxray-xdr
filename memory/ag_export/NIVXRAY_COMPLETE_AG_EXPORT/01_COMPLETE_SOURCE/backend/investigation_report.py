"""NivXRay Investigation-Report Synthesizer.
==========================================

When `/api/decode/smart` or `/api/decode/chain` finishes analysing a
payload, this module renders a **human-readable SOC report** from the
enriched signals (IOCs, MITRE techniques, LOLBAS binaries, verdict).

Why this exists
---------------
Plain-text PowerShell / cmd one-liners don't need any decoding — the
deterministic decoder recognises them as plaintext and returns
``output = input``. To the analyst the OUTPUT panel then looked
identical to their paste, which was rightfully confusing ("why did I
click Investigate?"). This synthesizer replaces that echo with a
compact SOC-format summary so the OUTPUT panel always shows *what
NivXRay actually learned* — even when there was nothing to decode.

Format is deliberately monospaced / plain-text so it renders cleanly in
the existing `<pre>` OUTPUT panel with no frontend changes required.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import textwrap


_SEP = "━" * 66


def _fmt_pairs(pairs: List[tuple], label_width: int = 12) -> List[str]:
    return [f"  {(l+':').ljust(label_width)} {v}" for l, v in pairs if v]


def _fmt_mitre(mitre: List[Dict[str, Any]]) -> List[str]:
    rows: List[str] = []
    for t in mitre[:8]:
        tid = t.get("id") or "?"
        name = (t.get("name") or "").strip()
        tactic = (t.get("tactic") or "").strip()
        line = f"    {tid:<10} {name}"
        if tactic:
            line += f"  · {tactic}"
        rows.append(line)
    return rows


def _fmt_iocs(iocs: Dict[str, List[str]]) -> List[str]:
    lines: List[str] = []
    order = [
        ("urls",     "URL     "),
        ("ips",      "IP      "),
        ("domains",  "Domain  "),
        ("emails",   "Email   "),
        ("md5",      "MD5     "),
        ("sha1",     "SHA-1   "),
        ("sha256",   "SHA-256 "),
        ("bitcoin_addresses", "BTC     "),
    ]
    for key, label in order:
        vals = (iocs or {}).get(key) or []
        for v in vals[:6]:
            lines.append(f"    {label}  {v}")
    return lines


def _fmt_lolbas(lolbas: List[Dict[str, Any]]) -> List[str]:
    seen: List[str] = []
    for l in (lolbas or [])[:8]:
        b = l.get("binary")
        if b and b not in seen:
            seen.append(b)
    return [", ".join(seen)] if seen else []


def _behavior_notes(input_text: str, mitre: List[Dict[str, Any]]) -> List[str]:
    """Lightweight, deterministic behavior narrative — one line per
    detected trick. No LLM required."""
    it = input_text or ""
    lo = it.lower()
    tids = {(m.get("id") or "") for m in (mitre or [])}
    notes: List[str] = []

    # Char-reverse `[1..0]` trick
    if "[1..0]" in it and "$e.length-1" in lo:
        notes.append("Uses PowerShell char-reverse `[1..0]` trick to hide inline strings")
    # AMSI / defender-bypass one-liners
    if "amsiscanbuffer" in lo or "amsiinitfailed" in lo:
        notes.append("Attempts AMSI bypass (SetValue on amsiInitFailed / patch AmsiScanBuffer)")
    # Service disable
    if "sc.exe stop" in lo or "stop-service" in lo:
        notes.append("Disables Windows services (Defender / update / logging)")
    # Download & execute patterns
    if any(k in lo for k in ("downloadstring", "downloadfile", "invoke-webrequest", "iwr ")):
        notes.append("Downloads remote content via WebClient / Invoke-WebRequest")
    if "iex " in lo or "invoke-expression" in lo:
        notes.append("Executes downloaded content in-memory with IEX (no disk write)")
    # Certutil abuse
    if "certutil" in lo and "-urlcache" in lo:
        notes.append("Abuses certutil.exe as a LOLBIN downloader (T1105)")
    # Base64 embedded
    if "-enc " in lo or "-encodedcommand" in lo:
        notes.append("Executes a Base64-encoded PowerShell command block")
    # Gzip stager
    if "gzipstream" in lo and "frombase64string" in lo:
        notes.append("In-memory Base64 → GZip decompression stager")
    # Registry / persistence
    if "reg add " in lo or "new-itemproperty" in lo:
        notes.append("Modifies registry (persistence / defense-evasion)")
    # Scheduled task
    if "schtasks" in lo or "register-scheduledtask" in lo:
        notes.append("Creates a scheduled task (persistence)")

    # Generic MITRE-based fallbacks so we always say something useful
    if not notes:
        if "T1059.001" in tids:
            notes.append("Executes PowerShell (T1059.001)")
        if "T1105" in tids:
            notes.append("Transfers a tool from a remote host (T1105)")
        if "T1140" in tids:
            notes.append("Deobfuscates / decodes payload content in-memory (T1140)")
    return notes[:6]


def _verdict_line(risk: Dict[str, Any]) -> str:
    if not risk:
        return "unknown"
    v = risk.get("verdict") or "unknown"
    s = risk.get("score")
    return f"{v}" + (f" · {int(s)}/100" if isinstance(s, (int, float)) else "")


def synthesize_report(
    *,
    input_text: str,
    output_text: str,
    engine: Optional[str],
    confidence: Optional[int],
    steps: List[Dict[str, Any]],
    iocs: Dict[str, List[str]],
    mitre: List[Dict[str, Any]],
    lolbas: List[Dict[str, Any]],
    risk: Optional[Dict[str, Any]] = None,
    family: Optional[Dict[str, Any]] = None,
    reached_shellcode: bool = False,
    corrupted_container: Optional[Dict[str, Any]] = None,
) -> str:
    """Build the SOC-report text.

    Returns an empty string when there is truly nothing to say (no IOCs,
    no MITRE, no LOLBAS, no chain applied) — the caller can then fall
    back to the raw decoded output.
    """
    has_signals = any([iocs, mitre, lolbas, steps, corrupted_container])
    if not has_signals:
        return ""

    is_passthrough = (
        (not steps or len(steps) == 0)
        and (output_text or "").strip() == (input_text or "").strip()
    )

    lines: List[str] = []
    lines.append(_SEP)
    header = "NIVXRAY INVESTIGATION SUMMARY"
    if is_passthrough:
        header += "  (payload already plaintext — no decode needed)"
    elif reached_shellcode:
        header += "  (shellcode reached)"
    elif corrupted_container:
        header += f"  (corrupted {corrupted_container.get('kind','container')})"
    lines.append(header)
    lines.append(_SEP)

    # Verdict / family / engine
    pairs = []
    if risk and risk.get("verdict"):
        pairs.append(("Verdict", _verdict_line(risk)))
    if family and family.get("family"):
        pairs.append(("Family",  family.get("family")))
    if engine:
        pairs.append(("Engine",  f"{engine} · conf {confidence or 0}/100"))
    if steps:
        step_names = " → ".join(s.get("op") for s in steps[:8])
        pairs.append(("Chain",   step_names))
    lines.extend(_fmt_pairs(pairs))

    # MITRE
    if mitre:
        lines.append("")
        lines.append("  MITRE ATT&CK")
        lines.extend(_fmt_mitre(mitre))

    # LOLBAS
    lb = _fmt_lolbas(lolbas)
    if lb:
        lines.append("")
        lines.append(f"  LOLBIN       {lb[0]}")

    # IOCs
    ioc_rows = _fmt_iocs(iocs or {})
    if ioc_rows:
        lines.append("")
        lines.append("  IOCs")
        lines.extend(ioc_rows)

    # Behavior narrative
    behavior = _behavior_notes(input_text, mitre or [])
    if behavior:
        lines.append("")
        lines.append("  Behavior")
        for i, b in enumerate(behavior, 1):
            for j, w in enumerate(textwrap.wrap(b, width=60)):
                prefix = f"    {i}." if j == 0 else "       "
                lines.append(f"{prefix} {w}")

    # Corruption footnote
    if corrupted_container:
        lines.append("")
        lines.append(f"  Integrity    ⚠ {corrupted_container.get('kind','container')} "
                     f"invalid: {corrupted_container.get('reason','')}")

    # Footer — always tell the analyst where the raw content lives.
    lines.append("")
    if is_passthrough:
        lines.append("  Original input preserved above in the INPUT box ↑")
    else:
        lines.append("  Per-layer decoded outputs available in the Chain / Trace panel ↑")
    lines.append(_SEP)

    return "\n".join(lines)


def synthesize_chain_report(
    stages: List[Dict[str, Any]],
    aggregate: Dict[str, Any],
) -> str:
    """Chain-analysis variant — same header + per-stage summary line +
    aggregate rollup. Used by the /api/decode/chain path so the OUTPUT
    panel shows a multi-stage report instead of concatenated payloads."""
    if not stages:
        return ""

    risk   = aggregate.get("risk") or {}
    family = aggregate.get("family") or {}
    iocs   = aggregate.get("iocs") or {}
    mitre  = aggregate.get("mitre") or []
    lolbas = aggregate.get("lolbas") or []

    lines: List[str] = []
    lines.append(_SEP)
    lines.append(f"NIVXRAY CHAIN INVESTIGATION  ·  {len(stages)} stages")
    lines.append(_SEP)

    pairs = []
    if risk.get("verdict"):
        pairs.append(("Verdict", _verdict_line(risk)))
    if family.get("family"):
        pairs.append(("Family",  family.get("family")))
    lines.extend(_fmt_pairs(pairs))

    lines.append("")
    lines.append("  Per-stage")
    for s in stages:
        idx = s.get("stage_index", 0)
        eng = s.get("engine") or "?"
        conf = s.get("confidence")
        preview = (s.get("input_preview") or "").split("\n")[0][:60]
        marker = ""
        if s.get("reached_shellcode"):
            marker = " · SHELLCODE"
        elif s.get("corrupt_payload"):
            marker = " · CORRUPT"
        lines.append(f"    #{idx}  engine={eng:<9} conf={conf or 0:>3}/100{marker}   {preview}")

    # MITRE rollup
    if mitre:
        lines.append("")
        lines.append("  MITRE ATT&CK (merged)")
        lines.extend(_fmt_mitre(mitre))

    # LOLBAS rollup
    lb = _fmt_lolbas(lolbas)
    if lb:
        lines.append("")
        lines.append(f"  LOLBIN (merged)  {lb[0]}")

    # IOC rollup
    ioc_rows = _fmt_iocs(iocs)
    if ioc_rows:
        lines.append("")
        lines.append("  IOCs (merged across stages)")
        lines.extend(ioc_rows)

    lines.append("")
    lines.append("  Per-stage inputs preserved in the Chain Analysis panel below ↓")
    lines.append(_SEP)
    return "\n".join(lines)
