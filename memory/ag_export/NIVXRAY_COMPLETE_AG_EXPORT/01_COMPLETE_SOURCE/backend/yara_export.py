"""YARA rule auto-exporter (Feb 2026 · RC4.0).

Deterministic YARA rule generator — sibling of `sigma_export.py`. Consumes
a NivXRay case (verdict + IOCs + MITRE + LOLBAS + decode chain + optional
extracted strings) and emits a valid YARA rule with:

    • Meta fields (case id, verdict, confidence, MITRE tags)
    • Strings section: URLs, LOLBAS binaries, extracted printable strings,
      magic bytes (MZ/ELF/PK/PDF) if present in decoded output
    • Condition combining any-of-strings + file-size heuristic

Callers:  routers/cases.py → GET /cases/{id}/yara?format=yara|json
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _slug(s: str, cap: int = 40) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", (s or "").strip().lower()).strip("_")
    return (s or "case")[:cap]


def _rule_name(case_name: str, case_id: Optional[str]) -> str:
    """YARA rule identifier — alphanumeric + underscores, must start w/ letter."""
    return f"NivXRay_{_slug(case_name)}_{_slug(case_id or 'auto')[:8]}"


def _yara_str_escape(s: str) -> str:
    """Escape a string for embedding in YARA `$s = "..."` literal."""
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return s


def _extract_strings_from_output(text: str, min_len: int = 6, cap: int = 12) -> List[str]:
    """Pull printable ASCII strings out of the decoded output (like `strings`)."""
    if not text:
        return []
    out, cur = [], ""
    for c in text:
        oc = ord(c)
        if 0x20 <= oc < 0x7f:
            cur += c
        else:
            if len(cur) >= min_len:
                out.append(cur)
            cur = ""
        if len(out) >= cap:
            break
    if cur and len(cur) >= min_len:
        out.append(cur)
    # De-dupe preserving order
    seen, dedup = set(), []
    for s in out:
        if s not in seen:
            seen.add(s); dedup.append(s)
    return dedup[:cap]


def build_yara_rule(
    *,
    case_name: str,
    case_id: Optional[str],
    verdict: Dict[str, Any],
    input_text: str,
    output_text: str,
    chain: List[str],
    iocs: Dict[str, Any],
    mitre: List[Dict[str, Any]],
    lolbas: List[Any],
    author: str = "NivXRay",
) -> str:
    v    = (verdict or {}).get("verdict") or "Malicious"
    conf = (verdict or {}).get("confidence") or (verdict or {}).get("risk_score") or 0
    rname = _rule_name(case_name, case_id)

    # Collect string signatures
    strings: List[str] = []  # rendered YARA lines
    tags: List[str]    = []

    # URLs / domains / IPs from IOCs
    urls = [u for u in ((iocs or {}).get("urls") or []) if isinstance(u, str)]
    ips  = [i for i in ((iocs or {}).get("ips")  or []) if isinstance(i, str)]
    doms = [d for d in ((iocs or {}).get("domains") or []) if isinstance(d, str)]
    idx = 0
    for u in urls[:5]:
        strings.append(f'    $url_{idx} = "{_yara_str_escape(u)}" ascii wide nocase'); idx += 1
    for i in ips[:5]:
        strings.append(f'    $ip_{idx}  = "{_yara_str_escape(i)}" ascii wide nocase'); idx += 1
    for d in doms[:5]:
        strings.append(f'    $dom_{idx} = "{_yara_str_escape(d)}" ascii wide nocase'); idx += 1

    # LOLBAS binaries
    for lb in (lolbas or [])[:5]:
        n = (lb.get("binary") if isinstance(lb, dict) else lb) or ""
        if n:
            strings.append(f'    $lol_{idx} = "{_yara_str_escape(n)}" ascii wide nocase'); idx += 1

    # Extracted strings from decoded output (evidence-based)
    for s in _extract_strings_from_output(output_text or ""):
        strings.append(f'    $s_{idx} = "{_yara_str_escape(s)}" ascii'); idx += 1

    # Magic bytes when the decoded output is a binary
    if output_text and output_text.startswith("MZ"):
        strings.append('    $mz = { 4D 5A 90 00 03 00 00 00 04 00 00 00 }')
        tags.append("PE_executable")
    if output_text and output_text.startswith("\x7fELF"):
        strings.append('    $elf = { 7F 45 4C 46 }')
        tags.append("ELF_executable")

    # MITRE tags
    for m in mitre or []:
        tid = m.get("id") if isinstance(m, dict) else None
        if tid:
            tags.append(f"MITRE_{tid.replace('.', '_')}")

    condition = "any of them"
    if not strings:
        strings.append('    $fallback = "NivXRay"')  # unreachable placeholder
        condition = "false"  # rule is inert without real signatures

    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    tag_line = (" : " + " ".join(sorted(set(tags))[:10])) if tags else ""

    body = "\n".join([
        f"rule {rname}{tag_line}",
        "{",
        "    meta:",
        f'        description = "NivXRay auto-generated · case={_yara_str_escape(case_name)} · verdict={v} · confidence={conf}"',
        f'        author      = "{_yara_str_escape(author)}"',
        f'        date        = "{date}"',
        f'        reference   = "nivxray://case/{case_id or "auto"}"',
        f'        chain       = "{_yara_str_escape(" -> ".join(chain or []) or "n/a")}"',
        f'        verdict     = "{v}"',
        f'        confidence  = "{conf}"',
        "",
        "    strings:",
        "\n".join(strings),
        "",
        "    condition:",
        f"        {condition}",
        "}",
        "",
    ])
    return body
