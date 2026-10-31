"""NXGEC → JSONL importer.

Parses the "NivXRay Gold Evaluation Corpus" .docx into a structured JSONL
fixture consumable by the batch evaluator and pytest regression suite.

Usage:
    python -m tests.fixtures.import_nxgec  <path.docx>  [output.jsonl]

Every "NXR-*-####" section becomes one JSON row with fields:
    id, title, volume, difficulty, category, platform, family,
    input, expected: { parser, behavior, decode_chain, artifacts,
                       mitre, lolbin, risk, severity, process_tree,
                       analyst_summary, validation }
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional


_FIELD_ALIASES = {
    "metadata":              "metadata",
    "input":                 "input",
    "input command":         "input",
    "expected parser output":"parser",
    "expected parser":       "parser",
    "expected behavior":     "behavior",
    "expected decode chain": "decode_chain",
    "expected artifacts":    "artifacts",
    "expected mitre att&ck": "mitre",
    "expected mitre attack": "mitre",
    "expected mitre":        "mitre",
    "expected lolbin":       "lolbin",
    "expected lolbins":      "lolbin",
    "expected risk & severity": "risk",
    "expected risk and severity": "risk",
    "expected risk":         "risk",
    "expected severity":     "severity",
    "expected process tree": "process_tree",
    "expected analyst summary": "analyst_summary",
    "validation checklist":  "validation",
    "validation":            "validation",
}

_CASE_ID_RX = re.compile(r"^(NXR-[A-Z0-9]+-\d{3,4})(?:\s*[-–:]\s*(.+))?$")
_VOLUME_RX  = re.compile(r"^Volume\s+(\d+)", re.IGNORECASE)
# Inline "Field: value" pairs used in Volumes 2–10 (Normal paragraphs).
_INLINE_FIELD_RX = re.compile(
    r"^(Category|Input|Expected\s+Parser(?:\s+Output)?|Expected\s+Behavior|"
    r"Expected\s+Decode\s+Chain|Expected\s+Artifacts|Expected\s+MITRE(?:\s+ATT&CK)?|"
    r"Expected\s+LOLBins?|Expected\s+Risk(?:\s+(?:&|and)\s+Severity)?|"
    r"Expected\s+Severity|Expected\s+Process\s+Tree|Expected\s+Analyst\s+Summary|"
    r"Validation(?:\s+Checklist)?|Difficulty|Platform|Family)"
    r"\s*:\s*(.*)$",
    re.IGNORECASE | re.DOTALL,
)


def _norm_key(text: str) -> Optional[str]:
    t = text.strip().lower().rstrip(":").strip()
    return _FIELD_ALIASES.get(t)


def parse_docx(path: str) -> List[Dict[str, Any]]:
    from docx import Document
    doc = Document(path)
    cases: List[Dict[str, Any]] = []

    cur_volume: Optional[int] = None
    cur_case:  Optional[Dict[str, Any]] = None
    cur_field: Optional[str] = None

    def _flush():
        nonlocal cur_case
        if cur_case and cur_case.get("raw", {}).get("input"):
            cases.append(cur_case)
        cur_case = None

    for p in doc.paragraphs:
        text  = p.text.strip()
        style = (p.style.name or "").lower()
        if not text:
            continue

        # Volume banner (Heading 2 "Volume N")
        vm = _VOLUME_RX.match(text)
        if vm and "heading" in style:
            cur_volume = int(vm.group(1))
            continue

        # Test case ID (Heading 2 "NXR-CMD-0001 - Title"  OR just "NXR-PS-0001")
        cm = _CASE_ID_RX.match(text)
        if cm and "heading" in style:
            _flush()
            cur_case = {
                "id":      cm.group(1),
                "title":   (cm.group(2) or "").strip(),
                "volume":  cur_volume,
                "input":   "",
                "expected": {},
                "raw":     {},
            }
            cur_field = None
            continue

        # Field label (Heading 3, volume-1 style)
        if "heading" in style:
            key = _norm_key(text)
            if key:
                cur_field = key
                if cur_case is not None:
                    cur_case["raw"].setdefault(key, [])
                continue

        # Volumes 2-10 inline "Field:\nvalue" — one field per Normal paragraph
        if cur_case is not None:
            m = _INLINE_FIELD_RX.match(text)
            if m:
                label = m.group(1).strip().lower()
                val   = m.group(2).strip()
                # Alias resolution
                key = _norm_key(label) or _FIELD_ALIASES.get(
                    label.replace(" checklist", "").strip()
                )
                if key is None:
                    # Try mapping known short forms
                    short = re.sub(r"^expected\s+", "", label).strip()
                    key = _FIELD_ALIASES.get(short) or short.replace(" ", "_")
                cur_field = key
                cur_case["raw"].setdefault(key, [])
                if val:
                    cur_case["raw"][key].append(val)
                continue

        # Body content — accumulate into current field of current case
        if cur_case and cur_field:
            cur_case["raw"][cur_field].append(text)

    _flush()

    # Post-process every case into a clean canonical shape
    for c in cases:
        raw = c.pop("raw", {})
        # metadata → parse Difficulty/Category/Platform/Family
        for line in raw.get("metadata", []):
            for pair in re.split(r"\s*(?:\n|,|;|\|)\s*", line):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    kk = k.strip().lower()
                    if kk in ("difficulty", "category", "platform", "family"):
                        c[kk] = v.strip()
        # input
        c["input"] = "\n".join(raw.get("input", [])).strip()
        # every other field → flat text under expected.*
        for fld in ("parser", "behavior", "decode_chain", "artifacts",
                    "mitre", "lolbin", "risk", "severity", "process_tree",
                    "analyst_summary", "validation"):
            if fld in raw:
                c["expected"][fld] = "\n".join(raw[fld]).strip()

        # Extra ready-to-assert scalars for pytest
        # · MITRE T-IDs list
        mitre_txt = c["expected"].get("mitre", "")
        c["expected_mitre_ids"] = sorted(set(re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", mitre_txt)))
        # · LOLBin binary names (from lines like "LOLBIN: certutil" or "- mshta.exe")
        lol_txt = c["expected"].get("lolbin", "")
        c["expected_lolbins"] = sorted({
            m.group(1).lower()
            for m in re.finditer(r"\b([a-zA-Z][\w\-]{2,20}\.exe|"
                                 r"certutil|mshta|regsvr32|rundll32|bitsadmin|"
                                 r"powershell|wmic|schtasks|vssadmin|wevtutil|"
                                 r"curl|wget|bash|python|docker|kubectl|aws)\b",
                                 lol_txt, flags=re.IGNORECASE)
            if m.group(1) not in ("None", "N/A")
        })
        # · Severity keyword
        sev_txt = (c["expected"].get("severity") or c["expected"].get("risk") or "").lower()
        for tag in ("critical", "high", "medium", "low", "informational", "benign"):
            if tag in sev_txt:
                c["expected_severity"] = tag.capitalize()
                break
    return [c for c in cases if c.get("input")]


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else "/tmp/nxgec.docx"
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "nxgec.jsonl")
    cases = parse_docx(src)
    with open(dst, "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print(f"[nxgec-import] {len(cases)} cases → {dst}")
    # Print per-volume tally
    from collections import Counter
    vols = Counter(c.get("volume") for c in cases)
    for v in sorted(k for k in vols if k is not None):
        print(f"    Volume {v}: {vols[v]} cases")


if __name__ == "__main__":
    main()
