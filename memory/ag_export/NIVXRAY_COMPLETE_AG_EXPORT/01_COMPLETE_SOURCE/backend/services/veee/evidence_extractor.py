"""
NivXRay · VEEE · Evidence Extractor (P0.15B · ADR-002 §3.1 stage 3)
────────────────────────────────────────────────────────────────────

Converts an ``OCRResult`` into ``NormalizedEvidence[]`` records.

Every record carries provenance per ADR-002 §5:
    · acquisition_level = "P3"
    · source            = "image"
    · image_url         (if known)
    · image_sha256      (computed)
    · bounding_box      (from OCR bbox — line-scoped)
    · ocr_engine        = "tesseract-5"
    · ocr_confidence    (per line)

The extractor NEVER emits Behaviors, MITRE tids, or Recommendations.
Semantic interpretation happens downstream via the Evidence
Canonicalizer + Behavior Classifier.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional

from services.veee.ocr_engine import OCRResult, OCRLine


# Deterministic recognisers — every regex is anchored, tested, and
# maps to a NormalizedEvidence ``type``.  Order matters: commandline
# is the coarsest — checked LAST so IOCs surface as their own record.
_IOC_PATTERNS = (
    ("ipv4",   re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("domain", re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\[?\.\]?)+[a-zA-Z]{2,}\b")),
    ("url",    re.compile(r"https?://[^\s\"'<>]+")),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1",   re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5",    re.compile(r"\b[a-fA-F0-9]{32}\b")),
)

# Tokens that make a line "look like a command line" — one of these
# in the first 3 tokens indicates OCR captured a shell payload.
_COMMAND_HEAD_HINTS = {
    "cmd", "cmd.exe",           "powershell", "powershell.exe", "pwsh",
    "reg", "reg.exe",           "sc", "sc.exe",                  "net", "net.exe",
    "schtasks", "schtasks.exe", "tasklist", "taskkill",
    "wmic", "wmic.exe",         "vssadmin", "wbadmin", "bcdedit",
    "mshta", "mshta.exe",       "rundll32", "rundll32.exe",      "regsvr32",
    "wscript", "cscript",       "certutil", "bitsadmin",         "curl",
    "wget",  "ping", "ping.exe","nslookup", "nltest", "whoami",
    "hostname", "ipconfig",     "python", "python.exe",          "tar",
    "msiexec", "msiexec.exe",   "psexec", "adfind",              "bloodhound",
}


def extract_evidence(ocr:       OCRResult,
                        image_url: str = "",
                        page:      Optional[int] = None,
                        image_bytes: Optional[bytes] = None,
                        ) -> List[Dict[str, Any]]:
    """Return a list of ``NormalizedEvidence`` records.

    Each command line becomes a ``commandline`` record.  Each
    stand-alone IOC also emits its own ``ioc`` record so hunt
    consumers can index them.
    """
    if not ocr or not ocr.lines:
        return []

    image_sha256 = (hashlib.sha256(image_bytes).hexdigest()
                       if image_bytes else None)
    records: List[Dict[str, Any]] = []
    for idx, line in enumerate(ocr.lines):
        text = line.text.strip()
        if not text:
            continue
        prov = _provenance(image_url, image_sha256, line, page,
                             mean_conf=ocr.mean_confidence)
        rec_type = _classify_line(text)
        records.append({
            "type":       rec_type,          # "commandline" | "caption"
            "text":       text,
            "provenance": prov,
        })
        # Also emit dedicated IOC records for any hit on the line.
        # These are additive — the command line record still carries
        # the full text, IOCs just get their own row too.
        for ioc_kind, m in _iter_iocs(text):
            records.append({
                "type":       "ioc",
                "ioc_kind":   ioc_kind,
                "text":       m,
                "provenance": {**prov, "note": f"ioc_from_line_{idx}"},
            })
    return records


# ══════════════════════════════════════════════════════════════════
# Provenance
# ══════════════════════════════════════════════════════════════════
def _provenance(image_url:    str,
                   image_sha256: Optional[str],
                   line:         OCRLine,
                   page:         Optional[int],
                   mean_conf:    float) -> Dict[str, Any]:
    bbox = line.bbox
    prov: Dict[str, Any] = {
        "source":            "image",
        "acquisition_level": "P3",
        "image_url":         image_url or None,
        "image_sha256":      image_sha256,
        "ocr_engine":        "tesseract-5",
        "ocr_confidence":    round(line.confidence, 3),
        "ocr_mean_confidence": round(mean_conf, 3),
    }
    if bbox is not None:
        prov["bounding_box"] = {"x": bbox.x, "y": bbox.y,
                                    "w": bbox.w, "h": bbox.h}
    if page is not None:
        prov["page"] = page
    # ── P0.15C-4 · propagate line-joining provenance ─────────────
    # Emit ``joined_from_lines`` ONLY when line joining actually
    # ran (per ADR-002 §5).  Non-joined lines omit the field so
    # existing consumers see byte-identical provenance shapes.
    joined = getattr(line, "joined_from_lines", None)
    if joined:
        prov["joined_from_lines"] = list(joined)
    return prov


# ══════════════════════════════════════════════════════════════════
# Line classification
# ══════════════════════════════════════════════════════════════════
def _classify_line(text: str) -> str:
    """Return ``"commandline"`` if the line starts with a recognised
    executable head, else ``"caption"``.  This is a purely
    syntactic decision — the Canonicalizer + Behavior Classifier
    make the semantic call downstream."""
    head_tokens = text.split(None, 3)[:3]
    for tok in head_tokens:
        cleaned = tok.strip('"').strip("'").lower()
        # Strip a path prefix if present (C:\...\foo.exe → foo.exe).
        leaf = cleaned.replace("/", "\\").split("\\")[-1]
        if leaf in _COMMAND_HEAD_HINTS or cleaned in _COMMAND_HEAD_HINTS:
            return "commandline"
    return "caption"


# ══════════════════════════════════════════════════════════════════
# IOC scanning
# ══════════════════════════════════════════════════════════════════
def _iter_iocs(text: str):
    for kind, pat in _IOC_PATTERNS:
        for m in pat.findall(text):
            # skip false-positive "domain" matches that are actually
            # file paths (contain \) or version numbers (all digits).
            if kind == "domain":
                if "\\" in m or all(ch.isdigit() or ch == "." for ch in m):
                    continue
            # ipv4 → domain regex is greedier, so dedupe
            yield (kind, m)


__all__ = ["extract_evidence"]
