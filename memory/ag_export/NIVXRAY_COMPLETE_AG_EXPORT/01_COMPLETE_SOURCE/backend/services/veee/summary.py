"""
NivXRay · VEEE Stage · Acquisition Summary (P0.15C-2 · ADR-002)
────────────────────────────────────────────────────────────────

Pure, read-only summary of what the acquisition layer produced.
Consumes ONLY ``veee_records`` and existing acquisition metadata.
Emits ONLY display counters — never Behaviors, MITRE, or
Recommendations.

Single-responsibility per Stage Isolation Rule (§0.1).
Tolerant of missing data per §0.2 · empty inputs yield an
all-zero summary (never raises, never surfaces "error").
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ── Recovered-category detectors (deterministic, pure regex) ─────
_PS_RX       = re.compile(r"(?i)\bpower(shell|shell\.exe|shell -)")
_REG_RX      = re.compile(r"(?i)\breg(\.exe)?\s+(add|delete|query|import|export)\b")
_URL_RX      = re.compile(r"(?i)https?://[^\s\"'<>]+")
_HASH_RX     = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_IOC_IP_RX   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IOC_DOM_RX  = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\[?\.\]?)+[a-zA-Z]{2,}\b")

# ── Command-head hints — mirror evidence_extractor for parity ────
_COMMAND_HEADS = {
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
    "reg", "reg.exe", "sc", "sc.exe", "net", "net.exe",
    "schtasks", "schtasks.exe", "tasklist", "taskkill",
    "wmic", "wmic.exe", "vssadmin", "wbadmin", "bcdedit",
    "mshta", "mshta.exe", "rundll32", "rundll32.exe", "regsvr32",
    "wscript", "cscript", "certutil", "bitsadmin", "curl",
    "wget", "ping", "ping.exe", "nslookup", "nltest", "whoami",
    "hostname", "ipconfig", "python", "python.exe", "tar",
    "msiexec", "msiexec.exe", "psexec", "adfind", "bloodhound",
}


def _looks_like_command(text: str) -> bool:
    if not text:
        return False
    for tok in text.split(None, 3)[:3]:
        leaf = tok.strip('"').strip("'").lower().split("\\")[-1].split("/")[-1]
        if leaf in _COMMAND_HEADS:
            return True
    return False


def compute_summary(structured_blocks: Optional[List[str]]        = None,
                        veee_records:      Optional[List[Dict[str, Any]]] = None,
                        html_text:         Optional[str]           = None,
                        images_seen_in_html: Optional[int]         = None,
                        processing_time_ms: Optional[float]        = None,
                        cache_hits:         Optional[int]          = None,
                        cache_misses:       Optional[int]          = None,
                        veee_enabled:      Optional[bool]          = None,
                        ) -> Dict[str, Any]:
    """Return the P0.15C-2 Acquisition Summary payload.  Never
    raises · missing inputs collapse to zero counters."""
    blocks    = structured_blocks or []
    records   = veee_records      or []
    html      = html_text         or ""

    # ── HTML section ─────────────────────────────────────────────
    html_section = {
        "paragraphs": html.count("<p ") + html.count("<p>"),
        "tables":     html.count("<table"),
        "code_blocks": html.count("<code") + html.count("<pre"),
    }

    # ── Images section (from VEEE provenance) ────────────────────
    ocr_candidates = 0
    processed      = 0
    skipped        = 0
    skipped_reasons: Dict[str, int] = {}
    ocr_confidences: List[float] = []
    for r in records:
        if r.get("type") == "skipped":
            skipped += 1
            reason = (r.get("provenance") or {}).get("reason") or "unknown"
            skipped_reasons[reason] = skipped_reasons.get(reason, 0) + 1
        else:
            processed += 1
            conf = (r.get("provenance") or {}).get("ocr_confidence")
            if isinstance(conf, (int, float)):
                ocr_confidences.append(float(conf))
        ocr_candidates += 1
    images_section = {
        "found":            images_seen_in_html if images_seen_in_html is not None else ocr_candidates,
        "ocr_candidates":   ocr_candidates,
        "processed":        processed,
        "skipped":          skipped,
        "skipped_reasons":  skipped_reasons,
    }

    # ── Recovered section ────────────────────────────────────────
    commands = ps_hits = reg_hits = urls = hashes = iocs = 0
    for r in records:
        if r.get("type") == "commandline":
            commands += 1
        text = (r.get("text") or "")
        if _PS_RX.search(text):   ps_hits += 1
        if _REG_RX.search(text):  reg_hits += 1
        urls   += len(_URL_RX.findall(text))
        hashes += len(_HASH_RX.findall(text))
        iocs   += len(_IOC_IP_RX.findall(text))
    recovered_section = {
        "commands":   commands,
        "powershell": ps_hits,
        "registry":   reg_hits,
        "urls":       urls,
        "hashes":     hashes,
        "iocs":       iocs,
    }

    # ── Quality section (operational KPIs · Amendment 5) ─────────
    ocr_commands_extracted = commands
    # Canonicalizer is a pure function on effective_head strings;
    # a record "canonicalizes successfully" if its text yields a
    # non-empty effective_head via the frozen canonicalizer.  We
    # avoid importing the canonicalizer here (Stage Isolation) —
    # instead we approximate via the command-head hint and
    # publish the exact numerator once P0.15C-4 line-joining
    # lands and can piggyback on the canonicalizer's own metrics.
    canonicalized_successfully = sum(
        1 for r in records
          if r.get("type") == "commandline"
          and _looks_like_command((r.get("text") or "")))
    classification_success_rate = (
        round(canonicalized_successfully / ocr_commands_extracted * 100.0, 1)
        if ocr_commands_extracted else 0.0
    )
    quality_section = {
        "average_ocr_confidence":         (round(sum(ocr_confidences)
                                                     / len(ocr_confidences), 3)
                                              if ocr_confidences else 0.0),
        "ocr_commands_extracted":         ocr_commands_extracted,
        "canonicalized_successfully":     canonicalized_successfully,
        "classification_success_rate":    classification_success_rate,
    }

    performance_section = {
        "processing_time_ms": (round(processing_time_ms, 1)
                                    if isinstance(processing_time_ms, (int, float))
                                    else 0.0),
        "cache_hits":         int(cache_hits or 0),
        "cache_misses":       int(cache_misses or 0),
    }

    # ── Pipeline Stage Health (P0.15C-2 refinement · 2026-02-09) ─
    # Display-only summary of per-stage acquisition health.  Every
    # status is DERIVED from counters already computed above — no
    # new backend behaviour, no semantic logic, no downstream data
    # dependency (Stage Isolation Rule §0.1).
    #
    # Status vocabulary (5 values):
    #   completed      · stage produced output as expected
    #   partial        · stage produced output with some skips/gaps
    #   failed         · stage received input but produced nothing
    #   disabled       · NVX_VEEE_ENABLED=0 (explicit flag off)
    #   not_available  · nothing to run against
    flag_off       = (veee_enabled is False)
    has_any_record = bool(records)
    has_html       = bool(html) or any(html_section.values())

    def _health(status: str, detail: str) -> Dict[str, str]:
        return {"status": status, "detail": detail}

    # HTML stage — succeeds if any HTML text or structural counters.
    if has_html:
        html_status = _health("completed",
                                  f"paragraphs={html_section['paragraphs']} · "
                                  f"tables={html_section['tables']} · "
                                  f"code_blocks={html_section['code_blocks']}")
    else:
        html_status = _health("not_available", "no HTML acquired")

    # Images stage — reflects discovery (images_seen_in_html) OR the
    # candidate list VEEE actually saw.
    n_found = images_section["found"]
    if n_found > 0:
        images_status = _health("completed", f"found={n_found}")
    elif flag_off:
        images_status = _health("disabled", "NVX_VEEE_ENABLED=0")
    else:
        images_status = _health("not_available", "no images discovered")

    # OCR stage — VEEE processed vs skipped counts.
    if flag_off and not has_any_record:
        ocr_status = _health("disabled", "NVX_VEEE_ENABLED=0")
    elif not has_any_record:
        ocr_status = _health("not_available", "no OCR candidates")
    elif processed > 0 and skipped == 0:
        ocr_status = _health("completed", f"processed={processed}")
    elif processed > 0 and skipped > 0:
        ocr_status = _health("partial",
                                 f"processed={processed} · skipped={skipped}")
    else:
        ocr_status = _health("failed",
                                 f"processed=0 · skipped={skipped}")

    # Canonicalizer stage — OCR-derived commands → canonical head.
    if ocr_commands_extracted == 0:
        if flag_off:
            canon_status = _health("disabled", "NVX_VEEE_ENABLED=0")
        else:
            canon_status = _health("not_available", "no commands extracted")
    elif canonicalized_successfully == ocr_commands_extracted:
        canon_status = _health(
            "completed",
            f"canonicalized={canonicalized_successfully}/{ocr_commands_extracted}")
    elif canonicalized_successfully > 0:
        canon_status = _health(
            "partial",
            f"canonicalized={canonicalized_successfully}/{ocr_commands_extracted}")
    else:
        canon_status = _health(
            "failed",
            f"canonicalized=0/{ocr_commands_extracted}")

    # Classifier stage — success rate mirrors canonicalized/extracted
    # today; the field name reserves room for a future classifier
    # metric without changing the schema.
    rate = classification_success_rate
    if ocr_commands_extracted == 0:
        if flag_off:
            classifier_status = _health("disabled", "NVX_VEEE_ENABLED=0")
        else:
            classifier_status = _health("not_available", "no commands to classify")
    elif rate >= 100.0:
        classifier_status = _health("completed", f"rate={rate}%")
    elif rate > 0.0:
        classifier_status = _health("partial", f"rate={rate}%")
    else:
        classifier_status = _health("failed", f"rate={rate}%")

    pipeline_health_section = {
        "html":          html_status,
        "images":        images_status,
        "ocr":           ocr_status,
        "canonicalizer": canon_status,
        "classifier":    classifier_status,
    }

    # ``veee_enabled`` remains a boolean for backward compatibility;
    # when the caller passes it explicitly we honour that value,
    # otherwise fall back to the "activity proxy" (records present).
    resolved_veee_enabled = (bool(veee_enabled) if veee_enabled is not None
                                                 else bool(records))

    return {
        "schema_version":       "1.0",
        "veee_enabled":         resolved_veee_enabled,
        "structured_blocks":    len(blocks),
        "sections": {
            "html":            html_section,
            "images":          images_section,
            "recovered":       recovered_section,
            "quality":         quality_section,
            "performance":     performance_section,
            "pipeline_health": pipeline_health_section,
        },
    }


__all__ = ["compute_summary"]
