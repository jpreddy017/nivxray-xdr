"""M0b · Passive registry of EXISTING adapters and analyzers (ADR-0014).

STRICTLY PASSIVE — nothing in this package is imported by any execution
path today.  It exists solely to give the capabilities NivXRay already
ships a stable, machine-readable identifier that later migrations
(M0d Router, M0g /api/investigate) can dispatch against.

Rules honoured (owner directive · M0b):
  • Registers only capabilities that already exist.  Broken/orphan/dead
    capabilities are registered in their CURRENT REAL STATE.
  • IDs are immutable.  New versions get new IDs (e.g. v2).
  • No adapter/analyzer implementation is modified or rewritten.
  • Nothing here activates OCR, URL acquisition, the mitre_regex demotion,
    or any other functional change.
  • If, after M0b, the SystemWeakness URL suddenly works, M0b is WRONG.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional


@dataclass(frozen=True)
class RegistryEntry:
    """A stable pointer to an EXISTING capability.  Immutable."""
    entry_id:            str                   # e.g. "sysmon.xml.v1"
    kind:                str                   # "adapter" | "analyzer"
    version:             str                   # "1"
    implementation_path: str                   # dotted-path to code
    accepts_formats:     FrozenSet[str]        # coarse format tags
    role:                str                   # short prose (audit-only)
    live_today:          bool                  # does the impl currently execute in production?
    notes:               str = ""


class RegistryError(RuntimeError):
    pass


class _Registry:
    """Passive lookup table.  No execution.  No dispatch.  No orchestration."""

    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._entries: Dict[str, RegistryEntry] = {}

    def register(self, entry: RegistryEntry) -> None:
        if entry.kind != self._kind:
            raise RegistryError(
                f"entry kind {entry.kind!r} does not match registry {self._kind!r}")
        if entry.entry_id in self._entries:
            raise RegistryError(f"duplicate id: {entry.entry_id!r}")
        if not entry.entry_id or not entry.entry_id.replace(".", "").replace("_", "").isalnum():
            raise RegistryError(f"invalid id shape: {entry.entry_id!r}")
        self._entries[entry.entry_id] = entry

    def get(self, entry_id: str) -> RegistryEntry:
        if entry_id not in self._entries:
            raise RegistryError(f"unknown id: {entry_id!r}")
        return self._entries[entry_id]

    def ids(self) -> List[str]:
        return sorted(self._entries.keys())

    def all(self) -> List[RegistryEntry]:
        # Deterministic order — sorted by id.
        return [self._entries[k] for k in sorted(self._entries.keys())]

    def __len__(self) -> int:
        return len(self._entries)


ADAPTER_REGISTRY  = _Registry("adapter")
ANALYZER_REGISTRY = _Registry("analyzer")


# ─── Adapter registrations (§5.1 of ADR-0014) ───────────────────────────────
_ADAPTERS = [
    RegistryEntry(
        entry_id="url.acquire.v1",
        kind="adapter", version="1",
        implementation_path="services.ida.acquisition:acquire_url",
        accepts_formats=frozenset({"url"}),
        role="Fetch URL via Trafilatura → readability → BS4 → Playwright cascade.",
        live_today=True,
        notes="Currently reachable only from /api/die/investigation-results "
              "behind _ACQUIRABLE_CLASSES + url_intent.acquirable gate.",
    ),
    RegistryEntry(
        entry_id="file.gridfs.v1",
        kind="adapter", version="1",
        implementation_path="services.files.store:FileStore",
        accepts_formats=frozenset({"file_upload"}),
        role="Stream, dedup, and persist uploaded bytes via GridFS.",
        live_today=True,
    ),
    RegistryEntry(
        entry_id="sysmon.xml.v1",
        kind="adapter", version="1",
        implementation_path="services.behavioral.sysmon_adapter:normalize_sysmon_xml",
        accepts_formats=frozenset({"sysmon_xml"}),
        role="Sysmon Event 1/3 XML → canonical evidence records.",
        live_today=True,
        notes="Strict E1/E3 only; fail-loud on other EIDs (per ADR-0010r).",
    ),
    RegistryEntry(
        entry_id="sysmon.evtx.v1",
        kind="adapter", version="1",
        implementation_path="services.behavioral.evtx_reader:decode_evtx_to_sysmon_xml",
        accepts_formats=frozenset({"evtx"}),
        role="Real .evtx bytes → wrapped Sysmon XML (transport only).",
        live_today=True,
        notes="Real python-evtx exercised in CI since ADR-0010w (Task 2).",
    ),
    RegistryEntry(
        entry_id="archive.zip.v1",
        kind="adapter", version="1",
        implementation_path="security.archive_guard:safe_iter_zip_members",
        accepts_formats=frozenset({"zip", "office"}),
        role="Iterate zip members with archive-guard limits.",
        live_today=True,
    ),
    RegistryEntry(
        entry_id="pdf.text.v1",
        kind="adapter", version="1",
        implementation_path="pdfplumber:open",
        accepts_formats=frozenset({"pdf"}),
        role="Extract plain text from PDF (in-line pdfplumber usage today).",
        live_today=True,
        notes="No PDF-specific analyzer exists yet; text pipeline consumes output.",
    ),
    RegistryEntry(
        entry_id="docx.text.v1",
        kind="adapter", version="1",
        implementation_path="security.archive_guard:safe_iter_zip_members",
        accepts_formats=frozenset({"docx", "pptx", "xlsx"}),
        role="Extract text from OOXML via zip iteration (in-line usage today).",
        live_today=True,
    ),
    RegistryEntry(
        entry_id="image.acquire.v1",
        kind="adapter", version="1",
        implementation_path="services.adapters.image_adapter:ImageAdapter",
        accepts_formats=frozenset({"png", "jpg", "jpeg", "webp", "gif", "bmp", "image"}),
        role="Image acquisition capability (bytes → PIL image + metadata).",
        live_today=False,
        notes="SHADOW — ImageAdapter exists at services/adapters/ but is "
              "un-imported from production.  Registered in its current dead state.",
    ),
    RegistryEntry(
        entry_id="text.passthrough.v1",
        kind="adapter", version="1",
        implementation_path="builtins:str",
        accepts_formats=frozenset({"plain_text"}),
        role="Trivial pass-through for pasted text (no acquisition needed).",
        live_today=True,
    ),
]

for _e in _ADAPTERS:
    ADAPTER_REGISTRY.register(_e)


# ─── Analyzer registrations (§5.2 of ADR-0014) ──────────────────────────────
_ANALYZERS = [
    RegistryEntry(
        entry_id="die.command.v1",
        kind="analyzer", version="1",
        implementation_path="services.die.api:analyze",
        accepts_formats=frozenset({
            "powershell", "cmd", "python", "bash", "javascript", "vbscript",
            "plain_text",
        }),
        role="DIE authoritative analyzer — AST + LOLBAS + IOC + technique catalogue.",
        live_today=True,
    ),
    RegistryEntry(
        entry_id="die.recursive.v1",
        kind="analyzer", version="1",
        implementation_path="services.die.recursive_decode:extract_decoded_layers",
        accepts_formats=frozenset({"base64_blob", "hex_blob", "plain_text"}),
        role="Recursive decoder: PS -Enc / .NET FromBase64String / bash base64 -d.",
        live_today=True,
        notes="Python base64.b64decode NOT recognised today — locked as-is.",
    ),
    RegistryEntry(
        entry_id="report_extractor.v1",
        kind="analyzer", version="1",
        implementation_path="services.ida.report_extractors:extract_all",
        accepts_formats=frozenset({"html", "plain_text"}),
        role="Article body → commands / IOCs / MITRE / actors / malware / CVEs.",
        live_today=True,
    ),
    RegistryEntry(
        entry_id="image.ocr.v1",
        kind="analyzer", version="1",
        implementation_path="services.adapters.image_adapter:ImageAdapter",
        accepts_formats=frozenset({"png", "jpg", "jpeg", "webp"}),
        role="Tesseract OCR on image bytes (existing shadow capability).",
        live_today=False,
        notes="SHADOW — not imported from production; registered in dead state.",
    ),
    RegistryEntry(
        entry_id="csv.edr.symantec.v1",
        kind="analyzer", version="1",
        implementation_path="services.die.csv_edr_analyzer:analyse_csv_edr",
        accepts_formats=frozenset({"csv"}),
        role="Symantec SEP-schema CSV column mapper → MITRE + IOC + LOLBAS.",
        live_today=True,
    ),
    RegistryEntry(
        entry_id="ioc_enrichment.v1",
        kind="analyzer", version="1",
        implementation_path="analysis_core:enrich_iocs",
        accepts_formats=frozenset({"url", "ip", "domain", "hash", "filename"}),
        role="Reputation enrichment for atomic IOC inputs (bounded TI + OSINT).",
        live_today=True,
    ),
    RegistryEntry(
        entry_id="pe.header.v1",
        kind="analyzer", version="1",
        implementation_path="services.pe_analyzer:analyze_pe",
        accepts_formats=frozenset({"pe"}),
        role="PE header + section summary (currently orphan — not fed to verdict).",
        live_today=True,
        notes="Orphan: registered but output does not participate in verdict today.",
    ),
    RegistryEntry(
        entry_id="narrative.canonical.v1",
        kind="analyzer", version="1",
        implementation_path=(
            "services.die.canonical_narrative_enrichment:enrich_narrative"),
        accepts_formats=frozenset({"plain_text", "html"}),
        role="Canonical prose-narrative rules → additional MITRE techniques.",
        live_today=True,
    ),
    RegistryEntry(
        entry_id="mitre.regex_diag.v1",
        kind="analyzer", version="1",
        implementation_path="operations:mitre_map",
        accepts_formats=frozenset({"plain_text"}),
        role="Legacy regex MITRE mapper — DIAGNOSTIC ONLY (not authoritative).",
        live_today=True,
        notes="Still fires today inside verdict_card; demotion is M6, not M0b.",
    ),
    RegistryEntry(
        entry_id="verdict.risk_score.v1",
        kind="analyzer", version="1",
        implementation_path="operations:risk_score",
        accepts_formats=frozenset({"plain_text"}),
        role="Verdict scorer (recalibrated Item-1, per ADR-0010f).",
        live_today=True,
    ),
    # ─── M0b-extension (ADR-0014d · 2026-02-15) ───────────────────────────
    # Two capabilities identified as class-A independent by the pre-M0f
    # architecture reassessment.  Registered PASSIVELY — nothing in
    # production consumes them via the registry yet.
    RegistryEntry(
        entry_id="report.narrative.v1",
        kind="analyzer", version="1",
        implementation_path="services.die.narrative:generate_report",
        accepts_formats=frozenset({"die_envelope"}),
        role="Deterministic 12-section report generator over the DIE envelope.",
        live_today=True,
        notes="Independent capability — consumes an already-analyzed env; "
              "not called from inside services.die.api:analyze. "
              "See ADR-0014d for the duplicate-execution proof.",
    ),
    RegistryEntry(
        entry_id="artifact.intel.v1",
        kind="analyzer", version="1",
        implementation_path="services.artifact_intelligence:dispatch",
        accepts_formats=frozenset({"bytes"}),
        role="Pluggable artifact analyzers (PE, DOCX, PDF, shellcode, …) "
              "dispatched by content magic.",
        live_today=True,
        notes="Independent top-level package with its own analyzers/ "
              "subdirectory and routes/artifacts.py entry-point.",
    ),
]

for _e in _ANALYZERS:
    ANALYZER_REGISTRY.register(_e)


def health_check() -> Dict[str, dict]:
    """Attempt to resolve every registered implementation_path.

    Read-only. Returns a status report per entry:
      {entry_id: {"kind","live_today","importable","reason"}}
    Never raises. Used by registry hygiene tests + observability.
    """
    import importlib
    report: Dict[str, dict] = {}
    for reg in (ADAPTER_REGISTRY, ANALYZER_REGISTRY):
        for e in reg.all():
            mod, _, attr = e.implementation_path.partition(":")
            entry_report = {"kind": e.kind, "live_today": e.live_today}
            try:
                m = importlib.import_module(mod)
                if attr and not hasattr(m, attr):
                    entry_report["importable"] = False
                    entry_report["reason"]     = f"module {mod!r} has no attribute {attr!r}"
                else:
                    entry_report["importable"] = True
                    entry_report["reason"]     = "ok"
            except Exception as ex:                                 # noqa: BLE001
                entry_report["importable"] = False
                entry_report["reason"]     = f"{type(ex).__name__}: {ex}"
            report[e.entry_id] = entry_report
    return report


__all__ = [
    "ADAPTER_REGISTRY",
    "ANALYZER_REGISTRY",
    "RegistryEntry",
    "RegistryError",
    "health_check",
]
