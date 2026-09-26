"""
P0.0 · NivXRay XDR Architecture Audit
─────────────────────────────────────

Authoritative source-code inventory of every declared NivXRay
engine family.  Non-invasive: reads Python source, extracts class
definitions, docstrings, imports and public callables — makes no
runtime assumptions.

For each family the user's master prompt calls out
(IUE, VEEE, DIE, IDE, ICE, UAIE, Verdict, Correlation, IKG,
Evidence Graph, Process Tree, Device Trajectory, and every other),
this module answers three deterministic questions:

    1. Is there a real implementation?           (files, symbols)
    2. What does it consume / produce?           (docstring hints)
    3. What are its stated dependencies?         (imports)

The audit is never a source of promotion.  It is the honest
starting point every subsequent P0 slice reads from.
"""
from __future__ import annotations
import ast
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ROOT = Path("/app/backend")


# ── Engine family patterns (from the master prompt) ──────────────
#
# Each key is the canonical family name; the pattern is the case-
# insensitive regex used to find implementations.  Patterns are
# intentionally conservative — false-negative is better than
# false-positive because false positives inflate readiness metrics.
#
_FAMILIES: dict[str, str] = {
    # NivXRay-Core analytical engines called out explicitly:
    "IUE":                  r"\b(iue|investigation_understanding_engine|investigation_understanding)\b",
    "VEEE":                 r"\b(veee|verdict_evidence_evaluation)\b",
    "DIE":                  r"\b(die|dispositional_intelligence_engine|dispositional_intelligence)\b",
    "IDE":                  r"\b(ide|inspection_disposition_engine|inspection_disposition)\b",
    "ICE":                  r"\b(ice|investigation_correlation_engine|investigation_correlation)\b",
    "UAIE":                 r"\b(uaie|unified_artifact_intelligence_engine)\b",

    # Downstream / classical engines:
    "VerdictEngine":        r"\bverdict_engine\b|\bverdict\.py\b",
    "CorrelationEngine":    r"\bcorrelation_engine\b|correlation_engine",
    "EvidenceEngine":       r"\bevidence_engine\b|evidence_engine",
    "GraphEngine":          r"\bgraph_engine\b|graph_engine",
    "IKG":                  r"\bikg\b|investigation_knowledge_graph|investigation_graph",
    "EvidenceGraph":        r"evidence_graph|graph_evidence",

    # Investigation surfaces:
    "ProcessTree":          r"process_tree|process[-_ ]tree",
    "DeviceTrajectory":     r"device_trajectory|trajectory_engine",
    "AttackStory":          r"attack_story|attack[-_ ]story",
    "MITREATTCK":           r"mitre|att[&_]?ck|attck",

    # Analysis fabric:
    "PEAnalyzer":           r"pe_analyzer|pe_analysis|analyze_pe",
    "ELFAnalyzer":          r"elf_analyzer|elf_analysis|analyze_elf",
    "OfficeAnalyzer":       r"office_analyzer|office_analysis|olevba",
    "ShellcodeAnalyzer":    r"shellcode",
    "AMSIAnalyzer":         r"amsi",
    "CommandAnalyzer":      r"command_analyzer|command_analysis|semantic_command",
    "ArtifactIntelligence": r"artifact_intel|artifact_intelligence",
    "IOCIntelligence":      r"ioc_intel|ioc_intelligence|iocs?_engine",
    "CommandIntelligence":  r"command_intel|command_intelligence",
    "MalwareIntelligence":  r"malware_intel|malware_intelligence",
    "AttackFingerprint":    r"attack_fingerprint|fingerprint",
    "BehaviorExtractor":    r"behavior_extract|behaviour_extract",
    "TechniqueDetector":    r"technique_detector|technique_detection",
    "MitigationEvidence":   r"mitigation_evidence|mitigation",
    "CEM":                  r"\bcem\b|canonical_event_model",
    "ConfidenceProvenance": r"confidence|provenance",
    "InterpreterIdentifier": r"interpreter_identif|interpreter_ident",
    "RecipePlanner":        r"recipe_planner|recipe_plan",
    "RecursiveChildPipeline": r"recursive_child|child_pipeline",

    # Content / detection:
    "SigmaEngine":          r"sigma_ingest|sigma_strict|sigma_engine",
    "Rules":                r"detection_rules|rule_engine|rules\.py",
    "LOLBAS":               r"lolbas",
    "YARA":                 r"\byara\b",

    # Ingestion:
    "Parsers":              r"/parsers?/|_parser\.py|parser_",
    "Normalizers":          r"/normaliz(er|ation)/|_normalizer\.py|normalize_",
    "Collectors":           r"/collectors?/|collector_",
    "DSM":                  r"\bdsm\b|device_support",
    "Decoders":             r"/decoders?/|decoder_",
    "Interpreters":         r"/interpreters?/|interpreter_",

    # Foundations:
    "SSOT":                 r"\bssot\b",
    "LaneA":                r"lane_a",
    "LaneB":                r"lane_b",
    "UIL":                  r"\buil\b",
    "KnowledgeBase":        r"knowledge_base|kb_engine|kb\.py",
}


@dataclass
class FileHit:
    path:       str
    symbols:    list[str]         # top-level class + function names
    imports:    list[str]         # external modules imported
    docstring:  str               # module docstring (truncated)
    size_bytes: int
    kind:       str               # "module" / "package_init"


@dataclass
class FamilyReport:
    family:          str
    pattern:         str
    hits:            list[FileHit] = field(default_factory=list)
    implementations: int = 0
    total_symbols:   int = 0

    def as_summary(self) -> dict:
        return {
            "family":          self.family,
            "pattern":         self.pattern,
            "implementations": self.implementations,
            "total_symbols":   self.total_symbols,
            "hits": [asdict(h) for h in self.hits],
        }


# ── Source-code walker ─────────────────────────────────────────

_SKIP_DIRS = {"__pycache__", ".venv", "venv", "node_modules",
                    ".pytest_cache", "site-packages", "tests"}


def _iter_python_files(root: Path):
    for p in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def _extract_symbols(text: str) -> tuple[list[str], list[str], str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], [], ""
    symbols: list[str] = []
    imports: set[str]  = set()
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef,
                                    ast.AsyncFunctionDef)):
            symbols.append(node.name)
        elif isinstance(node, ast.Import):
            for a in node.names: imports.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    return symbols, sorted(imports), (ast.get_docstring(tree) or "")


def _file_hit(path: Path) -> FileHit | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    symbols, imports, doc = _extract_symbols(text)
    return FileHit(
        path       = str(path.relative_to(ROOT)),
        symbols    = symbols,
        imports    = imports,
        docstring  = (doc[:400] + "…") if len(doc) > 400 else doc,
        size_bytes = path.stat().st_size,
        kind       = "package_init" if path.name == "__init__.py" else "module",
    )


def audit() -> dict:
    """
    Walk the backend source tree and populate one FamilyReport per
    declared engine family.  Returns the full audit payload.
    """
    all_hits: dict[str, FileHit] = {}
    for py in _iter_python_files(ROOT):
        h = _file_hit(py)
        if h: all_hits[h.path] = h

    reports: list[FamilyReport] = []
    for name, pattern in _FAMILIES.items():
        rx = re.compile(pattern, re.IGNORECASE)
        report = FamilyReport(family=name, pattern=pattern)
        for path, hit in all_hits.items():
            hay = path + "\n" + "\n".join(hit.symbols)
            if rx.search(hay):
                report.hits.append(hit)
                report.total_symbols += len(hit.symbols)
        report.implementations = len(report.hits)
        reports.append(report)

    # High-level rollups
    families_with_impl    = [r.family for r in reports if r.implementations > 0]
    families_without_impl = [r.family for r in reports if r.implementations == 0]

    return {
        "audit_version":   "P0.0-1",
        "root":            str(ROOT),
        "files_scanned":   len(all_hits),
        "families_total":  len(reports),
        "families_present": len(families_with_impl),
        "families_missing": len(families_without_impl),
        "families_present_list": families_with_impl,
        "families_missing_list": families_without_impl,
        "reports":         [r.as_summary() for r in reports],
        "honesty_note": (
            "This audit reports source-code PRESENCE only.  A family "
            "listed as 'present' has at least one Python module whose "
            "path or symbol name matches the family's regex.  Presence "
            "in this audit does NOT imply the module is runtime-ready, "
            "capability-verified, or execution-tested.  Runtime readiness "
            "is proven by the P0.2e Detection Execution Harness and the "
            "P0.4 Real E2E Replay slice — never by this audit."
        ),
    }
