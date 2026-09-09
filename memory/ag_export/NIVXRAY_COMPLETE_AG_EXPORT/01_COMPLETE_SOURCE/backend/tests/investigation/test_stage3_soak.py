"""Stage 3 Soak — validation harness against Phase 1 fixtures + alien corpus.

Owner mandate (2026-02-XX):
  · Use existing Phase 1 fixtures only (Sysmon, MDE-shape, Cisco,
    generic, encoded_cmd) plus the 5 alien corpus files.
  · No fabricated CS/SentinelOne/QRadar/Splunk — those are held
    until real sanitised samples arrive.
  · Do not move on until mappings are consistently analyst-defensible.

This module runs Stage 3 across every fixture, writes a Markdown
soak report at ``tests/investigation/stage3_soak_report.md``, and
asserts the invariants that guard against silent regressions.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from typing import Dict, List, Tuple

import pytest

from nivxforge.investigation.pipeline.input_classification import (
    classify_input,
)
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.schema_understanding import (
    SchemaFingerprint,
    understand_schema,
)
from nivxforge.investigation.pipeline.semantic_field_mapper import (
    SemanticMappingResult,
    map_semantic_fields,
)


ROOT = pathlib.Path(__file__).parent
CORPUS_DIR = ROOT / "corpus" / "alien"
REPORT_PATH = ROOT / "stage3_soak_report.md"


# ── Phase 1 fixtures (extracted verbatim from test_normalizers.py) ─

_PHASE1_FIXTURES: Dict[str, str] = {
    "cisco_secure_endpoint": json.dumps({
        "id": "e-42", "date": "2026-01-15T10:22:00Z",
        "detection": "W32.Trojan.Emotet",
        "event_type": "Threat Detected",
        "event_type_id": 1090519054,
        "connector_guid": "cg-1", "severity": "High",
        "computer": {"connector_guid": "cg-1", "hostname": "WKS-42",
                     "operating_system": "Windows 10"},
        "file": {"disposition": "Malicious",
                 "file_name": "invoice.exe",
                 "file_path": "C:/Users/John/Downloads/invoice.exe",
                 "identity": {"sha256": "a" * 64, "md5": "b" * 32}},
        "network_info": {"remote_ip": "198.51.100.7",
                         "remote_port": 443,
                         "dirty_url": "http://bad.com/p1"},
    }),
    "sysmon_process_create": json.dumps({
        "EventID": 1, "Computer": "host-a",
        "User": "CORP\\alice",
        "Image": "C:/Windows/System32/cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentImage": "C:/explorer.exe",
        "ParentCommandLine": "explorer.exe",
        "ProcessId": 1234, "ParentProcessId": 100,
        "Hashes": "SHA256=" + "d" * 64,
    }),
    "sysmon_dns_query": json.dumps({
        "EventID": 22, "Computer": "h1",
        "QueryName": "malicious.example",
        "QueryType": "A",
    }),
    "sysmon_network_connect": json.dumps({
        "EventID": 3, "Computer": "h1",
        "SourceIp": "10.0.0.1", "SourcePort": 5555,
        "DestinationIp": "1.2.3.4", "DestinationPort": 443,
        "Protocol": "tcp", "Initiated": "true",
    }),
    "generic_fallback_cmdline": json.dumps({
        "foo": 1, "cmdLine": "certutil -urlcache -f x y",
    }),
    "encoded_powershell_command":
        "powershell -EncodedCommand SGVsbG8=",
    # ECS-style flat dotted keys — recognised as Elastic Common Schema
    # by Schema Understanding.
    "elastic_ecs_process": json.dumps({
        "@timestamp": "2026-02-01T00:00:00Z",
        "host.name": "web-01",
        "user.name": "alice",
        "source.ip": "10.0.0.1",
        "destination.ip": "10.0.0.2",
        "process.name": "nginx",
        "event.category": "process",
        "event.action": "start",
    }),
    "key_value_syslog_style":
        "src_ip=10.0.0.1 dst_ip=10.0.0.2 proto=tcp uid=alice host=host01\n"
        "src_ip=10.0.0.3 dst_ip=10.0.0.4 proto=udp uid=bob host=host02",
}


# ── Soak analysis primitives ──────────────────────────────────────

@dataclass(frozen=True)
class FixtureReport:
    name: str
    schema_family: str
    schema_confidence: float
    candidate_count: int
    mapped_count: int
    ambiguous_count: int
    unmapped_count: int
    top_mappings: Tuple[Tuple[str, str, float, Tuple[str, ...]], ...]
    unmapped_fields: Tuple[str, ...]
    ambiguous_fields: Tuple[str, ...]
    defensibility_flags: Tuple[str, ...]


# Fields whose *normalized* form MUST map to a specific concept
# for the fixture to be considered analyst-defensible. Empty when
# alien corpus (no known-mapping expectations).
_DEFENSIBILITY_RULES: Dict[str, Dict[str, str]] = {
    "cisco_secure_endpoint": {
        "computer.hostname": "Host",
        "file.file_name":    "File",
        "network_info.remote_ip": "IP",
        "network_info.remote_port": "Port",
    },
    "sysmon_process_create": {
        "Computer":         "Host",
        "Image":            "Process",
        "CommandLine":      "Command",
        "ParentImage":      "Process",
        "ProcessId":        "Process",
    },
    "sysmon_network_connect": {
        "Computer":         "Host",
        "SourceIp":         "IP",
        "DestinationIp":    "IP",
        "SourcePort":       "Port",
        "DestinationPort":  "Port",
        "Protocol":         "Protocol",
    },
    "elastic_ecs_process": {
        "host.name":        "Host",
        "user.name":        "User",
        "source.ip":        "IP",
        "destination.ip":   "IP",
        "process.name":     "Process",
    },
    "key_value_syslog_style": {
        "src_ip":           "IP",
        "dst_ip":           "IP",
        "host":             "Host",
        "proto":            "Protocol",
    },
}


def _soak_fixture(name: str, raw: str) -> FixtureReport:
    classification = classify_input(raw)
    parsed = parse_input(raw, classification)
    fp: SchemaFingerprint = understand_schema(parsed)
    result: SemanticMappingResult = map_semantic_fields(fp, parsed)

    # Top 5 mappings by confidence, with first 2 provenance signals.
    ranked = sorted(result.mappings, key=lambda m: -m.confidence)
    top: List[Tuple[str, str, float, Tuple[str, ...]]] = []
    for m in ranked[:5]:
        sig_labels = tuple(p.signal for p in m.confidence_provenance[:3])
        top.append((m.surface_field, m.concept, m.confidence, sig_labels))

    # Defensibility check.
    flags: List[str] = []
    expected = _DEFENSIBILITY_RULES.get(name, {})
    actual: Dict[str, str] = {m.surface_field: m.concept
                              for m in result.mappings}
    for field, want_concept in expected.items():
        got = actual.get(field)
        if got is None:
            if field in result.unmapped_fields:
                flags.append(f"MISS  {field} → expected {want_concept}, "
                             f"got: unmapped")
            elif any(a.surface_field == field
                     for a in result.ambiguous_fields):
                flags.append(f"AMBIG {field} → expected {want_concept}, "
                             f"got: ambiguous")
            else:
                flags.append(f"MISS  {field} → expected {want_concept}, "
                             f"got: absent from candidate_fields")
        elif got != want_concept:
            flags.append(f"WRONG {field} → expected {want_concept}, "
                         f"got: {got}")

    return FixtureReport(
        name=name,
        schema_family=fp.schema_family,
        schema_confidence=fp.schema_confidence,
        candidate_count=len(fp.candidate_fields),
        mapped_count=len(result.mappings),
        ambiguous_count=len(result.ambiguous_fields),
        unmapped_count=len(result.unmapped_fields),
        top_mappings=tuple(top),
        unmapped_fields=tuple(result.unmapped_fields),
        ambiguous_fields=tuple(a.surface_field
                               for a in result.ambiguous_fields),
        defensibility_flags=tuple(flags),
    )


def _collect_alien_fixtures() -> Dict[str, str]:
    if not CORPUS_DIR.exists():
        return {}
    return {p.stem: p.read_text(encoding="utf-8")
            for p in sorted(CORPUS_DIR.glob("*.json"))}


def _all_fixtures() -> Dict[str, str]:
    fixtures = dict(_PHASE1_FIXTURES)
    for name, raw in _collect_alien_fixtures().items():
        fixtures[f"alien::{name}"] = raw
    return fixtures


# ── Report writer ────────────────────────────────────────────────

def _render_report(reports: List[FixtureReport]) -> str:
    lines: List[str] = []
    lines.append("# Stage 3 Semantic Field Mapping · Soak Report")
    lines.append("")
    lines.append(f"Generated by `soak_stage3.py` — "
                 f"{len(reports)} fixtures.")
    lines.append("")

    total_candidates = sum(r.candidate_count for r in reports)
    total_mapped = sum(r.mapped_count for r in reports)
    total_ambiguous = sum(r.ambiguous_count for r in reports)
    total_unmapped = sum(r.unmapped_count for r in reports)
    total_flags = sum(len(r.defensibility_flags) for r in reports)

    lines.append("## Aggregate")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|---|---|")
    lines.append(f"| Fixtures | {len(reports)} |")
    lines.append(f"| Candidate fields | {total_candidates} |")
    lines.append(f"| Mapped | {total_mapped} |")
    lines.append(f"| Ambiguous | {total_ambiguous} |")
    lines.append(f"| Unmapped | {total_unmapped} |")
    lines.append(f"| Defensibility flags | **{total_flags}** |")
    if total_candidates:
        rate = 100.0 * total_mapped / total_candidates
        lines.append(f"| Mapping rate | {rate:.1f}% |")
    lines.append("")

    lines.append("## Per-fixture detail")
    lines.append("")

    for r in reports:
        lines.append(f"### `{r.name}`")
        lines.append("")
        lines.append(f"- **schema**: `{r.schema_family}` "
                     f"(confidence {r.schema_confidence:.2f})")
        lines.append(f"- **fields**: "
                     f"{r.mapped_count} mapped · "
                     f"{r.ambiguous_count} ambiguous · "
                     f"{r.unmapped_count} unmapped · "
                     f"{r.candidate_count} total")
        if r.top_mappings:
            lines.append("- **top mappings**:")
            for surface, concept, conf, sigs in r.top_mappings:
                signal_str = ", ".join(sigs) if sigs else "—"
                lines.append(f"  - `{surface}` → **{concept}** "
                             f"({conf:.2f}) · {signal_str}")
        if r.ambiguous_fields:
            lines.append(f"- **ambiguous**: "
                         f"{', '.join(f'`{f}`' for f in r.ambiguous_fields)}")
        if r.unmapped_fields:
            preview = ", ".join(f"`{f}`" for f in r.unmapped_fields[:8])
            more = ("" if len(r.unmapped_fields) <= 8
                    else f" · +{len(r.unmapped_fields) - 8} more")
            lines.append(f"- **unmapped**: {preview}{more}")
        if r.defensibility_flags:
            lines.append("- **defensibility flags**:")
            for f in r.defensibility_flags:
                lines.append(f"  - {f}")
        else:
            lines.append("- **defensibility**: ✅ all expected "
                         "concepts mapped correctly (or no rules)")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Soak is analyst-facing evidence, not a code path. "
                 "Regenerated on every pytest run of "
                 "`test_stage3_soak.py`.*")
    return "\n".join(lines)


# ── Public entry points ──────────────────────────────────────────

def run_soak_and_write_report() -> Tuple[List[FixtureReport], pathlib.Path]:
    """Run the soak and persist the Markdown report. Returns
    (reports, report_path)."""
    fixtures = _all_fixtures()
    reports = [_soak_fixture(name, raw) for name, raw in fixtures.items()]
    REPORT_PATH.write_text(_render_report(reports), encoding="utf-8")
    return reports, REPORT_PATH


# ── Pytest gates ────────────────────────────────────────────────

class TestStage3Soak:

    def test_soak_runs_and_writes_report(self):
        reports, path = run_soak_and_write_report()
        assert path.exists()
        assert reports

    def test_no_defensibility_flags(self):
        """The soak-gate. If this fails, Stage 3 is NOT
        analyst-defensible and orchestrator rewiring is blocked."""
        reports, _ = run_soak_and_write_report()
        flagged = {r.name: r.defensibility_flags
                   for r in reports if r.defensibility_flags}
        assert not flagged, (
            "Stage 3 soak surfaced analyst-indefensible mappings:\n"
            + "\n".join(f"  {name}:\n    "
                        + "\n    ".join(flags)
                        for name, flags in flagged.items())
        )

    def test_alien_corpus_mapping_rate_floor(self):
        """Aggregate release metric — alien telemetry produces at
        least some canonical mappings."""
        reports, _ = run_soak_and_write_report()
        alien = [r for r in reports if r.name.startswith("alien::")]
        assert alien, "no alien corpus fixtures found"
        total_mapped = sum(r.mapped_count for r in alien)
        assert total_mapped >= 1
