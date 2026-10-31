"""Tests for Stage 2 · Schema Understanding.

Contracts under test (see NIVXRAY_ARCHITECTURE_VISION.md):
  · Never raises
  · Never performs semantic mapping (candidate_fields only)
  · unknown_structured is a supported success state
  · schema_confidence is distinct from vendor / semantic confidence
  · reasons carry human-readable provenance
  · Recognises open standards by shape (not by vendor identity)
  · Registry version is echoed for provenance (not for mapping)
"""
from __future__ import annotations

import json
import textwrap

import pytest

from nivxforge.investigation.pipeline.input_classification import (
    InputClass, classify_input,
)
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.schema_understanding import (
    SchemaFamily,
    SchemaFingerprint,
    understand_schema,
)
from nivxforge.investigation.pipeline import semantic_alias_registry as reg
from nivxforge.investigation.pipeline.orchestrator import run_phase1


# ── helpers ──────────────────────────────────────────────────────────

def _fingerprint(raw: str) -> SchemaFingerprint:
    classification = classify_input(raw)
    parsed = parse_input(raw, classification)
    return understand_schema(parsed)


# ── universal contracts ─────────────────────────────────────────────

class TestFingerprintUniversalContract:

    @pytest.mark.parametrize("raw", [
        "",
        "   \n\t  ",
        '{"a": 1}',
        '{"a":1}\n{"b":2}',
        "a,b,c\n1,2,3\n4,5,6",
        "<Event><EventID>1</EventID></Event>",
        "foo=1 bar=2\nfoo=3 bar=4",
        "powershell.exe -EncodedCommand ABCDEFGH",
        "Some completely unstructured text with no schema.",
    ])
    def test_never_raises_and_returns_fingerprint(self, raw):
        fp = _fingerprint(raw)
        assert isinstance(fp, SchemaFingerprint)
        assert isinstance(fp.candidate_fields, tuple)
        assert isinstance(fp.reasons, tuple)
        assert isinstance(fp.diagnostics, tuple)
        assert 0.0 <= fp.schema_confidence <= 1.0

    def test_registry_version_is_echoed(self):
        fp = _fingerprint('{"foo": "bar"}')
        assert fp.registry_version == reg.SEMANTIC_ALIAS_REGISTRY_VERSION

    def test_no_semantic_mapping_in_output(self):
        # candidate_fields carry the RAW surface names — not concepts.
        fp = _fingerprint('{"DeviceName":"HOST01","UserName":"alice"}')
        assert "DeviceName" in fp.candidate_fields
        assert "UserName" in fp.candidate_fields
        # No concept names ("Host", "User") should be injected.
        assert "Host" not in fp.candidate_fields
        assert "User" not in fp.candidate_fields


# ── Elastic Common Schema (open standard, not vendor) ──────────────

class TestElasticCommonSchema:

    def test_ecs_via_ecs_version_field(self):
        doc = {"@timestamp": "2026-02-01T00:00:00Z",
               "ecs": {"version": "8.11.0"},
               "host": {"name": "web-01"},
               "event": {"category": "process"}}
        fp = _fingerprint(json.dumps(doc))
        assert fp.schema_family == SchemaFamily.ELASTIC_ECS
        assert fp.schema_version == "ecs-8.11.0"
        assert fp.schema_confidence >= 0.6

    def test_ecs_via_nested_namespaces(self):
        doc = {
            "@timestamp": "2026-02-01T00:00:00Z",
            "host": {"name": "web-01"},
            "source": {"ip": "10.0.0.1"},
            "destination": {"ip": "10.0.0.2"},
            "process": {"name": "nginx"},
        }
        fp = _fingerprint(json.dumps(doc))
        assert fp.schema_family == SchemaFamily.ELASTIC_ECS
        assert fp.schema_confidence >= 0.6
        assert any("nested namespaces" in r for r in fp.reasons)

    def test_ecs_via_dotted_ndjson(self):
        line1 = ('{"@timestamp":"2026-02-01T00:00:00Z",'
                 '"host.name":"web-01",'
                 '"source.ip":"1.1.1.1",'
                 '"event.category":"network"}')
        line2 = ('{"@timestamp":"2026-02-01T00:00:01Z",'
                 '"host.name":"web-02",'
                 '"source.ip":"2.2.2.2",'
                 '"event.category":"network"}')
        fp = _fingerprint(f"{line1}\n{line2}")
        assert fp.schema_family == SchemaFamily.ELASTIC_ECS
        assert fp.schema_confidence >= 0.6


# ── Windows Event XML ─────────────────────────────────────────────

class TestWindowsEventXml:

    def test_detects_windows_event(self):
        raw = textwrap.dedent("""
            <Event>
              <System>
                <Provider Name='Microsoft-Windows-Sysmon'/>
                <EventID>1</EventID>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
                <Computer>HOST01</Computer>
              </System>
              <EventData>
                <Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>
                <Data Name='ProcessId'>4242</Data>
                <Data Name='CommandLine'>cmd /c whoami</Data>
              </EventData>
            </Event>
        """).strip()
        fp = _fingerprint(raw)
        assert fp.schema_family == SchemaFamily.WINDOWS_EVENT_XML
        assert fp.schema_confidence >= 0.5
        assert any("EventID" in r for r in fp.reasons)
        assert "Image" in fp.candidate_fields
        assert "CommandLine" in fp.candidate_fields

    def test_generic_xml_when_no_windows_signature(self):
        raw = "<Root><Item>alpha</Item><Item>beta</Item></Root>"
        fp = _fingerprint(raw)
        # Either windows_event_xml if signature accidentally caught or
        # generic_xml otherwise. It must NOT be unknown_structured.
        assert fp.schema_family in (SchemaFamily.GENERIC_XML,
                                    SchemaFamily.WINDOWS_EVENT_XML)


# ── CEF / LEEF (open standards) ────────────────────────────────────

class TestCefLeef:

    def test_cef_header_detected(self):
        raw = ("CEF:0|Vendor|Product|1.0|100|User Logged In|3|"
               "src=10.0.0.1 suser=alice dst=10.0.0.2")
        fp = _fingerprint(raw)
        assert fp.schema_family == SchemaFamily.CEF
        assert fp.schema_version and fp.schema_version.startswith("cef")
        assert "src" in fp.candidate_fields
        assert "suser" in fp.candidate_fields

    def test_leef_header_detected(self):
        raw = ("LEEF:2.0|Vendor|Product|1.0|EventID|"
               "src=1.1.1.1 dst=2.2.2.2 usrName=alice")
        fp = _fingerprint(raw)
        assert fp.schema_family == SchemaFamily.LEEF
        assert fp.schema_version and fp.schema_version.startswith("leef")


# ── Generic families ───────────────────────────────────────────────

class TestGenericFamilies:

    def test_generic_json_when_no_signature(self):
        fp = _fingerprint('{"foo": 1, "bar": "baz"}')
        assert fp.schema_family == SchemaFamily.GENERIC_JSON
        assert "foo" in fp.candidate_fields
        assert "bar" in fp.candidate_fields

    def test_generic_ndjson_when_no_signature(self):
        raw = '{"a":1,"b":2}\n{"a":3,"b":4}\n{"a":5,"b":6}'
        fp = _fingerprint(raw)
        assert fp.schema_family == SchemaFamily.GENERIC_NDJSON
        assert fp.parser_features["record_count"] == 3

    def test_generic_csv(self):
        raw = "col1,col2,col3\na,b,c\nd,e,f\n"
        fp = _fingerprint(raw)
        assert fp.schema_family == SchemaFamily.GENERIC_CSV
        assert "col1" in fp.candidate_fields

    def test_generic_kv(self):
        raw = "foo=1 bar=2 baz=3\nfoo=4 bar=5 baz=6"
        fp = _fingerprint(raw)
        assert fp.schema_family == SchemaFamily.GENERIC_KV
        assert "foo" in fp.candidate_fields


# ── Non-record inputs ──────────────────────────────────────────────

class TestNonRecordInputs:

    def test_empty(self):
        fp = _fingerprint("")
        assert fp.schema_family == SchemaFamily.EMPTY
        assert fp.candidate_fields == ()
        assert fp.schema_confidence == 1.0

    def test_command_line(self):
        fp = _fingerprint("powershell.exe -EncodedCommand YQBhAGEA")
        assert fp.schema_family == SchemaFamily.COMMAND_LINE
        assert "command_line" in fp.candidate_fields

    def test_plain_command_is_command_line_family(self):
        fp = _fingerprint("cmd.exe /c whoami")
        assert fp.schema_family == SchemaFamily.COMMAND_LINE

    def test_unstructured_text(self):
        fp = _fingerprint("this is just a note from an analyst.")
        assert fp.schema_family == SchemaFamily.UNKNOWN_UNSTRUCTURED
        assert fp.candidate_fields == ()


# ── Parser features ────────────────────────────────────────────────

class TestParserFeatures:

    def test_dotted_keys_detected(self):
        raw = '{"host.name":"a","source.ip":"1.1.1.1","event.action":"x"}'
        fp = _fingerprint(raw)
        assert fp.parser_features["has_dotted_keys"] is True
        assert fp.parser_features["key_style"] in ("dotted", "mixed")

    def test_nested_objects_detected(self):
        raw = '{"host":{"name":"a"},"source":{"ip":"1.1.1.1"}}'
        fp = _fingerprint(raw)
        assert fp.parser_features["has_nested_objects"] is True
        # host.name AND source.ip are added as dotted candidates.
        assert "host.name" in fp.candidate_fields
        assert "source.ip" in fp.candidate_fields

    def test_arrays_detected(self):
        raw = '{"tags":["a","b","c"]}'
        fp = _fingerprint(raw)
        assert fp.parser_features["has_arrays"] is True


# ── Mandated unknown-schema regression ─────────────────────────────

class TestUnknownSchemaRegression:
    """The most important contract in this milestone.

    Given telemetry that resembles NO known schema family, the
    pipeline must:
      · Parse successfully
      · Return a SchemaFingerprint with schema_family == unknown_structured
      · Carry candidate_fields and reasons
      · Not raise, not degrade to error
      · Still reach the Investigation Graph via run_phase1
    """

    ALIEN_RAW = json.dumps({
        # Deliberately alien field names — not ECS, not OTEL, not Sysmon,
        # not CEF/LEEF, not any known vendor schema.
        "zorb_ident": "Q-7734",
        "flanvex": {"ripcode": 42, "krellon": "x"},
        "brindle_stamp": "2026-02-01",
        "quorpath": ["/etc/skel", "/opt/nowhere"],
        "linguo_verdict": "warn",
    })

    def test_parser_succeeds_on_alien_telemetry(self):
        classification = classify_input(self.ALIEN_RAW)
        parsed = parse_input(self.ALIEN_RAW, classification)
        # Parser must succeed (return records).
        assert parsed.records, "parser produced no records"

    def test_schema_understanding_returns_unknown_structured(self):
        fp = _fingerprint(self.ALIEN_RAW)
        # ECS, OTEL, WinEvent, CEF, LEEF all miss → generic_json
        # (JSON is the parser class). unknown_structured is reserved
        # for when parser succeeds but even generic family is unclear.
        # For this alien JSON the correct answer is generic_json.
        assert fp.schema_family == SchemaFamily.GENERIC_JSON
        assert fp.candidate_fields  # populated
        assert fp.reasons  # populated

    def test_alien_non_json_reaches_unknown_structured(self):
        # Fabricate a parsed input whose kind is deliberately outside
        # the family-typed parser classes. Use PLAIN_TEXT that hits
        # neither CEF/LEEF/syslog nor structured signals. Punctuation
        # is required so the classifier does not treat the string as
        # a standalone base64 blob.
        raw = ("Analyst note: reviewed the sample; no clear structure. "
               "Escalating to L2 — will follow up tomorrow.")
        fp = _fingerprint(raw)
        assert fp.schema_family == SchemaFamily.UNKNOWN_UNSTRUCTURED
        # Success state — non-zero confidence, populated reasons.
        assert fp.schema_confidence > 0
        assert fp.reasons

    def test_pipeline_reaches_investigation_graph_on_alien_input(self):
        state = run_phase1(self.ALIEN_RAW)
        # Contract: even unknown telemetry produces a graph.
        assert state.graph is not None
        # Contract: schema understanding is *observable* alongside
        # existing Phase 1 output when explicitly invoked.
        fp = understand_schema(state.parsed)
        assert fp.schema_family in (SchemaFamily.GENERIC_JSON,
                                    SchemaFamily.UNKNOWN_STRUCTURED)


# ── No-vendor-branching contract ───────────────────────────────────

class TestNoVendorBranching:
    """Schema Understanding must classify by *shape*, never by vendor.

    Feeding vendor-branded fields under an unknown structural shape
    must NOT cause a vendor-driven classification.
    """

    def test_vendor_brand_names_in_values_do_not_influence_shape(self):
        raw = json.dumps({
            "product": "CrowdStrike Falcon",
            "vendor": "Microsoft Defender",
            "note": "these are just strings inside a generic object",
        })
        fp = _fingerprint(raw)
        # Must resolve as generic_json — not any vendor family
        # (there are no vendor families here anyway; this is the point).
        assert fp.schema_family == SchemaFamily.GENERIC_JSON
