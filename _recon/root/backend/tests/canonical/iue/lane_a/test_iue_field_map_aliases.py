"""Lane-A · Field-map alias resolution + alias_source provenance."""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


def _mk_parsed(raw_fields, record_id="r-1"):
    from services.iue.parsers._types import ParsedRecord
    return ParsedRecord(
        record_id=record_id,
        source_file_id="src-1",
        input_id="in-1",
        tenant_id="t-1",
        offset=0,
        raw_fields=raw_fields,
        parser_name="ndjson",
    )


def test_dictionary_aliases_map_to_canonical():
    from services.iue.normalizers.field_map import normalize

    n = normalize(_mk_parsed({
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "CommandLine": "powershell -enc AAAA",
        "sha256": "a" * 64,
    }))
    assert n.canonical_fields["canonical.source.ip"] == "10.0.0.1"
    assert n.canonical_fields["canonical.destination.ip"] == "10.0.0.2"
    assert n.canonical_fields["canonical.process.command_line"] == \
        "powershell -enc AAAA"
    assert n.canonical_fields["canonical.file.hash.sha256"] == "a" * 64


def test_alias_source_provenance_recorded():
    from services.iue.normalizers.field_map import normalize

    n = normalize(_mk_parsed({
        "sourceAddress": "10.0.0.5",     # CEF-style camelCase
        "CommandLine":   "cmd /c whoami",  # PascalCase
    }))
    src_key, src_source = n.alias_map["canonical.source.ip"]
    cmd_key, cmd_source = n.alias_map["canonical.process.command_line"]
    assert src_key == "sourceAddress"
    assert src_source == "dictionary"
    assert cmd_key == "CommandLine"
    assert cmd_source == "dictionary"


def test_type_infer_layer_resolves_unlabelled_hash():
    """Unknown key with a value that looks like SHA-256 → infer canonical
    field via type_infer layer (alias_source='type_infer')."""
    from services.iue.normalizers.field_map import normalize

    n = normalize(_mk_parsed({
        "weird_col": "b" * 64,
    }))
    assert n.canonical_fields.get("canonical.file.hash.sha256") == "b" * 64
    _, source = n.alias_map["canonical.file.hash.sha256"]
    assert source == "type_infer"


def test_unmapped_fields_are_recorded_not_dropped():
    from services.iue.normalizers.field_map import normalize

    n = normalize(_mk_parsed({
        "src_ip": "10.0.0.1",
        "unknown_column_a": "abc",
        "unknown_column_b": 123,
    }))
    assert set(n.unmapped_fields) >= {"unknown_column_a", "unknown_column_b"}
    # Raw fields never destroyed either
    assert n.raw_fields["unknown_column_a"] == "abc"
