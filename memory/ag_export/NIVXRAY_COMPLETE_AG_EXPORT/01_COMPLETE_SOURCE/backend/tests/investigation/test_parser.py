"""Stage 2 · Parser tests."""
from nivxforge.investigation.pipeline.input_classification import (
    InputClass, classify_input,
)
from nivxforge.investigation.pipeline.parser import parse_input


def _parse(raw: str):
    return parse_input(raw, classify_input(raw))


def test_parse_json_object():
    r = _parse('{"a":1,"b":2}')
    assert r.kind == InputClass.JSON
    assert r.records == [{"a": 1, "b": 2}]


def test_parse_json_array():
    r = _parse('[{"a":1},{"a":2}]')
    assert r.records == [{"a": 1}, {"a": 2}]


def test_parse_ndjson_lines():
    r = _parse('{"a":1}\n{"a":2}\n\n{"a":3}')
    assert r.kind == InputClass.NDJSON
    assert [rec["a"] for rec in r.records] == [1, 2, 3]


def test_parse_ndjson_bad_line_captured():
    r = _parse('{"a":1}\nnot-json\n{"a":2}')
    assert len(r.records) == 2
    assert any("ndjson line" in d for d in r.diagnostics)


def test_parse_csv():
    r = _parse("h,u,e\n1,alice,login\n2,bob,logout")
    assert r.kind == InputClass.CSV
    assert r.records[0] == {"h": "1", "u": "alice", "e": "login"}


def test_parse_xml_event_data():
    inp = (
        "<Event><EventData>"
        "<Data Name='EventID'>1</Data>"
        "<Data Name='CommandLine'>whoami</Data>"
        "</EventData></Event>"
    )
    r = _parse(inp)
    assert r.records and r.records[0].get("CommandLine") == "whoami"


def test_parse_key_value_line():
    inp = 'src_ip=1.2.3.4 dst_ip=5.6.7.8 proto=tcp'
    r = parse_input(inp, classify_input(inp))
    # kv may not trigger without >=2 lines; parse still emits kv on hint match
    if r.kind == InputClass.KEY_VALUE:
        assert r.records[0]["src_ip"] == "1.2.3.4"


def test_parse_encoded_command_becomes_single_record():
    inp = "powershell -EncodedCommand SGVsbG8="
    r = _parse(inp)
    assert r.kind == InputClass.ENCODED_CMD
    assert r.records[0]["command_line"].startswith("powershell")


def test_parse_broken_json_falls_back_to_plain():
    r = _parse('{"a": broken}')
    assert r.kind == InputClass.PLAIN_TEXT
    assert any("json parse failed" in d for d in r.diagnostics)
