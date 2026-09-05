"""Test the parsers module — RFC3164, RFC5424, path extraction."""
from framework.parsers import (
    parse_rfc3164, parse_rfc5424, parse_syslog_auto, get_path,
)


def test_rfc3164_typical_line():
    line = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
    p = parse_rfc3164(line)
    assert p["parsed"] is True
    assert p["parser"] == "rfc3164"
    assert p["facility"] == 4              # 34 >> 3 == 4 (auth)
    assert p["severity"] == 2              # 34 & 7 == 2 (crit)
    assert p["host"] == "mymachine"
    assert p["app"]  == "su"
    assert "failed for lonvick" in p["message"]


def test_rfc3164_with_pid():
    line = "<13>Aug 30 11:00:00 fw01 sshd[2413]: Failed password for admin from 10.0.0.5"
    p = parse_rfc3164(line)
    assert p["parsed"] is True
    assert p["app"] == "sshd"
    assert p["pid"] == 2413


def test_rfc3164_garbage_line_flagged_not_raised():
    p = parse_rfc3164("random garbage that isn't syslog")
    assert p["parsed"] is False
    assert "raw_line" in p


def test_rfc5424_typical_line():
    line = ('<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog '
            '- ID47 [exampleSDID@32473 iut="3"] BOMAn application event')
    p = parse_rfc5424(line)
    assert p["parsed"] is True
    assert p["parser"] == "rfc5424"
    assert p["version"] == 1
    assert p["facility"] == 20                # 165 >> 3 == 20
    assert p["severity"] == 5                 # 165 & 7 == 5 (notice)
    assert p["host"] == "mymachine.example.com"
    assert p["app"] == "evntslog"
    assert p["msgid"] == "ID47"
    assert p["structured"] is not None


def test_rfc5424_nil_structured():
    line = "<34>1 2024-08-30T12:00:00Z host01 sshd 4321 - - Auth ok"
    p = parse_rfc5424(line)
    assert p["parsed"] is True
    assert p["structured"] is None
    assert p["msgid"] is None or p["msgid"] == "-" or p["msgid"] is None


def test_syslog_auto_dispatch():
    # RFC5424 (has version octet)
    p5 = parse_syslog_auto("<34>1 2024-08-30T12:00:00Z h1 app 1 - - msg")
    assert p5["parser"] == "rfc5424"
    # RFC3164
    p3 = parse_syslog_auto("<34>Oct 11 22:14:15 mymachine su: msg")
    assert p3["parser"] == "rfc3164"


def test_get_path_dotted_and_index():
    obj = {"a": {"b": [{"c": 42}, {"c": 99}]}}
    assert get_path(obj, "a.b.0.c") == 42
    assert get_path(obj, "a.b.1.c") == 99
    assert get_path(obj, "a.missing", default="fallback") == "fallback"


def test_get_path_wildcard_first_non_null():
    obj = {"results": [None, None, {"id": "abc"}]}
    v = get_path(obj, "results[*]")
    assert v == {"id": "abc"}
