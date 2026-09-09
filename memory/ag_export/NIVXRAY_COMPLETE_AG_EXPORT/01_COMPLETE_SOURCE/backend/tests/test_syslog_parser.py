"""Round 38.5 · Syslog Parser (RFC5424 + RFC3164) regression.

Owner rules covered:
  * Deterministic: same input → same parsed dict.
  * Non-fabrication: unparseable line returns ``parsed: False`` with
    the raw line preserved — never invents fields.
  * Faithful field extraction on the golden PDFMaestro fixture used
    across the Investigation views.
"""
from __future__ import annotations
import sys, os

# The collector framework lives outside /app/backend — add it to
# sys.path so the pytest process can import it directly.
_COLLECTOR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                             "..", "..",
                                                             "apps",
                                                             "nivxray-xdr-collector"))
if _COLLECTOR not in sys.path:
    sys.path.insert(0, _COLLECTOR)

from framework.parsers import (           # noqa: E402
    parse_rfc5424, parse_rfc3164, parse_syslog_auto,
)


GOLDEN_5424 = (
    "<134>1 2026-08-30T23:26:15Z HN218095lvallucci "
    "CiscoSecureEndpoint 4428 EVT-1 - "
    "PDFMaestroUpdater.exe /checkupdate detected"
)
GOLDEN_3164 = (
    "<134>Aug 30 23:26:15 HN218095lvallucci "
    "CiscoSecureEndpoint[4428]: malware detected"
)


def test_parse_rfc5424_full():
    r = parse_rfc5424(GOLDEN_5424)
    assert r["parsed"] is True
    assert r["version"]    == 1
    assert r["facility"]   == 16
    assert r["severity"]   == 6
    assert r["timestamp"]  == "2026-08-30T23:26:15Z"
    assert r["host"]       == "HN218095lvallucci"
    assert r["app"]        == "CiscoSecureEndpoint"
    assert r["procid"]     == "4428"
    assert r["msgid"]      == "EVT-1"
    assert r["structured"] is None
    assert "PDFMaestroUpdater.exe" in r["message"]


def test_parse_rfc3164_full():
    r = parse_rfc3164(GOLDEN_3164)
    assert r["parsed"] is True
    assert r["facility"] == 16
    assert r["severity"] == 6
    assert r["host"]     == "HN218095lvallucci"
    assert r["app"]      == "CiscoSecureEndpoint"
    assert r["pid"]      == 4428
    assert "malware detected" in r["message"]


def test_parse_syslog_auto_routes_correctly():
    assert parse_syslog_auto(GOLDEN_5424)["parser"] == "rfc5424"
    assert parse_syslog_auto(GOLDEN_3164)["parser"] == "rfc3164"


def test_parser_never_fabricates_on_garbage():
    """Owner rule §11 — a non-syslog line must NOT be invented into
    fake fields.  The parser must return ``parsed: False`` and
    preserve the raw line for forensic inspection."""
    junk = "this is definitely not a syslog line"
    r5 = parse_rfc5424(junk)
    r3 = parse_rfc3164(junk)
    assert r5["parsed"] is False
    assert r5["raw_line"] == junk
    assert r3["parsed"] is False
    assert r3["raw_line"] == junk


def test_deterministic_output():
    """Same input → same output."""
    a = parse_rfc5424(GOLDEN_5424)
    b = parse_rfc5424(GOLDEN_5424)
    assert a == b


def test_registry_marks_parser_integrated():
    """The capability registry must NOT report NOT_YET_INTEGRATED for
    the Syslog Parser now that the connector is bound by the
    CollectorRuntime and the parser passes its regression suite."""
    import json, pathlib
    reg = pathlib.Path("/app/apps/nivxray-xdr/docs/"
                              "NIVXRAY_CAPABILITY_REGISTRY.json")
    data = json.loads(reg.read_text())
    entries = data.get("capabilities") if isinstance(data, dict) \
                  else data
    entry = next(e for e in entries
                    if e.get("id") == "engine.parser.syslog")
    assert entry["status"] == "INTEGRATED", entry["status"]
    assert entry["xdr_integrated"] is True
