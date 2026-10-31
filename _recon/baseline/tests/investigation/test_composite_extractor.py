"""Tests for the Composite Value Extractor.

Contracts:
  · Pure function, never raises
  · Never mutates input
  · Emits sibling fields prefixed by origin (e.g. Hashes.SHA256)
  · Ignores fields on the skip-list (url, uri, command_line, …)
  · Requires ≥ 2 KV pairs before expanding
  · Vendor-neutral — no vendor-specific regex or field names
"""
from __future__ import annotations

from nivxforge.investigation.pipeline.composite_extractor import (
    expand_composites,
)
from nivxforge.investigation.pipeline.parser import ParsedInput


def _pi(records):
    return ParsedInput(kind="json", records=records, text=None,
                        diagnostics=[])


class TestComposite:

    def test_sysmon_style_hashes_string_expanded(self):
        rec = {
            "EventID": 1,
            "Hashes": "SHA256=" + "d" * 64 + " MD5=" + "b" * 32,
        }
        out = expand_composites(_pi([rec]))
        got = out.records[0]
        assert got["Hashes.SHA256"] == "d" * 64
        assert got["Hashes.MD5"] == "b" * 32
        # Origin retained
        assert got["Hashes"] == rec["Hashes"]

    def test_generic_kv_string_expanded(self):
        rec = {"algorithms": "algo=rsa;bits=2048;padding=pkcs1"}
        out = expand_composites(_pi([rec]))
        got = out.records[0]
        assert got["algorithms.algo"] == "rsa"
        assert got["algorithms.bits"] == "2048"
        assert got["algorithms.padding"] == "pkcs1"

    def test_single_kv_pair_not_expanded(self):
        # Single pair could be genuine prose ("foo=bar" is just a
        # sentence); require min 2 pairs before considering composite.
        rec = {"note": "reason=timeout"}
        out = expand_composites(_pi([rec]))
        assert "note.reason" not in out.records[0]

    def test_url_field_never_expanded(self):
        rec = {"url": "https://example.com/x?a=1&b=2&c=3"}
        out = expand_composites(_pi([rec]))
        assert "url.a" not in out.records[0]
        assert out.records[0]["url"] == rec["url"]

    def test_command_line_never_expanded(self):
        rec = {"commandline": "cmd.exe /c set A=1 && set B=2 && exit"}
        out = expand_composites(_pi([rec]))
        # commandline field is on the skip list — no composite siblings.
        for k in out.records[0]:
            if k.startswith("commandline."):
                assert False, f"unexpected expansion: {k}"

    def test_does_not_mutate_input(self):
        rec = {"Hashes": "SHA256=" + "1" * 64 + " MD5=" + "2" * 32}
        pi = _pi([rec])
        out = expand_composites(pi)
        # Original records unchanged
        assert set(rec.keys()) == {"Hashes"}
        # New records enriched
        assert "Hashes.SHA256" in out.records[0]

    def test_never_raises_on_pathological_input(self):
        weird = _pi([
            {},
            {"k": None},
            {"k": 42},
            {"k": ["x", "y"]},
            {"k": {"nested": "value"}},
            "not-a-dict",
        ])
        out = expand_composites(weird)
        assert len(out.records) == len(weird.records)

    def test_empty_records_untouched(self):
        pi = _pi([])
        assert expand_composites(pi) is pi

    def test_no_composite_short_circuit(self):
        # A record with no expandable strings returns the SAME instance
        # (no unnecessary allocation).
        pi = _pi([{"a": "flat", "b": "flat"}])
        out = expand_composites(pi)
        assert out is pi
