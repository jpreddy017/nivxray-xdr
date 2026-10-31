"""P0-1B · Gate 2D-B1 · DDO + new encodings + false-reconstruction tests."""
from __future__ import annotations

import pytest

from services.decoder.base import (
    decode_url, decode_unicode_escape, decode_html_entities,
    decode_base32, decode_base85, decode_octal_ascii,
    decode_decimal_ascii, decode_base64_as_string,
)
from services.decoder.orchestrator import (
    orchestrate, INVARIANTS, MAX_DEPTH,
)


# ══════════════════════════════════════════════════════════════
# 1 · Positive tests — each codec produces expected output
# ══════════════════════════════════════════════════════════════
@pytest.mark.parametrize("fn,inp,expected", [
    (decode_url,               "hello%20world%21",            "hello world!"),
    (decode_unicode_escape,    r"\u0048\u0069",               "Hi"),
    (decode_html_entities,     "&#72;&#105;",                 "Hi"),
    (decode_base32,            "JBSWY3DPEBLW64TMMQ======",    "Hello World"),
    (decode_base85,            "<~87cURDZ~>",                 "Hello"),
    (decode_octal_ascii,       r"\101\102\103\104",           "ABCD"),
    (decode_decimal_ascii,     "72,101,108,108,111",          "Hello"),
    (decode_base64_as_string,  "SGVsbG8gV29ybGQ=",            "Hello World"),
])
def test_encoding_positive(fn, inp, expected):
    assert fn(inp) == expected


# ══════════════════════════════════════════════════════════════
# 2 · False-reconstruction guards — decoders MUST NOT emit
#     spurious outputs on ambiguous inputs
# ══════════════════════════════════════════════════════════════
_FALSE_RECON_CASES = [
    # Plain English text — no percent-encoding, must not URL-decode.
    (decode_url,               "hello world!"),
    # Bare English text — no escape sequences.
    (decode_unicode_escape,    "regular text"),
    # HTML unescape has entities but decoded output would be non-printable.
    (decode_html_entities,     "&#0;&#1;&#2;"),
    # Base32 that happens to be alphabet-valid but decodes to garbage.
    (decode_base32,            "AAAAAAAA"),
    # Bare printable ASCII shouldn't be treated as Ascii85 without wrapper.
    (decode_base85,            "hello"),
    # Random octal-looking prefix but not a valid sequence.
    (decode_octal_ascii,       "just text"),
    # Numbers that look like decimal ASCII but out of printable range.
    (decode_decimal_ascii,     "1,2,3,4,5"),
    # Base64 alphabet match but too short.
    (decode_base64_as_string,  "aa=="),
]

@pytest.mark.parametrize("fn,inp", _FALSE_RECON_CASES)
def test_false_reconstruction_rejected(fn, inp):
    """Decoder MUST return None (or unchanged), never fabricate."""
    out = fn(inp)
    assert out is None or out == inp, (
        f"{fn.__name__} fabricated a decode on ambiguous input: "
        f"{inp!r} → {out!r}")


# ══════════════════════════════════════════════════════════════
# 3 · DDO invariants
# ══════════════════════════════════════════════════════════════
def test_ddo_invariants_locked():
    assert INVARIANTS["static_only"]         is True
    assert INVARIANTS["execution"]           is False
    assert INVARIANTS["network_access"]      is False
    assert INVARIANTS["attck_promotion"]     is False
    assert INVARIANTS["bounded_depth"]       is True
    assert INVARIANTS["deterministic_order"] is True
    assert INVARIANTS["provenance_required"] is True
    assert INVARIANTS["MAX_DEPTH"]           == MAX_DEPTH


def test_ddo_bounded_depth():
    """Orchestrator must stop within MAX_DEPTH even on adversarial input."""
    r = orchestrate("%25" * 20)          # heavily URL-encoded
    assert len(r.layers) <= MAX_DEPTH


def test_ddo_deterministic_order():
    """Same input → same output, same layer sequence, twice in a row."""
    inp = "%68%65%6C%6C%6F"
    r1 = orchestrate(inp)
    r2 = orchestrate(inp)
    assert r1.final == r2.final
    assert [l.stage for l in r1.layers] == [l.stage for l in r2.layers]


def test_ddo_no_signature_stops_early():
    """When input has no codec signature, DDO must not attempt decoding."""
    r = orchestrate("this is regular english text with no encodings")
    assert len(r.layers) == 0
    assert r.attempts == 0


def test_ddo_provenance_on_every_layer():
    """Every emitted layer must carry provenance."""
    r = orchestrate("%68%65%6C%6C%6F%20%77%6F%72%6C%64%21")
    for l in r.layers:
        assert l.provenance.static_only is True
        assert l.provenance.execution is False
        assert l.provenance.attck_promotion is False
        assert l.provenance.decoded_from
        assert l.provenance.capability_name


def test_ddo_cycle_detection():
    """DDO must detect and stop on decode cycles."""
    # Feed an input where a decoder might oscillate — DDO cycle
    # detection via `seen_texts` prevents infinite loops.
    r = orchestrate("&amp;amp;amp;")
    assert len(r.layers) <= MAX_DEPTH


def test_ddo_no_regression_for_english():
    """Plain English must never be decoded — critical FP guard."""
    for text in ("Get-Process | Sort-Object CPU",
                 "ipconfig /all",
                 "hello world",
                 "AAAA BBBB CCCC"):
        r = orchestrate(text)
        assert len(r.layers) == 0, f"FP on benign: {text}"
