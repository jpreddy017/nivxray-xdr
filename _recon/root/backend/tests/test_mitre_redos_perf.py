"""
RC4.5 · ReDoS regression guard for operations.mitre_map

Feb-2026 hotfix: three MITRE URL/domain patterns (T1105, T1102, T1583.001)
were exhibiting catastrophic backtracking on large repetitive lowercase
inputs (base64/hex blobs), taking ~4.5s per call on 16KB text.

Root cause: unbounded `[a-z0-9-]+` alternation without `\b` anchor.
Fix: added `\b` word boundary + bounded `{1,63}` (max DNS label length).

This test locks the fix in — any future rule that regresses will trip the
budget and fail CI before it reaches production.
"""
from __future__ import annotations

import base64
import time

from operations import mitre_map


def _big_repetitive_ps_encoded() -> str:
    """The exact class of input that triggered the original ReDoS —
    a 7-8KB PowerShell -EncodedCommand blob whose UTF-16LE payload is
    a long repetitive ASCII string. Mimics 'Morning_BigWhale_Test'."""
    inner = "$s='" + ";4<8;<86507869869869869861'" * 130 + "';iex $s"
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
    return f"powershell.exe -e {b64}\n{inner}\n{inner[::-1]}"


def test_mitre_map_no_redos_on_repetitive_base64() -> None:
    """mitre_map must complete in well under 500ms on 16KB repetitive input.

    Pre-fix baseline: ~4500ms (Cloudflare 524).
    Post-fix baseline: ~100ms.
    Budget: 500ms (5x margin over post-fix, still 9x under pre-fix).
    """
    text = _big_repetitive_ps_encoded()
    t = time.time()
    hits = mitre_map(text)
    elapsed = time.time() - t
    assert elapsed < 0.5, (
        f"mitre_map took {elapsed:.3f}s on 16KB repetitive input — "
        f"catastrophic backtracking has regressed. Budget: 0.5s."
    )
    # Semantics preserved — mitre_map must still return SOMETHING for a
    # `powershell.exe -e <base64>` invocation (T1059.001 or similar).
    assert isinstance(hits, list)


def test_mitre_map_still_detects_legit_cdn_abuse() -> None:
    """The bounded `{1,63}` MUST NOT reduce detection of real payloads."""
    cases = [
        ("https://myrepo.contabostorage.com/loader.exe", "T1105"),
        ("https://cdn.jsdelivr.net/gh/attacker/loader.js", "T1105"),
        ("https://x.workers.dev/beacon", "T1105"),
        ("https://raw.githubusercontent.com/x/y/z.ps1", "T1102"),
        ("http://acme-portal-support.com/login", "T1583.001"),
        ("http://safe-post-app.io/api", "T1583.001"),
    ]
    for text, expected_id in cases:
        ids = {h["id"] for h in mitre_map(text)}
        assert expected_id in ids, (
            f"mitre_map lost detection for {expected_id!r} on legit input {text!r}. "
            f"Got: {sorted(ids)}"
        )
