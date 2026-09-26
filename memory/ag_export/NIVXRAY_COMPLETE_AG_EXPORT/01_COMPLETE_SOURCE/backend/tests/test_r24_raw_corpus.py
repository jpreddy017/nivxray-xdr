"""
Rule R24 · Analyst-Reported Raw-Paste Corpus (never break)
──────────────────────────────────────────────────────────
Complements the existing JSON-fixture harness with a lightweight
harness that runs on RAW analyst pastes (.txt / .raw / .b64) and
asserts the R23 + R24 performance contract.

The existing ``test_user_reported_corpus.py`` covers logical
decoding correctness (terminal_state, confidence, chain).  THIS
harness covers PERFORMANCE and BOUNDED RESOURCES:

    · backend_ms                 ≤ per-payload SLO
    · behaviors emitted          ≤ per-payload cap
    · metadata.performance       populated
    · decode_status.failed       must be false
    · deterministic render       same input → identical SSOT

Drop-in flow — no code changes needed to add a payload:

    1. Save ``<slug>.txt`` (or ``.raw`` / ``.b64``) into
       tests/user_reported_corpus/.
    2. Optionally add ``<slug>.slo.json`` alongside:
         { "max_ms": 5000, "max_behaviors": 60, "min_tactics": 4,
           "expect_decode": ["base64", "gzip", "powershell"] }
    3. pytest picks it up automatically.

If it once broke the platform, it can never silently break it
again (Rule R24 · immutable performance contract).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from services.die.investigation_results import render


CORPUS_DIR = Path(__file__).parent / "user_reported_corpus"


def _iter_raw_corpus():
    if not CORPUS_DIR.exists():
        return
    for path in sorted(CORPUS_DIR.iterdir()):
        if path.suffix.lower() in (".txt", ".raw"):
            yield path, path.read_text(encoding="utf-8", errors="replace")
        elif path.suffix.lower() == ".b64":
            try:
                yield path, base64.b64decode(path.read_bytes()).decode("utf-8", "replace")
            except Exception:
                continue


def _load_slo(payload_path: Path) -> dict:
    for cand in (payload_path.with_suffix(payload_path.suffix + ".slo.json"),
                 payload_path.with_name(payload_path.stem + ".slo.json")):
        if cand.exists():
            try:
                return json.loads(cand.read_text(encoding="utf-8"))
            except Exception:  # pragma: no cover
                pass
    return {}


_corpus = list(_iter_raw_corpus())


@pytest.mark.skipif(
    not _corpus,
    reason="No raw analyst pastes yet — drop .txt/.raw/.b64 into "
           "tests/user_reported_corpus/ to enable this regression suite.",
)
@pytest.mark.parametrize(
    "payload_path,payload_text",
    _corpus,
    ids=[str(p.name) for p, _ in _corpus] if _corpus else [],
)
class TestR24RawCorpus:
    """One parametrised class instance per payload so individual
    failures are attributable to a specific file."""

    def test_r24_performance_contract(self, payload_path, payload_text):
        slo = _load_slo(payload_path)
        max_ms         = float(slo.get("max_ms", 5000.0))
        max_behaviors  = int(slo.get("max_behaviors", 60))
        min_tactics    = int(slo.get("min_tactics", 0))
        expect_decode  = [d.lower() for d in slo.get("expect_decode", [])]

        out = render(payload_text)
        ssot = out["object"]

        perf = (ssot.get("metadata") or {}).get("performance") or {}
        assert perf, f"[{payload_path.name}] metadata.performance missing"

        backend_ms = perf.get("backend_ms")
        assert backend_ms is not None, "backend_ms missing"
        assert backend_ms <= max_ms, (
            f"[{payload_path.name}] backend_ms={backend_ms} > {max_ms}\n"
            f"stages={perf.get('stages_ms')}\n"
            f"warnings={perf.get('warnings')}\n"
            f"peak_memory_mb={perf.get('peak_memory_mb')}\n"
            f"decode_layers={len(perf.get('decode_layers') or [])}"
        )

        dec = ssot.get("decode_status") or {}
        assert not dec.get("failed"), \
            f"[{payload_path.name}] decode_status.failed=True: {dec}"

        inc = ssot.get("incident") or {}
        bh = inc.get("behaviors") or []
        assert len(bh) <= max_behaviors, \
            f"[{payload_path.name}] behaviors={len(bh)} > {max_behaviors}"

        tactics = {t for b in bh for t in (b.get("mitre_tactics") or [])}
        assert len(tactics) >= min_tactics, (
            f"[{payload_path.name}] tactics={sorted(tactics)} "
            f"has {len(tactics)}; minimum required = {min_tactics}"
        )

        if expect_decode:
            observed = " ".join(
                str(l.get("stage", "")).lower()
                for l in (perf.get("decode_layers") or [])
            )
            for needle in expect_decode:
                assert needle in observed, (
                    f"[{payload_path.name}] expected decode layer "
                    f"'{needle}' not observed; layers={observed!r}"
                )

    def test_deterministic_render(self, payload_path, payload_text):
        import copy
        def _strip_perf(s):
            s = copy.deepcopy(s)
            m = s.get("metadata") or {}
            m.pop("performance", None)
            m.pop("pipeline_timings", None)
            return s
        a = _strip_perf(render(payload_text)["object"])
        b = _strip_perf(render(payload_text)["object"])
        assert a == b, f"[{payload_path.name}] non-deterministic render"
