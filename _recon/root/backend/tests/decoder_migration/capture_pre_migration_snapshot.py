"""Gate 2D-B3.0 · Pre-migration parity snapshot capture.

This script freezes the pre-migration behaviour of the current
authoritative reference decoder (`recursive_decoder.peel_recursively`)
against every applicable .txt fixture under `tests/fixtures/`.

It writes THREE machine-readable artefacts under this directory:

    pre_migration_manifest.json    — fixture inventory + hashes
    fixture_codec_map.json         — which codec(s) each fixture exercises
    pre_migration_results.json     — reference decode snapshots

After Gate 2D-B3.1 (codec migration) lands, the same harness will
be re-invoked against the *candidate* migrated runtime and the
two snapshot sets compared byte-for-byte.

Execute from /app/backend:

    python -m tests.decoder_migration.capture_pre_migration_snapshot

The script is idempotent and deterministic.  Running it twice
produces byte-identical outputs.
"""
from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure repository root on sys.path when invoked directly.
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from services.die.preprocessor.recursive_decoder import peel_recursively  # noqa: E402

from tests.decoder_migration.parity_harness import (  # noqa: E402
    CODEC_CAPABILITIES,
    ANALYZER_CAPABILITIES,
    enumerate_fixtures,
    snapshot_reference,
    write_json,
)

HERE = Path(__file__).resolve().parent


def _read_text(path: Path) -> str:
    """Read a fixture as UTF-8 text; fall back to latin-1 for the
    handful of binary-tinted fixtures.  Byte-level parity is
    preserved via input_sha256 in the manifest."""
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def main() -> int:
    fixtures = enumerate_fixtures()
    fixtures_root = Path(__file__).resolve().parents[1] / "fixtures"

    # 1. Manifest — hashes + metadata
    manifest = {
        "gate": "P0-1B · Phase 2 · Gate 2D-B3.0 · Pre-migration snapshot",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "fixture_root": str(fixtures_root),
        "reference_impl": "services.die.preprocessor.recursive_decoder.peel_recursively",
        "codec_capabilities_tracked": list(CODEC_CAPABILITIES),
        "analyzer_capabilities_tracked": list(ANALYZER_CAPABILITIES),
        "total_fixtures": len(fixtures),
        "fixtures": [f.to_dict() for f in fixtures],
    }
    write_json(HERE / "pre_migration_manifest.json", manifest)

    # 2. Codec map — which codec-capability hints each fixture carries.
    codec_map: dict[str, list[str]] = {c: [] for c in CODEC_CAPABILITIES}
    analyzer_map: dict[str, list[str]] = {c: [] for c in ANALYZER_CAPABILITIES}
    for f in fixtures:
        for h in f.codec_hints:
            if h in codec_map:
                codec_map[h].append(f.fixture_id)
            elif h in analyzer_map:
                analyzer_map[h].append(f.fixture_id)
    fixture_codec_map = {
        "captured_at_utc": manifest["captured_at_utc"],
        "codec_to_fixtures": {k: sorted(v) for k, v in codec_map.items()},
        "analyzer_to_fixtures": {k: sorted(v) for k, v in analyzer_map.items()},
        "codec_fixture_counts": {k: len(v) for k, v in codec_map.items()},
        "analyzer_fixture_counts": {k: len(v) for k, v in analyzer_map.items()},
        "unhinted_fixtures": sorted(
            f.fixture_id for f in fixtures if not f.codec_hints
        ),
    }
    write_json(HERE / "fixture_codec_map.json", fixture_codec_map)

    # 3. Reference decode snapshots — one entry per fixture.
    snapshots: list[dict[str, object]] = []
    peeled_any = 0
    exceptions = 0
    latency_p_ms: list[float] = []
    for f in fixtures:
        text = _read_text(fixtures_root / f.path)
        snap = snapshot_reference(f, text, peel_recursively)
        snapshots.append(snap.to_dict())
        if snap.peeled_any:
            peeled_any += 1
        if not snap.ok:
            exceptions += 1
        latency_p_ms.append(snap.latency_ms)

    # Deterministic aggregate latency (single-run, informational only).
    latency_sorted = sorted(latency_p_ms)
    def _pct(p: float) -> float:
        if not latency_sorted:
            return 0.0
        k = max(0, min(len(latency_sorted) - 1, int(round((p / 100.0) * (len(latency_sorted) - 1)))))
        return latency_sorted[k]

    # Content-only signature — excludes timestamps + latency so the
    # hash is deterministic across runs and directly comparable to
    # the post-migration candidate snapshot.
    import hashlib as _hashlib
    content_only = []
    for s in snapshots:
        content_only.append({
            "fixture_id": s["fixture_id"],
            "ok": s["ok"],
            "exception": s["exception"],
            "final_sha256": s["final_sha256"],
            "final_bytes_len": s["final_bytes_len"],
            "layer_sequence": s["layer_sequence"],
            "layer_count": s["layer_count"],
            "layers_detail": s["layers_detail"],
            "provenance": s["provenance"],
            "peeled_any": s["peeled_any"],
        })
    content_signature = _hashlib.sha256(
        json.dumps(content_only, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    pre_results = {
        "gate": manifest["gate"],
        "captured_at_utc": manifest["captured_at_utc"],
        "reference_impl": manifest["reference_impl"],
        "fixture_count": len(fixtures),
        "peeled_any_count": peeled_any,
        "exception_count": exceptions,
        "content_signature_sha256": content_signature,
        "aggregate_latency_ms": {
            "p50": _pct(50.0),
            "p95": _pct(95.0),
            "p99": _pct(99.0),
            "mean": (sum(latency_p_ms) / len(latency_p_ms)) if latency_p_ms else 0.0,
            "max": (max(latency_p_ms) if latency_p_ms else 0.0),
        },
        "snapshots": snapshots,
    }
    write_json(HERE / "pre_migration_results.json", pre_results)

    # Console summary — deterministic, machine-parsable-ish
    print("─" * 68)
    print("Gate 2D-B3.0 · Pre-Migration Parity Snapshot")
    print("─" * 68)
    print(f"total fixtures        : {len(fixtures)}")
    print(f"peeled (final != raw) : {peeled_any}")
    print(f"exceptions raised     : {exceptions}")
    print(f"latency p50/p95/p99   : "
          f"{pre_results['aggregate_latency_ms']['p50']:.3f} / "
          f"{pre_results['aggregate_latency_ms']['p95']:.3f} / "
          f"{pre_results['aggregate_latency_ms']['p99']:.3f} ms")
    print(f"content signature     : {content_signature[:24]}…")
    print("codec fixture counts  :")
    for k, v in fixture_codec_map["codec_fixture_counts"].items():
        print(f"    {k:<20s} = {v}")
    print("analyzer fixture cnts :")
    for k, v in fixture_codec_map["analyzer_fixture_counts"].items():
        print(f"    {k:<20s} = {v}")
    print(f"unhinted fixtures     : {len(fixture_codec_map['unhinted_fixtures'])}")
    print("─" * 68)
    print("Artefacts written:")
    for name in ("pre_migration_manifest.json",
                 "fixture_codec_map.json",
                 "pre_migration_results.json"):
        print(f"    tests/decoder_migration/{name}")
    print("─" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
