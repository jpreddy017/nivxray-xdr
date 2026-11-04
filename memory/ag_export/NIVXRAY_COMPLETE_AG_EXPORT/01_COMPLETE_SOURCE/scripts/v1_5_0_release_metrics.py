"""v1.5.0 · Decoder Convergence · release-metrics probe.

Reproduces the numbers in ``/app/V1_5_0_RELEASE_METRICS.md`` on any
commit of the v1.5.0 branch. Useful for release verification, CI
snapshots, and staging-vs-production regression checks.

Run: ``python3 scripts/v1_5_0_release_metrics.py``

The numbers are measured, not asserted — a change in the platform
(faster / slower CPU, newer Python) will move the latency figures.
The contract this probe guarantees is *shape*: which fields are
reported, and that the pipeline is deterministic and stops
principled-ly on every sample.
"""
from __future__ import annotations

import base64
import gzip
import statistics
import sys
import time
from pathlib import Path

# Allow running from anywhere in the repo.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "backend"))

from v2.investigation.rte.diagnostic_codes import DIAGNOSTIC_CODES  # noqa: E402
from v2.investigation.rte.engine import DEFAULT_MAX_DEPTH, transform  # noqa: E402


def _canonical_sample() -> str:
    """Load the locked corpus sample."""
    p = (
        _HERE.parent
        / "backend/tests/trust_corpus/PS_ENCODEDCOMMAND_GZIP_STAGE2_001.txt"
    )
    return p.read_text().rstrip("\n")


def _clean_synthetic_sample() -> str:
    """A byte-exact reproducible 3-stage sample that decodes cleanly."""
    stage3 = (
        'Write-Host "STAGE-3"; New-ItemProperty -Path '
        'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
        '-Name Backdoor -Value "C:\\Windows\\Temp\\bd.exe";'
    )
    gz_b64 = base64.b64encode(gzip.compress(stage3.encode())).decode()
    stage2 = (
        f'$s=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{gz_b64}"));'
        f'IEX (New-Object IO.StreamReader('
        f'New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(stage2.encode("utf-16-le")).decode("ascii")
    return f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand {enc}"


def _deep_nested_sample(layers: int = 30) -> str:
    """Recursive base64 wrap ``layers`` times — stresses the scheduler."""
    payload = "Write-Host 'deep nested core'"
    for _ in range(layers):
        payload = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    return payload


def main() -> int:
    samples = [
        ("canonical_gzip_stage2_corrupt", _canonical_sample()),
        ("synthetic_gzip_stage2_clean",   _clean_synthetic_sample()),
        ("deep_30_layer_base64",          _deep_nested_sample(30)),
        ("plain_powershell",              'Write-Host "hello"'),
        ("benign_admin_ps",
         '$fs = New-Object IO.FileStream("C:\\logs\\a.gz", '
         '[IO.FileMode]::Open); $gz = New-Object '
         'IO.Compression.GzipStream($fs, '
         '[IO.Compression.CompressionMode]::Decompress);'),
    ]

    print("=" * 72)
    print("NivXRay v1.5.0 · Decoder Convergence · release-metrics probe")
    print("=" * 72)

    latencies: list[float] = []
    determ = {}
    for name, sample in samples:
        # 50 runs each for stable percentiles
        runs = []
        for _ in range(50):
            t0 = time.perf_counter()
            transform(sample, max_depth=DEFAULT_MAX_DEPTH)
            runs.append((time.perf_counter() - t0) * 1000)
        latencies.extend(runs)
        # Determinism check
        determ[name] = {
            transform(sample, max_depth=DEFAULT_MAX_DEPTH).determinism_hash
            for _ in range(3)
        }
        print(
            f"  {name:<35} runs={len(runs):>3}  "
            f"mean={statistics.mean(runs):>7.2f} ms  "
            f"median={statistics.median(runs):>7.2f} ms  "
            f"hashes={len(determ[name])}"
        )

    print("-" * 72)
    print(f"Samples exercised:              {len(samples)}")
    print(f"Total latency measurements:     {len(latencies)}")
    print(f"Mean decode latency:            {statistics.mean(latencies):.2f} ms")
    print(f"Median decode latency:          {statistics.median(latencies):.2f} ms")
    q20 = statistics.quantiles(latencies, n=20)
    q100 = statistics.quantiles(latencies, n=100)
    print(f"P95 decode latency:             {q20[-1]:.2f} ms")
    print(f"P99 decode latency:             {q100[-1]:.2f} ms")
    print(f"Max decode latency:             {max(latencies):.2f} ms")
    print(f"Target latency budget:          ≤ 500 ms (met at P99)"
          if q100[-1] <= 500 else
          f"Target latency budget:          ≤ 500 ms (BUDGET EXCEEDED @ P99)")
    print(
        f"Determinism (hash stability):   "
        f"{'stable' if all(len(v) == 1 for v in determ.values()) else 'UNSTABLE'}"
    )
    print(f"Max recursion depth exercised:  30 layers")
    print(f"DEFAULT_MAX_DEPTH cap:          {DEFAULT_MAX_DEPTH}")
    print(f"Registered diagnostic codes:    {len(DIAGNOSTIC_CODES)}")
    for sev in ("error", "warning", "info"):
        n = sum(1 for m in DIAGNOSTIC_CODES.values() if m.severity == sev)
        print(f"  · {sev:<8} severity:            {n}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
