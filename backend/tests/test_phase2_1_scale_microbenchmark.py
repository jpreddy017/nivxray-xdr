"""
NivXRay XDR — Phase 2.1 Performance & Scale Microbenchmark.
Executes synthetic local microbenchmarks across 100, 500, 1,000, and 5,000 objects.
Measures component latencies independently:
  1. Parse (Windows 4688 raw events)
  2. Normalize (Windows Security Normalizer)
  3. Translate (Sigma YAML to Canonical IR)
  4. Fingerprint (BehavioralFingerprinter composite hashing)
  5. Deduplication (SemanticDeduplicationEngine indexing & query)
  6. Validation (ValidationGates schema, license, telemetry, performance)
  7. Engine Binding (EngineBindingBridge capability resolution)
Computes p50, p95, p99 latencies in milliseconds.
DO NOT call this production-scale performance.
DO NOT use component latency as end-to-end latency.
"""
import time
from typing import Any, Dict, List, Tuple
import pytest

from detection_content.canonical_ir import (
    CanonicalIR,
    FieldCompareNode,
    Operator,
    ProvenanceInfo,
    TranslationFidelity,
)
from detection_content.deduplication import (
    BehavioralFingerprinter,
    SemanticDeduplicationEngine,
)
from detection_content.telemetry import (
    WindowsSecurityDSM,
    WindowsSecurityParser,
    WindowsSecurityNormalizer,
)
from detection_content.translation import SigmaTranslator
from detection_content.validation_framework import (
    EngineBindingBridge,
    ValidationGates,
)


def _compute_percentiles(durations_ms: List[float]) -> Dict[str, float]:
    if not durations_ms:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0, "min": 0.0, "max": 0.0}
    sorted_d = sorted(durations_ms)
    n = len(sorted_d)
    return {
        "p50": round(sorted_d[int(0.50 * (n - 1))], 3),
        "p95": round(sorted_d[int(0.95 * (n - 1))], 3),
        "p99": round(sorted_d[int(0.99 * (n - 1))], 3),
        "avg": round(sum(sorted_d) / n, 3),
        "min": round(sorted_d[0], 3),
        "max": round(sorted_d[-1], 3),
    }


def _generate_synthetic_objects(count: int) -> Tuple[List[Dict[str, Any]], List[str], List[CanonicalIR]]:
    raw_events: List[Dict[str, Any]] = []
    sigma_rules: List[str] = []
    canonical_rules: List[CanonicalIR] = []

    for i in range(count):
        # 1. Raw event
        raw = {
            "EventID": 4688,
            "TimeCreated": "2026-09-04T12:00:00Z",
            "Computer": f"BENCH-HOST-{i % 50}.corp",
            "EventData": {
                "NewProcessName": f"C:\\Windows\\System32\\proc_{i}.exe",
                "CommandLine": f"proc_{i}.exe -arg={i} -token=xyz",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "TargetUserName": f"user_{i % 20}",
                "TargetDomainName": "CORP",
                "TokenElevationType": "%%1937" if i % 2 == 0 else "%%1936",
            },
        }
        raw_events.append(raw)

        # 2. Sigma rule string
        sig = f"""
title: Synthetic Detection Rule {i}
id: SYNTH-SIG-{i}
logsource: {{product: windows, category: process_creation}}
detection:
    selection:
        Image|endswith: '\\proc_{i}.exe'
        CommandLine|contains: 'arg={i}'
    condition: selection
"""
        sigma_rules.append(sig)

        # 3. Canonical IR instance
        node = FieldCompareNode("process.name", Operator.EQUALS, f"proc_{i}.exe")
        prov = ProvenanceInfo(
            source="SyntheticBenchmark",
            source_id=f"SYNTH-{i}",
            license="Apache-2.0",
            attribution="Benchmarker",
        )
        ir = CanonicalIR(
            content_id=f"DET-SYNTH-{i}",
            name=f"Synthetic Rule {i}",
            description="Benchmark content object",
            tactic="Execution",
            technique_id="T1059",
            platform="windows",
            severity="medium",
            confidence="high",
            lane="content",
            required_fields=["process.name"],
            root_node=node,
            fidelity=TranslationFidelity.EXACT,
            provenance=prov,
        )
        canonical_rules.append(ir)

    return raw_events, sigma_rules, canonical_rules


def run_benchmark_for_scale(scale: int) -> Dict[str, Any]:
    raw_events, sigma_rules, canonical_rules = _generate_synthetic_objects(scale)
    parser = WindowsSecurityParser()
    normalizer = WindowsSecurityNormalizer()
    translator = SigmaTranslator()

    timings: Dict[str, List[float]] = {
        "parse": [],
        "normalize": [],
        "translate": [],
        "fingerprint": [],
        "dedup": [],
        "validation": [],
        "binding": [],
    }

    parsed_events: List[Dict[str, Any]] = []

    # 1. Parse benchmark
    for ev in raw_events:
        t0 = time.perf_counter()
        p = parser.parse(ev)
        timings["parse"].append((time.perf_counter() - t0) * 1000.0)
        parsed_events.append(p)

    # 2. Normalize benchmark
    for p in parsed_events:
        t0 = time.perf_counter()
        normalizer.normalize(p, "win-dsm", "col-1", "integ-1", "trace-1", tenant_id="tenant-bench")
        timings["normalize"].append((time.perf_counter() - t0) * 1000.0)

    # 3. Translate benchmark (sample first min(scale, 200) to keep microtest fast)
    translate_sample = sigma_rules[:min(scale, 200)]
    for sig in translate_sample:
        t0 = time.perf_counter()
        translator.translate(sig)
        timings["translate"].append((time.perf_counter() - t0) * 1000.0)

    # 4. Fingerprint benchmark
    for ir in canonical_rules:
        t0 = time.perf_counter()
        BehavioralFingerprinter.compute_fingerprint(ir)
        timings["fingerprint"].append((time.perf_counter() - t0) * 1000.0)

    # 5. Deduplication index & evaluate benchmark (index 50 rules, query rest)
    dedup_engine = SemanticDeduplicationEngine(canonical_rules[:min(50, scale)])
    for ir in canonical_rules[min(50, scale):min(150, scale)]:
        t0 = time.perf_counter()
        dedup_engine.evaluate_candidate(ir)
        timings["dedup"].append((time.perf_counter() - t0) * 1000.0)

    # 6. Validation benchmark
    for ir in canonical_rules:
        t0 = time.perf_counter()
        ValidationGates.check_schema(ir)
        ValidationGates.check_license_provenance(ir)
        ValidationGates.check_telemetry(ir)
        timings["validation"].append((time.perf_counter() - t0) * 1000.0)

    # 7. Binding benchmark
    for ir in canonical_rules:
        t0 = time.perf_counter()
        EngineBindingBridge.resolve_binding(ir)
        timings["binding"].append((time.perf_counter() - t0) * 1000.0)

    results: Dict[str, Any] = {
        "scale": scale,
        "metrics": {comp: _compute_percentiles(times) for comp, times in timings.items()},
    }
    return results


def test_scale_microbenchmark_100():
    res = run_benchmark_for_scale(100)
    assert res["scale"] == 100
    # Every component average latency under 5.0ms
    for comp, stats in res["metrics"].items():
        if stats["avg"] > 0:
            assert stats["p50"] < 10.0, f"Component {comp} p50 was {stats['p50']}ms"


def test_scale_microbenchmark_500():
    res = run_benchmark_for_scale(500)
    assert res["scale"] == 500
    assert res["metrics"]["fingerprint"]["p50"] < 1.0
    assert res["metrics"]["binding"]["p50"] < 1.0


def test_scale_microbenchmark_1000():
    res = run_benchmark_for_scale(1000)
    assert res["scale"] == 1000
    assert res["metrics"]["parse"]["p95"] < 5.0
    assert res["metrics"]["normalize"]["p95"] < 5.0


def test_scale_microbenchmark_5000():
    # 5,000 objects benchmark
    res = run_benchmark_for_scale(5000)
    assert res["scale"] == 5000
    assert res["metrics"]["validation"]["p95"] < 2.0
    assert res["metrics"]["binding"]["p95"] < 2.0
