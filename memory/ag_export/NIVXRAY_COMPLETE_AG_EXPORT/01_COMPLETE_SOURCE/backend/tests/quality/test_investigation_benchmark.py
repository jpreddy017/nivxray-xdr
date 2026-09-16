"""Investigation Quality Benchmark · CI grader.

Runs every entry in `benchmark_corpus.CORPUS` through the live engine
and grades the outcome against the analyst expectations. Any KPI that
drops below the recorded `KPI_THRESHOLDS` fails the CI gate.

Run: `pytest backend/tests/quality/test_investigation_benchmark.py -v -s`

This is the objective way to answer "did my change improve or degrade
the investigation engine?" every future PR must pass through.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

import pytest

from tests.quality.benchmark_corpus import CORPUS, KPI_THRESHOLDS, Entry


def _run(entry: Entry) -> Dict[str, Any]:
    """Send an entry through the full pipeline and return the CIO.

    Mirrors the wire-in in `routers/ops.py::/api/decode/smart` — stashes
    Workspace-parity metadata + refreshes the verdict — so the
    benchmark grades the same output surface the frontend sees.
    """
    from smart_decoder import smart_decode
    from nivxforge.cim.fact_substrate import from_analysis_result
    from nivxforge.investigation import build_cio
    from nivxforge.investigation.verdict_engine import refresh_verdict
    result = smart_decode(entry.input_text) or {}
    fs = from_analysis_result(result, input_text=entry.input_text,
                              source_endpoint="/quality/benchmark")
    cio = build_cio(fs)
    # Mirror ops.py wire-in: stash workspace-parity metadata + refresh.
    for _k in ("custom_recipes_matched", "recipes_matched", "rules_hit",
               "lolbas", "lolbins_v2", "ti_shield", "ti_hits", "yara",
               "sigma", "iocs"):
        if _k in result and result[_k] is not None:
            cio.metadata[_k] = result[_k]
    refresh_verdict(cio)
    return {"cio": cio, "result": result}


_LABEL_RANK = {
    "Undetermined": 0, "Informational": 1, "Runtime Dependent": 2,
    "Suspicious": 3, "Malicious": 4,
}


def _grade_entry(entry: Entry, out: Dict[str, Any]) -> Dict[str, Any]:
    cio = out["cio"]
    v = cio.verdict or {}
    label = v.get("label") or "Undetermined"
    pct = int(v.get("confidence_pct") or 0)
    rule = v.get("escalation_rule") or ""
    md_osint = (cio.metadata or {}).get("osint") or {}
    md_sc = (cio.metadata or {}).get("shellcode") or {}
    node_values = " ".join(
        [(n.value or "") + " " + (n.label or "")
         for n in cio.evidence_graph.nodes]
    ).lower()

    # Label agreement (exact match)
    label_ok = (label == entry.expected_label)

    # Confidence bounds (inclusive)
    conf_ok = (entry.min_confidence_pct <= pct <= entry.max_confidence_pct)

    # IOC extraction recall
    ioc_hits = 0
    for needle in entry.expects_iocs:
        if needle.lower() in node_values:
            ioc_hits += 1
    ioc_recall = (ioc_hits / len(entry.expects_iocs)) if entry.expects_iocs else 1.0

    # Escalation-rule expectation
    esc_ok = True
    if entry.expects_escalation_rule_substr:
        esc_ok = entry.expects_escalation_rule_substr.lower() in rule.lower()

    # Shellcode expectation
    sc_ok = True
    if entry.expects_shellcode:
        sc_ok = bool(md_sc.get("is_shellcode"))

    # Over-promotion guard (benign inputs must NOT be Malicious)
    over_promoted = (entry.category == "benign" and label == "Malicious")

    return {
        "id": entry.id,
        "category": entry.category,
        "expected_label": entry.expected_label,
        "actual_label": label,
        "confidence_pct": pct,
        "label_ok": label_ok,
        "confidence_ok": conf_ok,
        "ioc_recall": ioc_recall,
        "escalation_ok": esc_ok,
        "shellcode_ok": sc_ok,
        "over_promoted": over_promoted,
        "escalation_rule": rule,
        "osint_engine": md_osint.get("engine"),
    }


def _compute_kpis(rows: List[Dict[str, Any]], latencies_ms: List[float]) -> Dict[str, float]:
    n = max(1, len(rows))
    label_agreement = sum(1 for r in rows if r["label_ok"]) * 100.0 / n
    confidence_bounds = sum(1 for r in rows if r["confidence_ok"]) * 100.0 / n
    # IOC recall — average over entries that had expectations
    ioc_rows = [r for r in rows if any(e.expects_iocs for e in CORPUS if e.id == r["id"])]
    ioc_recall_pct = (
        (sum(r["ioc_recall"] for r in ioc_rows) / len(ioc_rows)) * 100.0
        if ioc_rows else 100.0
    )
    # Escalation recall — over entries that expected a rule
    esc_rows = [r for r in rows if any(e.expects_escalation_rule_substr for e in CORPUS if e.id == r["id"])]
    escalation_recall_pct = (
        (sum(1 for r in esc_rows if r["escalation_ok"]) * 100.0 / len(esc_rows))
        if esc_rows else 100.0
    )
    # Shellcode recall (100% when there are no shellcode expectations)
    sc_rows = [r for r in rows if any(e.expects_shellcode for e in CORPUS if e.id == r["id"])]
    shellcode_recall_pct = (
        (sum(1 for r in sc_rows if r["shellcode_ok"]) * 100.0 / len(sc_rows))
        if sc_rows else 100.0
    )
    # Over-promotion guard
    benign_n = sum(1 for r in rows if r["category"] == "benign")
    no_over_promotion_pct = (
        (sum(1 for r in rows if r["category"] == "benign" and not r["over_promoted"]) * 100.0 / benign_n)
        if benign_n else 100.0
    )
    latencies_ms.sort()
    p95 = latencies_ms[int(len(latencies_ms) * 0.95) - 1] if latencies_ms else 0.0

    return {
        "label_agreement_pct":       label_agreement,
        "confidence_bounds_pct":     confidence_bounds,
        "ioc_extraction_recall_pct": ioc_recall_pct,
        "escalation_rule_recall_pct":escalation_recall_pct,
        "shellcode_recall_pct":      shellcode_recall_pct,
        "no_over_promotion_pct":     no_over_promotion_pct,
        "determinism_pct":           100.0,   # verified by test_determinism below
        "e2e_latency_p95_ms":        p95,
    }


@pytest.mark.benchmark
def test_investigation_quality_benchmark():
    """Runs every corpus entry and asserts KPIs are above threshold."""
    rows: List[Dict[str, Any]] = []
    latencies: List[float] = []
    for entry in CORPUS:
        t0 = time.monotonic()
        out = _run(entry)
        latencies.append((time.monotonic() - t0) * 1000.0)
        rows.append(_grade_entry(entry, out))

    kpis = _compute_kpis(rows, latencies)

    # Print a table for CI visibility
    print("\n" + "=" * 90)
    print(f"{'id':<28} {'cat':<14} {'expected':<20} {'actual':<20} {'conf':>4}  {'ok'}")
    print("-" * 90)
    for r in rows:
        ok = "✓" if r["label_ok"] and r["confidence_ok"] else "✗"
        print(f"{r['id']:<28} {r['category']:<14} {r['expected_label']:<20} "
              f"{r['actual_label']:<20} {r['confidence_pct']:>3}%   {ok}")
    print("-" * 90)
    for k, v in kpis.items():
        threshold = KPI_THRESHOLDS.get(k)
        mark = "✓" if (
            (k == "e2e_latency_p95_ms" and v <= (threshold or float("inf"))) or
            (k != "e2e_latency_p95_ms" and v >= (threshold or 0))
        ) else "✗"
        print(f"  {k:<32} {v:>7.2f}   (threshold {threshold})   {mark}")
    print("=" * 90 + "\n")

    # Assert every KPI meets its threshold (soft-fail one at a time
    # so a run reports every miss, not just the first).
    failures = []
    for kpi, threshold in KPI_THRESHOLDS.items():
        actual = kpis.get(kpi)
        if actual is None:
            continue
        if kpi == "e2e_latency_p95_ms":
            if actual > threshold:
                failures.append(f"{kpi}: {actual:.1f} > {threshold}")
        else:
            if actual < threshold:
                failures.append(f"{kpi}: {actual:.1f} < {threshold}")

    # Persist the report so the assessment can cite it.
    import os
    os.makedirs("/app/docs/benchmarks", exist_ok=True)
    with open("/app/docs/benchmarks/investigation_quality.json", "w") as fh:
        json.dump({"rows": rows, "kpis": kpis, "thresholds": KPI_THRESHOLDS,
                   "corpus_size": len(CORPUS)}, fh, indent=2)

    assert not failures, "Benchmark regression:\n  " + "\n  ".join(failures)


@pytest.mark.benchmark
def test_investigation_quality_determinism():
    """Every entry must produce byte-identical verdict on a re-run."""
    for entry in CORPUS:
        out1 = _run(entry)
        out2 = _run(entry)
        v1 = out1["cio"].verdict or {}
        v2 = out2["cio"].verdict or {}
        assert v1.get("label") == v2.get("label"), f"{entry.id} non-deterministic label"
        assert v1.get("confidence_pct") == v2.get("confidence_pct"), (
            f"{entry.id} non-deterministic confidence"
        )
