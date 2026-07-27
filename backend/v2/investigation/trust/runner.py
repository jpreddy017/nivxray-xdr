"""Trust Metrics runner — the scoring engine.

Runs the unified Investigation Brain pipeline against every corpus
sample and produces a :class:`TrustReport` scoring the four locked
metrics. Deterministic and side-effect-free.
"""
from __future__ import annotations

from ..pipeline import investigate
from .models import SampleResult, SampleSpec, TrustReport, VerdictExpected


def score(samples: list[SampleSpec]) -> TrustReport:
    """Run every sample and produce the aggregate report."""
    per_sample: list[SampleResult] = []
    accuracy_hits = 0
    honesty_hits = 0
    explain_hits = 0
    unknown_hits = 0
    unknown_total = 0
    hard_failures = 0

    for spec in samples:
        result = investigate(spec.input)
        fired = {i.category.value for i in result.intent.intents}
        failures: list[str] = []
        warnings: list[str] = []

        # ── ACCURACY ─────────────────────────────────────────────
        verdict_ok = (result.verdict.band.value == spec.expected_verdict.value)
        if verdict_ok:
            accuracy_hits += 1
        else:
            failures.append(
                f"verdict expected `{spec.expected_verdict.value}` "
                f"but got `{result.verdict.band.value}`"
            )

        # ── HONESTY ──────────────────────────────────────────────
        # 1. Every fired intent MUST carry canonical evidence with a source.
        # 2. Every ``must_not_fire`` intent must NOT appear.
        # 3. Verdict.reason must not contain any forbidden word for
        #    this sample (e.g. "credential theft" on a Write-Host).
        honesty_ok = True
        for intent in result.intent.intents:
            if not intent.evidence:
                failures.append(f"intent `{intent.category.value}` has no evidence")
                honesty_ok = False
            else:
                for ev in intent.evidence:
                    if not ev.source or not ev.rationale:
                        failures.append(
                            f"intent `{intent.category.value}` evidence "
                            "missing source or rationale"
                        )
                        honesty_ok = False
                        break
        for banned in spec.must_not_fire:
            if banned in fired:
                failures.append(f"forbidden intent `{banned}` fired")
                honesty_ok = False
        lower_reason = (result.verdict.reason or "").lower()
        for word in spec.forbidden_words_in_verdict:
            if word.lower() in lower_reason:
                failures.append(
                    f"verdict reason contains forbidden phrase `{word}`"
                )
                honesty_ok = False
        # Every claim in verdict.evidence MUST originate from a fired intent —
        # no verdict evidence is fabricated.
        intent_ev_ids = {(ev.source, ev.observation)
                          for i in result.intent.intents for ev in i.evidence}
        for ev in result.verdict.evidence:
            if (ev.source, ev.observation) not in intent_ev_ids:
                failures.append(
                    "verdict cites evidence not present in any fired intent — "
                    "unsupported claim"
                )
                honesty_ok = False
                break
        if honesty_ok:
            honesty_hits += 1
        else:
            hard_failures += 1

        # ── EXPLAINABILITY ───────────────────────────────────────
        # Every intent that MUST fire per the spec is present.
        # Every fired intent yields at least one supporting-evidence edge
        # in the evidence graph.
        explain_ok = True
        for req in spec.must_fire_intents:
            if req not in fired:
                failures.append(f"required intent `{req}` did not fire")
                explain_ok = False
        # Cross-check via the Evidence Graph — every intent node must be
        # reachable from at least one supporting-evidence edge.
        intent_nodes = [n for n in result.graph.nodes if n.kind.value == "intent"]
        for n in intent_nodes:
            supports = [
                e for e in result.graph.edges
                if e.dst == n.id and e.kind.value == "supports"
            ]
            if not supports:
                failures.append(f"intent node `{n.id}` has no supporting-evidence edges")
                explain_ok = False
        if explain_ok:
            explain_hits += 1

        # ── UNKNOWN HANDLING ─────────────────────────────────────
        if spec.must_admit_unknown:
            unknown_total += 1
            admitted = (
                result.verdict.band.value == "runtime_dependent"
                or "runtime_dependent" in fired
            )
            if admitted:
                unknown_hits += 1
            else:
                failures.append(
                    "sample marked `must_admit_unknown` but tool over-claimed "
                    "certainty (no runtime_dependent verdict or intent)"
                )
                hard_failures += 1

        per_sample.append(SampleResult(
            sample_id=spec.id,
            passed=(len(failures) == 0),
            verdict_actual=result.verdict.band.value,
            verdict_expected=spec.expected_verdict.value,
            failures=failures,
            warnings=warnings,
        ))

    total = max(1, len(samples))
    return TrustReport(
        total_samples=len(samples),
        accuracy=accuracy_hits / total,
        honesty=honesty_hits / total,
        explainability=explain_hits / total,
        unknown_handling=(unknown_hits / unknown_total) if unknown_total else 1.0,
        hard_failures=hard_failures,
        per_sample=per_sample,
    )


__all__ = ["score"]
