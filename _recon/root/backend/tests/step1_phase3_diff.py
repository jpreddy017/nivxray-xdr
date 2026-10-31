"""ADR-004 Step 1 · Phase 3 · Canonical Engine Diff Report.

Extends the Phase 2 4-way comparison with a 5th column — the
CANONICAL engine (`backend/v2/verdict/canonical.py`) driven by
`CanonicalVerdictInput` derived from `InvestigationModel`.

Per owner directive:
    * Canonical input contract is derived from the investigation/
      evidence model — NOT from any legacy engine's shape.
    * Legacy engines A/B/D remain compat parity references only.
    * No scoring redesign; weights preserved.
    * Suspicious-as-floor and Runtime Dependent preserved.
    * Zero UNEXPLAINED before Phase 4 consumer switch.

Outputs
───────
* JSON: `backend/corpus/vendor/v1/reports/step1_phase3_diff_report.json`
* Markdown: `memory/STEP1_PHASE3_REPORT.md`
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from tests.step1_diff_report import (
    GROUND_TRUTH,
    _engine_A_nivxforge,
    _engine_B_verdict_v2,
    _engine_C_v2_score,
    _engine_D_ps_verdict,
    _classify_divergence,
)

_HERE        = Path(__file__).resolve().parent
_REPORTS_DIR = _HERE.parent / "corpus" / "vendor" / "v1" / "reports"
_MEMORY_DIR  = Path("/app/memory")


def _engine_CANONICAL(f) -> Dict[str, Any]:
    """Native contract: `CanonicalVerdictInput`. Built from `fixture.commands`
    via the `from_commands` shim (a full InvestigationModel isn't
    available for raw fixtures — the shim is the honest baseline)."""
    try:
        from v2.verdict.canonical_input import from_commands
        from v2.verdict.canonical import score
    except Exception as e:
        return {"engine": "CANONICAL", "error": f"import: {type(e).__name__}: {e!s}"}
    try:
        inp = from_commands(list(f.commands))
        v   = score(inp)
        return {
            "engine":         "CANONICAL",
            "label":          v.label,
            "score_pct":      int(v.confidence_pct),
            "top_score":      int(v.top_score),
            "n_events":       int(v.n_events),
            "n_signals":      int(v.n_signals),
            "floor_applied":  v.floor_applied,
            "reason":         (v.reason or "")[:200],
        }
    except Exception as e:
        return {"engine": "CANONICAL", "error": f"{type(e).__name__}: {e!s}"}


def build_report() -> Dict[str, Any]:
    from tests.test_p015c5_vendor_corpus_v1 import VENDOR_CORPUS_V1
    entries: List[Dict[str, Any]] = []
    for f in VENDOR_CORPUS_V1:
        engines_out = {
            "A_nivxforge":  _engine_A_nivxforge(f),
            "B_verdict_v2": _engine_B_verdict_v2(f),
            "C_v2_score":   _engine_C_v2_score(f),
            "D_ps_verdict": _engine_D_ps_verdict(f),
            "CANONICAL":    _engine_CANONICAL(f),
        }
        classification = _classify_divergence(f.fixture_id, engines_out)
        entries.append({
            "fixture_id":    f.fixture_id,
            "vendor":        f.vendor,
            "article_title": f.article_title,
            "engines":       engines_out,
            "classification": classification,
        })

    counts = {"PRESERVED": 0, "CORRECTED": 0,
                  "INTENTIONAL": 0, "UNEXPLAINED": 0,
                  "INPUT-CONTRACT-UNRESOLVED": 0}
    for e in entries:
        for eng, r in e["classification"]["per_engine"].items():
            counts[r["class"]] += 1

    # Per-engine tallies
    per_engine_counts: Dict[str, Dict[str, int]] = {}
    for eng_id in ["A_nivxforge", "B_verdict_v2", "C_v2_score",
                        "D_ps_verdict", "CANONICAL"]:
        c = {"PRESERVED": 0, "CORRECTED": 0,
                 "INTENTIONAL": 0, "UNEXPLAINED": 0,
                 "INPUT-CONTRACT-UNRESOLVED": 0}
        for e in entries:
            c[e["classification"]["per_engine"][eng_id]["class"]] += 1
        per_engine_counts[eng_id] = c

    return {
        "schema_version":   "1.0",
        "purpose":          "ADR-004 Step 1 · Phase 3 · Canonical engine + 4-way legacy comparison",
        "engines_probed":   ["A_nivxforge", "B_verdict_v2", "C_v2_score",
                                  "D_ps_verdict", "CANONICAL"],
        "canonical_input_contract": {
            "source":    "backend/v2/verdict/canonical_input.py::CanonicalVerdictInput",
            "builder":   "from_investigation_model(m: InvestigationModel)",
            "shim":      "from_commands(cmds: list[str])  · parity-only",
            "wrapper":   "backend/v2/verdict/canonical.py::score(inp: CanonicalVerdictInput)",
            "note":      ("Derived from `v2.investigation.model.InvestigationModel` "
                              "(the pre-existing 9-bucket evidence model). "
                              "Does NOT inherit any legacy verdict engine's shape."),
        },
        "corpus_id":        "vendor-v1",
        "fixture_count":    len(entries),
        "class_counts":     counts,
        "per_engine_counts": per_engine_counts,
        "entries":          entries,
    }


def write_report():
    r = build_report()
    json_path = _REPORTS_DIR / "step1_phase3_diff_report.json"
    json_path.write_text(json.dumps(r, indent=2, sort_keys=True))

    lines: List[str] = [
        "# ADR-004 Step 1 · Phase 3 · Canonical Engine Diff Report",
        "",
        "_Auto-generated by `backend/tests/step1_phase3_diff.py`._",
        "_Do NOT edit by hand — regenerate with `python -m tests.step1_phase3_diff`._",
        "",
        "## Canonical input contract (owner-mandated architecture)",
        "",
        "Per the 2026-08-10 owner directive, the canonical verdict-input "
        "contract is derived from the **existing investigation/evidence "
        "model** (`v2.investigation.model.InvestigationModel` — the 9-bucket "
        "source-agnostic evidence model already in the codebase). It does "
        "NOT inherit any legacy verdict engine's shape.",
        "",
        "```",
        "                        ANY INPUT",
        "                            ↓",
        "          v2.investigation.model.InvestigationModel",
        "                            ↓",
        "  from_investigation_model(m)  →  CanonicalVerdictInput",
        "                            ↓",
        "  canonical.score(inp)      →  CanonicalVerdict",
        "```",
        "",
        "### Files added in Phase 3",
        "",
        "| File | Purpose |",
        "|---|---|",
        "| `backend/v2/verdict/canonical_input.py` | Defines `CanonicalEvent` + `CanonicalVerdictInput` + `from_investigation_model` (the only canonical builder) + `from_commands` (parity shim). |",
        "| `backend/v2/verdict/canonical.py`       | The canonical wrapper. Consumes `CanonicalVerdictInput`, invokes `v2.verdict.engine.score` per event, aggregates deterministically. Preserves Suspicious-as-floor and Runtime Dependent semantics verbatim. |",
        "| `backend/tests/step1_phase3_diff.py`   | Re-runs the Phase 2 comparison with the canonical engine as the 5th column. |",
        "| `backend/tests/test_step1_phase3_gate.py` | CI gate — same zero-UNEXPLAINED contract. |",
        "",
        "### What was NOT changed",
        "",
        "- `backend/v2/verdict/weights.py` — untouched. Same scoring weights.",
        "- `backend/v2/verdict/signals.py` — untouched. Same detectors.",
        "- `backend/v2/verdict/engine.py::score(event, ctx)` — untouched. Same per-event logic.",
        "- All 4 legacy engines (A/B/C/D) — untouched. Still active for their existing consumers.",
        "- No router / workspace / consumer wire has been changed.",
        "",
        "## Aggregate class counts across 14×5 = 70 cells",
        "",
        "| Class | Count |",
        "|---|---|",
    ]
    for k in ("PRESERVED", "CORRECTED", "INTENTIONAL",
                  "INPUT-CONTRACT-UNRESOLVED", "UNEXPLAINED"):
        lines.append(f"| **{k}** | {r['class_counts'][k]} |")

    lines += [
        "",
        "## Per-engine class breakdown",
        "",
        "| Engine | PRESERVED | CORRECTED | INTENTIONAL | INPUT-UNRESOLVED | UNEXPLAINED |",
        "|---|---|---|---|---|---|",
    ]
    for eng_id, c in r["per_engine_counts"].items():
        lines.append(
            f"| `{eng_id}` | {c['PRESERVED']} | {c['CORRECTED']} | "
            f"{c['INTENTIONAL']} | {c['INPUT-CONTRACT-UNRESOLVED']} | "
            f"{c['UNEXPLAINED']} |"
        )

    lines += [
        "",
        "## Per-fixture 5-column comparison",
        "",
        "| Fixture | GT | A · nivxforge | B · verdict_v2 | C · v2 score | D · ps_verdict | **CANONICAL** |",
        "|---|---|---|---|---|---|---|",
    ]
    for e in r["entries"]:
        gt = e["classification"]["ground_truth"]
        eng = e["engines"]
        cls = e["classification"]["per_engine"]

        def _cell(eng_id: str) -> str:
            o = eng[eng_id]
            c = cls[eng_id]["class"]
            if "error" in o:
                return f"ERROR · {c}"
            lbl = o.get("label")
            sc  = o.get("score_pct")
            return f"{lbl}/{sc} · {c}"

        lines.append(
            f"| `{e['fixture_id']}` | **{gt}** | {_cell('A_nivxforge')} | "
            f"{_cell('B_verdict_v2')} | {_cell('C_v2_score')} | "
            f"{_cell('D_ps_verdict')} | **{_cell('CANONICAL')}** |"
        )

    # Divergence commentary for CANONICAL column only (5th column is what matters now)
    lines += [
        "",
        "## Canonical engine divergences (only column that matters going forward)",
        "",
    ]
    canonical_only = [(e, e["classification"]["per_engine"]["CANONICAL"])
                            for e in r["entries"]]
    for e, cell in canonical_only:
        if cell["class"] == "PRESERVED":
            continue
        eng_out = e["engines"]["CANONICAL"]
        lbl = eng_out.get("label", "ERROR")
        sc  = eng_out.get("score_pct", "-")
        floor = eng_out.get("floor_applied") or "—"
        lines.append(
            f"### `{e['fixture_id']}` · GT={e['classification']['ground_truth']} · CANONICAL="
            f"{lbl}/{sc} · {cell['class']}"
        )
        lines.append(f"- Floor applied: `{floor}`")
        lines.append(f"- {cell['explanation']}")
        lines.append("")

    # Phase 4 Wave 1 gate
    lines += [
        "## Phase 4 Wave 1 · Read-only side-by-side (AUTHORISED by owner 2026-08-10)",
        "",
        "Wave 1 has been AUTHORISED. Read-only shadow attach is now wired:",
        "",
        "- `backend/v2/verdict/shadow.py::compute_shadow(cio)` — projects CIO metadata → `InvestigationModel`, builds `CanonicalVerdictInput`, scores canonical, computes Input-Completeness, classifies divergence.",
        "- `backend/routers/auto_investigate.py` — attaches `result[\"verdict_shadow\"]` immediately after the existing `verdict` is refreshed. Never blocks; never replaces the primary verdict.",
        "",
        "### Wave 1 gate checklist (owner-mandated, 2026-08-10)",
        "",
        f"- **UNEXPLAINED count** on this report: {r['class_counts']['UNEXPLAINED']} (must be 0).",
        f"- **CANONICAL PRESERVED**: {r['per_engine_counts']['CANONICAL']['PRESERVED']} / 14 on the bare-command shim.",
        f"- **CANONICAL INPUT-CONTRACT-UNRESOLVED**: {r['per_engine_counts']['CANONICAL']['INPUT-CONTRACT-UNRESOLVED']} / 14 — tracked, NOT declared false-negatives, awaiting real-world observation.",
        f"- **CANONICAL INTENTIONAL**: {r['per_engine_counts']['CANONICAL']['INTENTIONAL']} / 14 — preserved Suspicious-as-floor / Runtime Dependent scope.",
        "",
        "### Observation-window telemetry captured per real investigation",
        "",
        "- `verdict_shadow.existing_verdict`  → the label + confidence + reason of the current engine A verdict",
        "- `verdict_shadow.verdict_canonical` → the label + confidence + top contributors of the canonical engine",
        "- `verdict_shadow.input_completeness` → which of the 9 InvestigationModel buckets were populated + completeness %",
        "- `verdict_shadow.divergence`         → AGREE / INPUT-CONTRACT-UNRESOLVED / INTENTIONAL-SCOPE / POTENTIAL-FALSE-NEGATIVE / POTENTIAL-FALSE-POSITIVE / OTHER-DIVERGENCE",
        "",
        "### Wave 1 STOP conditions (must all hold before Wave 2 authorisation)",
        "",
        "1. Sufficient sample coverage across `rich`/`moderate`/`sparse`/`minimal` completeness classes.",
        "2. Zero POTENTIAL-FALSE-POSITIVE cells at `rich` completeness.",
        "3. Every POTENTIAL-FALSE-NEGATIVE at `rich` completeness has an owner-approved explanation.",
        "4. The 11 previously INPUT-CONTRACT-UNRESOLVED cells (or their real-world equivalents) have been re-observed with `rich` or `moderate` completeness.",
        "",
        "_STOP · Wave 1 attached, observation window opens on next production traffic. Wave 2 (consumer switch) NOT authorised._",
    ]

    md_path = _MEMORY_DIR / "STEP1_PHASE3_REPORT.md"
    md_path.write_text("\n".join(lines))
    return {"json": str(json_path), "md": str(md_path)}


if __name__ == "__main__":
    paths = write_report()
    print(json.dumps(paths, indent=2))
