"""Workspace Audit CI Gate — the release blocker.

Runs the full Workspace validation corpus (see `workspace_audit.py`)
inside pytest so every PR must produce a Workspace with **zero P0
and zero P1 defects** before it can merge.

Per the user's Workspace Stabilization Directive, the release gate is
NOT "pytest 202/202 pass" — it is "the Workspace produces correct,
deterministic, explainable investigations for every supported command
line". This test is that gate.

Defect classification (analyst-impact ordered, NOT engine-boundary):
    P0 — Incorrect decoded output, incorrect final payload, incorrect
         analysis, incorrect verdict, fabricated output, missing
         evidence, incorrect execution boundary.
    P1 — Incorrect MITRE mapping, incorrect IOC extraction, incorrect
         storyline, incorrect confidence, missing explanation.
    P2 — UI rendering inconsistencies, formatting, cosmetic issues.

If this test fails, the fix must:
    1. Root-cause the defect in the owning engine.
    2. Add a permanent regression sample in `workspace_audit.py`.
    3. Verify the sample flips from P0/P1 → clean.
"""
from __future__ import annotations

import json
from pathlib import Path

from tests.workspace_audit import run_audit


REPORT_PATH = Path(__file__).resolve().parent / "reports" / "workspace_audit_report.json"


def test_workspace_audit_zero_p0_and_p1_defects() -> None:
    rep = run_audit()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(rep, indent=2))

    p0 = rep["defects_by_severity"]["P0"]
    p1 = rep["defects_by_severity"]["P1"]

    if p0 or p1:
        lines = [f"❌ Workspace Audit found {p0} P0 + {p1} P1 defect(s):"]
        for d in rep["defects"]:
            if d["severity"] in ("P0", "P1"):
                lines.append(
                    f"  · [{d['severity']}] {d['sample']} → "
                    f"{d['section']}: {d['issue']}"
                )
        lines.append(f"Full report: {REPORT_PATH}")
        raise AssertionError("\n".join(lines))


def test_workspace_audit_corpus_covers_every_mandated_category() -> None:
    """Guardrail — every mandated analyst-visible category must remain
    in the corpus. Prevents accidental deletion of a validation sample
    while a defect fix is being backed out."""
    rep = run_audit()
    covered = {s["category"] for s in rep["per_sample"]}
    required = {
        "plain",                 # Plain PS commands
        "encoded",               # -EncodedCommand PS
        "multi_layer",           # Nested obfuscation chains
        "download_cradle",       # IEX + WebClient
        "lolbas",                # Non-PS LOLBAS binaries
        "crypto",                # AES / RC4 / XOR
        "reflection",            # Runtime-generated / dynamic key
    }
    missing = required - covered
    assert not missing, (
        f"Workspace Audit corpus missing mandated category / categories: "
        f"{sorted(missing)}. Every supported command-line family must "
        f"be represented before the release gate can pass."
    )
