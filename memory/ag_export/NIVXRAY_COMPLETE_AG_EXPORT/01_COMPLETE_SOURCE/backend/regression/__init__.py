"""NivXRay Regression Corpus + Auto-Benchmark (Feb-2026 roadmap #3 + #4).

Two tightly-coupled features:

    A. Regression Corpus (`regression_corpus` collection)
       -------------------------------------------------
       Versioned samples with an expected decoded output + optional
       expected decode chain. Populated by:
         - Analyst corrections via `POST /api/learning/correction`
           with `promote_to_corpus: true`
         - Direct admin creation via `POST /api/regression/corpus/entries`

    B. Auto-Benchmark (`regression_runs` + `regression_gate` collections)
       -----------------------------------------------------------------
       Executes every corpus sample against the current decoder engine,
       captures actual output + chain, compares with the expected value,
       and produces a run record. Diffs against the PREVIOUS run to
       highlight flips (TP → FN and FN → TP) — the core signal.

       A singleton "gate" doc caches the last pass rate so downstream
       features (sample-library promote, admin ops) can refuse to accept
       changes when the regression suite is failing.

Data model
----------

`regression_corpus`
    {
        _id, name, input, expected_output, expected_chain, source,
        created_at, created_by, version, notes,
    }

`regression_runs`
    {
        _id, started_at, finished_at, trigger, total, passed, failed,
        pass_rate, previous_run_id, flips: [{sample_id, name, from, to,
                                              expected, actual, diff}],
        results: [{sample_id, name, pass, expected_output, actual_output,
                   expected_chain, actual_chain, diff_type, error}],
    }

`regression_gate`
    { _id: "singleton", last_pass_rate, last_run_id, last_run_at }
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId


CORPUS = "regression_corpus"
RUNS = "regression_runs"
GATE = "regression_gate"
GATE_ID = "singleton"

# Below this pass rate, downstream gates (sample-library promote, etc.)
# should refuse to accept changes.
DEFAULT_GATE_THRESHOLD = 1.0


# =====================================================================
# Corpus CRUD
# =====================================================================
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stringify_id(doc: Dict[str, Any]) -> Dict[str, Any]:
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc


async def add_corpus_entry(
    db,
    *,
    name: str,
    input_text: str,
    expected_output: str,
    expected_chain: Optional[List[Dict[str, Any]]] = None,
    source: str = "analyst-correction",
    created_by: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Insert a new regression sample. Returns the inserted document."""
    doc: Dict[str, Any] = {
        "name": name or f"sample-{_now()}",
        "input": input_text,
        "expected_output": expected_output,
        "expected_chain": expected_chain or [],
        "source": source,
        "created_at": _now(),
        "created_by": created_by,
        "version": 1,
        "notes": notes,
    }
    r = await db[CORPUS].insert_one(doc)
    doc["_id"] = str(r.inserted_id)
    return doc


async def list_corpus_entries(
    db, limit: int = 200, source: Optional[str] = None,
) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 200), 1000))
    q = {"source": source} if source else {}
    cursor = db[CORPUS].find(q).sort("created_at", -1).limit(limit)
    entries: List[Dict[str, Any]] = []
    async for doc in cursor:
        entries.append(_stringify_id(doc))
    return entries


async def get_corpus_entry(db, entry_id: str) -> Optional[Dict[str, Any]]:
    try:
        oid = ObjectId(entry_id)
    except Exception:
        return None
    doc = await db[CORPUS].find_one({"_id": oid})
    return _stringify_id(doc) if doc else None


async def delete_corpus_entry(db, entry_id: str) -> bool:
    try:
        oid = ObjectId(entry_id)
    except Exception:
        return False
    r = await db[CORPUS].delete_one({"_id": oid})
    return r.deleted_count > 0


async def corpus_count(db) -> int:
    return await db[CORPUS].count_documents({})


# =====================================================================
# Benchmark runner
# =====================================================================
def _chain_ops(chain: Optional[List[Dict[str, Any]]]) -> List[str]:
    if not chain:
        return []
    return [s.get("op") or "" for s in chain if isinstance(s, dict)]


def _classify_diff(expected: str, actual: str,
                    expected_chain: List[str], actual_chain: List[str]) -> str:
    """Categorize the failure mode for UI reporting."""
    if expected == actual and expected_chain == actual_chain:
        return "match"
    if expected == actual:
        return "chain-differs"
    if expected_chain == actual_chain:
        return "output-differs"
    return "both-differ"


def _run_one_sample(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Execute one corpus sample through `deterministic_best_decode`."""
    from analysis_core import deterministic_best_decode

    sample_id = entry.get("_id")
    name = entry.get("name") or "unnamed"
    inp = entry.get("input") or ""
    expected_out = entry.get("expected_output") or ""
    expected_chain_full = entry.get("expected_chain") or []
    expected_ops = _chain_ops(expected_chain_full)

    try:
        result = deterministic_best_decode(inp, analysis_mode="balanced")
    except Exception as e:
        return {
            "sample_id": sample_id,
            "name": name,
            "pass": False,
            "expected_output": expected_out,
            "actual_output": "",
            "expected_chain": expected_ops,
            "actual_chain": [],
            "diff_type": "exception",
            "error": f"{type(e).__name__}: {e}",
            "confidence": None,
        }

    actual_out = result.get("output") or ""
    actual_chain = _chain_ops(result.get("steps") or [])
    confidence = None
    reasoning = result.get("reasoning") or {}
    if isinstance(reasoning, dict):
        conf_obj = reasoning.get("confidence")
        if isinstance(conf_obj, dict):
            confidence = conf_obj.get("confidence")

    # Chain equality: exact-match on op names. Order-preserving.
    # Output equality: byte-exact match (post-strip).
    output_match = actual_out.strip() == expected_out.strip()
    chain_match = (not expected_ops) or (actual_chain == expected_ops)

    passed = output_match and chain_match
    diff_type = _classify_diff(
        expected_out.strip(), actual_out.strip(),
        expected_ops, actual_chain,
    )
    if passed:
        diff_type = "match"

    return {
        "sample_id": sample_id,
        "name": name,
        "pass": passed,
        "expected_output": expected_out,
        "actual_output": actual_out,
        "expected_chain": expected_ops,
        "actual_chain": actual_chain,
        "diff_type": diff_type,
        "error": None,
        "confidence": confidence,
    }


async def _get_previous_run(db) -> Optional[Dict[str, Any]]:
    cursor = db[RUNS].find({}).sort("started_at", -1).limit(1)
    docs = await cursor.to_list(length=1)
    return docs[0] if docs else None


def _compute_flips(
    prev: Optional[Dict[str, Any]], current_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """A "flip" is a sample whose pass status changed between runs.

    Direction encoded as: {"from": "pass" | "fail", "to": "pass" | "fail"}
    Only reports samples present in BOTH runs.
    """
    if not prev:
        return []
    prev_map = {r["sample_id"]: r for r in (prev.get("results") or [])
                 if r.get("sample_id")}
    flips: List[Dict[str, Any]] = []
    for r in current_results:
        sid = r.get("sample_id")
        if sid not in prev_map:
            continue
        prev_pass = bool(prev_map[sid].get("pass"))
        curr_pass = bool(r.get("pass"))
        if prev_pass == curr_pass:
            continue
        flips.append({
            "sample_id": sid,
            "name": r.get("name"),
            "from": "pass" if prev_pass else "fail",
            "to": "pass" if curr_pass else "fail",
            "expected": r.get("expected_output"),
            "actual": r.get("actual_output"),
            "diff_type": r.get("diff_type"),
        })
    return flips


async def _update_gate(db, run: Dict[str, Any]) -> None:
    await db[GATE].update_one(
        {"_id": GATE_ID},
        {"$set": {
            "last_pass_rate": run["pass_rate"],
            "last_run_id": run["_id"],
            "last_run_at": run["finished_at"],
            "last_total": run["total"],
            "last_passed": run["passed"],
            "last_failed": run["failed"],
        }},
        upsert=True,
    )


async def run_benchmark(
    db, *, trigger: str = "manual", triggered_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute the full regression corpus and store the run record."""
    started = _now()
    entries = await list_corpus_entries(db, limit=10_000)
    prev = await _get_previous_run(db)

    results: List[Dict[str, Any]] = []
    passed = 0
    failed = 0
    for e in entries:
        r = _run_one_sample(e)
        results.append(r)
        if r["pass"]:
            passed += 1
        else:
            failed += 1

    total = len(results)
    pass_rate = (passed / total) if total else 1.0
    flips = _compute_flips(prev, results)
    new_regressions = [f for f in flips if f["to"] == "fail"]
    resolved = [f for f in flips if f["to"] == "pass"]
    affected_decoders = sorted({
        op for r in results if not r["pass"]
        for op in (r.get("expected_chain") or []) + (r.get("actual_chain") or [])
        if op
    })

    finished = _now()
    run: Dict[str, Any] = {
        "started_at": started,
        "finished_at": finished,
        "trigger": trigger,
        "triggered_by": triggered_by,
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(pass_rate, 4),
        "previous_run_id": (prev or {}).get("_id"),
        "flips": flips,
        "new_regressions": new_regressions,
        "resolved_regressions": resolved,
        "affected_decoders": affected_decoders,
        "results": results,
    }
    insert = await db[RUNS].insert_one(run)
    run["_id"] = str(insert.inserted_id)
    if run.get("previous_run_id") is not None:
        run["previous_run_id"] = str(run["previous_run_id"])
    await _update_gate(db, run)
    return run


# =====================================================================
# Run history
# =====================================================================
async def list_runs(db, limit: int = 30) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 30), 200))
    cursor = db[RUNS].find({}).sort("started_at", -1).limit(limit)
    runs: List[Dict[str, Any]] = []
    async for doc in cursor:
        # Trim `results` for list view to keep the payload light
        light = {k: v for k, v in doc.items() if k != "results"}
        light = _stringify_id(light)
        if light.get("previous_run_id") is not None:
            light["previous_run_id"] = str(light["previous_run_id"])
        runs.append(light)
    return runs


async def get_run(db, run_id: str) -> Optional[Dict[str, Any]]:
    try:
        oid = ObjectId(run_id)
    except Exception:
        return None
    doc = await db[RUNS].find_one({"_id": oid})
    if not doc:
        return None
    doc = _stringify_id(doc)
    if doc.get("previous_run_id") is not None:
        doc["previous_run_id"] = str(doc["previous_run_id"])
    return doc


async def get_latest_run(db) -> Optional[Dict[str, Any]]:
    return await _get_previous_run(db)


# =====================================================================
# Gate
# =====================================================================
async def get_gate(db) -> Dict[str, Any]:
    doc = await db[GATE].find_one({"_id": GATE_ID})
    if not doc:
        return {"last_pass_rate": None, "last_run_id": None, "last_run_at": None}
    doc.pop("_id", None)
    if doc.get("last_run_id") is not None:
        doc["last_run_id"] = str(doc["last_run_id"])
    return doc


async def gate_permits_promotion(db, threshold: float = DEFAULT_GATE_THRESHOLD) -> Dict[str, Any]:
    """Return {ok, reason, gate} — ok=True iff last pass rate ≥ threshold.

    If no runs have executed yet, the gate is PERMISSIVE (no history to
    block on). Callers should decide policy independently.
    """
    gate = await get_gate(db)
    lpr = gate.get("last_pass_rate")
    if lpr is None:
        return {"ok": True, "reason": "no-runs-yet", "gate": gate}
    if lpr < threshold:
        return {
            "ok": False,
            "reason": (
                f"last regression pass_rate {lpr:.2%} < threshold {threshold:.2%}"
            ),
            "gate": gate,
        }
    return {"ok": True, "reason": "regression-passing", "gate": gate}
