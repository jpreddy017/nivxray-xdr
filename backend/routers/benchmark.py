"""Public Benchmark Router  (P1 · Feb 2026)

Endpoints (ALL PUBLIC — no auth):
  * GET  /api/benchmark/real-world           — running JSON metrics
  * GET  /api/benchmark/real-world/download  — full corpus (CSV/JSON export)
  * POST /api/benchmark/refresh              — refresh the ledger + re-run

The public score is what makes NivXRay's claims verifiable. Anyone can
inspect the number, download the corpus, and reproduce it locally.

Under the hood we cache the last run for 15 minutes to protect the pod
from a spike of benchmark hits — the JSON report on disk is authoritative.
"""
from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

# make sibling `tests` importable
sys.path.insert(0, "/app/backend")
sys.path.insert(0, "/app/backend/tests")

from tests.real_world_stress_suite import (  # noqa: E402
    CORPUS, THRESHOLDS, run_and_report, check_gate, REPORT_JSON,
)

router = APIRouter(prefix="/benchmark", tags=["benchmark"])

_CACHE: Dict[str, Any] = {"ts": 0.0, "payload": None}
_CACHE_TTL_S = 15 * 60  # 15 minutes


def _load_cached_or_fresh() -> Dict[str, Any]:
    now = time.time()
    if _CACHE["payload"] and (now - _CACHE["ts"] < _CACHE_TTL_S):
        return _CACHE["payload"]
    # Prefer on-disk report over a fresh run — the pytest CI writes it.
    if REPORT_JSON.exists():
        try:
            payload = json.loads(REPORT_JSON.read_text(encoding="utf-8"))
            _CACHE["payload"] = payload
            _CACHE["ts"] = now
            return payload
        except Exception:
            pass
    payload = run_and_report()
    _CACHE["payload"] = payload
    _CACHE["ts"] = now
    return payload


@router.get("/real-world")
async def get_real_world_benchmark():
    """Public running metrics for the Real-World Stress Corpus."""
    payload = _load_cached_or_fresh()
    s = payload["summary"]
    ok, fails = check_gate(s)
    return {
        "corpus_size":       s["total"],
        "generated_at":      s["generated_at"],
        "gate": {
            "ok":            ok,
            "failures":      fails,
            "thresholds":    THRESHOLDS,
        },
        "metrics": {
            "mitre_hit_rate":  s["mitre_hit_rate"],
            "undecoded_rate":  s["undecoded_rate"],
            "ioc_recall":      s["ioc_recall"],
            "marker_hit_rate": s["marker_hit_rate"],
            "avg_layers":      s["avg_layers"],
            "avg_latency_ms":  s["avg_latency_ms"],
        },
        "per_family":        s["per_family"],
        "sources": [
            "Sophos X-Ops",
            "TrendMicro Research",
            "Any.Run public tasks",
            "MalwareBazaar",
            "Mandiant",
            "CrowdStrike",
            "MITRE ATT&CK",
            "Atomic Red Team",
        ],
        "corpus_download":   "/api/benchmark/real-world/download",
        "html_report":       "/downloads/real_world_stress.html",
    }


@router.get("/real-world/download")
async def download_corpus():
    """Publishes the full curated corpus (metadata + raw_input + ground truth)."""
    export = [{
        "id":                e["id"],
        "family":            e["family"],
        "source":            e["source"],
        "stack_id":          e["stack_id"],
        "layers":            e["layers"],
        "min_layers":        e["min_layers"],
        "raw_input":         e["raw_input"],
        "ground_truth":      e["ground_truth"],
        "expected_mitre":    e["expected_mitre"],
        "expected_iocs":     e["expected_iocs"],
    } for e in CORPUS]
    return JSONResponse(content={
        "count":  len(export),
        "corpus": export,
        "notice": (
            "Every payload is reconstructed from a documented public incident "
            "write-up so ground truth is verifiable. Use for defensive research "
            "and detection engineering only."
        ),
    })


@router.post("/refresh")
async def refresh_and_rerun():
    """Runs the corpus feed refresh + re-executes the suite. Bypasses cache."""
    try:
        from corpus_refresh import refresh_once
        refresh = await refresh_once()
    except Exception as e:
        refresh = {"ok": False, "error": str(e)}
    payload = run_and_report()
    _CACHE["payload"] = payload
    _CACHE["ts"] = time.time()
    return {
        "refresh": refresh,
        "summary": payload["summary"],
    }
