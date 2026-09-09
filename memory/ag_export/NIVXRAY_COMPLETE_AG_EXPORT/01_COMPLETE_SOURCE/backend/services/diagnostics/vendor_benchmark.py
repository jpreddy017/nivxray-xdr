"""
NivXRay · Vendor Corpus Benchmark Harness
──────────────────────────────────────────

Measures analyst-outcome deltas across the Vendor Corpus v1
fixtures.  Runs the full deterministic pipeline TWICE — once with
VEEE disabled (legacy baseline) and once with VEEE enabled — and
reports per-fixture + aggregate counts for:

    · Commands recovered            (post-canonicalization)
    · Behaviors clustered           (ICE behavior_clusters)
    · MITRE techniques matched      (unique T-ids surfaced)
    · Recommendations generated     (incident.recommendations)

Design (per user brief 2026-02-09):
    · Pure · no I/O beyond writing the JSON trend file
    · Deterministic · same corpus in → same numbers out
    · Read-only against services · never mutates production data
    · Not wired into any request path — invoked from tests / CLI

The trend file (``corpus/vendor/v1/reports/sprint_trend.json``) is
APPEND-ONLY.  Every benchmark run adds a snapshot; historical
sprints are preserved so we can graph movement over time.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════
# 1. Fixture generation (matches P0.15C-5 corpus loader)
# ══════════════════════════════════════════════════════════════════
_MONO_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
]


def _load_font(size: int = 18):
    from PIL import ImageFont
    for p in _MONO_FONT_CANDIDATES:
        if Path(p).is_file():
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def _render_screenshot(commands: List[str],
                          width: int = 900,
                          padding: int = 12,
                          line_h: int = 26,
                          size: int = 18) -> bytes:
    from PIL import Image, ImageDraw
    height = padding * 2 + line_h * len(commands)
    img = Image.new("L", (width, height), 255)
    draw = ImageDraw.Draw(img)
    font = _load_font(size)
    y = padding
    for cmd in commands:
        draw.text((padding, y), cmd, fill=0, font=font)
        y += line_h
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _fixture_html(title: str, vendor: str, fixture_id: str) -> str:
    return (f'<article><h1>{title}</h1>'
                f'<p>Vendor {vendor} · fixture {fixture_id}.</p>'
                f'<img src="https://vendor.example/{fixture_id}.png"/>'
                f'</article>')


# ══════════════════════════════════════════════════════════════════
# 2. Pipeline invocation
# ══════════════════════════════════════════════════════════════════
def _run_pipeline_on_fixture(fixture, *, veee_enabled: bool) -> Dict[str, Any]:
    """Run the full acquisition→correlation pipeline on ONE fixture
    and return the measurable outputs.

    Never touches the network — assembles the SSOT locally.
    """
    from services.ida.report_extractors import extract_all
    from services.ice.correlate         import correlate

    html = _fixture_html(fixture.article_title,
                              fixture.vendor,
                              fixture.fixture_id)
    structured_blocks: List[str] = []
    veee_records: List[Dict[str, Any]] = []

    # ── VEEE (feature-flagged) ────────────────────────────────
    if veee_enabled:
        os.environ["NVX_VEEE_ENABLED"] = "1"
        from services.veee import extract_from_image
        png = _render_screenshot(fixture.commands)
        for rec in extract_from_image(png,
                                            image_url=f"https://vendor.example/{fixture.fixture_id}.png"):
            veee_records.append(rec)
            if rec.get("type") != "skipped" and rec.get("text"):
                structured_blocks.append(rec["text"])
    else:
        os.environ["NVX_VEEE_ENABLED"] = "0"

    # ── Article text feed for the classifier ──────────────────
    #   IDA's default acquisition path collects article text +
    #   structured_blocks and hands them to `extract_all`.  We
    #   mirror that composition here.
    article_text = "\n".join([html] + structured_blocks)
    ext = extract_all(article_text, structured_blocks=structured_blocks)

    # ── SSOT ─────────────────────────────────────────────────
    ssot = {
        "report_extraction": ext,
        "acquired_document": {
            "url":                f"https://vendor.example/{fixture.fixture_id}",
            "final_text":         article_text,
            "structured_blocks":  structured_blocks,
            "veee_records":       veee_records,
        },
        "document_profile": {"vendor": fixture.vendor,
                                 "title":  fixture.article_title},
    }

    ice = correlate(ssot)
    incident = ice.get("incident") or {}

    behaviors        = incident.get("behaviors")        or []
    mitre_matrix     = incident.get("mitre")            or []
    recommendations  = incident.get("recommendations")  or []
    commands         = (ext.get("commands") or [])

    # Aggregate the unique MITRE technique universe across the
    # incident.mitre matrix + all behavior clusters.
    tech_ids: set = set()
    for row in mitre_matrix:
        for t in (row.get("techniques") or []):
            tid = t["id"] if isinstance(t, dict) else t
            if tid:
                tech_ids.add(tid)
    for b in behaviors:
        for m in (b.get("mitre") or []):
            tid = m["id"] if isinstance(m, dict) else m
            if tid:
                tech_ids.add(tid)

    # ── Quality dashboard metrics (2026-02-09 · validation sprint) ─
    # False "Command execution" fallback count — a rising number
    # signals classifier gaps.
    generic_fallback = sum(1 for c in commands
                                    if (c.get("purpose") or "") == "Command execution")
    # Mean OCR confidence across VEEE records (0.0 when VEEE is off).
    _confs = [((r.get("provenance") or {}).get("ocr_confidence"))
                  for r in veee_records
                  if r.get("type") != "skipped"
                    and (r.get("provenance") or {}).get("ocr_confidence") is not None]
    mean_ocr_conf = (sum(_confs) / len(_confs)) if _confs else 0.0
    # Recommendation coverage — fraction of behaviors covered by ≥1
    # recommendation (empty behaviors → 0.0).
    total_beh    = max(1, len(behaviors))
    covered_beh  = 0
    behavior_labels = {b.get("label") for b in behaviors if b.get("label")}
    for rec in recommendations:
        target = rec.get("target") or rec.get("behavior") or rec.get("label")
        if target in behavior_labels:
            covered_beh += 1
    coverage = min(1.0, covered_beh / total_beh) if len(behaviors) else 0.0

    return {
        "fixture_id":       fixture.fixture_id,
        "vendor":           fixture.vendor,
        "commands":                len(commands),
        "behaviors":               len(behaviors),
        "mitre":                   len(tech_ids),
        "recommendations":         len(recommendations),
        "html_commands":           len(fixture.commands),
        "veee_lift":               (len(commands) if veee_enabled else 0),
        # Quality-dashboard metrics (2026-02-09):
        "generic_fallback":        generic_fallback,
        "mean_ocr_confidence":     round(mean_ocr_conf, 3),
        "recommendation_coverage": round(coverage, 3),
    }


# ══════════════════════════════════════════════════════════════════
# 3. Benchmark run
# ══════════════════════════════════════════════════════════════════
def run_benchmark(*, sprint: Optional[str] = None) -> Dict[str, Any]:
    """Run the corpus in both modes and return the structured
    snapshot.  Does NOT write to disk — call ``persist_snapshot``
    to append it to the trend file."""
    # Late import to avoid a circular dep during module load.
    from tests.test_p015c5_vendor_corpus_v1 import VENDOR_CORPUS_V1

    started = time.time()

    off_results: List[Dict[str, Any]] = []
    on_results:  List[Dict[str, Any]] = []
    for fixture in VENDOR_CORPUS_V1:
        off_results.append(_run_pipeline_on_fixture(fixture, veee_enabled=False))
        on_results.append(_run_pipeline_on_fixture(fixture, veee_enabled=True))

    def _agg(rows: List[Dict[str, Any]]) -> Dict[str, float]:
        n = max(1, len(rows))
        confs = [r.get("mean_ocr_confidence") or 0.0 for r in rows
                     if (r.get("mean_ocr_confidence") or 0.0) > 0.0]
        return {
            "commands":                sum(r["commands"]                for r in rows),
            "behaviors":               sum(r["behaviors"]               for r in rows),
            "mitre":                   sum(r["mitre"]                   for r in rows),
            "recommendations":         sum(r["recommendations"]         for r in rows),
            # Quality signals (2026-02-09):
            "generic_fallback":        sum(r.get("generic_fallback", 0)         for r in rows),
            "mean_ocr_confidence":     round((sum(confs) / len(confs)) if confs else 0.0, 3),
            "recommendation_coverage": round(sum(r.get("recommendation_coverage", 0.0)
                                                          for r in rows) / n, 3),
        }

    off_agg = _agg(off_results)
    on_agg  = _agg(on_results)
    delta   = {k: on_agg[k] - off_agg[k] for k in on_agg}

    snapshot = {
        "schema_version": "1.0",
        "sprint":         sprint or _sprint_id(),
        "timestamp_utc":  datetime.now(timezone.utc).isoformat(),
        "corpus": {
            "id":       "vendor-v1",
            "fixtures": len(VENDOR_CORPUS_V1),
        },
        "aggregate": {
            "flag_off": off_agg,
            "flag_on":  on_agg,
            "delta":    delta,
        },
        "per_fixture": {
            "flag_off": off_results,
            "flag_on":  on_results,
        },
        "duration_ms": int((time.time() - started) * 1000),
    }
    return snapshot


def _sprint_id() -> str:
    """Deterministic sprint id derived from the current date —
    format sprint-YYYYMMDD."""
    return "sprint-" + datetime.now(timezone.utc).strftime("%Y%m%d")


# ══════════════════════════════════════════════════════════════════
# 4. Trend file persistence (append-only history)
# ══════════════════════════════════════════════════════════════════
def _reports_dir() -> Path:
    root = Path(__file__).resolve().parent.parent.parent / "corpus" / "vendor" / "v1" / "reports"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _trend_path() -> Path:
    return _reports_dir() / "sprint_trend.json"


def persist_snapshot(snapshot: Dict[str, Any]) -> Path:
    """Append the snapshot to the trend history file.  The file
    format is a JSON object with a ``history`` array; each run
    appends one entry keyed by ``sprint`` — later runs with the
    same sprint id REPLACE their peer so re-running the benchmark
    within a single day is idempotent (only the last run wins for
    that day)."""
    path = _trend_path()
    history: List[Dict[str, Any]] = []
    if path.exists():
        try:
            existing = json.loads(path.read_text())
            history  = list(existing.get("history") or [])
        except Exception:
            history = []
    # Replace any prior entry with the same sprint id (idempotent).
    history = [h for h in history if h.get("sprint") != snapshot["sprint"]]
    history.append(snapshot)
    history.sort(key=lambda h: h.get("sprint") or "")
    path.write_text(json.dumps({
        "schema_version": "1.0",
        "corpus_id":       snapshot["corpus"]["id"],
        "count":           len(history),
        "history":         history,
    }, indent=2, sort_keys=True))
    return path


def latest_snapshot_from_trend() -> Optional[Dict[str, Any]]:
    p = _trend_path()
    if not p.exists():
        return None
    try:
        raw = json.loads(p.read_text())
        h   = raw.get("history") or []
        return h[-1] if h else None
    except Exception:
        return None


__all__ = ["run_benchmark", "persist_snapshot",
                "latest_snapshot_from_trend", "_run_pipeline_on_fixture"]
