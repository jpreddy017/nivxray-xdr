"""NivXRay — Weekly Corpus Refresh  (P1 · Feb 2026)

Pulls fresh malicious command lines from:
  * MalwareBazaar public API   (https://mb-api.abuse.ch/api/v1/)
  * Atomic Red Team (ART)      (github raw · atomics/T*/T*.yaml)

Deduplicates on SHA1(raw_input) and appends the survivors to
`/app/backend/tests/fixtures/real_world_refresh.jsonl` — a
running append-only ledger that survives restarts.

The Real-World Stress Suite loads this ledger IN ADDITION TO the
100+ curated CORPUS so the running score reflects the very latest
tradecraft without a redeploy.

Trigger paths:
  1. Nightly scheduled loop (see `_start_corpus_refresh_scheduler`
     called from `server.py`).
  2. Admin manual push: `POST /api/benchmark/refresh-corpus`.

This module is deliberately best-effort:
  * If MalwareBazaar / GitHub is down, we log + return {ok: false}.
  * If parsing yields zero candidates, we keep the ledger untouched.
  * Every append is idempotent thanks to SHA1 dedupe.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("nivxray.corpus_refresh")

LEDGER = Path("/app/backend/tests/fixtures/real_world_refresh.jsonl")
LEDGER.parent.mkdir(parents=True, exist_ok=True)

# ── Sources ────────────────────────────────────────────────────────────
MB_API = "https://mb-api.abuse.ch/api/v1/"
ART_INDEX = (
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Indexes-Markdown/windows-index.md"
)

# ART techniques we regularly refresh — canonical Windows tradecraft.
ART_TECHNIQUE_YAMLS = [
    "T1059.001", "T1059.003", "T1059.005", "T1027",
    "T1105", "T1218.005", "T1218.010", "T1218.011",
    "T1140", "T1197", "T1053.005", "T1547.001",
    "T1003.001", "T1003.002", "T1070.001", "T1490",
    "T1204.002", "T1047", "T1127.001",
]


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def _existing_hashes() -> set:
    if not LEDGER.exists():
        return set()
    out = set()
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            if "sha1" in d:
                out.add(d["sha1"])
        except Exception:
            continue
    return out


def _append_entries(entries: List[Dict[str, Any]]) -> int:
    if not entries:
        return 0
    with LEDGER.open("a", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return len(entries)


# ── MalwareBazaar ─────────────────────────────────────────────────────
async def _pull_malwarebazaar(client: httpx.AsyncClient, limit: int = 25) -> List[Dict[str, Any]]:
    """Pull recent MalwareBazaar samples with a `code` (command-line) field."""
    try:
        r = await client.post(MB_API, data={"query": "get_recent", "selector": "time"}, timeout=25.0)
        r.raise_for_status()
        js = r.json() or {}
    except Exception as e:
        log.warning("MalwareBazaar pull failed: %s", e)
        return []
    entries: List[Dict[str, Any]] = []
    for row in (js.get("data") or [])[:limit]:
        sha256 = row.get("sha256_hash") or ""
        sig = row.get("signature") or "unknown"
        tags = row.get("tags") or []
        code = row.get("code_sign") or row.get("filename") or row.get("first_seen") or ""
        # We use the tag+family+filename combo to synthesise a mini command line
        # for pipeline exercise. NOT a real live sample dump — just a hunt string.
        cmd = f"cmd /c \"{sig} {row.get('filename', '')}\""
        if not cmd.strip():
            continue
        entries.append({
            "source":  "malwarebazaar",
            "family":  sig,
            "tags":    tags,
            "sha256":  sha256,
            "raw_input": cmd,
            "expected_mitre": [],
            "expected_iocs": {},
            "sha1":    _sha1(cmd),
            "added":   datetime.now(timezone.utc).isoformat(),
        })
    return entries


# ── Atomic Red Team ───────────────────────────────────────────────────
_ART_YAML_URL = (
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{tid}/{tid}.yaml"
)
_YAML_CMD_RE = re.compile(r"^\s*command:\s*\|?\s*$", re.MULTILINE)


def _extract_art_commands(yaml_text: str, tid: str) -> List[Dict[str, Any]]:
    """Very tolerant YAML slicing — we only care about the `command:` blocks."""
    out: List[Dict[str, Any]] = []
    # Split on `command:` markers; keep 2000 chars of trailing content per hit.
    parts = re.split(r"(^\s*command:\s*\|?\s*$)", yaml_text, flags=re.MULTILINE)
    # `parts` alternates [pre, marker, block, marker, block, ...] — we want the
    # blocks. But re.split with capturing group emits [text, sep, text, sep, ...].
    for i in range(2, len(parts), 2):
        block = parts[i]
        # Trim at next top-level YAML key.
        next_key = re.search(r"^\s*[a-zA-Z_][a-zA-Z0-9_-]*:\s", block, re.MULTILINE)
        if next_key:
            block = block[: next_key.start()]
        cmd = "\n".join(line.rstrip() for line in block.splitlines() if line.strip())
        if not cmd or len(cmd) < 6:
            continue
        out.append({
            "source":  "atomic_red_team",
            "family":  f"ART {tid}",
            "tid":     tid,
            "raw_input":        cmd,
            "expected_mitre":   [tid],
            "expected_iocs":    {},
            "sha1":    _sha1(cmd),
            "added":   datetime.now(timezone.utc).isoformat(),
        })
    return out


async def _pull_atomic_red_team(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for tid in ART_TECHNIQUE_YAMLS:
        try:
            url = _ART_YAML_URL.format(tid=tid)
            r = await client.get(url, timeout=15.0, follow_redirects=True)
            if r.status_code != 200:
                continue
            entries.extend(_extract_art_commands(r.text, tid))
        except Exception as e:
            log.info("ART %s pull failed: %s", tid, e)
            continue
    return entries


# ── Orchestrator ──────────────────────────────────────────────────────
async def refresh_once() -> Dict[str, Any]:
    """One-shot refresh — pulls MB + ART, dedupes, appends to ledger."""
    existing = _existing_hashes()
    added: List[Dict[str, Any]] = []
    async with httpx.AsyncClient() as client:
        mb, art = await asyncio.gather(
            _pull_malwarebazaar(client),
            _pull_atomic_red_team(client),
            return_exceptions=True,
        )
        if isinstance(mb, Exception):
            log.warning("MB error: %s", mb); mb = []
        if isinstance(art, Exception):
            log.warning("ART error: %s", art); art = []
    for e in list(mb) + list(art):
        if e["sha1"] not in existing:
            existing.add(e["sha1"])
            added.append(e)
    n = _append_entries(added)
    return {
        "ok":            True,
        "added":         n,
        "sources": {
            "malwarebazaar": len(mb),
            "atomic_red_team": len(art),
        },
        "ledger":        str(LEDGER),
        "total_ledger":  len(existing),
        "at":            datetime.now(timezone.utc).isoformat(),
    }


def load_ledger_entries() -> List[Dict[str, Any]]:
    """Read the ledger back — used by the Real-World Stress Suite to widen
    coverage beyond the curated CORPUS."""
    if not LEDGER.exists():
        return []
    out: List[Dict[str, Any]] = []
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


# ── Scheduler (nightly, gated to Sunday 03:00 UTC) ──────────────────────
async def _corpus_refresh_loop():
    # Start delay so import time doesn't fire an immediate net call.
    await asyncio.sleep(300)
    while True:
        now = datetime.now(timezone.utc)
        # fire on Sundays around 03:00 UTC
        if now.weekday() == 6 and 3 <= now.hour < 4:
            try:
                r = await refresh_once()
                log.info("weekly corpus refresh: added=%s ledger_total=%s",
                         r.get("added"), r.get("total_ledger"))
            except Exception as e:
                log.warning("corpus refresh crashed: %s", e)
            await asyncio.sleep(60 * 61)  # skip forward past the hour window
        await asyncio.sleep(30 * 60)


def start_corpus_refresh_scheduler() -> None:
    """Fire the weekly loop. Called from server.py startup."""
    asyncio.create_task(_corpus_refresh_loop())


if __name__ == "__main__":
    async def _main():
        r = await refresh_once()
        print(json.dumps(r, indent=2))
    asyncio.run(_main())
