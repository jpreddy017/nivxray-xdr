"""Regression test: the exact user-reported Cobalt-Strike / Meterpreter stager.

Locks the recursive decode-and-route chain for the real-world payload:

    outer base64  →  gzip  →  extract nested $var_code base64  →  base64-decode
       →  xor(0x23)  →  x86 Metasploit reverse_tcp shellcode

If ANY step regresses, this test breaks and we know before shipping.
"""
import base64
import gzip
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401 — register op registry
from magic_decoder import magic_decode
from command_analyzer import analyze_command
from shellcode_analyzer import analyze as shellcode_analyze


# ----- fixtures ------------------------------------------------------------ #

def _sample_path() -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures",
                        "meterpreter_gzip_xor_stager.txt")


def _load_sample() -> str:
    with open(_sample_path()) as f:
        return f.read().strip()


def _outer_b64(text: str) -> str:
    m = re.search(r'FromBase64String\("([^"]+)"\)', text)
    assert m, "outer FromBase64String literal missing"
    return m.group(1)


def _expected_shellcode() -> bytes:
    """Reproduce the ground-truth shellcode bytes without going through the
    decoder — used to assert the pipeline recovers *exactly* the same bytes."""
    text = _load_sample()
    outer = base64.b64decode(_outer_b64(text))
    plain = gzip.decompress(outer).decode("utf-8", errors="replace")
    inner = re.search(r"FromBase64String\('([^']+)'\)", plain).group(1)
    raw = base64.b64decode(inner)
    return bytes(b ^ 0x23 for b in raw)


# ----- assertions ---------------------------------------------------------- #

def test_ground_truth_matches_metasploit_prologue():
    sc = _expected_shellcode()
    assert sc[:8] == b"\xfc\xe8\x89\x00\x00\x00\x60\x89", \
        f"unexpected shellcode prologue: {sc[:8].hex()}"
    assert len(sc) == 834


def test_magic_decoder_finds_full_chain():
    outer = _outer_b64(_load_sample())
    r = magic_decode(outer, max_depth=6, max_branches=5, top_n=10)
    # Locate a candidate whose chain contains gzip → extract-payload →
    # base64-decode → xor:0x23 in that order.
    def _chain_ops(t):
        return [c.get("op") for c in t.get("chain") or []]
    winner = None
    for t in r["top_results"]:
        ops = _chain_ops(t)
        # Exact 4-op chain — no further decoding beyond the xor step.
        if ops == ["gzip-decompress", "extract-payload",
                   "base64-decode", "xor"] and t.get("is_shellcode"):
            winner = t; break
    assert winner is not None, \
        f"magic decoder did NOT surface the full base64→gzip→b64→xor chain. " \
        f"Top chains: {[_chain_ops(t) for t in r['top_results'][:5]]}"
    # Bytes match
    assert winner.get("output_bytes_len") == 834
    assert winner.get("output_hex", "").startswith("fce889000000")
    assert winner.get("is_shellcode") is True


def test_shellcode_analyzer_extracts_c2_from_recovered_bytes():
    sc = _expected_shellcode()
    r = shellcode_analyze(sc, arch="x86")
    assert r["arch"] == "x86"
    assert r["is_shellcode"] is True
    # First insn must be `cld`, second `call` (Metasploit PEB walker prologue)
    assert r["disassembly"][0]["op"] == "cld"
    assert r["disassembly"][1]["op"] == "call"
    # C2 IP present in extracted strings (real IOC — 149.28.81.19)
    all_strings = "\n".join(r["iocs"]["strings_top"])
    assert "149.28.81.19" in r["iocs"]["ips"] or "149.28.81.19" in all_strings, \
        f"C2 IP 149.28.81.19 missing from IOC extraction. IPs: {r['iocs']['ips']}"


def test_command_analyzer_end_to_end():
    r = analyze_command(_load_sample())
    # Outer FromBase64String should be identified & auto-decoded
    assert any(p["role"] == "[Convert]::FromBase64String argument"
               and p["confidence"] >= 0.90 and p["auto_decoded"]
               for p in r["identified_payloads"])
    # There must be at least one decode chain that ends EITHER on the loader
    # script (`func_get_proc_address` text) OR on the terminal MSFvenom
    # shellcode (`\xfc\xe8` prologue) — both are valid outcomes now that the
    # analyzer peels through nested layers automatically.
    combined = "\n".join(d.get("final_output") or "" for d in r["decode_chains"])
    reached_loader   = "func_get_proc_address" in combined
    reached_shellcode = any(d.get("is_shellcode") for d in r["decode_chains"]) \
                       or combined.encode("latin-1", errors="replace").startswith(b"\xfc\xe8")
    assert reached_loader or reached_shellcode, \
        f"outer base64+gzip did not decode to loader script OR shellcode. combined={combined[:200]!r}"
    # Execution-flow badges should flag IEX (from the outer command)
    labels = [e["label"] for e in r.get("execution_flow") or []]
    assert "Invoke-Expression" in labels
