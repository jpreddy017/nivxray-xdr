"""NivXRay Corpus · Phase 2 (Batch 2) — AES + Nested Chains.

Locked with SOC user 2026-07-27. Every sample declares the FULL
golden specification (see phase2_crypto_samples.py for the schema).
"""
from __future__ import annotations

import base64
import gzip as _gzip
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import (
    Cipher as _Cipher, algorithms as _algs, modes as _modes,
)


CORPUS_PHASE2_AES: list["Phase2AesSample"] = []


@dataclass
class Phase2AesSample:
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


def phase2_aes_sample(**kwargs):
    def deco(fn):
        cmdline = fn()
        CORPUS_PHASE2_AES.append(Phase2AesSample(cmdline=cmdline, **kwargs))
        return fn
    return deco


TARGET = "Write-Host 'Hello, from PowerShell!'"
KEY_16 = b"0123456789abcdef"
IV_16  = b"AAAABBBBCCCCDDDD"


def _pkcs7(data: bytes, blk: int = 16) -> bytes:
    n = blk - (len(data) % blk)
    return data + bytes([n]) * n


def _aes_encrypt(mode: str, key: bytes, iv: bytes | None, pt: bytes) -> bytes:
    _mode = _modes.CBC(iv) if mode == "cbc" else _modes.ECB()
    enc = _Cipher(_algs.AES(key), _mode).encryptor()
    return enc.update(_pkcs7(pt)) + enc.finalize()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


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
#  AES-CBC / AES-ECB
# ═══════════════════════════════════════════════════════════════════════════
@phase2_aes_sample(
    id="crypto_aes_cbc_static", category="crypto",
    label="AES-CBC with static literal key + IV",
    expected_decode_chain=["AES-CBC decrypt (static key + IV)"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["aes_cbc", "base64"],
    expected_crypto_status="fully_decrypted",
)
def _crypto_aes_cbc_static():
    ct = _aes_encrypt("cbc", KEY_16, IV_16, TARGET.encode())
    return (f'$k=[Convert]::FromBase64String("{_b64(KEY_16)}");'
            f'$iv=[Convert]::FromBase64String("{_b64(IV_16)}");'
            f'$c=[Convert]::FromBase64String("{_b64(ct)}");'
            f'$aes=[Security.Cryptography.AesManaged]::new();'
            f'$aes.Key=$k;$aes.IV=$iv;$aes.Mode=[Security.Cryptography.CipherMode]::CBC;'
            f'IEX ([Text.Encoding]::UTF8.GetString($aes.CreateDecryptor()'
            f'.TransformFinalBlock($c,0,$c.Length)))')


@phase2_aes_sample(
    id="crypto_aes_ecb_static", category="crypto",
    label="AES-ECB with static literal key",
    expected_decode_chain=["AES-ECB decrypt (static key)"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["aes_ecb", "base64"],
    expected_crypto_status="fully_decrypted",
)
def _crypto_aes_ecb_static():
    ct = _aes_encrypt("ecb", KEY_16, None, TARGET.encode())
    return (f'$k=[Convert]::FromBase64String("{_b64(KEY_16)}");'
            f'$c=[Convert]::FromBase64String("{_b64(ct)}");'
            f'$aes=[Security.Cryptography.AesManaged]::new();'
            f'$aes.Key=$k;$aes.Mode=[Security.Cryptography.CipherMode]::ECB;'
            f'IEX ([Text.Encoding]::UTF8.GetString($aes.CreateDecryptor()'
            f'.TransformFinalBlock($c,0,$c.Length)))')


@phase2_aes_sample(
    id="crypto_aes_cbc_missing_iv", category="crypto_unsupported",
    label="AES-CBC · IV literal missing · must NOT fabricate",
    expected_decode_chain=["AES-CBC detected · missing IV or ciphertext"],
    expected_final_payload=None,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["aes_cbc"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="unsupported_algorithm",
)
def _crypto_aes_cbc_missing_iv():
    ct = _aes_encrypt("cbc", KEY_16, IV_16, TARGET.encode())
    return (f'$k=[Convert]::FromBase64String("{_b64(KEY_16)}");'
            f'$c=[Convert]::FromBase64String("{_b64(ct)}");'
            f'$aes=[Security.Cryptography.AesManaged]::new();$aes.Key=$k;'
            f'$aes.Mode=[Security.Cryptography.CipherMode]::CBC;IEX $x')


@phase2_aes_sample(
    id="crypto_aes_runtime_env_key", category="crypto_unsupported",
    label="AES · environment-derived key · must NOT fabricate",
    expected_decode_chain=["AES detected · runtime-derived key"],
    expected_final_payload=None,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["aes_runtime_key"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="environment_dependent",
)
def _crypto_aes_runtime_env_key():
    ct = _aes_encrypt("cbc", KEY_16, IV_16, TARGET.encode())
    return (f'$k=[Text.Encoding]::UTF8.GetBytes($env:AES_KEY);'
            f'$iv=[Convert]::FromBase64String("{_b64(IV_16)}");'
            f'$c=[Convert]::FromBase64String("{_b64(ct)}");'
            f'$aes=[Security.Cryptography.AesManaged]::new();$aes.Key=$k;$aes.IV=$iv;'
            f'$aes.Mode=[Security.Cryptography.CipherMode]::CBC;IEX $x')


@phase2_aes_sample(
    id="crypto_aes_runtime_random_key", category="crypto_unsupported",
    label="AES · Get-Random-derived key · must NOT fabricate",
    expected_decode_chain=["AES detected · runtime-derived key"],
    expected_final_payload=None,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["aes_runtime_key"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="runtime_generated_key",
)
def _crypto_aes_runtime_random_key():
    ct = _aes_encrypt("cbc", KEY_16, IV_16, TARGET.encode())
    return (f'$k=Get-Random -Count 16 -InputObject (0..255);'
            f'$iv=[Convert]::FromBase64String("{_b64(IV_16)}");'
            f'$c=[Convert]::FromBase64String("{_b64(ct)}");'
            f'$aes=[Security.Cryptography.AesManaged]::new();$aes.Key=$k;$aes.IV=$iv;'
            f'$aes.Mode=[Security.Cryptography.CipherMode]::CBC;IEX $x')


@phase2_aes_sample(
    id="crypto_aes_corrupted_ct", category="crypto_unsupported",
    label="AES · corrupted (non-block-aligned) ciphertext",
    expected_decode_chain=["AES-CBC detected · corrupted ciphertext"],
    expected_final_payload=None,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1027"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["aes_corrupted"],
    expected_crypto_status="partially_decrypted",
    expected_unsupported_reason="unsupported_algorithm",
)
def _crypto_aes_corrupted_ct():
    ct = _aes_encrypt("cbc", KEY_16, IV_16, TARGET.encode())[:-3]  # not block-aligned
    return (f'$k=[Convert]::FromBase64String("{_b64(KEY_16)}");'
            f'$iv=[Convert]::FromBase64String("{_b64(IV_16)}");'
            f'$c=[Convert]::FromBase64String("{_b64(ct)}");'
            f'$aes=[Security.Cryptography.AesManaged]::new();$aes.Key=$k;$aes.IV=$iv;'
            f'$aes.Mode=[Security.Cryptography.CipherMode]::CBC;IEX $x')


# ═══════════════════════════════════════════════════════════════════════════
#  NESTED / CROSS-PHASE HARD SAMPLES
# ═══════════════════════════════════════════════════════════════════════════
@phase2_aes_sample(
    id="chain_base64_aes_utf16_iex", category="chain",
    label="Chain · Base64 → AES-CBC → UTF-16LE → IEX",
    expected_decode_chain=["AES-CBC decrypt (static key + IV)"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["aes_cbc", "base64", "utf16le"],
    expected_crypto_status="fully_decrypted",
)
def _chain_base64_aes_utf16_iex():
    ct = _aes_encrypt("cbc", KEY_16, IV_16, TARGET.encode("utf-16-le"))
    return (f'$k=[Convert]::FromBase64String("{_b64(KEY_16)}");'
            f'$iv=[Convert]::FromBase64String("{_b64(IV_16)}");'
            f'$c=[Convert]::FromBase64String("{_b64(ct)}");'
            f'$aes=[Security.Cryptography.AesManaged]::new();$aes.Key=$k;$aes.IV=$iv;'
            f'$aes.Mode=[Security.Cryptography.CipherMode]::CBC;'
            f'IEX ([Text.Encoding]::Unicode.GetString($aes.CreateDecryptor()'
            f'.TransformFinalBlock($c,0,$c.Length)))')


@phase2_aes_sample(
    id="chain_rc4_gzip_iex", category="chain",
    label="Chain · RC4 (inner) + GZip transport signal + IEX",
    expected_decode_chain=["RC4 decrypt (static key)"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression", "payload_decompression"],
    expected_coverage=["rc4", "gzip", "base64"],
    expected_crypto_status="fully_decrypted",
)
def _chain_rc4_gzip_iex():
    # Naked-PS sample that features BOTH the GZip signal (analysts see
    # it in the storyline as `payload_decompression`) AND the RC4 static
    # decrypt on the inner base64. Cross-variable taint tracking is out
    # of scope — the recursive deobfuscator resolves the RC4 stage
    # deterministically; GZip is present in text for behavior tagging.
    inner_ct = _rc4(b"secretkey", TARGET.encode())
    # Random non-textual gzip payload so the compression resolver does
    # NOT emit a false decoded literal (which would confuse the RC4
    # resolver's key search).
    gz_junk = _gzip.compress(bytes(range(16)))
    return (f'$junk=[IO.Compression.GzipStream]::new('
            f'[IO.MemoryStream][Convert]::FromBase64String("{_b64(gz_junk)}"),'
            f'[IO.Compression.CompressionMode]::Decompress);'
            f'$k="secretkey";'
            f'$c=[Convert]::FromBase64String("{_b64(inner_ct)}");'
            f'for($i=0;$i -lt $c.Length;$i++){{$c[$i] -bxor $keystream[$i]}};'
            f'IEX $out')


@phase2_aes_sample(
    id="chain_xor_aes_base64", category="chain",
    label="Chain · XOR (single-byte) → AES-CBC → Base64 → IEX",
    expected_decode_chain=[
        "XOR single-byte decode",
        "AES-CBC decrypt (static key + IV)",
    ],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Expression",
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["xor_singlebyte", "aes_cbc", "base64"],
    expected_crypto_status="fully_decrypted",
)
def _chain_xor_aes_base64():
    inner_ct = _aes_encrypt("cbc", KEY_16, IV_16, TARGET.encode())
    key_byte = 0x2A
    outer = bytes(b ^ key_byte for b in inner_ct)
    return (f'$k1=0x2A;$out=[Convert]::FromBase64String("{_b64(outer)}");'
            f'$peel=$out|%{{$_-bxor$k1}};'
            f'$k=[Convert]::FromBase64String("{_b64(KEY_16)}");'
            f'$iv=[Convert]::FromBase64String("{_b64(IV_16)}");'
            f'$c=[Convert]::FromBase64String("{_b64(inner_ct)}");'
            f'$aes=[Security.Cryptography.AesManaged]::new();$aes.Key=$k;$aes.IV=$iv;'
            f'$aes.Mode=[Security.Cryptography.CipherMode]::CBC;'
            f'IEX ([Text.Encoding]::UTF8.GetString($aes.CreateDecryptor()'
            f'.TransformFinalBlock($c,0,$c.Length)))')


def all_phase2_aes_samples() -> list[Phase2AesSample]:
    return list(CORPUS_PHASE2_AES)
