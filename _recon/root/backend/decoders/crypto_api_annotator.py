"""RC4.1 · Crypto API annotator (Feb 2026).

Scans the input for cryptographic API usage patterns and emits deterministic
annotations. This is the "honest verdict" layer — when static recovery cannot
proceed because a cipher requires runtime primitives or an environment-derived
key, the annotator surfaces WHICH algorithm and WHY.

Patterns surfaced:
    · AES-CBC          (Aes.Create + Key + IV + Mode='CBC')
    · AES-GCM          (AesGcm + Decrypt)
    · ChaCha20         (ChaCha20Poly1305)
    · RijndaelManaged  (System.Security.Cryptography.RijndaelManaged)
    · RC4              (0..255 loop + KSA + PRGA + -bxor)
    · DES / 3DES       (DESCryptoServiceProvider, TripleDESCryptoServiceProvider)
    · DPAPI            (ProtectedData.Unprotect)
    · OpenSSL          (openssl enc -aes-256-cbc, -rc4, -chacha20)
    · GPG              (gpg --decrypt, gpg2)
    · MachineGuid key  (HKLM:\\SOFTWARE\\Microsoft\\Cryptography + MachineGuid)
    · C2-fetched key   (DownloadString(...) + Aes.Key = ...)

Each detection is registered as a `crypto-api-annotator` op result containing:
    output      — original payload (identity transform)
    notes       — one-line human summary per algorithm detected
    algorithm   — list of detected algorithm identifiers
    key_source  — inline | dpapi | machineguid | c2-derived | runtime
    recovery    — "static-complete" | "runtime-required"
    mitre_hints — MITRE ATT&CK sub-technique IDs
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from operations import op


# ── Algorithm signatures — case-insensitive multi-token match ──────────────
_SIGS = [
    # (algorithm, [required tokens...], key_source, recovery, mitre)
    ("AES-CBC",              ["aes", "createdecryptor", "mode"],       "inline", "runtime-required", ["T1027", "T1140"]),
    ("AES-CBC",              ["aes.create()", "$aes.mode"],             "inline", "runtime-required", ["T1027", "T1140"]),
    ("AES-CBC",              ["aes]::create", "mode ="],                "inline", "runtime-required", ["T1027", "T1140"]),
    ("AES-CBC",              ["[system.security.cryptography.aes]::create"], "inline", "runtime-required", ["T1027", "T1140"]),
    ("AES-GCM",              ["aesgcm", "decrypt"],                     "inline", "runtime-required", ["T1027", "T1140"]),
    ("AES-GCM",              ["aesgcm]::new"],                          "inline", "runtime-required", ["T1027", "T1140"]),
    ("ChaCha20-Poly1305",    ["chacha20poly1305"],                      "inline", "runtime-required", ["T1027", "T1140"]),
    ("ChaCha20",             ["openssl", "chacha20"],                   "inline", "runtime-required", ["T1027", "T1140"]),
    ("RijndaelManaged",      ["rijndaelmanaged"],                       "inline", "runtime-required", ["T1027", "T1140"]),
    ("DES",                  ["descryptoserviceprovider"],              "inline", "runtime-required", ["T1027", "T1140"]),
    ("3DES",                 ["tripledescryptoserviceprovider"],        "inline", "runtime-required", ["T1027", "T1140"]),
    ("3DES",                 ["openssl", "des3"],                       "inline", "runtime-required", ["T1027", "T1140"]),
    ("RC4",                  ["0..255", "-bxor"],                       "inline", "static-complete",  ["T1027", "T1140"]),
    ("RC4",                  ["0..255", "$s[", "-bxor"],                "inline", "static-complete",  ["T1027", "T1140"]),
    ("RC4",                  ["openssl", "-rc4"],                       "inline", "runtime-required", ["T1027", "T1140"]),
    ("DPAPI",                ["protecteddata]::unprotect"],             "dpapi",   "runtime-required", ["T1140", "T1555.003"]),
    ("DPAPI",                ["protecteddata", "unprotect"],            "dpapi",   "runtime-required", ["T1140", "T1555.003"]),
    ("OpenSSL:AES-CBC",      ["openssl", "aes-", "cbc"],                "inline", "runtime-required", ["T1027", "T1140"]),
    ("OpenSSL:AES-CBC",      ["openssl", "enc", "aes-256-cbc"],         "inline", "runtime-required", ["T1027", "T1140"]),
    ("GPG-symmetric",        ["gpg", "--decrypt"],                      "inline", "runtime-required", ["T1140", "T1027.006"]),
    ("GPG-symmetric",        ["gpg", "-d"],                             "inline", "runtime-required", ["T1140", "T1027.006"]),
    ("GPG-symmetric",        ["gpg2", "--decrypt"],                     "inline", "runtime-required", ["T1140", "T1027.006"]),
    ("MachineGuid-derived",  ["hklm", "microsoft", "cryptography", "machineguid"], "env-derived", "runtime-required", ["T1082", "T1140"]),
    ("C2-fetched-key",       ["downloadstring", "$key"],                 "c2-derived", "runtime-required", ["T1071.001", "T1140"]),
    ("C2-fetched-key",       ["downloadstring", "aes.key"],              "c2-derived", "runtime-required", ["T1071.001", "T1140"]),
    # Direct algorithm-word mentions — for stubs / comments where the crypto
    # loop isn't inlined but the analyst has annotated the algorithm.
    ("RC4",                  [" rc4"],                                    "inline", "static-complete",  ["T1027", "T1140"]),
    ("RC4",                  ["rc4 with"],                                "inline", "static-complete",  ["T1027", "T1140"]),
    ("XOR-multi-inline",     ["[byte[]]", "-bxor", "$k[$i"],             "inline", "static-complete",  ["T1027", "T1140"]),
]


def _find_all(low: str) -> List[Dict[str, Any]]:
    """Return de-duplicated list of matched algorithm hits."""
    seen: Set[str] = set()
    hits: List[Dict[str, Any]] = []
    for algo, tokens, ksrc, recovery, mitre in _SIGS:
        if all(t in low for t in tokens) and algo not in seen:
            seen.add(algo)
            hits.append({
                "algorithm": algo,
                "key_source": ksrc,
                "recovery":   recovery,
                "mitre":      list(mitre),
                "why":        " + ".join(f"`{t}`" for t in tokens),
            })
    return hits


@op("crypto-api-annotator",
    "Detect crypto API usage patterns",
    "Cryptography / Annotations",
    "Scans the input for cryptographic API signatures (AES, RC4, ChaCha20, "
    "RijndaelManaged, DES, 3DES, DPAPI, OpenSSL, GPG, MachineGuid-derived, "
    "C2-fetched keys). Emits an identity-transform result whose notes and "
    "MITRE hints surface every detected algorithm — used by the honest-verdict "
    "layer to distinguish 'decode failed' from 'static recovery complete · "
    "runtime decryption required'.")
def op_crypto_api_annotator(data: str, args: Dict[str, Any] | None = None) -> str:
    if not data:
        return data
    low = data.lower()
    hits = _find_all(low)
    if not hits:
        return data
    header = "▼ CRYPTO API DETECTED (RC4.1 · honest-verdict)\n"
    lines = [header]
    for h in hits:
        lines.append(f"  · {h['algorithm']:<24} key_source={h['key_source']} "
                     f"recovery={h['recovery']}  ({h['why']})")
    lines.append("")
    lines.append("Note: When key_source ∈ {dpapi, c2-derived, env-derived} the")
    lines.append("      corresponding decryption stage requires runtime execution")
    lines.append("      or emulation — this is a malware-design limitation, not")
    lines.append("      a decoder capability gap.")
    lines.append("")
    return "\n".join(lines) + "\n" + data
