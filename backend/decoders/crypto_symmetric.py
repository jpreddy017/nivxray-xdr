"""Symmetric-crypto decoder plugins — AES-CBC / AES-ECB / RC4.

Design
------
Encryption ALWAYS needs a key. We follow a three-tier strategy so the
recursive orchestrator can still make useful progress without hand-holding:

1.  **Inline-key auto-recovery** — before giving up we scan the surrounding
    context (previous decoded layers, the raw input, PowerShell / CMD /
    JS variable literals) for a plausible key. Precision-first: only accept
    a candidate that decrypts the payload to ≥ 70 %-printable text.

2.  **Analyst-supplied key** — the manual Chain-Recipe UI passes a `key`
    (and optional `iv`, `mode`) via `args`. This path is deterministic and
    always attempted first.

3.  **KEY REQUIRED emit** — if neither path yields printable output the
    plugin returns the ORIGINAL payload unchanged plus an explanation +
    tradecraft flag so the analyst UI can prompt: "Provide key to decrypt."

Coverage
--------
* `aes-cbc-decrypt`  — AES-128 / AES-192 / AES-256 in CBC + ECB
                        (PKCS7 unpadded). GCM lives in a future patch.
* `rc4-decrypt`      — Classic ARC4 stream cipher.

Why not ChaCha20 yet?  Real-world commodity malware still favours RC4 + AES
by ~10x; ChaCha20 is on the RC3.0 roadmap.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from crypto_hints import (
    extract_key_candidates, extract_iv_candidates, extract_ciphertext_blob,
    detect_encryption_shape,
)
from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    MitreHint,
    PluginResult,
    TradecraftFlag,
)
from engine.registry import DecoderRegistry


# ── Shared helpers ───────────────────────────────────────────────────────
def _b64_or_hex_to_bytes(s: str) -> Optional[bytes]:
    """Return raw bytes for a payload string that could be base64 or hex.

    Falls back to extracting the LONGEST b64/hex blob embedded within a
    wrapper (e.g. `$key="…"; $ct="AAAA…"`) so the plugins never confuse
    the wrapper text for ciphertext.
    """
    stripped = re.sub(r"\s+", "", s or "")
    if not stripped:
        return None
    # First try the whole string as one blob.
    try:
        pad = "=" * (-len(stripped) % 4)
        b = base64.b64decode(stripped + pad, validate=False)
        if b and len(b) >= 16:
            return b
    except (binascii.Error, ValueError):
        pass
    if all(c in "0123456789abcdefABCDEF" for c in stripped) \
            and len(stripped) % 2 == 0 and len(stripped) >= 32:
        try:
            return bytes.fromhex(stripped)
        except ValueError:
            pass
    # Fallback: longest embedded b64/hex blob (handles PS/JS/CMD wrappers).
    return extract_ciphertext_blob(s or "")


def _key_candidates(payload: str, ctx: AnalysisContext,
                     args: Dict[str, Any]) -> List[bytes]:
    """Analyst key (highest priority) + single-artifact regex hints.
    NEVER brute-force. NEVER scan external context."""
    out: List[bytes] = []
    seen: set = set()

    def _push(k):
        if not k:
            return
        if isinstance(k, str):
            k = k.encode()
        if k in seen:
            return
        seen.add(k)
        out.append(k)

    ak = args.get("key") if args else None
    if ak:
        _push(ak)
        if isinstance(ak, str):
            if all(c in "0123456789abcdefABCDEF" for c in ak) and len(ak) % 2 == 0:
                try:
                    _push(bytes.fromhex(ak))
                except ValueError:
                    pass
            try:
                _push(base64.b64decode(ak + "=" * (-len(ak) % 4), validate=False))
            except (binascii.Error, ValueError):
                pass

    for k in extract_key_candidates(payload or ""):
        _push(k)
    return out


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return printable / len(b)


# ═══════════════════════════════════════════════════════════════════════
# RC4 (ARC4) plugin
# ═══════════════════════════════════════════════════════════════════════
class Rc4Decoder(BaseDecoder):
    id = "rc4-decrypt"
    name = "RC4 (ARC4) Decrypt"
    category = "encryption"
    cost = 4                # slower than base64 but still cheap
    tags = ("rc4", "arc4", "stream-cipher", "malware", "loader")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        # Payload must decode to at least 16 bytes of high-entropy data.
        raw = _b64_or_hex_to_bytes(payload)
        if raw is None or len(raw) < 16:
            return DetectResult(confidence=0.0, why="Payload doesn't decode to ≥16 raw bytes")
        # Entropy check on the EXTRACTED ciphertext blob (not the wrapper).
        from crypto_hints import _entropy as _ent
        ent = _ent(raw)
        if ent < 5.5:
            return DetectResult(confidence=0.0,
                                why=f"Ciphertext-blob entropy {ent:.2f} < 5.5 — not RC4-shaped")
        # A key candidate must be discoverable OR analyst-supplied.
        cands = _key_candidates(payload, ctx, {})
        if not cands:
            # We still emit a "KEY REQUIRED" ghost result via detect at low
            # confidence — the orchestrator won't select us but the analyst
            # UI can surface the hint from the trace.
            return DetectResult(
                confidence=0.20,
                why=("High-entropy blob; no inline key hint found — "
                     "supply a key via Chain-Recipe args to decrypt."),
                args={"needs_key": True, "raw_len": len(raw)},
            )
        return DetectResult(
            confidence=0.75,
            why=(f"High-entropy {len(raw)}B blob + {len(cands)} inline key hint(s)"),
            args={"needs_key": False, "raw_len": len(raw)},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        raw = _b64_or_hex_to_bytes(payload)
        if raw is None:
            return PluginResult(output=payload, notes=["rc4: payload isn't b64/hex — skipped"])

        for key in _key_candidates(payload, ctx, args or {}):
            if not key or len(key) < 1 or len(key) > 256:
                continue
            try:
                cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
                dec = cipher.decryptor()
                plain = dec.update(raw) + dec.finalize()
            except Exception:
                continue
            if _printable_ratio(plain) >= 0.70:
                # UTF-8 decode with replace so binary blobs still surface.
                text = plain.decode("utf-8", errors="replace")
                return PluginResult(
                    output=text,
                    notes=[f"RC4 decrypted with key {key[:16]!r}"
                           + ("…" if len(key) > 16 else "")],
                    mitre_hints=[
                        MitreHint(id="T1027", technique="Obfuscated Files or Information",
                                  tactic="Defense Evasion",
                                  evidence=f"RC4 encryption with recovered key",
                                  source="heuristic"),
                        MitreHint(id="T1140", technique="Deobfuscate/Decode Files or Information",
                                  tactic="Defense Evasion",
                                  evidence="RC4 stream cipher",
                                  source="heuristic"),
                    ],
                    tradecraft=[TradecraftFlag(
                        flag="rc4-encryption-recovered",
                        severity="high",
                        evidence=f"{len(raw)}B ciphertext, key {len(key)}B, "
                                  f"plaintext printable {_printable_ratio(plain):.0%}",
                    )],
                    explanation=(
                        "Decrypted an RC4 (ARC4) ciphertext by recovering the "
                        "key from adjacent context. RC4 is a common choice in "
                        "commodity loaders (Emotet stager, RemcosRAT config, "
                        "cheap crypters) because it's one-line to implement."
                    ),
                )
        # No key worked — return original + KEY REQUIRED tradecraft.
        return PluginResult(
            output=payload,
            notes=["rc4: no viable key — analyst input required"],
            tradecraft=[TradecraftFlag(
                flag="rc4-key-required",
                severity="medium",
                evidence=(f"High-entropy {len(raw)}B blob resembles an RC4 "
                          "ciphertext; provide a key via Chain-Recipe "
                          "args (`key=…`) to decrypt."),
            )],
            explanation=("RC4 detector fired but no key hint could be "
                          "recovered from surrounding context. Retry with "
                          "an analyst-supplied key."),
        )


# ═══════════════════════════════════════════════════════════════════════
# AES-CBC + AES-ECB plugin
# ═══════════════════════════════════════════════════════════════════════
class AesCbcDecoder(BaseDecoder):
    id = "aes-cbc-decrypt"
    name = "AES-CBC / AES-ECB Decrypt"
    category = "encryption"
    cost = 5
    tags = ("aes", "cbc", "ecb", "malware", "loader", "encryption")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        raw = _b64_or_hex_to_bytes(payload)
        # AES block size is 16; require at least 2 full blocks.
        if raw is None or len(raw) < 32 or len(raw) % 16 != 0:
            return DetectResult(
                confidence=0.0,
                why=("AES needs ≥32B, block-aligned ciphertext "
                     f"(got {len(raw) if raw else 0}B)"),
            )
        if fp.entropy < 6.5:
            # fp.entropy is computed on the WHOLE payload — when the
            # ciphertext is embedded inside a wrapper (`$key=...; $ct="…"`)
            # the wrapper text drags entropy down. Re-check on the
            # extracted ciphertext blob before rejecting.
            from crypto_hints import _entropy as _ent
            blob_ent = _ent(raw)
            if blob_ent < 6.0:
                return DetectResult(
                    confidence=0.0,
                    why=f"Ciphertext-blob entropy {blob_ent:.2f} < 6.0 — not AES-shaped",
                )
        cands = _key_candidates(payload, ctx, {})
        # Also try IV recovery from context.
        iv_hits = extract_iv_candidates(payload or "")
        if not cands:
            return DetectResult(
                confidence=0.20,
                why=("Block-aligned high-entropy blob; no inline key hint — "
                     "supply key (and optional IV) via Chain-Recipe args."),
                args={"needs_key": True, "raw_len": len(raw),
                      "iv_hints": len(iv_hits)},
            )
        return DetectResult(
            confidence=0.72,
            why=(f"Block-aligned {len(raw)}B blob + {len(cands)} key hint(s)"
                  + (f" + {len(iv_hits)} IV hint(s)" if iv_hits else "")),
            args={"needs_key": False, "raw_len": len(raw),
                   "iv_hints": len(iv_hits)},
        )

    def _try_iv_candidates(self, payload: str,
                            analyst_iv: Optional[str]) -> Iterable[bytes]:
        # Priority: analyst → context regex → zero IV → first-block-of-ciphertext.
        seen: set = set()

        def _emit(iv):
            if not iv:
                return
            if isinstance(iv, str):
                iv = iv.encode()
            if len(iv) == 16 and iv not in seen:
                seen.add(iv)
                yield iv

        if analyst_iv:
            yield from _emit(analyst_iv)
            # try hex
            if isinstance(analyst_iv, str) and all(
                    c in "0123456789abcdefABCDEF" for c in analyst_iv) \
                    and len(analyst_iv) % 2 == 0:
                try:
                    yield from _emit(bytes.fromhex(analyst_iv))
                except ValueError:
                    pass
        for iv_bytes in extract_iv_candidates(payload or ""):
            yield from _emit(iv_bytes)
        yield from _emit(b"\x00" * 16)

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        raw = _b64_or_hex_to_bytes(payload)
        if raw is None:
            return PluginResult(output=payload,
                                notes=["aes: payload isn't b64/hex — skipped"])
        analyst_iv = (args or {}).get("iv")
        analyst_mode = ((args or {}).get("mode") or "").upper()

        def _unpad(b: bytes) -> bytes:
            if not b or len(b) % 16 != 0:
                return b
            pad = b[-1]
            if 1 <= pad <= 16 and b[-pad:] == bytes([pad]) * pad:
                return b[:-pad]
            return b

        best: Optional[Tuple[bytes, str, bytes]] = None    # (plain, mode, key)
        for key in _key_candidates(payload, ctx, args or {}):
            if len(key) not in (16, 24, 32):
                # Also accept hex-encoded 32/48/64-char keys.
                if isinstance(key, bytes) and \
                        all(c in b"0123456789abcdefABCDEF" for c in key) \
                        and len(key) in (32, 48, 64):
                    try:
                        key = bytes.fromhex(key.decode())
                    except ValueError:
                        continue
                else:
                    continue
            # Try CBC first (with each candidate IV), then ECB.
            candidates_mode = ["CBC", "ECB"] if not analyst_mode else [analyst_mode]
            for mode_name in candidates_mode:
                if mode_name == "CBC":
                    for iv in self._try_iv_candidates(payload, analyst_iv):
                        try:
                            cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                                             backend=default_backend())
                            dec = cipher.decryptor()
                            plain = _unpad(dec.update(raw) + dec.finalize())
                        except Exception:
                            continue
                        if _printable_ratio(plain) >= 0.70:
                            best = (plain, f"AES-{len(key)*8}-CBC · IV {iv.hex()[:8]}…", key)
                            break
                    if best:
                        break
                elif mode_name == "ECB":
                    try:
                        cipher = Cipher(algorithms.AES(key), modes.ECB(),
                                         backend=default_backend())
                        dec = cipher.decryptor()
                        plain = _unpad(dec.update(raw) + dec.finalize())
                    except Exception:
                        continue
                    if _printable_ratio(plain) >= 0.70:
                        best = (plain, f"AES-{len(key)*8}-ECB", key)
                        break
            if best:
                break

        if best:
            plain, mode_desc, key = best
            text = plain.decode("utf-8", errors="replace")
            return PluginResult(
                output=text,
                notes=[f"{mode_desc} decrypted with {len(key)}B key"],
                mitre_hints=[
                    MitreHint(id="T1027", technique="Obfuscated Files or Information",
                              tactic="Defense Evasion",
                              evidence=f"{mode_desc} encryption recovered",
                              source="heuristic"),
                    MitreHint(id="T1140", technique="Deobfuscate/Decode Files or Information",
                              tactic="Defense Evasion",
                              evidence=f"{mode_desc}", source="heuristic"),
                ],
                tradecraft=[TradecraftFlag(
                    flag="aes-encryption-recovered",
                    severity="high",
                    evidence=(f"{len(raw)}B ciphertext, key {len(key)}B, "
                               f"printable {_printable_ratio(plain):.0%}"),
                )],
                explanation=(
                    f"Decrypted an {mode_desc} ciphertext by recovering the "
                    "key + IV from adjacent context (or an analyst-supplied "
                    "key via Chain-Recipe args). AES is common in commercial "
                    "crypters, .NET malware, and PowerShell loaders."
                ),
            )

        return PluginResult(
            output=payload,
            notes=["aes: no key/mode combo yielded printable plaintext"],
            tradecraft=[TradecraftFlag(
                flag="aes-key-required",
                severity="medium",
                evidence=(f"Block-aligned {len(raw)}B blob; no inline key "
                          "recovered. Provide `key` (and optional `iv`/`mode`) "
                          "via Chain-Recipe args to decrypt."),
            )],
            explanation=("AES detector fired but no recoverable key produced "
                          "printable output. Retry with analyst-supplied key."),
        )


DecoderRegistry.register(Rc4Decoder())
DecoderRegistry.register(AesCbcDecoder())


# ═══════════════════════════════════════════════════════════════════════
# crypto-detect — lightweight structural detector (no decryption).
# Fires WHENEVER a payload looks like a ciphertext, even if we can't
# recover a key. Emits a KEY REQUIRED tradecraft flag + explanation so
# the analyst UI can prompt for a key without the analyst having to
# manually notice "hey this blob is suspicious".
# ═══════════════════════════════════════════════════════════════════════
class CryptoDetectDecoder(BaseDecoder):
    id = "crypto-detect"
    name = "Ciphertext Shape Detector"
    category = "intelligence"       # signal-only, no data transform
    cost = 1
    tags = ("crypto", "aes", "rc4", "detector", "no-decrypt")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        shape = detect_encryption_shape(payload or "")
        if not shape:
            return DetectResult(confidence=0.0, why="No ciphertext shape")
        # We fire at LOW confidence because we don't actually decode anything.
        # The orchestrator's intelligence pass surfaces the tradecraft/hint
        # even at low confidence; decoder chaining is unaffected.
        return DetectResult(
            confidence=0.30,
            why=shape["why"],
            args=shape,
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        shape = args or detect_encryption_shape(payload or "") or {}
        algos = shape.get("algorithms") or ["unknown"]
        byte_len = shape.get("byte_len", 0)
        # Try to recover a key from the same artifact — if found we do NOT
        # emit KEY REQUIRED (the AES / RC4 decoder plugin will do the work
        # in the same layer).
        keys_found = len(extract_key_candidates(payload or ""))
        ivs_found = len(extract_iv_candidates(payload or ""))
        need_msg = []
        if keys_found == 0:
            need_msg.append("key")
        if "AES-CBC/ECB" in algos and ivs_found == 0:
            need_msg.append("iv (16 bytes, for CBC only)")
        needs = ", ".join(need_msg) if need_msg else "(all inputs present)"
        # Pass-through the payload; this decoder is signal-only.
        note = (f"Ciphertext shape: {'/'.join(algos)} · {byte_len}B · "
                f"entropy {shape.get('entropy', '?')} · needs: {needs}")
        result = PluginResult(
            output=payload,
            notes=[note],
        )
        if keys_found == 0:
            result.tradecraft.append(TradecraftFlag(
                flag="crypto-key-required",
                severity="medium",
                evidence=(f"{'/'.join(algos)} ciphertext ({byte_len}B) "
                          f"detected, but no inline key literal was found "
                          f"in the same artifact. Provide `key` "
                          + ("(+ optional `iv`) " if "AES-CBC/ECB" in algos else "")
                          + "via Chain-Recipe args to decrypt."),
            ))
            result.mitre_hints.append(MitreHint(
                id="T1027.013",
                technique="Encrypted/Encoded File",
                tactic="Defense Evasion",
                evidence=f"{'/'.join(algos)} ciphertext detected without inline key",
                source="heuristic",
            ))
        result.explanation = (
            "Structural ciphertext detector — flags encrypted blobs so the "
            "analyst can supply a key without manually eyeballing entropy. "
            "This step never decrypts."
        )
        return result


DecoderRegistry.register(CryptoDetectDecoder())
