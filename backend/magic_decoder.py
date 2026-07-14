"""NivXRay — "Magic" recursive auto-decoder (CyberChef-parity).

Given a payload, tries every plausible decode operation, scores the output,
and recursively expands the best branches. Returns the top-N final results
sorted by score, plus the ordered recipe that produced each.

Scoring heuristics combine:
  - printable-ASCII ratio       (0-1)  — reward readable text
  - english-word density        (0-1)  — reward real words in the output
  - structure signatures        (bonus)  — JSON/HTML/URL/PS keywords/PE header/hex/utf-16
  - length sanity               (0-1)  — punish very short or absurdly long output
  - obfuscation entropy penalty (0-1)  — penalize very high entropy (still encrypted/random)

Time-boxed: max_depth (default 4) × max_branches (default 3), fully synchronous
and finishes in < 400 ms for typical inputs.
"""
from __future__ import annotations
import base64
import binascii
import math
import re
from typing import Any, Dict, List, Optional, Tuple

from operations import run_operation

# Small dictionary of common English words — used for word-density scoring.
_COMMON_WORDS = set("""
the be to of and a in that have i it for not on with he as you do at this but his by from they we
say her she or an will my one all would there their what so up out if about who get which go me
when make can like time no just him know take people into year your good some could them see other
than then now look only come its over think also back after use two how our work first well way
even new want because any these give day most us http https url domain ip ipv4 ipv6 mail email
password user admin login exit exec eval file open close create delete run start stop server client
key token secret cert cred config error debug info true false null void class function return
value string object list array count size length name host port script command process malware
attack exploit payload shellcode backdoor rootkit trojan phish encode decode encrypt decrypt
base64 hex url html json xml powershell bash python microsoft windows linux system network
""".split())

# Signatures that give big scoring bonuses.
_JSON_START = re.compile(r"^\s*[\[{]")
_URL_RE     = re.compile(r"https?://[^\s\"'<>]+")
_PS_KWORDS  = re.compile(r"\b(IEX|Invoke-Expression|Invoke-WebRequest|Net\.WebClient|DownloadString|DownloadFile|Add-MpPreference|New-Object|System\.Reflection|VirtualAlloc|CreateThread)\b", re.IGNORECASE)
_HTML_RE    = re.compile(r"<(?:html|body|script|iframe|div|a\s|meta|link)\b", re.IGNORECASE)
_PE_HEADER  = re.compile(r"^\s*MZ.{50,120}This program (?:cannot|must)", re.DOTALL)
_UTF16_HINT = re.compile(r"(?:[ -~]\x00){10,}")
_HEX_BLOB   = re.compile(r"^[0-9a-fA-F]{20,}$")


# =============================================================================
# Scoring
# =============================================================================
def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq: Dict[int, int] = {}
    for x in b:
        freq[x] = freq.get(x, 0) + 1
    return -sum((c / len(b)) * math.log2(c / len(b)) for c in freq.values())


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    b = s.encode("utf-8", errors="replace")
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return printable / len(b)


def _english_density(s: str) -> float:
    words = re.findall(r"[A-Za-z][A-Za-z']{2,}", s.lower())
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in _COMMON_WORDS)
    return hits / max(len(words), 1)


def _structure_bonus(s: str) -> Tuple[float, List[str]]:
    bonuses: List[str] = []
    total = 0.0
    if _JSON_START.match(s) and s.count("{") + s.count("[") >= 1:
        total += 0.20; bonuses.append("json-shape")
    if _URL_RE.search(s):
        total += 0.20; bonuses.append("url")
    if _PS_KWORDS.search(s):
        total += 0.35; bonuses.append("ps-keywords")
    if _HTML_RE.search(s):
        total += 0.15; bonuses.append("html")
    if _PE_HEADER.match(s):
        total += 0.30; bonuses.append("pe-header")
    if _UTF16_HINT.search(s):
        total += 0.20; bonuses.append("utf16-embedded")
    return total, bonuses


def score_output(s: str) -> Dict[str, Any]:
    """Return a scalar `score` (higher = better) plus a breakdown."""
    if not s:
        return {"score": 0.0, "reasons": ["empty"]}
    if len(s) > 200_000:
        return {"score": 0.0, "reasons": ["output-too-large"]}
    pr = _printable_ratio(s)
    ed = _english_density(s)
    ent = _entropy(s.encode("utf-8", errors="replace"))
    sb, bonuses = _structure_bonus(s)
    # normalize entropy penalty: 3.5-6 = healthy natural text, 6.5+ = likely still-encoded
    ent_penalty = max(0.0, (ent - 6.2) / 2.0)  # 0 at 6.2, ~1 at 8.2
    ent_penalty = min(ent_penalty, 0.35)
    # size sanity — prefer 20 to 20000 chars
    L = len(s)
    if L < 8:
        size_score = 0.1
    elif L > 20000:
        size_score = 0.5
    else:
        size_score = 1.0
    score = (0.30 * pr) + (0.30 * ed) + (0.15 * size_score) + sb - ent_penalty
    reasons = []
    if pr > 0.9: reasons.append(f"printable={pr:.2f}")
    if ed > 0.03: reasons.append(f"english-density={ed:.2f}")
    reasons.extend(bonuses)
    if ent_penalty > 0.05: reasons.append(f"entropy-penalty={ent_penalty:.2f} (entropy={ent:.2f})")
    return {
        "score": round(score, 4),
        "printable": round(pr, 3),
        "english": round(ed, 3),
        "entropy": round(ent, 3),
        "size": L,
        "reasons": reasons,
    }


# =============================================================================
# Candidate op selection
# =============================================================================
# Each candidate returns a list of (op_id, args) tuples to try given the input.
def _pick_candidates(payload: str) -> List[Dict[str, Any]]:
    cands: List[Dict[str, Any]] = []
    s = payload.strip()
    if not s:
        return cands
    # Base64 detection
    b64only = re.sub(r"\s+", "", s)
    is_b64 = b64only and re.fullmatch(r"[A-Za-z0-9+/=_-]+", b64only) and len(b64only) >= 8
    if is_b64:
        cands.append({"op": "base64-decode", "args": {}})
        cands.append({"op": "utf16-be-decode", "args": {}})
        cands.append({"op": "utf32-le-decode", "args": {}})
        # Compression ops accept base64/hex directly — try them speculatively so a
        # base64+gzip / base64+zlib / base64+lzma / base64+bzip2 chain is discovered
        # without relying on magic-byte detection on the (utf-8-replaced) string.
        cands.append({"op": "gzip-decompress", "args": {}})
        cands.append({"op": "zlib-decompress", "args": {}})
        cands.append({"op": "lzma-decompress", "args": {}})
        cands.append({"op": "bzip2-decompress", "args": {}})
        # If the base64 prefix maps to a known signature, prioritise that chain
        try:
            from signatures import match_b64_signature
            sig = match_b64_signature(b64only)
            if sig:
                # Insert the signature chain ops at the FRONT so magic explores them first
                for step_op in reversed(sig["chain"]):
                    cands.insert(0, {"op": step_op, "args": {}})
        except Exception:
            pass
    # UTF-16LE hint — half the bytes are 0x00 in alternating positions
    if _UTF16_HINT.search(s) or "\x00" in s:
        cands.append({"op": "utf16le-decode", "args": {}})
    # Binary magic bytes AFTER a decode step (gzip, zlib, LZMA/XZ, PE)
    if s.startswith("\x1f\x8b"):
        cands.insert(0, {"op": "gzip-decompress", "args": {}})
    if s.startswith("\x78\x9c") or s.startswith("\x78\xda") or s.startswith("\x78\x01"):
        cands.insert(0, {"op": "zlib-decompress", "args": {}})
    if s.startswith("\xfd7zXZ") or s.startswith("\xfd7z\x58\x5a"):
        cands.insert(0, {"op": "lzma-decompress", "args": {}})
    if s.startswith("BZh"):
        cands.insert(0, {"op": "bzip2-decompress", "args": {}})
    # Hex detection (≥ 20 chars, even length). Prepend when the buffer is
    # UNAMBIGUOUSLY hex (only 0-9a-f, no uppercase letters beyond a-f) so it
    # beats base64/utf16 speculation with tight max_branches budgets.
    if _HEX_BLOB.match(b64only) and len(b64only) % 2 == 0:
        # Strictly hex → prioritise; ambiguous (uppercase letters G-Z) is caught
        # by base64 detection above so we don't accidentally down-rank base64.
        if re.fullmatch(r"[0-9a-fA-F]+", b64only):
            cands.insert(0, {"op": "hex-decode", "args": {}})
        else:
            cands.append({"op": "hex-decode", "args": {}})
    # URL-encoded
    if re.search(r"%[0-9A-Fa-f]{2}", s):
        cands.append({"op": "url-decode", "args": {}})
    # HTML entities
    if "&#" in s or re.search(r"&\w+;", s):
        cands.append({"op": "html-decode", "args": {}})
    # ROT13
    if re.fullmatch(r"[A-Za-z\s.,!?\"'\-]{10,}", s):
        cands.append({"op": "rot13", "args": {}})
    # PowerShell -EncodedCommand
    if re.search(r"-e(?:c|nc|ncoded(?:command)?)?\s+[A-Za-z0-9+/=\s]{16,}", s, re.IGNORECASE):
        cands.append({"op": "powershell-encoded", "args": {}})
    # JS charcode
    if "String.fromCharCode" in s:
        cands.append({"op": "js-charcode-decode", "args": {}})
    # JS \x-escapes
    if re.search(r"\\x[0-9a-fA-F]{2}", s):
        cands.append({"op": "js-hex-strings-decode", "args": {}})
    # ASCII85
    if s.startswith("<~") and s.endswith("~>"):
        cands.append({"op": "ascii85-decode", "args": {}})
    # JWT — 3 base64url segments joined by dots
    if re.fullmatch(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*", s):
        cands.insert(0, {"op": "jwt-decode", "args": {}})
    # Refang defanged IOCs
    if re.search(r"hxxps?://|\[\.\]|\[dot\]|\[at\]", s, re.IGNORECASE):
        cands.append({"op": "refang-iocs", "args": {}})
    # Nested FromBase64String / atob('…') payloads — re-scan the CURRENT text
    # for another quoted base64 blob. Common in Cobalt-Strike / Empire stagers
    # where the outer base64 unzips to a script containing a *second* base64.
    try:
        from payload_sanitizer import find_all_base64_spans, find_xor_key
        nested = find_all_base64_spans(s, min_len=24)
        # Only trigger if the current text looks like a script/wrapper (not the
        # payload itself) — avoid infinite base64→base64 loops.
        looks_wrapped = any(m in s for m in (
            "FromBase64String", "atob(", "base64_decode", "-EncodedCommand", "$var_code",
        ))
        if nested and looks_wrapped:
            cands.insert(0, {"op": "extract-payload", "args": {}, "_nested_b64": nested[0]})

        # XOR key parsed directly from surrounding code (-bxor 35, ^ 0x2A, etc.)
        xk = find_xor_key(s)
        if xk is not None:
            cands.insert(0, {"op": "xor", "args": {"key": f"0x{xk:02x}"}})

        # Repeating-key XOR brute — trigger on high-entropy alphanum/base64 or
        # pure-hex buffers that look like ciphertext. Cheap fallback, only
        # explored when the standard chain didn't produce clean text.
        s_ent = _entropy(s.encode("utf-8", errors="replace"))
        if len(s) >= 32 and s_ent >= 4.5 and (
            re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) or
            re.fullmatch(r"[0-9a-fA-F\s]+", s)
        ):
            cands.append({"op": "xor-brute", "args": {"key_len": "auto"}})
    except Exception:
        pass

    # de-dup while preserving order
    seen = set()
    unique: List[Dict[str, Any]] = []
    for c in cands:
        k = c["op"]
        if k in seen:
            continue
        seen.add(k)
        unique.append(c)
    return unique


# =============================================================================
# Recursive search
# =============================================================================
def magic_decode(payload: str, max_depth: int = 4, max_branches: int = 3,
                 min_score_delta: float = 0.05, top_n: int = 3) -> Dict[str, Any]:
    """Return the top-N final decode chains sorted by score.

    Each result: {chain: [{op, args}, ...], output, score_breakdown, path_scores}
    """
    from payload_sanitizer import sanitize_encapsulated_payload

    # THUMB RULE: ISOLATE THE PAYLOAD STRING FIRST — strip script wrappers.
    isolated = sanitize_encapsulated_payload(payload)
    working = isolated if isolated else payload
    isolation_note = None
    if isolated and isolated != payload.strip():
        isolation_note = f"Isolated {len(isolated)}-char base64 payload from script wrapper"

    initial_score = score_output(working)
    best_results: List[Dict[str, Any]] = []

    # Preserve the XOR key from the ORIGINAL wrapper text before isolation
    # strips it — otherwise `powershell $c = FromBase64String("..."); ...
    # -bxor 35` loses the key when the sanitizer collapses down to the
    # bare base64 blob. Seeds ctx so the very first `_walk` iteration can
    # plan the deterministic base64→xor chain.
    _initial_ctx: Dict[str, Any] = {}
    try:
        from payload_sanitizer import find_xor_key as _fxk
        _wrapper_key = _fxk(payload)
        if _wrapper_key is not None:
            _initial_ctx["xor_key"] = _wrapper_key
    except Exception:
        pass

    def _walk(cur: str, chain: List[Dict[str, Any]], depth: int, path_scores: List[float],
              ctx: Dict[str, Any]):
        # Record the current state as a candidate result too — decoding can peak
        # partway through then degrade.
        sb = score_output(cur)
        best_results.append({
            "chain": list(chain),
            "output": cur,
            "score_breakdown": sb,
            "path_scores": list(path_scores) + [sb["score"]],
        })
        if depth >= max_depth:
            return
        # Refresh the XOR key from the current layer, if visible. This lets
        # the key detected inside the decompressed PowerShell body propagate
        # forward into the *next* layer where the base64 → xor chain fires.
        try:
            from payload_sanitizer import find_xor_key
            k = find_xor_key(cur)
            if k is not None:
                ctx = {**ctx, "xor_key": k}
        except Exception:
            pass
        cands = _pick_candidates(cur)[:max_branches]
        # If we're sitting on a clean-base64 buffer AND we've captured a XOR
        # key from a previous layer, plan the deterministic base64 → xor chain.
        if ctx.get("xor_key") is not None:
            b64_only = re.sub(r"\s+", "", cur)
            if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", b64_only) and len(b64_only) >= 12:
                cands.insert(0, {
                    "op": "base64-decode", "args": {},
                    "_then_xor": ctx["xor_key"],
                })
        for c in cands:
            try:
                if c.get("op") == "extract-payload" and "_nested_b64" in c:
                    # Snap the input down to the nested base64 span so subsequent
                    # decoders operate ONLY on the isolated payload — this is
                    # the "re-scan after every layer" rule.
                    nxt = c["_nested_b64"]
                else:
                    nxt = run_operation(c["op"], cur, c["args"])
            except Exception:
                continue
            if not nxt or nxt == cur:
                continue
            nsb = score_output(nxt)
            clean_step = {"op": c["op"], "args": c.get("args") or {}}
            # Deterministic follow-up: base64 → xor(known_key) plan.
            if "_then_xor" in c:
                try:
                    # Do base64+xor on RAW BYTES of the ORIGINAL base64 buffer
                    # (`cur`), not through the UTF-8-corrupted `nxt`. This is
                    # the correct path for CobaltStrike / Metasploit stagers
                    # where the inner payload is x86/x64 shellcode.
                    import base64 as _b64
                    key = c["_then_xor"]
                    b64_str = re.sub(r"\s+", "", cur)
                    raw = _b64.b64decode(b64_str + "=" * (-len(b64_str) % 4),
                                          validate=False)
                    xored_bytes = bytes(b ^ key for b in raw)
                    # Represent as hex so downstream shellcode-magic detection
                    # (\xfc\xe8, \xfc\x48, MZ, etc.) sees real bytes.
                    hex_out = xored_bytes.hex()
                    xsb = score_output(hex_out)
                    step_xor = {"op": "xor", "args": {"key": f"0x{key:02x}"}}
                    best_results.append({
                        "chain": chain + [clean_step, step_xor],
                        "output": xored_bytes.decode("latin-1"),  # 1:1 byte↔codepoint preservation
                        "output_hex": hex_out,
                        "output_bytes_len": len(xored_bytes),
                        "score_breakdown": xsb,
                        "path_scores": list(path_scores) + [sb["score"], xsb["score"]],
                    })
                    # Continue walking from the hex form so a subsequent
                    # candidate can further decode if needed.
                    _walk(hex_out, chain + [clean_step, step_xor],
                          depth + 2, path_scores + [sb["score"], xsb["score"]], ctx)
                    continue
                except Exception:
                    pass
            if nsb["score"] < sb["score"] - 0.30:  # branch massively regressed — prune
                # …unless a XOR key is known — the pruned base64 output is
                # probably XORed bytes we still want to try.
                if ctx.get("xor_key") is None:
                    continue
            _walk(nxt, chain + [clean_step], depth + 1,
                  path_scores + [sb["score"]], ctx)

    _walk(working, [], 0, [], _initial_ctx)

    # Chain-completion bonus — reward outputs that survived multiple decode
    # layers AND are cleanly printable. Applied to every candidate BEFORE the
    # top-N cut so a longer correct chain surfaces above short partial ones.
    # GUARD: skip when the output STILL looks like an encoded blob (pure hex,
    # pure base64) — those chains almost always represent a walker that
    # went one step too far. Otherwise "Cobalt Strike stager" (short readable)
    # gets outranked by a 7-op chain that produced 60 chars of hex.
    #
    # SHELLCODE BOOST: when the output bytes look like x86/x64/ARM shellcode
    # (MSFvenom / Cobalt-Strike stagers), that's a TERMINAL state — no more
    # decoding needed. Boost hard so it beats deeper over-decoded chains.
    #
    # STRICT: only fires when the FIRST bytes match a KNOWN prologue signature
    # (e.g. `fc e8` = cld;call, `fd 7b` = ARM64 stp). Entropy-only is not
    # sufficient — random over-decoded bytes may also have high entropy but
    # they're not real shellcode.
    from shellcode_analyzer import starts_with_known_prologue as _known_prologue
    for r in best_results:
        chain_len = len(r.get("chain") or [])
        pr = r["score_breakdown"].get("printable", 0.0)
        out = (r.get("output") or "").strip()
        still_encoded = bool(
            out and (
                re.fullmatch(r"[0-9a-fA-F]{20,}", out) is not None
                or re.fullmatch(r"[A-Za-z0-9+/]{20,}={0,2}", out) is not None
            )
        )
        if chain_len >= 3 and pr >= 0.95 and not still_encoded:
            r["score_breakdown"]["score"] = round(
                r["score_breakdown"]["score"] + 0.05 * min(chain_len, 6), 4
            )
            r["score_breakdown"]["reasons"] = list(
                r["score_breakdown"].get("reasons") or []
            ) + [f"chain-complete-bonus (+{0.05 * min(chain_len, 6):.2f})"]

        # Shellcode terminal-state boost — the walker should stop here.
        # Only fires when the chain has AT LEAST one decoding op (bare
        # extract-payload doesn't count) so we don't mis-flag inputs that
        # were shellcode to start with. STRICT: known prologue only.
        if chain_len >= 2 and out and len(out) >= 20:
            try:
                raw = out.encode("latin-1") if all(ord(c) < 256 for c in out) \
                                            else out.encode("utf-8", errors="replace")
                if _known_prologue(raw):
                    r["score_breakdown"]["score"] = round(
                        r["score_breakdown"]["score"] + 0.35, 4
                    )
                    r["score_breakdown"]["reasons"] = list(
                        r["score_breakdown"].get("reasons") or []
                    ) + ["shellcode-terminal-state (+0.35)"]
                    r["is_shellcode"] = True
            except Exception:
                pass

    # Deduplicate by (output snippet + chain length) and keep top-N
    seen = set()
    dedup: List[Dict[str, Any]] = []
    for r in sorted(best_results, key=lambda x: -x["score_breakdown"]["score"]):
        k = (r["output"][:200], len(r["chain"]))
        if k in seen:
            continue
        seen.add(k)
        # Prepend the isolation step to every chain so the analyst can see the wrapper strip
        if isolation_note:
            r = {**r, "chain": [{"op": "extract-payload", "args": {}}] + r["chain"]}
        dedup.append(r)
        if len(dedup) >= top_n:
            break

    # Chain-completion bonus — reward outputs that survived multiple decode
    # layers AND are cleanly printable. This surfaces the correct fully-decoded
    # chain (base64→gzip→base64→xor) above intermediate stopping points.
    for r in dedup:
        pass
    dedup.sort(key=lambda r: -r["score_breakdown"]["score"])

    # Annotate the top-N with the shellcode stop-condition — flags outputs that
    # should be routed to the disassembler view instead of another decode layer.
    try:
        from shellcode_analyzer import shannon_entropy, is_shellcode
        for r in dedup:
            out = r.get("output") or ""
            # For byte-preserving chains (base64→xor compound), use latin-1
            # roundtrip which is 1:1 codepoint↔byte. Fall back to utf-8 for
            # normal text outputs.
            try:
                raw = out.encode("latin-1") if all(ord(c) < 256 for c in out) \
                                            else out.encode("utf-8", errors="replace")
            except Exception:
                raw = out.encode("utf-8", errors="replace")
            ent = shannon_entropy(raw)
            r["entropy"] = round(ent, 3)
            r["is_shellcode"] = is_shellcode(raw)
            if r["is_shellcode"]:
                r["stop_condition"] = {
                    "reason": "high_entropy_no_encoding_markers"
                              if not raw[:2] in (b"\xfc\xe8", b"\xfc\xeb", b"\xfc\x48", b"MZ") else "shellcode_prologue",
                    "route_to": "disassembler",
                    "entropy": r["entropy"],
                }
                # Surface hex preview for downstream shellcode analyzer
                if "output_hex" not in r:
                    r["output_hex"] = raw.hex()
    except Exception:
        pass

    return {
        "initial_score": initial_score,
        "candidates_explored": len(best_results),
        "isolation_note": isolation_note,
        "top_results": dedup,
    }
