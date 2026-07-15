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
_SHELL_KWORDS = re.compile(
    r"\b(?:whoami|hostname|ipconfig|ifconfig|uname|systeminfo|"
    r"powershell|pwsh|cmd|bash|/bin/sh|/bin/bash|curl|wget|nc|netcat|"
    r"mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|msbuild|installutil|"
    r"schtasks|reg\.exe|reg\s+add|wmic|net\s+user|Add-MpPreference|"
    r"Get-Process|Set-Process|Start-Process|Start-BitsTransfer|"
    r"Invoke-RestMethod|Invoke-WebRequest|ClickFix|CAPTCHA)\b",
    re.IGNORECASE,
)
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
    if _SHELL_KWORDS.search(s):
        total += 0.15; bonuses.append("shell-keywords")
    if _HTML_RE.search(s):
        total += 0.15; bonuses.append("html")
    if _PE_HEADER.match(s):
        total += 0.30; bonuses.append("pe-header")
    if _UTF16_HINT.search(s):
        total += 0.20; bonuses.append("utf16-embedded")
    # PS backtick-obfuscation PENALTY — the scoring above rewards long English
    # words, but attackers use backticks to shatter `WebClient` into `W`e`B`C`l`i`e`n`T
    # so the raw obfuscated form accidentally scores higher than the
    # deobfuscated one (short fragments aren't checked against COMMON_WORDS).
    # Discount ≈ backtick density so deobfuscate always wins its tie.
    _bt = len(re.findall(r"`[A-Za-z]", s))
    if _bt >= 4 and _bt / max(1, len(s)) > 0.05:
        total -= min(0.40, _bt / max(1, len(s)))
        bonuses.append("ps-backtick-obfuscation")
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
def _pick_candidates(payload: str, chain: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    cands: List[Dict[str, Any]] = []
    s = payload.strip()
    if not s:
        return cands
    # IMPORTANT: for magic-byte detection use the UNSTRIPPED payload — Python's
    # `str.strip()` treats `\x1f` (0x1F, Unit Separator) as whitespace and
    # will happily strip the leading byte off a gzip magic (`1f 8b`), which
    # then causes the `startswith("\x1f\x8b")` check below to silently miss
    # every base64→xor(brute)→gzip chain in the wild.
    raw = payload
    # Base64 detection
    b64only = re.sub(r"\s+", "", s)
    is_b64 = b64only and re.fullmatch(r"[A-Za-z0-9+/=_-]+", b64only) and len(b64only) >= 8
    # ── Base32 detection ────────────────────────────────────────────────
    # Base32 alphabet = A-Z + 2-7 (RFC 4648). Distinguishable from base64:
    # no lowercase, no `+`, no `/`, no digits {0,1,8,9}. If it looks like
    # base32, PRIORITIZE it over base64 (which would otherwise steal the
    # candidate slot with lowercase-friendly alphabet).
    #
    # RFC 4648 §6: "Decoders MAY treat lower-case letters as their upper-case
    # equivalents." Attackers routinely lowercase Base32 blobs for evasion,
    # so we accept both cases here (the decoder itself uppercases).
    b32_test = b64only.upper()
    is_b32 = (b64only
              and re.fullmatch(r"[A-Z2-7=]+", b32_test)
              and len(b32_test) >= 16
              and len(b32_test) % 8 in (0, 2, 4, 5, 7))
    if is_b32:
        cands.insert(0, {"op": "base32-decode", "args": {}})
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
    # ── ASCII decimal codes stream ──────────────────────────────────────
    # Detect "126 124 101 65 122 ..." (space/comma-separated ints 0-255).
    # Heuristic: ≥ 8 tokens, ≥ 80% look like realistic byte values, and the
    # NON-digit chars are almost entirely whitespace/commas (otherwise it's
    # ordinary text that happens to contain numbers).
    _tokens = re.findall(r"\d+", s)
    if len(_tokens) >= 8:
        realistic = sum(1 for t in _tokens if 0 <= int(t) <= 255)
        non_digit = re.sub(r"\d+", "", s)
        non_digit_stripped = re.sub(r"[\s,]+", "", non_digit)
        # If ≥ 80% of tokens are byte-sized AND the input is essentially just
        # digits + separators, this IS an ASCII-code stream — prioritise it.
        if realistic / len(_tokens) > 0.80:
            if len(non_digit_stripped) < 3:
                # Pure decimal-code stream → HIGH priority (front of queue).
                cands.insert(0, {"op": "ascii-decimal-decode", "args": {}})
            elif re.search(r"\d[\s,]+\d", s):
                cands.append({"op": "ascii-decimal-decode", "args": {}})
    # UTF-16LE hint — half the bytes are 0x00 in alternating positions
    if _UTF16_HINT.search(s) or "\x00" in s:
        cands.append({"op": "utf16le-decode", "args": {}})
    # Binary magic bytes AFTER a decode step (gzip, zlib, LZMA/XZ, PE).
    # NOTE: check against `raw` (unstripped) — see comment at top of function.
    #
    # ▲ FORENSIC RULE — magic bytes have HIGHEST priority.
    # When a well-known container's magic sequence is present, we propose
    # ONLY that container's decompress op and mark the branch as
    # `_magic_locked`. If decompression subsequently fails (CRC / truncated
    # stream), the walker records a "Corrupted <container>" terminal state
    # and refuses to fall back to xor-brute / rot13 / caesar / etc.
    # That's the behaviour a forensic tool must exhibit — a corrupt archive
    # is corrupt, not "maybe secretly xor'd".
    _magic_container = None
    if raw.startswith("\x1f\x8b"):
        _magic_container = "GZIP"
    elif raw.startswith("\x78\x9c") or raw.startswith("\x78\xda") or raw.startswith("\x78\x01"):
        _magic_container = "ZLIB"
    elif raw.startswith("\xfd7zXZ") or raw.startswith("\xfd7z\x58\x5a"):
        _magic_container = "LZMA"
    elif raw.startswith("BZh"):
        _magic_container = "BZIP2"

    if _magic_container is not None:
        op_map = {
            "GZIP":  "gzip-decompress",
            "ZLIB":  "zlib-decompress",
            "LZMA":  "lzma-decompress",
            "BZIP2": "bzip2-decompress",
        }
        # ── Speculative-bytes guard ─────────────────────────────────────
        # If we ARRIVED at these bytes via a brute-force op (xor-brute /
        # xor / rot13 / reverse), the "magic bytes" are LIKELY coincidence
        # from the brute picking a key that maximises magic-alignment.
        # Don't lock — return the compressed candidate PLUS the normal
        # candidate list so scoring compares them fairly.
        #
        # Only when the arrival path is composed of lossless / deterministic
        # transforms (base64/hex/utf16le/env-expand/…) do we trust the magic
        # match and lock the branch to "corrupted container" on failure.
        _speculative_ops = {"xor-brute", "xor", "rot13", "reverse"}
        _chain_ops = {c.get("op") for c in (chain or [])}
        if _chain_ops & _speculative_ops:
            cands.insert(0, {"op": op_map[_magic_container], "args": {}})
            # fall through — no early return, let scoring pick the winner
        else:
            return [{
                "op": op_map[_magic_container],
                "args": {},
                "_magic_locked": _magic_container,
            }]
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
    # ROT13 — permissive alphabet lets us catch obfuscated command-lines
    # (`phey uggc://…`, `vq;jubnzv;…`). The heuristic scorer picks a winner
    # by English-density AFTER decode, so a false-positive ROT13 candidate
    # on ordinary English text gets naturally pruned.
    if re.fullmatch(r"[A-Za-z0-9\s.,;:!?\"'/@\-\_\(\)\[\]]{10,}", s):
        cands.append({"op": "rot13", "args": {}})
    # PowerShell -EncodedCommand
    if re.search(r"-e(?:c|nc|ncoded(?:command)?)?\s+[A-Za-z0-9+/=\s]{16,}", s, re.IGNORECASE):
        cands.append({"op": "powershell-encoded", "args": {}})
    # PowerShell backtick obfuscation — `I`E`X, `N`e`T`.`W`e`B`C`l`i`e`N`T
    # etc. When >= 15 % of the input is `<letter> pairs, insert the
    # deobfuscator at the FRONT so subsequent decoders see the plaintext.
    # This must run BEFORE _PS_KWORDS since the backtick-obfuscated form
    # doesn't match `\bIEX\b` etc.
    _bt_pairs = len(re.findall(r"`[A-Za-z]", s))
    if _bt_pairs >= 4 and _bt_pairs / max(1, len(s)) > 0.10:
        cands.insert(0, {"op": "powershell-deobfuscate", "args": {}})
    # JS charcode — MUST be inserted BEFORE extract-payload otherwise the
    # wrapper stripper collapses `String.fromCharCode(108,111,...)` into a
    # gibberish digit run and the js-charcode-decode op never fires.
    if "String.fromCharCode" in s or "fromCharCode(" in s:
        cands.insert(0, {"op": "js-charcode-decode", "args": {}})
    # JS \x-escapes — same priority rationale as js-charcode.
    if re.search(r"(?:\\x[0-9a-fA-F]{2}){3,}", s):
        cands.insert(0, {"op": "js-hex-strings-decode", "args": {}})
    # \uNNNN unicode escapes (JS/PowerShell obfuscation).
    if re.search(r"(?:\\u[0-9a-fA-F]{4}){3,}", s):
        cands.insert(0, {"op": "unicode-escape", "args": {}})
    # Backslash-octal ASCII stream — `\110\145\154\154\157` → "Hello".
    if re.search(r"(?:\\[0-7]{2,3}){3,}", s):
        cands.insert(0, {"op": "octal-ascii-decode", "args": {}})
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
        # CASE-INSENSITIVE — attackers commonly use `fROMBase64sTriNG` /
        # `AtOb(` / `-encodedCoMMand` to evade string-signature detection.
        _s_low = s.lower()
        looks_wrapped = any(m in _s_low for m in (
            "frombase64string", "atob(", "base64_decode", "-encodedcommand", "$var_code",
        ))
        if nested and looks_wrapped:
            cands.insert(0, {"op": "extract-payload", "args": {}, "_nested_b64": nested[0]})

        # ── Nested Base32 quoted blob in a wrapper ──────────────────────
        # Detect patterns like:
        #   $x = 'JFCVQIBHK5ZGS5DFF...' ; ConvertFrom-Base32Encoded $x
        # or any custom PS cmdlet + a quoted [A-Z2-7]+ literal ≥ 24 chars.
        # Extract-payload has no rule for arbitrary custom-cmdlets, so we
        # short-circuit here by isolating the quoted string as the payload
        # and inserting `extract-payload → base32-decode` at the front.
        _b32_quoted = re.findall(r"['\"]([A-Za-z2-7=]{24,})['\"]", s)
        # Filter to strings that are UNAMBIGUOUSLY base32 (upper-cased ⊆ [A-Z2-7=])
        _b32_valid = [
            q for q in _b32_quoted
            if re.fullmatch(r"[A-Z2-7=]+", q.upper())
            and len(q) % 8 in (0, 2, 4, 5, 7)
            # Must NOT already be flagged as base64 (base64 alphabet is a
            # superset of base32; the priority test is that the string
            # contains ONLY base32-safe chars: no 0, 1, 8, 9, +, /, or -).
            and not re.search(r"[019+/\-]", q)
        ]
        # Also require the surrounding text mentions base32-like wrapper hints
        # OR is a PS invocation (`$var = 'blob'; ...`). Prevents random uppercase
        # words like URL slugs from falsely triggering.
        _wrapper_hint = ("base32" in _s_low or "convertfrom-base32" in _s_low
                         or bool(re.search(r"\$\w+\s*=\s*['\"]", s)))
        if _b32_valid and _wrapper_hint:
            # Sort longest-first — that's the payload
            _b32_valid.sort(key=len, reverse=True)
            cands.insert(0, {"op": "extract-payload", "args": {}, "_nested_b32": _b32_valid[0]})
            cands.insert(1, {"op": "base32-decode", "args": {}})

        # XOR key parsed directly from surrounding code (-bxor 35, ^ 0x2A, etc.)
        xk = find_xor_key(s)
        if xk is not None:
            cands.insert(0, {"op": "xor", "args": {"key": f"0x{xk:02x}"}})

        # Repeating-key XOR brute — trigger on:
        #   (a) high-entropy alphanumeric/base64 text  (ciphertext-as-text)
        #   (b) high-entropy hex text
        #   (c) high-entropy RAW BINARY BYTES (previous step decoded to bytes
        #       that don't decompress cleanly — likely XOR-obfuscated stream)
        # (c) is the key case for `base64 → XOR → gzip` stagers: base64-decode
        # produces raw XOR'd gzip bytes that no other op can handle, and
        # `_score_downstream_magic` in xor-brute will find the correct key by
        # scoring the recovered gzip magic prefix.
        s_ent = _entropy(s.encode("latin-1", errors="replace"))
        looks_b64 = re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) is not None
        looks_hex = re.fullmatch(r"[0-9a-fA-F\s]+", s) is not None
        # "Binary": ≥10% of chars are non-printable control bytes.
        # This is a much stronger binary signal than entropy alone on short
        # buffers (e.g. an 81-byte gzip-compressed stream has entropy ~5.7
        # which slips under a 6.0 threshold, but the same buffer has ~40%
        # control bytes).
        ctrl_ratio = sum(
            1 for c in s if ord(c) < 32 and c not in "\t\r\n"
        ) / max(1, len(s))
        looks_binary = len(s) >= 16 and ctrl_ratio >= 0.10
        if len(s) >= 16 and (
            (s_ent >= 4.5 and (looks_b64 or looks_hex)) or looks_binary
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
    # EXCEPTION: if the wrapper contains `String.fromCharCode(...)` or
    # `\xNN`-escape blocks, DO NOT sanitize — the sanitizer would collapse the
    # digit / hex tokens away and destroy the structure. We need those to
    # survive so `js-charcode-decode` / `js-hex-strings-decode` can fire in
    # the candidate generator below.
    _skip_isolation = (
        "String.fromCharCode" in payload or
        bool(re.search(r"(?:\\x[0-9a-fA-F]{2}){4,}", payload))
    )
    if _skip_isolation:
        isolated = None
    else:
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
        cands = _pick_candidates(cur, chain=chain)[:max_branches]
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
            # Guard: don't apply the same crypto op twice in a row (rot13 → rot13,
            # xor-brute → xor-brute, xor → xor-brute etc). These loops signal
            # over-decoding on already-clean text (from Feb-2026 regression:
            # meterpreter chain kept looping xor-brute after xor finished).
            _blocked_repeats = {"xor-brute", "xor", "rot13", "reverse"}
            if chain and c.get("op") in _blocked_repeats:
                prev_op = chain[-1].get("op")
                if prev_op == c.get("op") or (
                    c.get("op") == "xor-brute" and prev_op == "xor"
                ) or (
                    c.get("op") == "xor" and prev_op == "xor-brute"
                ):
                    continue
            # Guard: don't try further crypto ops on an output that already
            # looks like known shellcode (fc e8 89..., 48 31 d2..., etc.) —
            # that's the terminal state we're chasing, not more decoding.
            if c.get("op") in {"xor-brute", "xor", "rot13"} and cur:
                try:
                    from shellcode_analyzer import starts_with_known_prologue
                    raw_cur = cur.encode("latin-1") if all(ord(x) < 256 for x in cur) \
                                                    else cur.encode("utf-8", errors="replace")
                    if starts_with_known_prologue(raw_cur):
                        continue
                except Exception:
                    pass
            try:
                if c.get("op") == "extract-payload" and "_nested_b64" in c:
                    # Snap the input down to the nested base64 span so subsequent
                    # decoders operate ONLY on the isolated payload — this is
                    # the "re-scan after every layer" rule.
                    nxt = c["_nested_b64"]
                elif c.get("op") == "extract-payload" and "_nested_b32" in c:
                    # Same rule for nested base32 blobs (custom-cmdlet wrappers).
                    nxt = c["_nested_b32"]
                else:
                    nxt = run_operation(c["op"], cur, c["args"])
            except Exception as _e:
                # ── FORENSIC RULE — corrupted container terminal state ────
                # When a magic-byte-locked decompress fails (BadGzipFile /
                # CRC mismatch / truncated stream), we record the failure as
                # the TERMINAL state for this branch. No fallback to xor-brute
                # or any other transformation — a corrupt archive is corrupt.
                if c.get("_magic_locked"):
                    label = c["_magic_locked"]
                    step_err = {
                        "op": c["op"],
                        "args": c.get("args") or {},
                        "_magic_locked": label,
                        "_error": f"{type(_e).__name__}: {_e}",
                    }
                    best_results.append({
                        "chain": chain + [step_err],
                        "output": (
                            f"[Corrupted {label} container] "
                            f"{type(_e).__name__}: {_e}. "
                            "Deterministic decoder will not brute-force inside a "
                            "corrupted container. Enable Aggressive Recovery to "
                            "attempt salvage."
                        ),
                        "score_breakdown": {
                            "score":    0.0,
                            "printable": 0.0,
                            "english":   0.0,
                            "entropy":   0.0,
                            "size":      0,
                            "reasons":   [f"corrupted-{label.lower()}-container"],
                        },
                        "path_scores": list(path_scores) + [0.0],
                        "corrupted_container": {
                            "kind":   label,
                            "reason": str(_e),
                        },
                    })
                    return   # stop the ENTIRE branch — no further candidates
                continue
            if not nxt or nxt == cur:
                continue
            # Self-inverse guard: ROT13 / reverse applied on an already-clean
            # readable string only makes sense when the OUTPUT is MEASURABLY
            # BETTER (more English words / shell keywords / URL / structure)
            # than the input. Otherwise the op is destroying signal.
            if c.get("op") in ("rot13", "reverse"):
                def _signal(text: str) -> float:
                    sc = 0.0
                    sc += _english_density(text)
                    if _PS_KWORDS.search(text): sc += 0.35
                    if _SHELL_KWORDS.search(text): sc += 0.15
                    if _URL_RE.search(text): sc += 0.20
                    return sc
                if _signal(nxt) <= _signal(cur) + 0.005:
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
                    hex_out = xored_bytes.hex()
                    step_xor = {"op": "xor", "args": {"key": f"0x{key:02x}"}}
                    # Try UTF-8 decode FIRST — a lot of xor'd payloads are
                    # ordinary ASCII scripts (`id;whoami`, PowerShell). Only
                    # fall back to the hex/latin-1 dual representation when
                    # the bytes are truly binary.
                    plain_out = None
                    try:
                        candidate = xored_bytes.decode("utf-8")
                        printable = sum(1 for c2 in candidate if 32 <= ord(c2) < 127 or c2 in "\r\n\t")
                        if candidate and printable / max(1, len(candidate)) >= 0.90:
                            plain_out = candidate
                    except UnicodeDecodeError:
                        pass
                    if plain_out is not None:
                        # Clean text branch — record & keep walking on the plaintext
                        psb = score_output(plain_out)
                        best_results.append({
                            "chain": chain + [clean_step, step_xor],
                            "output": plain_out,
                            "score_breakdown": psb,
                            "path_scores": list(path_scores) + [sb["score"], psb["score"]],
                        })
                        # Clear the xor_key so we don't re-plan another
                        # base64→xor step on the already-decoded plaintext.
                        _ctx_next = {k: v for k, v in ctx.items() if k != "xor_key"}
                        _walk(plain_out, chain + [clean_step, step_xor],
                              depth + 2, path_scores + [sb["score"], psb["score"]], _ctx_next)
                    else:
                        # Binary branch — surface hex + latin-1 for shellcode analyzer
                        xsb = score_output(hex_out)
                        best_results.append({
                            "chain": chain + [clean_step, step_xor],
                            "output": xored_bytes.decode("latin-1"),  # 1:1 byte↔codepoint preservation
                            "output_hex": hex_out,
                            "output_bytes_len": len(xored_bytes),
                            "score_breakdown": xsb,
                            "path_scores": list(path_scores) + [sb["score"], xsb["score"]],
                        })
                        _ctx_next = {k: v for k, v in ctx.items() if k != "xor_key"}
                        _walk(hex_out, chain + [clean_step, step_xor],
                              depth + 2, path_scores + [sb["score"], xsb["score"]], _ctx_next)
                    continue
                except Exception:
                    pass
            if nsb["score"] < sb["score"] - 0.30:  # branch massively regressed — prune
                # …unless a XOR key is known — the pruned base64 output is
                # probably XORed bytes we still want to try.
                # …unless the pruned output looks like high-entropy binary
                # (potential XOR-obfuscated or compressed content that only
                # xor-brute or a decompression op can rescue).
                # …unless we're deliberately isolating a nested b64/b32
                # payload — the isolated blob almost always scores lower than
                # the surrounding script wrapper, and pruning here would kill
                # the ONLY viable path to the true plaintext.
                if c.get("op") == "extract-payload" and (
                    "_nested_b64" in c or "_nested_b32" in c
                ):
                    pass  # always follow through
                else:
                    looks_binary = (
                        len(nxt) >= 24 and
                        _entropy(nxt.encode("latin-1", errors="replace")) >= 6.0
                    )
                    if ctx.get("xor_key") is None and not looks_binary:
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
    # Tie-breaker: when magic scores are equal, prefer a NON-empty chain over
    # a "no-op passthrough". Otherwise pure decimal / bare Base32 blobs that
    # decode cleanly to ASCII (e.g. `105 100 59 119 104` → `id;who`) get
    # shadowed by the "return input unchanged" candidate. Both score identically
    # under the printable/english heuristic, but the decoded chain is the
    # right answer for a decoder tool.
    def _sort_key(r):
        chain_len = len(r.get("chain") or [])
        return (-r["score_breakdown"]["score"], 0 if chain_len > 0 else 1)
    dedup.sort(key=_sort_key)

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

    # ── FORENSIC RULE — corrupted-container elevation ───────────────────
    # If ANY branch discovered a corrupted magic-byte container, promote it
    # to the TOP of the results — even if it was dedup'd out of the top-N
    # by scoring. The analyst needs to see the exact CRC / data-error reason,
    # not a garbage xor-brute output that only scored higher because it
    # looked vaguely printable.
    corrupted = None
    for r in best_results:
        if r.get("corrupted_container"):
            corrupted = r
            break
    if corrupted:
        # Prepend the isolation step so the chain reads correctly on the UI.
        if isolation_note:
            corrupted = {**corrupted,
                         "chain": [{"op": "extract-payload", "args": {}}] + corrupted["chain"]}
        dedup = [corrupted] + [r for r in dedup if not r.get("corrupted_container")]

    return {
        "initial_score": initial_score,
        "candidates_explored": len(best_results),
        "isolation_note": isolation_note,
        "top_results": dedup,
        "corrupted_container": (corrupted or {}).get("corrupted_container"),
    }
