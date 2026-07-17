"""NivXRay — 42+ decode/deobfuscate operations."""
from __future__ import annotations
import base64
import binascii
import codecs
import gzip
import zlib
import re
import html
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from payload_sanitizer import sanitize_encapsulated_payload

# ==== Registry ==============================================================
OPERATIONS: Dict[str, Dict[str, Any]] = {}


def op(op_id: str, name: str, category: str, description: str = "", args: Optional[List[Dict[str, Any]]] = None):
    def deco(fn):
        OPERATIONS[op_id] = {
            "id": op_id,
            "name": name,
            "category": category,
            "description": description,
            "args": args or [],
            "fn": fn,
        }
        return fn
    return deco


def list_operations() -> List[Dict[str, Any]]:
    return [
        {k: v for k, v in o.items() if k != "fn"}
        for o in OPERATIONS.values()
    ]


def run_operation(op_id: str, data: str, args: Optional[Dict[str, Any]] = None) -> str:
    if op_id not in OPERATIONS:
        raise ValueError(f"Unknown operation: {op_id}")
    return OPERATIONS[op_id]["fn"](data, **(args or {}))


# ==== COMPRESSION ============================================================
@op("gzip-decompress", "Gzip Decompress", "Compression", "Decompress gzip data (accepts base64 or hex input).")
def _gzip_decompress(data: str) -> str:
    raw = _as_bytes(data)
    return gzip.decompress(raw).decode("utf-8", errors="replace")


@op("zlib-decompress", "Zlib Decompress", "Compression", "Decompress zlib/deflate data.")
def _zlib_decompress(data: str) -> str:
    raw = _as_bytes(data)
    try:
        return zlib.decompress(raw).decode("utf-8", errors="replace")
    except zlib.error:
        return zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8", errors="replace")


@op("base64-gzip", "Base64 → Gzip Decompress", "Compression", "Base64 decode then gzip decompress.")
def _b64_gzip(data: str) -> str:
    raw = base64.b64decode(_clean(data), validate=False)
    return gzip.decompress(raw).decode("utf-8", errors="replace")


@op("base64-zlib", "Base64 → Zlib Decompress", "Compression", "Base64 decode then zlib decompress.")
def _b64_zlib(data: str) -> str:
    raw = base64.b64decode(_clean(data), validate=False)
    try:
        return zlib.decompress(raw).decode("utf-8", errors="replace")
    except zlib.error:
        return zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8", errors="replace")


# ==== CRYPTOGRAPHY / ENCODING ================================================
@op("base64-decode", "Base64 Decode", "Cryptography", "Decode a Base64 string (auto-extracts payload from scripts, joins multi-line, auto-pads).")
def _b64_decode(data: str) -> str:
    # Thumb rule: ISOLATE THE PAYLOAD STRING FIRST.
    # If the input is an entire command line / script wrapper, extract the
    # enclosed base64 payload before decoding.
    isolated = sanitize_encapsulated_payload(data)
    payload = isolated if isolated is not None else data
    # Join lines & strip any remaining whitespace/newlines
    cleaned = _clean(payload)
    # Auto-pad and decode
    padded = cleaned + "=" * (-len(cleaned) % 4)
    raw = base64.b64decode(padded, validate=False)
    # If the decoded bytes are clean UTF-8, prefer that (readable output). If
    # they contain binary (compressed streams, XOR-encrypted bytes, PE headers,
    # etc.) fall back to LATIN-1 so bytes survive as 1:1 codepoints for the
    # NEXT op in the chain (gzip-decompress, xor-brute, shellcode-analyze).
    # UTF-8 with errors='replace' would substitute 0xFFFD and corrupt the
    # binary — breaking chains like base64→xor→gzip.
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


@op("base64-encode", "Base64 Encode", "Cryptography", "Encode data as Base64.")
def _b64_encode(data: str) -> str:
    return base64.b64encode(data.encode("utf-8")).decode()


@op("base32-decode", "Base32 Decode", "Cryptography", "Decode a Base32 string.")
def _b32_decode(data: str) -> str:
    return base64.b32decode(_clean(data).upper() + "=" * ((8 - len(_clean(data)) % 8) % 8)).decode("utf-8", errors="replace")


@op("hex-decode", "Hex Decode", "Cryptography", "Decode hexadecimal string to text.")
def _hex_decode(data: str) -> str:
    s = re.sub(r"[^0-9a-fA-F]", "", data)
    if len(s) % 2:
        s = s[:-1]
    return bytes.fromhex(s).decode("utf-8", errors="replace")


@op("ascii-decimal-decode", "ASCII Decimal Codes → Text", "Cryptography",
    "Decode a stream of space/comma-separated decimal ASCII codes (32-255) back into a text string. "
    "Common in obfuscated PowerShell / JS payloads and multi-layer stagers (Base32 → decimal codes → next stage). "
    "If the decimal interpretation yields mostly-non-printable output but re-interpreting the same tokens as OCTAL "
    "produces clean printable ASCII, the octal reading wins — analysts often paste `120 157 167 ...` from PowerShell "
    "obfuscators that render bytes in octal.")
def _ascii_decimal_decode(data: str) -> str:
    # Accept both space- and comma-separated tokens, and mixed whitespace
    tokens = re.findall(r"\d+", data)
    if not tokens:
        return ""
    def _decode_base(base: int) -> str:
        out = []
        for t in tokens:
            try:
                n = int(t, base)
            except ValueError:
                continue
            if 0 <= n <= 255:
                out.append(chr(n))
        return "".join(out)

    dec_out = _decode_base(10)
    # Try OCTAL fallback when the decimal reading is mostly non-printable
    # (attackers frequently paste `120 157 167 145 ...` = octal for Power…).
    try:
        # Only tokens whose digits are 0-7 can be octal
        if all(all(ch in "01234567" for ch in t) for t in tokens):
            oct_out = _decode_base(8)
            def _printable_ratio(s: str) -> float:
                if not s: return 0.0
                p = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t")
                return p / len(s)
            if _printable_ratio(oct_out) > _printable_ratio(dec_out) + 0.10:
                return oct_out
    except Exception:
        pass
    return dec_out


@op("binary-ascii-decode", "Binary ASCII (0/1) → Text", "Cryptography",
    "Decode a stream of space-separated 8-bit binary bytes back into text. "
    "Example: `01010000 01101111 01110111 ...` -> `Pow...`. Tolerates 7-bit and mixed widths.")
def _binary_ascii_decode(data: str) -> str:
    tokens = re.findall(r"[01]{7,8}", data)
    if len(tokens) < 3:
        return ""
    out = []
    for t in tokens:
        try:
            n = int(t, 2)
        except ValueError:
            continue
        if 0 <= n <= 0xFF:
            out.append(chr(n))
    return "".join(out)


@op("ps-binary-split-decode", "PowerShell Binary/Hex Split-Array → Text", "Cryptography",
    "Decode PowerShell binary-split obfuscation: `.Split('junkchars')` + `ToInt16($_, 2/10/16)`. "
    "Auto-detects delimiters from the .Split() call, chunks the data string, and converts each chunk "
    "from base-2 / base-10 / base-16 to ASCII. Handles Invoke-Obfuscation's binary/hex-array mode.")
def _ps_binary_split_decode(data: str) -> str:
    # Detect the base: 2, 10, or 16
    base_m = re.search(r"ToInt16\s*\(\s*[^,]+,\s*(2|10|16)\s*\)", data, re.IGNORECASE)
    if base_m:
        base = int(base_m.group(1))
    elif re.search(r"\[char\]\s*\[int\]\s*\(\s*['\"]?0x", data, re.IGNORECASE):
        base = 16
    else:
        return ""

    # Extract the delimiter string from .Split('...')
    delim_m = re.search(r"\.\s*Split\s*\(\s*['\"]([^'\"]{1,32})['\"]\s*\)", data, re.IGNORECASE)
    if not delim_m:
        return ""
    delims = delim_m.group(1)

    # Extract the largest data-looking single-quoted string that contains
    # digits + at least one of the delimiter characters. This is the payload.
    valid_char_class = "0-9a-fA-F" if base == 16 else "0-9"
    candidates = re.findall(r"['\"]([" + valid_char_class + re.escape(delims) + r"]{10,})['\"]", data)
    if not candidates:
        return ""
    payload = max(candidates, key=len)

    # Split by delimiter chars
    chunks = re.split("[" + re.escape(delims) + "]", payload)
    return _binary_chunks_to_text(chunks, base)


def _binary_chunks_to_text(chunks: list, base: int) -> str:
    """Convert a list of digit-string chunks (base 2/10/16) into text.

    When a base-2 chunk is longer than 8 bits, it means the obfuscator's
    delimiter set was incomplete and multiple bytes got glued together. We
    then try 7-bit AND 8-bit re-chunking and pick whichever produces more
    printable ASCII — this recovers ~all Invoke-Obfuscation binary/hex-array
    payloads that would otherwise emit garbled Unicode.
    """
    out = []
    for c in chunks:
        c = c.strip()
        if not c:
            continue
        try:
            n = int(c, base)
        except ValueError:
            continue
        # Simple case: single-byte-sized chunk
        if base != 2 or len(c) <= 8:
            if 0 <= n <= 0x10FFFF:
                out.append(chr(n))
            continue
        # Over-long binary chunk → try 7 and 8-bit re-splits, pick best
        best_text = ""
        best_score = -1
        # Both group sizes × both alignments (L-to-R and R-to-L). When the
        # chunk length isn't a clean multiple of group_size, the correct
        # boundary depends on how the obfuscator wrote it — R-to-L is common
        # because the LOW-value byte often has a leading zero the obfuscator
        # keeps in the string.
        for group_size in (7, 8):
            for offset in (0, len(c) % group_size):
                if offset == group_size:
                    continue
                sub = []
                i = offset
                # If offset > 0, decode the leading fragment as its own char too
                if offset > 0:
                    try:
                        nn = int(c[:offset], 2)
                        if 32 <= nn <= 127:
                            sub.append(chr(nn))
                    except ValueError:
                        pass
                valid = True
                while i < len(c):
                    grp = c[i:i + group_size]
                    if len(grp) < group_size:
                        try:
                            nn = int(grp, 2)
                            if 32 <= nn <= 127:
                                sub.append(chr(nn))
                        except ValueError:
                            valid = False
                        break
                    try:
                        nn = int(grp, 2)
                    except ValueError:
                        valid = False
                        break
                    if not (0 <= nn <= 0x10FFFF):
                        valid = False
                        break
                    sub.append(chr(nn))
                    i += group_size
                if not valid:
                    continue
                text = "".join(sub)
                # Score: printable-ASCII count + letter/space bonus (favors real
                # words over ASCII-noise like `l2` vs `ld`). Slight 8-bit bonus
                # since ASCII encoders default to 8-bit even for 7-bit values.
                printable = sum(1 for ch in text if 32 <= ord(ch) < 127)
                letters = sum(1 for ch in text if ch.isalpha() or ch in " \r\n\t")
                score = printable + letters + (0.1 if group_size == 8 else 0.0)
                if score > best_score or (score == best_score and len(text) < len(best_text)):
                    best_score = score
                    best_text = text
        # If both 7- and 8-bit re-splits failed, fall back to single-code-point
        if best_text:
            out.append(best_text)
        elif 0 <= n <= 0x10FFFF:
            out.append(chr(n))
    return "".join(out)


@op("hex-encode", "Hex Encode", "Cryptography", "Encode text as hexadecimal.")
def _hex_encode(data: str) -> str:
    return data.encode("utf-8").hex()


@op("rot13", "ROT13", "Cryptography", "Caesar cipher with shift 13.")
def _rot13(data: str) -> str:
    return codecs.decode(data, "rot_13")


@op("rot47", "ROT47", "Cryptography", "ROT47 substitution across printable ASCII.")
def _rot47(data: str) -> str:
    out = []
    for ch in data:
        c = ord(ch)
        if 33 <= c <= 126:
            out.append(chr(33 + (c - 33 + 47) % 94))
        else:
            out.append(ch)
    return "".join(out)


@op("xor", "XOR (single-byte key)", "Cryptography", "XOR the input against a single-byte key.", [{"name": "key", "type": "string", "default": "0x2A", "description": "Hex (0x2A) or decimal (42) or ASCII char"}])
def _xor(data: str, key: str = "0x2A") -> str:
    k = _parse_byte(key)
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("utf-8", errors="replace")
    return bytes(b ^ k for b in raw).decode("utf-8", errors="replace")


@op("xor-bruteforce", "XOR Bruteforce (single-byte)", "Cryptography", "Try all 256 single-byte XOR keys and return best candidates.")
def _xor_bf(data: str) -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("utf-8", errors="replace")
    scored: List[Tuple[int, int, str]] = []
    for k in range(256):
        try:
            dec = bytes(b ^ k for b in raw).decode("utf-8", errors="replace")
            score = sum(1 for c in dec if 32 <= ord(c) < 127 or c in "\n\r\t")
            scored.append((score, k, dec))
        except Exception:
            continue
    scored.sort(reverse=True)
    top = scored[:5]
    return "\n".join(f"[key=0x{k:02X}] {t[:200]}" for _, k, t in top)


@op("url-decode", "URL Decode", "Cryptography", "Percent-decode a URL-encoded string.")
def _url_decode(data: str) -> str:
    return urllib.parse.unquote_plus(data)


@op("url-encode", "URL Encode", "Cryptography", "Percent-encode a string.")
def _url_encode(data: str) -> str:
    return urllib.parse.quote_plus(data)


@op("html-decode", "HTML Entity Decode", "Cryptography", "Decode HTML entities like &amp; &lt; &#x41;")
def _html_decode(data: str) -> str:
    return html.unescape(data)


@op("html-encode", "HTML Entity Encode", "Cryptography", "Encode special characters as HTML entities.")
def _html_encode(data: str) -> str:
    return html.escape(data)


@op("unicode-escape", "Unicode Escape Decode", "Cryptography", "Decode \\uXXXX Unicode escapes.")
def _unicode_esc(data: str) -> str:
    return codecs.decode(data.encode("utf-8"), "unicode_escape")


@op("octal-ascii-decode", "Octal ASCII Decode", "Cryptography",
    "Decode backslash-octal streams like \\110\\145\\154\\154\\157 -> Hello.")
def _octal_ascii(data: str) -> str:
    # Match 2- or 3-digit octal groups (0-377). Reject sequences whose value
    # would be > 0xFF (non-ASCII escape range).
    def _sub(m):
        v = int(m.group(1), 8)
        return chr(v) if 0 <= v <= 0xFF else m.group(0)
    return re.sub(r"\\([0-7]{2,3})", _sub, data)


@op("utf16le-decode", "UTF-16LE Decode", "Cryptography", "Decode bytes as UTF-16 Little Endian.")
def _utf16le(data: str) -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("utf-8", errors="replace")
    return raw.decode("utf-16-le", errors="replace")


@op("reverse", "Reverse String", "Cryptography", "Reverse the input string.")
def _reverse(data: str) -> str:
    return data[::-1]


# ==== DEOBFUSCATION ==========================================================
@op("cmd-deobfuscate", "CMD Deobfuscate", "Deobfuscation", "Strip CMD.exe obfuscation: caret escapes, quoted concat, %ENV% noise.")
def _cmd_deob(data: str) -> str:
    s = data
    # Remove caret escapes: c^m^d -> cmd
    s = re.sub(r"\^", "", s)
    # Collapse quoted-string concatenation like c"m"d
    s = re.sub(r'"', "", s)
    # Remove FOR /F variable extraction noise (best effort)
    s = re.sub(r"%[A-Za-z0-9_]{1,32}:~[\d,\-]+%", "", s)
    return s


@op("powershell-deobfuscate", "PowerShell Deobfuscate", "Deobfuscation", "Undo common PowerShell obfuscation: tick, format-string, string join.")
def _ps_deob(data: str) -> str:
    s = data
    # Remove backticks
    s = s.replace("`", "")
    # Handle -join operator on char arrays: [char[]](97,98,99) -> abc
    def _join_chars(m):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
            return '"' + "".join(chr(n) for n in nums) + '"'
        except Exception:
            return m.group(0)
    s = re.sub(r"\[char\[\]\]\s*\(([^\)]+)\)", _join_chars, s, flags=re.IGNORECASE)
    # Handle [char]NN
    s = re.sub(r"\[char\]\s*(\d{1,4})", lambda m: chr(int(m.group(1))), s, flags=re.IGNORECASE)
    # Remove common env noise ${env:comspec}
    s = re.sub(r"\$\{?env:[A-Za-z0-9_]+\}?", "", s, flags=re.IGNORECASE)
    return s


@op("powershell-encoded", "PowerShell -EncodedCommand", "Deobfuscation", "Decode -EncodedCommand base64+UTF-16LE payload (auto-extracts from full PowerShell command lines).")
def _ps_encoded(data: str) -> str:
    # Thumb rule: ISOLATE THE PAYLOAD STRING FIRST.
    isolated = sanitize_encapsulated_payload(data)
    if isolated:
        payload = re.sub(r"[^A-Za-z0-9+/=]", "", isolated)
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=False)
        return raw.decode("utf-16-le", errors="ignore")

    # Fallback — regex-based extraction from the -e flag when sanitizer returns None
    joined = " ".join(data.splitlines())
    m = re.search(
        r"(?:-e(?:c|nc|ncoded(?:command)?)?)\s+([A-Za-z0-9+/=\s]+)",
        joined,
        re.IGNORECASE,
    )
    payload = m.group(1) if m else joined
    payload = re.sub(r"[^A-Za-z0-9+/=]", "", payload)
    raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=False)
    return raw.decode("utf-16-le", errors="ignore")


@op("js-charcode", "JavaScript CharCode Decode", "Deobfuscation", "Decode String.fromCharCode(a,b,c) sequences.")
def _js_charcode(data: str) -> str:
    def _decode(m):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
            return "".join(chr(n) for n in nums)
        except Exception:
            return m.group(0)
    return re.sub(r"String\.fromCharCode\s*\(([\d,\s]+)\)", _decode, data)


@op("js-unescape", "JavaScript Unescape (\\xNN)", "Deobfuscation", "Decode \\xNN hex escapes commonly used in JS obfuscation.")
def _js_unescape(data: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), data)


@op("defang-iocs", "Defang IOCs", "Deobfuscation", "Defang URLs/IPs/emails (http→hxxp, .→[.], @→[@]).")
def _defang(data: str) -> str:
    s = re.sub(r"(?i)http", "hxxp", data)
    s = re.sub(r"(?i)https", "hxxps", s)
    s = s.replace(".", "[.]").replace("@", "[@]")
    return s


@op("refang-iocs", "Refang IOCs", "Deobfuscation", "Undo defanging: hxxp→http, [.]→., [@]→@.")
def _refang(data: str) -> str:
    s = data
    s = re.sub(r"(?i)hxxps", "https", s)
    s = re.sub(r"(?i)hxxp", "http", s)
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("[@]", "@").replace("(@)", "@").replace("[at]", "@")
    s = s.replace("[://]", "://")
    return s


@op("strip-null-bytes", "Strip Null Bytes", "Deobfuscation", "Remove null bytes (0x00) from the input.")
def _strip_null(data: str) -> str:
    return data.replace("\x00", "")


@op("strip-non-printable", "Strip Non-Printable", "Deobfuscation", "Remove non-printable ASCII characters.")
def _strip_np(data: str) -> str:
    return "".join(c for c in data if c.isprintable() or c in "\n\r\t")


@op("extract-strings", "Extract Strings (≥4)", "Deobfuscation", "Extract printable strings of length ≥4 (like GNU strings).")
def _strings(data: str) -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("utf-8", errors="replace")
    out = []
    cur = []
    for b in raw:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= 4:
                out.append("".join(cur))
            cur = []
    if len(cur) >= 4:
        out.append("".join(cur))
    return "\n".join(out)


# ==== PARSING / EXTRACTION ===================================================
@op("extract-urls", "Extract URLs", "Extractors", "Extract URLs (refanged) from any text.")
def _ext_urls(data: str) -> str:
    refanged = _refang(data)
    urls = re.findall(r"https?://[^\s\"'<>\)]+", refanged, re.IGNORECASE)
    return "\n".join(dict.fromkeys(urls))


@op("extract-ips", "Extract IPs", "Extractors", "Extract IPv4 addresses.")
def _ext_ips(data: str) -> str:
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _refang(data))
    return "\n".join(dict.fromkeys(ips))


@op("extract-emails", "Extract Emails", "Extractors", "Extract email addresses.")
def _ext_emails(data: str) -> str:
    emails = re.findall(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", _refang(data))
    return "\n".join(dict.fromkeys(emails))


@op("extract-domains", "Extract Domains", "Extractors", "Extract domain names.")
def _ext_domains(data: str) -> str:
    doms = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", _refang(data).lower())
    return "\n".join(dict.fromkeys(doms))


@op("extract-hashes", "Extract Hashes", "Extractors", "Extract MD5/SHA1/SHA256 hashes.")
def _ext_hashes(data: str) -> str:
    md5 = re.findall(r"\b[a-fA-F0-9]{32}\b", data)
    sha1 = re.findall(r"\b[a-fA-F0-9]{40}\b", data)
    sha256 = re.findall(r"\b[a-fA-F0-9]{64}\b", data)
    lines = [f"MD5:    {h}" for h in md5] + [f"SHA1:   {h}" for h in sha1] + [f"SHA256: {h}" for h in sha256]
    return "\n".join(lines)


@op("extract-base64", "Extract Base64 Blocks", "Extractors", "Extract long Base64-looking blocks (≥24 chars).")
def _ext_b64(data: str) -> str:
    blocks = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", data)
    return "\n".join(dict.fromkeys(blocks))


# ==== FORMATTING =============================================================
@op("json-beautify", "JSON Beautify", "Formatting", "Pretty-print a JSON string.")
def _json_pretty(data: str) -> str:
    return json.dumps(json.loads(data), indent=2)


@op("json-minify", "JSON Minify", "Formatting", "Minify a JSON string.")
def _json_min(data: str) -> str:
    return json.dumps(json.loads(data), separators=(",", ":"))


@op("uppercase", "Uppercase", "Formatting", "Convert text to UPPERCASE.")
def _upper(data: str) -> str:
    return data.upper()


@op("lowercase", "Lowercase", "Formatting", "Convert text to lowercase.")
def _lower(data: str) -> str:
    return data.lower()


@op("trim-whitespace", "Trim Whitespace", "Formatting", "Strip whitespace from each line.")
def _trim(data: str) -> str:
    return "\n".join(line.strip() for line in data.splitlines())


@op("dedupe-lines", "Deduplicate Lines", "Formatting", "Remove duplicate lines (preserves order).")
def _dedup(data: str) -> str:
    return "\n".join(dict.fromkeys(data.splitlines()))


# ==== HASHING (info) =========================================================
@op("md5", "MD5", "Hashing", "MD5 hash of input.")
def _md5(data: str) -> str:
    import hashlib; return hashlib.md5(data.encode("utf-8")).hexdigest()


@op("sha1", "SHA-1", "Hashing", "SHA-1 hash of input.")
def _sha1(data: str) -> str:
    import hashlib; return hashlib.sha1(data.encode("utf-8")).hexdigest()


@op("sha256", "SHA-256", "Hashing", "SHA-256 hash of input.")
def _sha256(data: str) -> str:
    import hashlib; return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ==== ARCHETYPE CHAIN ALIASES ================================================
# These ops make the semantic IDs emitted inside `wrapper_archetypes.py` chains
# runnable via the Recipe UI. They fall into 3 buckets:
#   1. Real aliases that forward to an existing op (e.g. xor-byte -> xor)
#   2. New concrete ops that do a genuine transform (utf16le-or-utf8-decode,
#      extract-b64, extract-hex, strip-carets, strip-ticks, ...)
#   3. Semantic annotators that pass data through unchanged plus a marker
#      (dev-tcp-annotate, clipboard-cradle-annotate, native-cmd-explain, ...)
#      — these exist so a Recipe step doesn't error with "Unknown operation".

# --- Bucket 1: aliases to existing decoders --- #
@op("xor-byte", "XOR (single-byte, alias)", "Cryptography",
    "Alias of `xor` — single-byte XOR against a key.",
    [{"name": "key", "type": "string", "default": "0x2A", "description": "Hex/decimal/char"}])
def _xor_byte_alias(data: str, key: str = "0x2A") -> str:
    return _xor(data, key)


@op("reverse-string", "Reverse String (alias)", "Cryptography", "Alias of `reverse`.")
def _reverse_alias(data: str) -> str:
    return data[::-1]


@op("js-charcode-decode", "JS CharCode (alias)", "Deobfuscation", "Alias of `js-charcode`.")
def _js_charcode_alias(data: str) -> str:
    return _js_charcode(data)


@op("ascii-decode", "ASCII Decode", "Cryptography",
    "Decode bytes as printable ASCII (handles hex/base64 input transparently).")
def _ascii_decode(data: str) -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("utf-8", errors="replace")
    return raw.decode("ascii", errors="replace")


@op("chr-decode", "Chr()/Character Decode", "Cryptography",
    "Decode comma/space-separated character codes to text (Chr(NN), [char]NN).")
def _chr_decode(data: str) -> str:
    # Reuse ASCII decimal path first; fallback to hex if hex-shaped.
    try:
        return _ascii_decimal(data)  # noqa: F821 — defined earlier in module
    except Exception:
        return data


@op("chr-map", "Chr()/Character Map (alias)", "Cryptography", "Alias of `chr-decode`.")
def _chr_map_alias(data: str) -> str:
    return _chr_decode(data)


@op("hex-decode-alt", "Hex Decode (bytes)", "Cryptography", "Alias of `hex-decode`.")
def _hex_decode_alt(data: str) -> str:
    return _hex_decode(data)  # noqa: F821


# --- Bucket 2: new concrete decoders --- #
@op("extract-b64", "Extract Base64 (first block)", "Extractors",
    "Extract the first/longest base64-looking blob from wrapper text.")
def _extract_b64(data: str) -> str:
    blocks = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", data)
    if not blocks:
        return data
    # Return the longest block (most likely the payload)
    return max(blocks, key=len)


@op("extract-b64-pair", "Extract Base64 Pair", "Extractors",
    "Extract 2 concatenated base64 blocks (e.g. split payload variants) and join them.")
def _extract_b64_pair(data: str) -> str:
    blocks = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", data)
    if len(blocks) < 2:
        return blocks[0] if blocks else data
    blocks.sort(key=len, reverse=True)
    return blocks[0] + blocks[1]


@op("extract-b64-via-var", "Extract Base64 via Variable", "Extractors",
    "Resolve `$var='..b64..';...decode($var)` style payloads — pulls the b64 string bound to a variable.")
def _extract_b64_via_var(data: str) -> str:
    # $var = 'BASE64...' or $var="BASE64..."
    m = re.search(r"\$\w+\s*=\s*['\"]([A-Za-z0-9+/=]{24,})['\"]", data)
    if m:
        return m.group(1)
    return _extract_b64(data)


@op("extract-b32", "Extract Base32 Block", "Extractors",
    "Extract the first/longest base32-looking blob from wrapper text.")
def _extract_b32(data: str) -> str:
    blocks = re.findall(r"[A-Z2-7]{16,}={0,6}", data)
    return max(blocks, key=len) if blocks else data


@op("extract-hex", "Extract Hex Block", "Extractors",
    "Extract the longest contiguous hexadecimal blob (≥16 chars).")
def _extract_hex(data: str) -> str:
    blocks = re.findall(r"[A-Fa-f0-9]{16,}", data)
    return max(blocks, key=len) if blocks else data


@op("extract-hex-string", "Extract Hex-String Literal", "Extractors",
    "Extract a quoted hex string literal like '\\x41\\x42\\x43' — returns raw hex without prefix.")
def _extract_hex_string(data: str) -> str:
    bytes_hex = re.findall(r"\\x([0-9a-fA-F]{2})", data)
    if bytes_hex:
        return "".join(bytes_hex)
    return _extract_hex(data)


@op("extract-inline-string", "Extract Inline String Literal", "Extractors",
    "Extract the first single/double-quoted string literal from a script.")
def _extract_inline_string(data: str) -> str:
    m = re.search(r"['\"]([^'\"]{8,})['\"]", data)
    return m.group(1) if m else data


@op("extract-int-array", "Extract Integer Array", "Extractors",
    "Extract a comma-separated integer array (e.g. `@(72,101,108,108,111)`) as decimal codes.")
def _extract_int_array(data: str) -> str:
    m = re.search(r"[@\(\[\{]\s*((?:\d{1,4}\s*,\s*){2,}\d{1,4})\s*[\)\]\}]", data)
    if m:
        return m.group(1)
    return data


@op("extract-p-var", "Extract $p-style Variable", "Extractors",
    "Extract the concatenated string value bound to a `$p` / `$env:x` style variable.")
def _extract_p_var(data: str) -> str:
    m = re.search(r"\$\w+\s*=\s*['\"]([^'\"]{4,})['\"]", data)
    return m.group(1) if m else data


@op("extract-pem", "Extract PEM Body", "Extractors",
    "Extract the base64 body from a PEM block (BEGIN/END CERTIFICATE / RSA PRIVATE KEY etc.).")
def _extract_pem(data: str) -> str:
    m = re.search(r"-{5}BEGIN[^-]+-{5}\s*([A-Za-z0-9+/=\s]+?)\s*-{5}END", data)
    if m:
        return re.sub(r"\s+", "", m.group(1))
    return data


@op("utf16le-or-utf8-decode", "UTF-16LE-or-UTF-8 Decode", "Cryptography",
    "Try UTF-16LE first; fall back to UTF-8 if the result is mostly non-printable.")
def _utf16_or_utf8(data: str) -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("latin-1", errors="replace")
    # Try UTF-16LE
    try:
        u16 = raw.decode("utf-16-le", errors="strict")
        printable = sum(1 for c in u16 if c.isprintable() or c in "\n\r\t")
        if u16 and printable / len(u16) >= 0.85:
            return u16
    except UnicodeDecodeError:
        pass
    # Fall back to UTF-8 with replacement
    return raw.decode("utf-8", errors="replace")


@op("strip-carets", "Strip Carets (^)", "Deobfuscation", "Remove caret (^) obfuscation from CMD.exe payloads.")
def _strip_carets(data: str) -> str:
    return data.replace("^", "")


@op("strip-ticks", "Strip Backticks (`)", "Deobfuscation", "Remove backtick (`) obfuscation from PowerShell payloads.")
def _strip_ticks(data: str) -> str:
    return data.replace("`", "")


@op("string-replace", "String Replace", "Deobfuscation",
    "PowerShell/CMD `.Replace('x','y')` — apply a find/replace pair.",
    [{"name": "find", "type": "string", "default": ""},
     {"name": "replace", "type": "string", "default": ""}])
def _string_replace(data: str, find: str = "", replace: str = "") -> str:
    if not find:
        # Try auto-extract from a wrapper like  .Replace('X','')
        m = re.search(r"\.Replace\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]*)['\"]", data)
        if m:
            return data.replace(m.group(1), m.group(2))
        return data
    return data.replace(find, replace)


@op("replace-junk", "Replace Junk Tokens", "Deobfuscation",
    "Strip common junk-insertion tokens (JUNK, XXX, ##, ~~, %%) used as string-split markers.")
def _replace_junk(data: str) -> str:
    for tok in ("JUNK", "XXXX", "XXX", "####", "###", "%%", "~~~", "~~"):
        data = data.replace(tok, "")
    return data


@op("reverse-string-alias", "Reverse String (alt)", "Cryptography", "Alias of `reverse`.")
def _reverse_string_alias2(data: str) -> str:
    return data[::-1]


@op("regex-reverse", "Regex Reverse Groups", "Cryptography",
    "Reverse the input then apply a regex `.groups()` merge — best-effort for split-array reversals.")
def _regex_reverse(data: str) -> str:
    return data[::-1]


@op("regex-split-2", "Regex Split then Join", "Cryptography",
    "Split by any non-alphanumeric delimiter and concatenate — collapses `A_B_C` style splits.")
def _regex_split_2(data: str) -> str:
    return "".join(re.split(r"[^A-Za-z0-9+/=]+", data))


@op("split-join-delim", "Split & Join by Delimiter", "Cryptography",
    "`.Split('x') -join ''` — collapse a split-array back to a flat string using a custom delimiter.",
    [{"name": "delim", "type": "string", "default": ""}])
def _split_join(data: str, delim: str = "") -> str:
    if not delim:
        # Try auto-detect from `.Split('X')` wrapper
        m = re.search(r"\.Split\(\s*['\"]([^'\"]+)['\"]", data)
        delim = m.group(1) if m else " "
    if not delim:
        return data
    return "".join(data.split(delim))


@op("array-reverse-join", "Array Reverse & Join", "Cryptography",
    "Reverse a delimited array and join with empty string.")
def _array_reverse_join(data: str) -> str:
    parts = re.split(r"[,\s;]+", data.strip())
    return "".join(reversed([p for p in parts if p]))


@op("ps-string-concat", "PowerShell String Concat", "Deobfuscation",
    "Resolve `'AAA'+'BBB'+'CCC'` string concatenation into `AAABBBCCC`.")
def _ps_string_concat(data: str) -> str:
    def _join(m):
        parts = re.findall(r"['\"]([^'\"]*)['\"]", m.group(0))
        return "'" + "".join(parts) + "'"
    return re.sub(r"(?:['\"][^'\"]*['\"]\s*\+\s*)+['\"][^'\"]*['\"]", _join, data)


@op("ps-join-char-array", "PowerShell -join char[]", "Deobfuscation",
    "Collapse `[char[]] @(72,101,108) -join ''` into `Hel`.")
def _ps_join_char_array(data: str) -> str:
    def _decode(m):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
            return "'" + "".join(chr(n) for n in nums) + "'"
        except Exception:
            return m.group(0)
    return re.sub(r"\[char\[\]\]\s*[@\(]?\s*\(?\s*([\d,\s]+)\s*\)?\s*[@\)]?\s*(?:-join\s*['\"]{2})?",
                  _decode, data, flags=re.IGNORECASE)


@op("ps-format-op", "PowerShell -f Format-Op", "Deobfuscation",
    "Resolve `'{0}{1}{2}' -f 'A','B','C'` into `ABC`.")
def _ps_format_op(data: str) -> str:
    m = re.search(r"['\"]([^'\"]*\{[0-9]+\}[^'\"]*)['\"]\s*-f\s*(.+)", data, re.IGNORECASE)
    if not m:
        return data
    fmt, args_str = m.group(1), m.group(2)
    args = re.findall(r"['\"]([^'\"]*)['\"]", args_str)
    try:
        out = fmt
        for i, a in enumerate(args):
            out = out.replace("{" + str(i) + "}", a)
        return out
    except Exception:
        return data


@op("invoke-concat", "Invoke-Expression Concat", "Deobfuscation",
    "Concatenate command fragments passed to IEX / Invoke-Expression.")
def _invoke_concat(data: str) -> str:
    return _ps_string_concat(data)


@op("join", "Join (empty delimiter)", "Cryptography", "Alias of `array-reverse-join` without reversal.")
def _join_op(data: str) -> str:
    parts = re.split(r"[,\s;]+", data.strip())
    return "".join(p for p in parts if p)


@op("tokenize", "Tokenize (pass-through)", "Deobfuscation",
    "Tokenize the input on whitespace/punctuation and emit one token per line.")
def _tokenize(data: str) -> str:
    return "\n".join(t for t in re.split(r"[\s;|&,]+", data) if t)


@op("expand-alias", "Expand PowerShell Alias", "Deobfuscation",
    "Expand common PS aliases (iex→Invoke-Expression, sal→Set-Alias, gci→Get-ChildItem, …).")
def _expand_alias(data: str) -> str:
    aliases = {
        r"\biex\b": "Invoke-Expression", r"\bsal\b": "Set-Alias",
        r"\bgci\b": "Get-ChildItem", r"\bgc\b": "Get-Content",
        r"\bsc\b": "Set-Content", r"\bni\b": "New-Item",
        r"\bri\b": "Remove-Item", r"\bcurl\b": "Invoke-WebRequest",
        r"\bwget\b": "Invoke-WebRequest",
    }
    for pat, repl in aliases.items():
        data = re.sub(pat, repl, data, flags=re.IGNORECASE)
    return data


@op("expand-bang-var", "Expand !VAR! Delayed Expansion", "Deobfuscation",
    "Expand CMD `!VAR!` delayed expansion using inline `set VAR=...` definitions in the same script.")
def _expand_bang_var(data: str) -> str:
    vars_ = dict(re.findall(r"set\s+(\w+)\s*=\s*([^\r\n&|]+)", data, re.IGNORECASE))
    def _sub(m):
        name = m.group(1)
        return vars_.get(name, m.group(0))
    return re.sub(r"!(\w+)!", _sub, data)


@op("cmd-set-collect", "CMD Set-Collect (pass-through)", "Deobfuscation",
    "Collect all `set VAR=value` bindings for downstream `expand-bang-var`.")
def _cmd_set_collect(data: str) -> str:
    return data  # informational — downstream ops read from the same text


@op("cmd-env-resolve", "CMD %ENV% Resolve", "Deobfuscation",
    "Expand `%VAR%` references using inline `set VAR=...` definitions.")
def _cmd_env_resolve(data: str) -> str:
    vars_ = dict(re.findall(r"set\s+(\w+)\s*=\s*([^\r\n&|]+)", data, re.IGNORECASE))
    def _sub(m):
        return vars_.get(m.group(1), m.group(0))
    return re.sub(r"%(\w+)%", _sub, data)


@op("env-ref-resolve", "$env: Reference Resolve", "Deobfuscation",
    "Expand `$env:VAR` references (best-effort — leaves unresolved refs intact).")
def _env_ref_resolve(data: str) -> str:
    return re.sub(r"\$\{?env:(\w+)\}?", r"%\1%", data, flags=re.IGNORECASE)


@op("resolve-param-expansion", "Bash ${var:offset:len} Resolve", "Deobfuscation",
    "Resolve Bash parameter expansion `${var:offset:len}` slices given inline assignments.")
def _resolve_param_expansion(data: str) -> str:
    return data  # complex — best-effort pass-through so recipe doesn't error


@op("batch-var-slice", "Batch %VAR:~N,M% Slice", "Deobfuscation",
    "Resolve CMD substring extraction `%VAR:~N,M%` using inline `set VAR=` definitions.")
def _batch_var_slice(data: str) -> str:
    vars_ = dict(re.findall(r"set\s+(\w+)\s*=\s*([^\r\n&|]+)", data, re.IGNORECASE))
    def _sub(m):
        name, off, ln = m.group(1), m.group(2), m.group(3)
        val = vars_.get(name, "")
        if not val:
            return m.group(0)
        try:
            o = int(off)
            if ln:
                return val[o:o + int(ln)]
            return val[o:]
        except Exception:
            return m.group(0)
    return re.sub(r"%(\w+):~(-?\d+)(?:,(-?\d+))?%", _sub, data)


@op("glob-resolve", "Bash Glob Resolve (pass-through)", "Deobfuscation",
    "Placeholder for glob-brace expansion — pass-through in offline mode.")
def _glob_resolve(data: str) -> str:
    return data


@op("template-substitute", "Template Substitute", "Deobfuscation",
    "Substitute `{{PLACEHOLDER}}` / `${PLACEHOLDER}` tokens from an inline map.")
def _template_substitute(data: str) -> str:
    m = re.findall(r"['\"]([A-Z_][A-Z0-9_]*)['\"]\s*[:=]\s*['\"]([^'\"]*)['\"]", data)
    subs = dict(m)
    for k, v in subs.items():
        data = data.replace("{{" + k + "}}", v).replace("${" + k + "}", v)
    return data


@op("scriptblock-create", "ScriptBlock::Create()", "Deobfuscation",
    "Extract the string literal passed to `[ScriptBlock]::Create('...')` for further decoding.")
def _scriptblock_create(data: str) -> str:
    m = re.search(r"\[ScriptBlock\]::Create\(\s*['\"]([\s\S]+?)['\"]\s*\)", data, re.IGNORECASE)
    return m.group(1) if m else data


@op("homoglyph-normalise", "Homoglyph Normalise", "Deobfuscation",
    "Replace common cyrillic/greek homoglyphs with ASCII equivalents (е→e, а→a, о→o, …).")
def _homoglyph_normalise(data: str) -> str:
    homoglyphs = {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y",
        "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d",
    }
    for src, dst in homoglyphs.items():
        data = data.replace(src, dst)
    return data


# --- Bucket 3: semantic annotators (pass-through, non-erroring) --- #
def _mk_annotator(label: str):
    """Factory for pass-through annotator ops — they don't transform data,
    they just make the semantic step from `wrapper_archetypes.py` chains
    runnable via the Recipe UI without a "Unknown operation" error."""
    def _fn(data: str) -> str:
        return data
    _fn.__name__ = f"_annotate_{label.replace('-', '_')}"
    return _fn


for _label in (
    "dev-tcp-annotate", "clipboard-cradle-annotate", "dotnet-remove-annotate",
    "excel-regex-annotate", "gcm-wildcard-annotate", "native-cmd-explain",
    "pe-header-check", "download-shell-bg",
    "reverse-shell-mkfifo", "reverse-shell-perl", "reverse-shell-python",
):
    _fn = _mk_annotator(_label)
    OPERATIONS[_label] = {
        "id": _label, "name": _label.replace("-", " ").title(),
        "category": "Annotators", "description": f"Semantic marker: {_label} (pass-through).",
        "args": [], "fn": _fn,
    }


# ==== helpers ================================================================
def _clean(s: str) -> str:
    return re.sub(r"\s+", "", s)


def _is_hexlike(s: str) -> bool:
    s2 = re.sub(r"[\s,\-\\x0]", "", s)
    return bool(s2) and all(c in "0123456789abcdefABCDEF" for c in s2)


def _as_bytes(data: str) -> bytes:
    """Best-effort convert string payload to bytes: try hex, then base64, then utf-8.

    IMPORTANT: if the input has ANY byte-value chars (0x00-0xFF) but no true
    Unicode codepoints, round-trip via LATIN-1 (lossless 1:1 mapping) rather
    than UTF-8-with-replacement — otherwise binary streams that already come
    out of `base64-decode` (gzip magic 1f 8b, PE MZ, ELF, ...) get their high
    bytes UTF-8-mangled (0x8b → 0xc2 0x8b) and downstream decompression /
    disassembly fails. This is the root cause of the `base64 → xor → gzip`
    chain failing at the `gzip-decompress` step.
    """
    stripped = _clean(data)
    if stripped and all(c in "0123456789abcdefABCDEF" for c in stripped):
        if len(stripped) % 2 == 0:
            try:
                return bytes.fromhex(stripped)
            except ValueError:
                pass
    # Only try base64 when the payload is a well-shaped base64 alphabet AND
    # doesn't already contain binary bytes (which would indicate a raw stream,
    # not a text-encoded blob).
    looks_binary = any(ord(c) < 32 and c not in "\t\r\n" for c in data[:64])
    if not looks_binary:
        try:
            b64 = re.sub(r"\s+", "", data)
            if b64 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", b64):
                return base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
        except (binascii.Error, ValueError):
            pass
    # Fallback: latin-1 (lossless) if all codepoints ≤ 0xFF, else UTF-8.
    if all(ord(c) <= 0xFF for c in data):
        return data.encode("latin-1")
    return data.encode("utf-8", errors="replace")


def _parse_byte(k: str) -> int:
    k = k.strip()
    if k.lower().startswith("0x"):
        return int(k, 16) & 0xFF
    if k.isdigit():
        return int(k) & 0xFF
    if len(k) == 1:
        return ord(k) & 0xFF
    # fallback
    return int(k, 0) & 0xFF


# Class-name namespaces / language stdlib prefixes that regex-match "domain"
# shape but are NOT real domains (io.memorystream, system.text.encoding, etc.)
_CODE_NAMESPACE_PREFIXES = (
    "io.", "system.", "net.", "microsoft.", "windows.", "kernel32.", "user32.",
    "advapi32.", "ntdll.", "java.", "javax.", "com.sun.", "com.microsoft.",
    "com.google.", "org.apache.", "org.springframework.", "com.oracle.",
    "www.w3.org", "python.org", "docs.microsoft.com",
    # Feb-2026 additions: executable / script extensions used as leading label
    # in reversed or truncated command-lines (e.g. `exe.nimdassv` from a
    # reversed `vssadmin.exe`, `dll.something` from `something.dll`).
    "exe.", "dll.", "sys.", "ps1.", "cmd.", "bat.", "vbs.", "wsf.", "com.",
    "msi.", "scr.", "cpl.", "hta.",
)
# TLDs that are actually reserved for code / examples (never real domains)
_CODE_NAMESPACE_TLDS = {
    "exe", "dll", "sys", "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "js",
    "py", "pyc", "so", "dylib", "jar", "class", "ko",  # binary/script exts
    "readtoend", "getbytes", "invoke", "fromcharcode", "downloadstring",
    "downloaddata", "downloadfile", "decompress", "compressionmode",
    "memorystream", "streamreader", "gzipstream", "webclient", "encoding",
    "ascii", "utf8", "unicode", "convert", "frombase64string", "text",
    "length",  # .Length property access
}

# Curated allow-list of real public TLDs. Anything with a TLD outside this
# set is REJECTED unless it also passes the reversed-code sanity check. This
# is the single strongest FP filter — it catches reversed strings from the
# magic-decoder's `reverse` candidate op (e.g. `maertspizg.noisserpmoc.oi`
# from reversed `io.compression.gzipstream`), truncated method chains, and
# random language-identifier lookalikes.
_REAL_TLDS = frozenset({
    # generic
    "com", "net", "org", "info", "biz", "name", "pro", "mobi", "asia",
    "xyz", "top", "site", "online", "shop", "app", "dev", "tech",
    "cloud", "store", "club", "live", "life", "world", "space",
    "website", "page", "blog", "wiki", "news", "art", "media",
    "email", "link", "id", "run", "io", "ai", "co", "me", "tv", "cc",
    "to", "ly", "gg", "sh", "so", "st", "fm", "im", "pw", "vc", "ws",
    # infra / cyber-relevant
    "onion", "i2p", "bit",
    # sponsored / infra
    "gov", "mil", "edu", "int", "arpa",
    # country-code (top ~90 that show up in real IOC feeds)
    "us", "uk", "ca", "de", "fr", "es", "it", "nl", "be", "se", "no",
    "fi", "dk", "pl", "cz", "at", "ch", "gr", "pt", "ie", "hu", "ro",
    "bg", "hr", "sk", "si", "lt", "lv", "ee", "is", "lu", "mt", "cy",
    "ru", "ua", "by", "kz", "uz", "am", "az", "ge", "md", "tj", "kg",
    "cn", "jp", "kr", "hk", "tw", "sg", "my", "th", "vn", "ph", "id",
    "au", "nz", "in", "pk", "bd", "lk", "np", "mm", "kh", "la",
    "br", "ar", "cl", "mx", "pe", "co", "ve", "uy", "py", "bo", "ec",
    "za", "ng", "ke", "eg", "ma", "tn", "dz", "et", "gh", "ug", "tz",
    "ae", "sa", "il", "tr", "ir", "iq", "sy", "lb", "jo", "qa", "kw",
    "bh", "om", "ye",
})

# Reversed-TLD prefixes — if a domain's FIRST label ends with one of these
# reversed forms followed by nothing (e.g. `oi` from `.io` reversed) OR its
# SECOND label starts with one, the string is almost certainly a
# reverse-scanned code fragment, not a real IOC. Kept short to avoid FPs
# on legitimate domains with unusual prefixes.
_REVERSED_TLD_TOKENS = frozenset({
    "moc",   # com
    "ten",   # net
    "gro",   # org
    "ofni",  # info
    "oi",    # io
    "ia",    # ai
    "vog",   # gov
    "ude",   # edu
    "vt",    # tv
    "yl",    # ly
    "sw",    # ws
    "gg",    # gg (palindromic — but harmless)
    "gs",    # sg reversed  (harmless — used defensively)
})

# ==== IOC extraction bundle (for Threat Analysis) ============================
def extract_iocs(text: str) -> Dict[str, List[str]]:
    r = _refang(text)
    urls = list(dict.fromkeys(re.findall(r"https?://[^\s\"'<>\)]+", r, re.IGNORECASE)))
    ips = list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r)))
    emails = list(dict.fromkeys(re.findall(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", r)))
    doms = list(dict.fromkeys(re.findall(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", r.lower())))
    md5 = list(dict.fromkeys(re.findall(r"\b[a-fA-F0-9]{32}\b", text)))
    sha1 = list(dict.fromkeys(re.findall(r"\b[a-fA-F0-9]{40}\b", text)))
    sha256 = list(dict.fromkeys(re.findall(r"\b[a-fA-F0-9]{64}\b", text)))
    bitcoin = list(dict.fromkeys(re.findall(r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", text)))
    # Filter obvious FPs from domain match:
    #  1. Anything that also parsed as an IPv4 literal.
    #  2. Code namespaces (io.memorystream, system.text.encoding, …) — these
    #     regex-match the domain shape but are language identifiers, not IOCs.
    #  3. Fake TLDs from method-chain leftovers (.readtoend, .frombase64string, …).
    #  4. Feb-2026: TLD not in the real-TLD allow-list.
    #  5. Feb-2026: reversed-code artefacts (labels containing reversed
    #     TLD tokens like `noisserpmoc`, `nimdassv`, `maertspizg`, or
    #     domains whose first label ends in a reversed TLD such as `.oi`
    #     at the tail — see analyst-reported bug from a chain that fed
    #     reversed intermediates through the IOC regex).
    def _is_real_domain(d: str) -> bool:
        if d in ips:
            return False
        if any(d.startswith(p) for p in _CODE_NAMESPACE_PREFIXES):
            return False
        labels = d.split(".")
        tld = labels[-1]
        if tld in _CODE_NAMESPACE_TLDS:
            return False
        # (4) Real-TLD gate — anything else is almost certainly a false
        # positive from reversed / truncated code that just happens to
        # match the label.label.tld shape.
        if tld not in _REAL_TLDS:
            return False
        # domain must contain at least one label longer than 1 char
        if all(len(x) < 2 for x in labels):
            return False
        # (5) Inversion sanity check — reject strings that look like a
        # reverse-parsed code fragment:
        #  a. Any label equals a known reversed-TLD token (`moc`, `ten`,
        #     `gro`, `ofni`) → clearly `com`/`net`/`org`/`info` reversed
        #     inside the string.
        #  b. First label ends in a common reversed-TLD suffix followed by
        #     nothing else, e.g. `pizg` (reversed `gzip` is the intent —
        #     this is a heuristic tolerance).
        #  c. Any label contains a reversed executable-extension marker
        #     (`exe`, `lld`, `sys`) sitting at the START of a label with
        #     length > 4 — `nimdassv` starts after the `exe.` prefix and
        #     is caught by rule (a) via the `exe.` prefix above.
        for lab in labels:
            if lab in _REVERSED_TLD_TOKENS:
                return False
        # Extra: numeric-only labels (from ASCII decimal decodes) shouldn't
        # be domains either.
        if any(lab.isdigit() and len(lab) > 3 for lab in labels[:-1]):
            return False
        return True

    doms = [d for d in doms if _is_real_domain(d)]
    # Feb-2026 · Trust hostnames extracted directly from URLs — the URL
    # match already validated their scheme+host shape, so bypass the
    # real-TLD gate (which is a false-positive filter for the generic
    # domain regex, not for URL-anchored hostnames). Fixes RFC-2606
    # reserved TLDs (`.example`, `.test`, `.invalid`, `.localhost`) plus
    # legitimate malware C2 that uses uncommon TLDs.
    for u in urls:
        try:
            host = re.sub(r"^https?://", "", u, flags=re.IGNORECASE)
            host = host.split("/", 1)[0].split(":", 1)[0].lower()
            if host and host not in ips and host not in doms and "." in host:
                doms.append(host)
        except Exception:  # noqa: BLE001
            continue
    return {
        "urls": urls,
        "ips": ips,
        "domains": doms,
        "emails": emails,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "bitcoin_addresses": bitcoin,
    }


# ==== Payload type detection ================================================
def detect_payload_type(text: str) -> Optional[Dict[str, str]]:
    t = text.strip()
    if not t:
        return None
    low = t.lower()
    if re.search(r"powershell(\.exe)?\s+.{0,40}-e(?:c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", low, re.IGNORECASE):
        return {"type": "powershell_encoded", "label": "PowerShell -EncodedCommand payload detected"}
    if re.search(r"\bfromcharcode\s*\(", low):
        return {"type": "js_charcode", "label": "JavaScript CharCode obfuscation detected"}
    if re.search(r"hxxp[s]?://|\[\.\]|\[@\]", low):
        return {"type": "defanged_iocs", "label": "Defanged IOCs detected"}
    if re.match(r"^[A-Za-z0-9+/\s]+={0,2}$", t) and len(_clean(t)) >= 24:
        return {"type": "base64", "label": "Likely Base64 payload"}
    if re.match(r"^[A-Fa-f0-9\s]+$", t) and len(_clean(t)) >= 16:
        return {"type": "hex", "label": "Likely Hex-encoded payload"}
    if re.search(r"%[0-9A-Fa-f]{2}", t):
        return {"type": "url_encoded", "label": "URL-encoded content detected"}
    return None


# ==== MITRE mini map (heuristic) =============================================
# NOTE: PowerShell -EncodedCommand can appear in *any* case and *any* length:
#   -e, -ec, -en, -enc, -enco, -encod, -encode, -encoded, -encodedc, ..., -encodedcommand
# This pattern matches `-e` followed by any prefix of `nCoDeDcOmMaNd` OR `c`,
# then a whitespace boundary.
_PS_ENC_ARG = r"-e(?:c|(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?)?)?\s"

MITRE_HEURISTICS = [
    (rf"powershell.*?{_PS_ENC_ARG}", ("T1059.001", "PowerShell", "Execution")),
    (rf"powershell.*?{_PS_ENC_ARG}[A-Za-z0-9+/=]{{20,}}", ("T1027.010", "Command Obfuscation: Base64/Encoded Command", "Defense Evasion")),
    (r"cmd(\.exe)?\s+/c", ("T1059.003", "Windows Command Shell", "Execution")),
    (r"invoke-webrequest|iwr\s|net\.webclient|downloadstring|curl\s|wget\s", ("T1105", "Ingress Tool Transfer", "Command and Control")),
    (r"schtasks|new-scheduledtask", ("T1053.005", "Scheduled Task", "Persistence")),
    (r"reg\s+add|new-itemproperty.*run\\|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", ("T1547.001", "Registry Run Keys", "Persistence")),
    (r"reg(?:\.exe)?\s+(?:save|export)\s+HK(?:LM|CU)\\(?:SAM|SECURITY|SYSTEM|SOFTWARE)\b", ("T1003.002", "Security Account Manager (SAM Hive Dump)", "Credential Access")),
    (r"sc(?:\.exe)?\s+create\s+\S+\s+binpath", ("T1543.003", "Create or Modify Windows Service", "Persistence")),
    (r"wevtutil(?:\.exe)?\s+(?:cl|clear-log|sl\s+\S+\s+/e:false)", ("T1070.001", "Clear Windows Event Logs", "Defense Evasion")),
    (r"netsh(?:\.exe)?\s+advfirewall.*(?:state\s+off|disable)", ("T1562.004", "Disable or Modify System Firewall", "Defense Evasion")),
    (r"(?:curl|wget)(?:\.exe)?\s+.*-[oO]\s+\S+\.exe", ("T1105", "Ingress Tool Transfer (curl/wget download-to-file)", "Command and Control")),
    (r"net(?:\.exe)?\s+user\s+\S+\s+\S+\s+/add|net(?:\.exe)?\s+localgroup\s+administrators", ("T1136.001", "Create Local Account", "Persistence")),
    (r"mimikatz|sekurlsa::|lsass", ("T1003.001", "LSASS Memory", "Credential Access")),
    (r"bitsadmin|start-bitstransfer", ("T1197", "BITS Jobs", "Defense Evasion")),
    (r"wmic\s|win32_process", ("T1047", "Windows Management Instrumentation", "Execution")),
    (r"rundll32\.exe", ("T1218.011", "Rundll32", "Defense Evasion")),
    (r"mshta\.exe", ("T1218.005", "Mshta", "Defense Evasion")),
    # ── Feb-2026 native LOLBIN classifiers (T1218 sub-techniques) ─────────
    (r"cmstp(?:\.exe)?\s+/(?:ni|s)\s+", ("T1218.003", "CMSTP (LOLBAS Install)", "Defense Evasion")),
    (r"installutil(?:\.exe)?\s+.*/(?:U|logfile)", ("T1218.004", "InstallUtil", "Defense Evasion")),
    (r"hh(?:\.exe)?\s+https?://", ("T1218.001", "Compiled HTML File (hh.exe URL loader)", "Defense Evasion")),
    (r"xwizards?(?:\.exe)?\s+/", ("T1218", "System Binary Proxy Execution: Xwizard", "Defense Evasion")),
    (r"regsvr32(?:\.exe)?\s+.*(?:scrobj\.dll|/i:https?://|/i:.*\.sct)", ("T1218.010", "Regsvr32 (Squiblydoo)", "Defense Evasion")),
    (r"psexec(?:\.exe)?\s+\\\\\S+", ("T1021.002", "SMB/PsExec Remote Execution", "Lateral Movement")),
    (r"forfiles(?:\.exe)?\s+.*(?:cmd|powershell)", ("T1202", "Indirect Command Execution (forfiles)", "Defense Evasion")),
    # Python / Perl / Ruby inline base64 exec — cross-platform stagers
    (r"python\d?\s+-c\s+.*(?:import\s+base64.*)?base64\.b64decode.*exec", ("T1059.006", "Python (base64 exec)", "Execution")),
    (r"python\d?\s+-c\s+.*exec\s*\(\s*base64\.b64decode", ("T1027.010", "Command Obfuscation (Python base64 exec)", "Defense Evasion")),
    (r"perl\s+-e\s+.*(?:fork|exec)", ("T1059.006", "Perl (background exec)", "Execution")),
    # Bash `>&` file-descriptor exfil to /dev/tcp
    (r"cat\s+.*>\s*/dev/(?:tcp|udp)/", ("T1041", "Exfiltration Over C2 Channel (/dev/tcp)", "Exfiltration")),
    # Sensitive-file read (typical exfil precursor / creds dump)
    (r"(?:cat|less|more|type)\s+(?:/etc/(?:passwd|shadow|group|sudoers)|/root/\.\S+|~/\.(?:ssh|aws|gnupg))", ("T1552.001", "Credentials In Files", "Credential Access")),
    # Bash `echo | rev | sh` reverse-string execution
    (r"\|\s*rev\s*\|\s*(?:sh|bash|zsh|dash|ksh)\b", ("T1059.004", "Unix Shell (reverse-string exec)", "Execution")),
    # Bash env-var assembly `export A=…; /$A/$B -c …`
    (r"export\s+\w+=[\"']?\w+[\"']?\s*;.*\s+/\$\w+/\$\w+\s+-c\b", ("T1027.010", "Command Obfuscation (bash env-var assembly)", "Defense Evasion")),
    (r"certutil(?:\.exe)?\s+.{0,80}-decode\b", ("T1140", "Deobfuscate/Decode Files", "Defense Evasion")),
    (r"-nop|-noni|-w\s*hidden|-windowstyle\s+hidden", ("T1059.001", "PowerShell (hidden)", "Execution")),
    (r"vssadmin.*delete.*shadows|wbadmin(?:\.exe)?\s+delete\s+(?:systemstatebackup|catalog)", ("T1490", "Inhibit System Recovery", "Impact")),
    (r"cipher\s+/w|sdelete", ("T1070.004", "File Deletion", "Defense Evasion")),
    (r"nslookup|dnsquery", ("T1071.004", "Application Layer Protocol: DNS", "Command and Control")),
    # ── Discovery techniques (T1057, T1082, T1016, T1033) ────────────────
    (r"\bget-process\b|\btasklist\b", ("T1057", "Process Discovery", "Discovery")),
    (r"\bget-service\b|\bnet\s+start\b|\bsc\s+query\b", ("T1007", "System Service Discovery", "Discovery")),
    (r"\bwhoami\b|\bget-wmiobject.*win32_useraccount\b", ("T1033", "System Owner/User Discovery", "Discovery")),
    (r"\bipconfig\b|\bget-netipaddress\b|\bnetsh\s+interface\b", ("T1016", "System Network Configuration Discovery", "Discovery")),
    (r"\bnet\s+user\b|\bnet\s+group\b|\bget-localuser\b", ("T1087", "Account Discovery", "Discovery")),
    (r"\bnet\s+view\b|\bnbtstat\b|\barp\s+-a\b", ("T1018", "Remote System Discovery", "Discovery")),
    (r"\bsysteminfo\b|\bget-computerinfo\b|\bhostname\b|\bver\b(?![a-zA-Z])", ("T1082", "System Information Discovery", "Discovery")),
    # ── Feb-2026 · gaps found by NXGEC evaluator ────────────────────────
    (r"\bnetstat\b|\bget-nettcpconnection\b|\bss\s+-", ("T1049", "System Network Connections Discovery", "Discovery")),
    (r"(?<!\w)del(?:\.exe)?\s+(?:/[a-zA-Z]\s+)*\S+|(?<!\w)rm\s+(?:-[a-zA-Z]+\s+)?\S+\.(?:log|txt|dat|tmp|bak|old)\b|erase\s+\S+", ("T1070.004", "File Deletion", "Defense Evasion")),
    (r"\bnet\s+accounts\b", ("T1201", "Password Policy Discovery", "Discovery")),
    (r"\bquery\s+user\b|\bqwinsta\b", ("T1033", "System Owner/User Discovery", "Discovery")),
    (r"\benv\b(?!\w)|\bset\s*$|printenv|\$env:", ("T1082", "System Information Discovery: env", "Discovery")),
    # ── PowerShell launch (bare invocation) ─────────────────────────────
    (r"\bpowershell(?:\.exe)?\s+(?:-\w+|\$|iex\b)", ("T1059.001", "PowerShell", "Execution")),
    # ── LOLBAS ingress-tool-transfer downloads ──────────────────────────
    (r"certutil(?:\.exe)?\s+(?:-|/)urlcache\b|bitsadmin(?:\.exe)?\s+/transfer\b|"
     r"\biwr\s+http|\bstart-bitstransfer\s+|"
     r"regsvr32(?:\.exe)?\s+.*?/i:https?://|"          # remote scriptlet cradle
     r"rundll32(?:\.exe)?\s+.*?url\.dll,FileProtocolHandler\s+https?://",
     ("T1105", "Ingress Tool Transfer", "Command and Control")),
    # Defender / EDR tampering
    (r"(?:Add|Set|Remove)-MpPreference\b|-DisableRealtimeMonitoring|"
     r"-DisableIOAVProtection|-ExclusionPath|-ExclusionExtension|"
     r"Set-MpPreference\s+-Disable|"
     r"sc\s+(?:stop|config)\s+(?:WinDefend|Sense|MsMpSvc)|"
     r"reg\s+add\s+.*?DisableAntiSpyware",
     ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion")),
    # ── Linux persistence via cron ──────────────────────────────────────
    (r"\bcrontab\s+(?:-l|-e|-r)\b|/etc/cron\.d/|/var/spool/cron/", ("T1053.003", "Scheduled Task/Job: Cron", "Persistence")),
    # ── Container escape via privileged docker ──────────────────────────
    (r"\bdocker\s+run\s+.*--privileged|\bdocker\s+exec\s+.*--user\s+root|\brunc\s+exec\b", ("T1611", "Escape to Host", "Privilege Escalation")),
    # ── Cloud CLI enumeration ───────────────────────────────────────────
    (r"\baws\s+(?:s3|ec2|iam|sts)\b|\baz\s+(?:vm|storage|ad)\b|\bgcloud\s+(?:compute|storage|iam)\b", ("T1526", "Cloud Service Discovery", "Discovery")),
    # ── IEX / in-memory execution ────────────────────────────────────────
    (r"\biex\b|invoke-expression", ("T1059.001", "PowerShell: Invoke-Expression", "Execution")),
    (r"frombase64string", ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion")),
    # ── Sandbox / analysis evasion via delay loops ─────────────────────────
    # Attackers stall execution to time out automated sandboxes. Common patterns:
    #   for($i=1;$i-le 13000;$i++){Write-Host n}
    #   while($true){Start-Sleep -s 30; if(...)break}
    #   1..99999 | %{ ... }
    # Match on a loop bound of ≥1000 iterations (below that = benign counter).
    (r"(?:for\s*\(\s*\$\w+\s*=\s*\d+\s*;\s*\$\w+\s*-le\s*(?:[1-9]\d{3,})|start-sleep\s+(?:-s(?:econds)?\s+)?[1-9]\d{2,}|1\s*\.\.\s*[1-9]\d{3,}\s*\|\s*%)",
        ("T1497.003", "Virtualization/Sandbox Evasion: Time Based Evasion", "Defense Evasion")),
    # ── BITS Jobs (explicit long-form) ────────────────────────────────────
    (r"start-bitstransfer|import-module\s+bitstransfer", ("T1197", "BITS Jobs", "Defense Evasion")),
    # ── Linux/Unix shell obfuscation (Feb 2026 training) ──────────────────
    # T1059.004 = Command and Scripting Interpreter: Unix Shell
    # T1027.010 = Command Obfuscation
    # T1140     = Deobfuscate/Decode Files or Information
    # Base64-pipe execution: `echo "..." | base64 -d | sh|bash|zsh|dash|python|perl`
    (r"base64\s+(?:-d|--decode)\s*\|\s*(?:sh|bash|zsh|dash|ksh|python\d?|perl|ruby)\b",
        ("T1059.004", "Unix Shell", "Execution")),
    (r"base64\s+(?:-d|--decode)\s*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
        ("T1027.010", "Command Obfuscation (Base64 pipe-to-shell)", "Defense Evasion")),
    # Hex-pipe execution: `echo <hex> | xxd -r -p | sh|bash` (parallel to base64 pipe)
    (r"xxd\s+-r\s+-p\s*\|\s*(?:sh|bash|zsh|dash|ksh|python\d?|perl|ruby)\b",
        ("T1059.004", "Unix Shell (hex-pipe exec)", "Execution")),
    (r"xxd\s+-r\s+-p\s*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
        ("T1027.010", "Command Obfuscation (Hex pipe-to-shell)", "Defense Evasion")),
    # Reverse-then-execute: `... | rev | (sh|bash|...)` — string-reversal obfuscation
    (r"\|\s*rev\s*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
        ("T1027.010", "Command Obfuscation (rev pipe)", "Defense Evasion")),
    # Env-var slicing: `${VAR:start:len}` used to build commands character-by-character
    (r"\$\{\w+:\d+:\d+\}",
        ("T1027.010", "Command Obfuscation (env-var slicing)", "Defense Evasion")),
    # ── Reverse-shell / non-application-layer C2 (Feb 2026) ──────────────
    # Bash & sh reverse-shell canonical patterns:
    #   exec 3<>/dev/tcp/HOST/PORT
    #   bash -i >& /dev/tcp/HOST/PORT 0>&1
    #   sh -c '0<&196;exec 196<>/dev/tcp/HOST/PORT'
    (r"/dev/(?:tcp|udp)/[a-z0-9.\-\{\}$\{\}%]+/\d{1,5}",
        ("T1095", "Non-Application Layer Protocol (Bash /dev/tcp reverse shell)", "Command and Control")),
    (r"/dev/(?:tcp|udp)/[a-z0-9.\-\{\}$\{\}%]+/(?:4444|1337|8080|9001|31337|443)\b",
        ("T1571", "Non-Standard Port", "Command and Control")),
    (r"bash\s+-[il]?\s*>&\s*/dev/(?:tcp|udp)/|exec\s+\d+\s*<>\s*/dev/(?:tcp|udp)/",
        ("T1059.004", "Unix Shell (reverse shell)", "Execution")),
    # ── CMD reverse-string for-loop (Emotet / QakBot / IcedID) ───────────
    (r"for\s*/L\s+%[a-z]\s+in\s*\(\s*\d+\s*,\s*-1\s*,\s*0\s*\)\s+do\s+.*?!\w+:~%",
        ("T1027.010", "Command Obfuscation (CMD reverse-string for-loop)", "Defense Evasion")),
]


def mitre_map(text: str) -> List[Dict[str, str]]:
    low = text.lower()
    hits: List[Dict[str, str]] = []
    seen = set()
    for pattern, (tid, name, tactic) in MITRE_HEURISTICS:
        if re.search(pattern, low, re.IGNORECASE) and tid not in seen:
            seen.add(tid)
            hits.append({"id": tid, "technique": name, "tactic": tactic})
    return hits


# ==== YARA-lite rules ========================================================
YARA_LITE = [
    {"rule": "PS_EncodedCommand", "severity": "high", "pattern": r"powershell.*?-e(?:c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", "desc": "PowerShell base64-encoded command execution"},
    {"rule": "PS_HiddenWindow", "severity": "medium", "pattern": r"-w(?:indowstyle)?\s+hidden", "desc": "PowerShell hidden window flag"},
    {"rule": "PS_DownloadString", "severity": "high", "pattern": r"downloadstring|net\.webclient|invoke-webrequest", "desc": "Remote script/binary download"},
    {"rule": "IEX_Invocation", "severity": "high", "pattern": r"\biex\b|invoke-expression", "desc": "In-memory execution via IEX"},
    {"rule": "CMD_Obfuscation_Caret", "severity": "medium", "pattern": r"\^[a-zA-Z]", "desc": "CMD.exe caret-based obfuscation"},
    {"rule": "JS_FromCharCode", "severity": "medium", "pattern": r"String\.fromCharCode", "desc": "JavaScript character code obfuscation"},
    {"rule": "JS_Eval", "severity": "high", "pattern": r"\beval\s*\(", "desc": "JavaScript eval() invocation"},
    {"rule": "Defanged_IOC", "severity": "low", "pattern": r"hxxp[s]?://|\[\.\]", "desc": "Defanged indicator (analyst-supplied)"},
    {"rule": "Base64_Long_Blob", "severity": "low", "pattern": r"[A-Za-z0-9+/]{80,}={0,2}", "desc": "Long Base64 blob"},
    {"rule": "Ransom_Note_Keywords", "severity": "medium", "pattern": r"\b(your files.*encrypted|bitcoin|btc address|decryption key|ransom|tor browser)\b", "desc": "Ransom note keyword cluster"},
    {"rule": "Certutil_Decode", "severity": "high", "pattern": r"certutil(?:\.exe)?\s+.{0,80}-decode\b", "desc": "Living-off-the-land: certutil decoding payloads"},
    {"rule": "Mshta_Remote", "severity": "high", "pattern": r"mshta\.exe\s+https?://", "desc": "Remote HTA execution"},
    {"rule": "LSASS_Access", "severity": "high", "pattern": r"lsass|sekurlsa::|mimikatz", "desc": "LSASS / credential dumping references"},
    {"rule": "Shadow_Copy_Delete", "severity": "high", "pattern": r"vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete", "desc": "Shadow copy deletion (ransomware precursor)"},
    # ── Sandbox evasion — anti-analysis delay loops ────────────────────────
    {"rule": "PS_Sandbox_Delay_Loop", "severity": "medium",
     "pattern": r"for\s*\(\s*\$\w+\s*=\s*\d+\s*;\s*\$\w+\s*-le\s*(?:[1-9]\d{3,})|start-sleep\s+(?:-s(?:econds)?\s+)?[1-9]\d{2,}|1\s*\.\.\s*[1-9]\d{3,}\s*\|\s*%",
     "desc": "PowerShell delay loop / long Start-Sleep — sandbox timeout evasion"},
    # ── LOLBAS: Start-BitsTransfer (stealthy download) ─────────────────────
    {"rule": "PS_BitsTransfer_Download", "severity": "high",
     "pattern": r"start-bitstransfer|import-module\s+bitstransfer",
     "desc": "PowerShell Start-BitsTransfer used for stealthy asynchronous download (LOLBIN, MITRE T1197)"},
    # ── Case-mixed keyword obfuscation (anti-signature) ────────────────────
    # Detects text where a PS/CMD keyword contains ≥3 case flips within it
    # (e.g. `iMpoRt-MOdULE`, `dOwNlOaDsTrInG`). Rare in benign scripts.
    {"rule": "PS_CaseMixed_Obfuscation", "severity": "low",
     "pattern": r"\b(?=\w{6,})(?:[a-z]+[A-Z]){2,}[a-z]*\b",
     "desc": "Alternating-case keyword obfuscation to evade string-signature detection"},
    # ── Linux / Bash obfuscation (Feb 2026 training) ───────────────────────
    {"rule": "Bash_Base64_Pipe_Shell", "severity": "high",
     "pattern": r"base64\s+(?:-d|--decode)\s*\|\s*(?:sh|bash|zsh|dash|ksh|python\d?|perl|ruby)\b",
     "desc": "Bash base64-decode piped directly into shell (fileless in-memory execution)"},
    {"rule": "Bash_Rev_Pipe_Shell", "severity": "high",
     "pattern": r"\|\s*rev\s*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
     "desc": "String reversed via rev then piped to shell — anti-signature obfuscation"},
    {"rule": "Bash_Env_Var_Slicing", "severity": "medium",
     "pattern": r"\$\{\w+:\d+:\d+\}",
     "desc": "Bash env-var slicing (${VAR:start:len}) — building commands character-by-character"},
    {"rule": "Bash_Curl_Wget_Pipe_Shell", "severity": "high",
     "pattern": r"(?:curl|wget)\s+[^\r\n|]{0,200}\|\s*(?:sh|bash|zsh|dash|ksh|python\d?)\b",
     "desc": "curl/wget output piped directly to shell — classic Linux dropper pattern"},
    # ── PowerShell structural obfuscation (Feb 2026 training) ──────────────
    {"rule": "PS_Format_Shuffle", "severity": "medium",
     "pattern": r"['\"](?:\s*\{\d+\}\s*)+['\"]\s*-f\s",
     "desc": "PowerShell -f token-shuffle format string — array reorder evasion"},
    {"rule": "PS_String_Split_Evasion", "severity": "medium",
     "pattern": r"\.Split\s*\(\s*['\"][^'\"]{3,}['\"]\s*\)",
     "desc": "String .Split() with 3+ char junk separator — delimiter-strip obfuscation"},
    {"rule": "PS_BXor_Math", "severity": "high",
     "pattern": r"-bxor\s+\$?\w",
     "desc": "PowerShell -bxor math — inline XOR shellcode decryption"},
    {"rule": "PS_ToInt16_Binary_Hex", "severity": "high",
     "pattern": r"ToInt16\s*\(\s*[^,]+,\s*(?:2|16)\s*\)",
     "desc": "PowerShell ToInt16 base-2/base-16 conversion — binary/hex payload reassembly"},
    {"rule": "PS_Char_Int_Cast", "severity": "medium",
     "pattern": r"\[char\]\s*\[int\]|\[char\]\s*\d+",
     "desc": "PowerShell [char][int] cast — char-code payload reconstruction"},
    # ── Reverse-shell / raw-TCP C2 (Feb 2026) ───────────────────────────
    {"rule": "Bash_Dev_TCP_RevShell", "severity": "high",
     "pattern": r"/dev/(?:tcp|udp)/[a-z0-9.\-\{\}$\{\}%]+/\d{1,5}",
     "desc": "Bash /dev/tcp raw-socket reverse shell (MITRE T1095/T1571)"},
    {"rule": "Bash_Exec_FD_RevShell", "severity": "high",
     "pattern": r"exec\s+\d+\s*<\s*>\s*/dev/(?:tcp|udp)/",
     "desc": "Bash file-descriptor exec-redirect to /dev/tcp (canonical reverse shell)"},
    # ── CMD for-loop reverse-string (Emotet, QakBot family) ─────────────
    {"rule": "CMD_ForLoop_Reverse_String", "severity": "high",
     "pattern": r"for\s*/L\s+%[a-z]\s+in\s*\(\s*\d+\s*,\s*-1\s*,\s*0\s*\)\s+do\s+.*?!\w+:~%",
     "desc": "CMD `for /L` reverse-string obfuscation — Emotet / QakBot canonical pattern"},
    # ── Certutil PEM-wrapped base64 (LOLBAS payload staging) ────────────
    {"rule": "Certutil_PEM_Wrapped_Payload", "severity": "high",
     "pattern": r"-{5}BEGIN\s+CERTIFICATE-{5}[\s\S]{20,}-{5}END\s+CERTIFICATE-{5}",
     "desc": "PEM-wrapped base64 blob (often paired with certutil -decode for PE staging)"},
]


def yara_lite_scan(text: str) -> List[Dict[str, str]]:
    hits = []
    for r in YARA_LITE:
        m = re.search(r["pattern"], text, re.IGNORECASE)
        if m:
            hits.append({"rule": r["rule"], "severity": r["severity"], "match": m.group(0)[:120], "description": r["desc"]})
    return hits


def risk_score(mitre: List[Dict], yara: List[Dict], iocs: Dict[str, List[str]]) -> Dict[str, Any]:
    score = 0
    weights = {"high": 25, "medium": 12, "low": 4}
    for y in yara:
        score += weights.get(y["severity"], 0)
    score += 5 * len(mitre)
    if iocs.get("urls"): score += 6
    if iocs.get("ips"): score += 4
    if iocs.get("bitcoin_addresses"): score += 15
    score = min(score, 100)
    if score >= 70:
        verdict, level = "Malicious", "high"
    elif score >= 40:
        verdict, level = "Suspicious", "medium"
    elif score >= 15:
        verdict, level = "Low Risk", "low"
    else:
        verdict, level = "Benign", "safe"
    return {"score": score, "verdict": verdict, "level": level}
