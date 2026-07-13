"""NivXary — 42+ decode/deobfuscate operations."""
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
@op("base64-decode", "Base64 Decode", "Cryptography", "Decode a Base64 string.")
def _b64_decode(data: str) -> str:
    return base64.b64decode(_clean(data), validate=False).decode("utf-8", errors="replace")


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


@op("powershell-encoded", "PowerShell -EncodedCommand", "Deobfuscation", "Decode -EncodedCommand base64+UTF-16LE payload from a PowerShell command line.")
def _ps_encoded(data: str) -> str:
    m = re.search(r"(?:-e(?:c|nc|ncoded(?:command)?)?)\s+([A-Za-z0-9+/=]{20,})", data, re.IGNORECASE)
    payload = m.group(1) if m else _clean(data)
    raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=False)
    try:
        return raw.decode("utf-16-le")
    except Exception:
        return raw.decode("utf-8", errors="replace")


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


# ==== helpers ================================================================
def _clean(s: str) -> str:
    return re.sub(r"\s+", "", s)


def _is_hexlike(s: str) -> bool:
    s2 = re.sub(r"[\s,\-\\x0]", "", s)
    return bool(s2) and all(c in "0123456789abcdefABCDEF" for c in s2)


def _as_bytes(data: str) -> bytes:
    """Best-effort convert string payload to bytes: try hex, then base64, then utf-8."""
    stripped = _clean(data)
    if stripped and all(c in "0123456789abcdefABCDEF" for c in stripped):
        if len(stripped) % 2 == 0:
            try:
                return bytes.fromhex(stripped)
            except ValueError:
                pass
    try:
        return base64.b64decode(stripped + "=" * (-len(stripped) % 4), validate=False)
    except (binascii.Error, ValueError):
        pass
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
    # filter obvious FPs from domain match
    doms = [d for d in doms if d not in ips]
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
MITRE_HEURISTICS = [
    (r"powershell.*?-e(?:c|nc)?\s", ("T1059.001", "PowerShell", "Execution")),
    (r"cmd(\.exe)?\s+/c", ("T1059.003", "Windows Command Shell", "Execution")),
    (r"invoke-webrequest|iwr\s|net\.webclient|downloadstring|curl\s|wget\s", ("T1105", "Ingress Tool Transfer", "Command and Control")),
    (r"schtasks|new-scheduledtask", ("T1053.005", "Scheduled Task", "Persistence")),
    (r"reg\s+add|new-itemproperty.*run\\|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", ("T1547.001", "Registry Run Keys", "Persistence")),
    (r"mimikatz|sekurlsa::|lsass", ("T1003.001", "LSASS Memory", "Credential Access")),
    (r"bitsadmin|start-bitstransfer", ("T1197", "BITS Jobs", "Defense Evasion")),
    (r"wmic\s|win32_process", ("T1047", "Windows Management Instrumentation", "Execution")),
    (r"rundll32\.exe", ("T1218.011", "Rundll32", "Defense Evasion")),
    (r"mshta\.exe", ("T1218.005", "Mshta", "Defense Evasion")),
    (r"certutil\.exe.*-decode", ("T1140", "Deobfuscate/Decode Files", "Defense Evasion")),
    (r"-nop|-noni|-w\s*hidden|-windowstyle\s+hidden", ("T1059.001", "PowerShell (hidden)", "Execution")),
    (r"vssadmin.*delete.*shadows", ("T1490", "Inhibit System Recovery", "Impact")),
    (r"cipher\s+/w|sdelete", ("T1070.004", "File Deletion", "Defense Evasion")),
    (r"nslookup|dnsquery", ("T1071.004", "Application Layer Protocol: DNS", "Command and Control")),
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
    {"rule": "Certutil_Decode", "severity": "high", "pattern": r"certutil\.exe.*-decode", "desc": "Living-off-the-land: certutil decoding payloads"},
    {"rule": "Mshta_Remote", "severity": "high", "pattern": r"mshta\.exe\s+https?://", "desc": "Remote HTA execution"},
    {"rule": "LSASS_Access", "severity": "high", "pattern": r"lsass|sekurlsa::|mimikatz", "desc": "LSASS / credential dumping references"},
    {"rule": "Shadow_Copy_Delete", "severity": "high", "pattern": r"vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete", "desc": "Shadow copy deletion (ransomware precursor)"},
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
