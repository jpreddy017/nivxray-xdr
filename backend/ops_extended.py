"""NivXRay — Extended operations (Session 5).

Adds ~40 high-value CyberChef-parity operations across:
    - Symmetric crypto  (AES/DES/3DES/RC4/ChaCha20)
    - Hashing / HMAC   (SHA3, MD4, RIPEMD-160, HMAC variants)
    - Compression      (bzip2, LZMA, LZ4)
    - Codecs           (UTF-16BE, UTF-32, CP1252/ANSI, ASCII85)
    - Structured data  (JWT, ASN.1/DER, X.509, MessagePack)
    - Binary parsing   (PE, ELF, PDF header)
    - JavaScript       (beautify, hex-string decoder)

All operations register into the same OPERATIONS registry from operations.py
via the shared `op` decorator. Missing library imports are guarded so a single
missing dep doesn't break the whole module import.
"""
from __future__ import annotations
import base64
import binascii
import bz2
import codecs
import hashlib
import hmac
import json
import lzma
import re
import struct
from typing import Any, Dict, List, Optional

from operations import op

# ==== optional third-party deps ============================================
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    from cryptography.hazmat.primitives import padding as _crypto_padding  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False

try:
    import lz4.frame as _lz4frame  # type: ignore
    import lz4.block as _lz4block  # type: ignore
    _HAS_LZ4 = True
except Exception:  # pragma: no cover
    _HAS_LZ4 = False

try:
    import msgpack as _msgpack  # type: ignore
    _HAS_MSGPACK = True
except Exception:  # pragma: no cover
    _HAS_MSGPACK = False

try:
    import jwt as _pyjwt  # type: ignore
    _HAS_JWT = True
except Exception:  # pragma: no cover
    _HAS_JWT = False

try:
    import pefile as _pefile  # type: ignore
    _HAS_PEFILE = True
except Exception:  # pragma: no cover
    _HAS_PEFILE = False

try:
    from elftools.elf.elffile import ELFFile as _ELFFile  # type: ignore
    _HAS_ELFTOOLS = True
except Exception:  # pragma: no cover
    _HAS_ELFTOOLS = False

try:
    import jsbeautifier as _jsbeautifier  # type: ignore
    _HAS_JSBEAUTIFIER = True
except Exception:  # pragma: no cover
    _HAS_JSBEAUTIFIER = False

try:
    from pyasn1.codec.der.decoder import decode as _der_decode  # type: ignore
    from pyasn1.codec.native.encoder import encode as _asn1_to_native  # type: ignore
    _HAS_ASN1 = True
except Exception:  # pragma: no cover
    _HAS_ASN1 = False


# ==== helpers ==============================================================
def _bin_from(data: str, encoding: str = "utf-8") -> bytes:
    """Best-effort convert a string input into bytes for a crypto op.

    Accepts: base64 (with or without padding), hex, or raw text.
    """
    s = (data or "").strip()
    # hex?
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)+", s):
        return bytes.fromhex(re.sub(r"\s+", "", s))
    # base64?
    try:
        b64 = re.sub(r"\s+", "", s)
        if b64 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", b64):
            padded = b64 + "=" * (-len(b64) % 4)
            return base64.b64decode(padded, validate=False)
    except Exception:
        pass
    return s.encode(encoding, errors="replace")


def _key_from(k: str) -> bytes:
    return _bin_from(k)


def _try_utf8(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        # If not UTF-8, return hex preview so nothing is silently truncated
        return f"<binary: {len(b)} bytes>\n" + b.hex(sep=" ", bytes_per_sep=1)[:2400]


def _unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        return data
    try:
        unpadder = _crypto_padding.PKCS7(block_size * 8).unpadder()
        return unpadder.update(data) + unpadder.finalize()
    except Exception:
        return data


# =============================================================================
# CRYPTO — symmetric decrypt
# =============================================================================
_CRYPTO_ARGS = [
    {"name": "key", "type": "string", "required": True, "help": "hex or base64"},
    {"name": "iv",  "type": "string", "required": False, "help": "hex or base64 (16 bytes for AES, 8 for DES/3DES)"},
]


@op("aes-cbc-decrypt", "AES-CBC Decrypt", "Cryptography",
    "Decrypt AES-128/192/256 in CBC mode with PKCS#7 unpadding.", args=_CRYPTO_ARGS)
def _aes_cbc_dec(data: str, key: str = "", iv: str = "", **_) -> str:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography library not installed")
    ct = _bin_from(data)
    k = _key_from(key)
    ivb = _bin_from(iv) if iv else b"\x00" * 16
    c = Cipher(algorithms.AES(k), modes.CBC(ivb), backend=default_backend())
    dec = c.decryptor()
    pt = dec.update(ct) + dec.finalize()
    return _try_utf8(_unpad_pkcs7(pt, 16))


@op("aes-gcm-decrypt", "AES-GCM Decrypt", "Cryptography",
    "Decrypt AES-GCM. Provide key, iv (nonce). Tag is the last 16 bytes of ciphertext.", args=_CRYPTO_ARGS)
def _aes_gcm_dec(data: str, key: str = "", iv: str = "", **_) -> str:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography library not installed")
    ct_full = _bin_from(data)
    if len(ct_full) < 16:
        raise ValueError("ciphertext too short (need at least 16 bytes for tag)")
    ct, tag = ct_full[:-16], ct_full[-16:]
    c = Cipher(algorithms.AES(_key_from(key)), modes.GCM(_bin_from(iv), tag), backend=default_backend())
    dec = c.decryptor()
    return _try_utf8(dec.update(ct) + dec.finalize())


@op("aes-ecb-decrypt", "AES-ECB Decrypt", "Cryptography",
    "Decrypt AES in ECB mode (no IV) with PKCS#7 unpadding.", args=[_CRYPTO_ARGS[0]])
def _aes_ecb_dec(data: str, key: str = "", **_) -> str:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography library not installed")
    ct = _bin_from(data)
    c = Cipher(algorithms.AES(_key_from(key)), modes.ECB(), backend=default_backend())
    dec = c.decryptor()
    return _try_utf8(_unpad_pkcs7(dec.update(ct) + dec.finalize(), 16))


@op("des-cbc-decrypt", "DES-CBC Decrypt", "Cryptography",
    "Decrypt DES in CBC mode with PKCS#7 unpadding (key/iv 8 bytes).", args=_CRYPTO_ARGS)
def _des_cbc_dec(data: str, key: str = "", iv: str = "", **_) -> str:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography library not installed")
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES  # DES via TripleDES for API
    ct = _bin_from(data)
    k = _key_from(key)
    ivb = _bin_from(iv) if iv else b"\x00" * 8
    # `cryptography` deprecated 8-byte DES; use TripleDES with 8-byte key which is DES.
    if len(k) == 8:
        c = Cipher(TripleDES(k), modes.CBC(ivb), backend=default_backend())
    elif len(k) in (16, 24):
        c = Cipher(TripleDES(k), modes.CBC(ivb), backend=default_backend())
    else:
        raise ValueError("DES key must be 8, 16, or 24 bytes")
    dec = c.decryptor()
    return _try_utf8(_unpad_pkcs7(dec.update(ct) + dec.finalize(), 8))


@op("3des-cbc-decrypt", "3DES-CBC Decrypt", "Cryptography",
    "Decrypt Triple-DES in CBC mode with PKCS#7 unpadding (key 16 or 24 bytes).", args=_CRYPTO_ARGS)
def _tdes_cbc_dec(data: str, key: str = "", iv: str = "", **_) -> str:
    return _des_cbc_dec(data, key=key, iv=iv)  # same wrapper handles 3DES


@op("rc4-decrypt", "RC4 (ARC4) Decrypt", "Cryptography",
    "Decrypt RC4 stream cipher. Same operation as encrypt — feed ciphertext + key.", args=[_CRYPTO_ARGS[0]])
def _rc4_dec(data: str, key: str = "", **_) -> str:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography library not installed")
    ct = _bin_from(data)
    c = Cipher(algorithms.ARC4(_key_from(key)), mode=None, backend=default_backend())
    dec = c.decryptor()
    return _try_utf8(dec.update(ct) + dec.finalize())


@op("chacha20-decrypt", "ChaCha20 Decrypt", "Cryptography",
    "Decrypt ChaCha20 stream cipher. Key must be 32 bytes, nonce 16 bytes.",
    args=[_CRYPTO_ARGS[0], {"name": "nonce", "type": "string", "required": True, "help": "16 bytes (hex or base64)"}])
def _chacha20_dec(data: str, key: str = "", nonce: str = "", **_) -> str:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography library not installed")
    ct = _bin_from(data)
    n = _bin_from(nonce)
    if len(n) == 12:  # RFC 7539 nonce — prepend 4-byte counter=0
        n = b"\x00\x00\x00\x00" + n
    if len(n) != 16:
        raise ValueError("ChaCha20 nonce must be 16 bytes (or 12 with an implicit counter)")
    c = Cipher(algorithms.ChaCha20(_key_from(key), n), mode=None, backend=default_backend())
    dec = c.decryptor()
    return _try_utf8(dec.update(ct) + dec.finalize())


# =============================================================================
# HASHING / HMAC / KDF
# =============================================================================
@op("sha3-256", "SHA3-256", "Hashing", "SHA-3 256-bit hash.")
def _sha3_256(data: str) -> str:
    return hashlib.sha3_256(data.encode("utf-8", errors="replace")).hexdigest()


@op("sha3-512", "SHA3-512", "Hashing", "SHA-3 512-bit hash.")
def _sha3_512(data: str) -> str:
    return hashlib.sha3_512(data.encode("utf-8", errors="replace")).hexdigest()


@op("md4", "MD4", "Hashing", "MD4 hash (rare — used by NTLM).")
def _md4(data: str) -> str:
    try:
        return hashlib.new("md4", data.encode("utf-8", errors="replace")).hexdigest()
    except ValueError:
        # OpenSSL 3+ disables MD4 by default — fall back to manual impl if needed
        raise RuntimeError("MD4 disabled by the installed OpenSSL. Use NTLM decode instead.")


@op("ripemd-160", "RIPEMD-160", "Hashing", "RIPEMD-160 hash (used by Bitcoin address derivation).")
def _ripemd(data: str) -> str:
    try:
        return hashlib.new("ripemd160", data.encode("utf-8", errors="replace")).hexdigest()
    except ValueError:
        raise RuntimeError("RIPEMD-160 disabled by the installed OpenSSL.")


_HMAC_ARGS = [{"name": "key", "type": "string", "required": True, "help": "HMAC key (utf-8 or hex/base64)"}]


@op("hmac-sha1", "HMAC-SHA1", "Hashing", "Keyed HMAC-SHA1.", args=_HMAC_ARGS)
def _hmac_sha1(data: str, key: str = "", **_) -> str:
    return hmac.new(_key_from(key), data.encode("utf-8", errors="replace"), hashlib.sha1).hexdigest()


@op("hmac-sha256", "HMAC-SHA256", "Hashing", "Keyed HMAC-SHA256.", args=_HMAC_ARGS)
def _hmac_sha256(data: str, key: str = "", **_) -> str:
    return hmac.new(_key_from(key), data.encode("utf-8", errors="replace"), hashlib.sha256).hexdigest()


@op("hmac-sha512", "HMAC-SHA512", "Hashing", "Keyed HMAC-SHA512.", args=_HMAC_ARGS)
def _hmac_sha512(data: str, key: str = "", **_) -> str:
    return hmac.new(_key_from(key), data.encode("utf-8", errors="replace"), hashlib.sha512).hexdigest()


@op("hmac-md5", "HMAC-MD5", "Hashing", "Keyed HMAC-MD5.", args=_HMAC_ARGS)
def _hmac_md5(data: str, key: str = "", **_) -> str:
    return hmac.new(_key_from(key), data.encode("utf-8", errors="replace"), hashlib.md5).hexdigest()


@op("pbkdf2-sha256", "PBKDF2-HMAC-SHA256", "Hashing",
    "Password-based key derivation. Args: salt (utf-8), iterations, length (bytes, default 32).",
    args=[
        {"name": "salt", "type": "string", "required": True},
        {"name": "iterations", "type": "int", "required": False, "default": 100000},
        {"name": "length", "type": "int", "required": False, "default": 32},
    ])
def _pbkdf2(data: str, salt: str = "", iterations: int = 100000, length: int = 32, **_) -> str:
    it = int(iterations or 100000)
    ln = int(length or 32)
    dk = hashlib.pbkdf2_hmac("sha256", data.encode("utf-8"), salt.encode("utf-8"), it, dklen=ln)
    return dk.hex()


# =============================================================================
# COMPRESSION
# =============================================================================
@op("bzip2-decompress", "Bzip2 Decompress", "Compression", "Decompress a bzip2-compressed blob (accepts base64 or hex).")
def _bz2_dec(data: str) -> str:
    return _try_utf8(bz2.decompress(_bin_from(data)))


@op("lzma-decompress", "LZMA/XZ Decompress", "Compression", "Decompress an LZMA/XZ blob (accepts base64 or hex).")
def _lzma_dec(data: str) -> str:
    return _try_utf8(lzma.decompress(_bin_from(data)))


@op("lz4-frame-decompress", "LZ4 Frame Decompress", "Compression", "Decompress an LZ4-framed blob.")
def _lz4_frame_dec(data: str) -> str:
    if not _HAS_LZ4:
        raise RuntimeError("lz4 library not installed")
    return _try_utf8(_lz4frame.decompress(_bin_from(data)))


@op("lz4-block-decompress", "LZ4 Block Decompress", "Compression",
    "Decompress an LZ4 block (raw). Requires uncompressed_size hint.",
    args=[{"name": "uncompressed_size", "type": "int", "required": True}])
def _lz4_block_dec(data: str, uncompressed_size: int = 0, **_) -> str:
    if not _HAS_LZ4:
        raise RuntimeError("lz4 library not installed")
    return _try_utf8(_lz4block.decompress(_bin_from(data), uncompressed_size=int(uncompressed_size or 0)))


# =============================================================================
# CODECS
# =============================================================================
@op("utf16-be-decode", "UTF-16BE Decode", "Codecs",
    "Decode a UTF-16 big-endian byte stream (hex/base64/raw).")
def _utf16be(data: str) -> str:
    return _bin_from(data).decode("utf-16-be", errors="replace")


@op("utf32-le-decode", "UTF-32LE Decode", "Codecs",
    "Decode a UTF-32 little-endian byte stream.")
def _utf32le(data: str) -> str:
    return _bin_from(data).decode("utf-32-le", errors="replace")


@op("utf32-be-decode", "UTF-32BE Decode", "Codecs",
    "Decode a UTF-32 big-endian byte stream.")
def _utf32be(data: str) -> str:
    return _bin_from(data).decode("utf-32-be", errors="replace")


@op("cp1252-decode", "ANSI/CP1252 Decode", "Codecs",
    "Decode a Windows CP1252 (ANSI) byte stream.")
def _cp1252(data: str) -> str:
    return _bin_from(data).decode("cp1252", errors="replace")


@op("ascii85-decode", "ASCII85 Decode", "Codecs", "Decode Adobe ASCII85 (btoa) or z85-style input.")
def _a85(data: str) -> str:
    s = data.strip()
    # Adobe delimiters
    if s.startswith("<~") and s.endswith("~>"):
        s = s[2:-2]
    try:
        return _try_utf8(base64.a85decode(s, adobe=False))
    except Exception:
        return _try_utf8(base64.a85decode(data.encode(), adobe=True))


@op("base85-decode", "Base85 (RFC1924) Decode", "Codecs", "Decode RFC 1924 base85.")
def _b85(data: str) -> str:
    return _try_utf8(base64.b85decode(data.strip()))


# =============================================================================
# STRUCTURED DATA
# =============================================================================
@op("jwt-decode", "JWT Decode (header + payload)", "Structured Data",
    "Split and decode a JWT — returns pretty-printed header + payload (no signature verify).")
def _jwt_decode(data: str) -> str:
    s = data.strip()
    parts = s.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (need at least header.payload)")
    def _b64url(x: str) -> Dict[str, Any]:
        pad = x + "=" * (-len(x) % 4)
        return json.loads(base64.urlsafe_b64decode(pad).decode("utf-8", errors="replace"))
    header = _b64url(parts[0])
    payload = _b64url(parts[1])
    return json.dumps({"header": header, "payload": payload,
                       "signature_b64url": parts[2] if len(parts) > 2 else None}, indent=2)


@op("jwt-verify", "JWT Verify (HS256/384/512)", "Structured Data",
    "Verify a JWT signature with a shared secret (HS256/HS384/HS512 only).",
    args=[{"name": "secret", "type": "string", "required": True}])
def _jwt_verify(data: str, secret: str = "", **_) -> str:
    if not _HAS_JWT:
        raise RuntimeError("PyJWT not installed")
    try:
        payload = _pyjwt.decode(data.strip(), secret, algorithms=["HS256", "HS384", "HS512"])
        return json.dumps({"valid": True, "payload": payload}, indent=2)
    except Exception as e:
        return json.dumps({"valid": False, "error": str(e)}, indent=2)


@op("asn1-parse", "ASN.1/DER Parse", "Structured Data", "Parse a DER-encoded ASN.1 blob into a Python-style tree.")
def _asn1_parse(data: str) -> str:
    if not _HAS_ASN1:
        raise RuntimeError("pyasn1 not installed")
    der = _bin_from(data)
    obj, _rest = _der_decode(der)
    return json.dumps(_asn1_to_native(obj), indent=2, default=lambda o: repr(o))


@op("msgpack-decode", "MessagePack Decode", "Structured Data", "Decode a MessagePack blob to JSON.")
def _mp(data: str) -> str:
    if not _HAS_MSGPACK:
        raise RuntimeError("msgpack not installed")
    return json.dumps(_msgpack.unpackb(_bin_from(data), raw=False, strict_map_key=False), indent=2, default=str)


@op("json-diff", "JSON Structural Diff", "Structured Data",
    "Compare input (line 1 = A, line 2 = B — both must be JSON) and print keys that differ.")
def _json_diff(data: str) -> str:
    lines = data.strip().splitlines()
    if len(lines) < 2:
        raise ValueError("need two JSON blobs, one per line")
    a, b = json.loads(lines[0]), json.loads(lines[1])
    diff = {"only_in_A": [], "only_in_B": [], "changed": []}
    keys = set(a.keys() if isinstance(a, dict) else []) | set(b.keys() if isinstance(b, dict) else [])
    for k in sorted(keys):
        av, bv = (a or {}).get(k, "__missing__"), (b or {}).get(k, "__missing__")
        if av == "__missing__": diff["only_in_B"].append(k)
        elif bv == "__missing__": diff["only_in_A"].append(k)
        elif av != bv: diff["changed"].append({"key": k, "A": av, "B": bv})
    return json.dumps(diff, indent=2, default=str)


# =============================================================================
# BINARY / EXECUTABLE PARSING
# =============================================================================
@op("pe-header-parse", "PE Header Parse (Windows EXE/DLL)", "Binary Analysis",
    "Parse a Portable Executable header — machine, sections, imports, timestamp.")
def _pe_parse(data: str) -> str:
    if not _HAS_PEFILE:
        raise RuntimeError("pefile not installed")
    b = _bin_from(data)
    pe = _pefile.PE(data=b, fast_load=True)
    result = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "num_sections": pe.FILE_HEADER.NumberOfSections,
        "characteristics": hex(pe.FILE_HEADER.Characteristics),
        "sections": [
            {"name": s.Name.decode(errors="replace").strip("\x00"),
             "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
             "entropy": round(s.get_entropy(), 3)}
            for s in pe.sections
        ],
    }
    try:
        pe.parse_data_directories()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            result["imports"] = [
                {"dll": e.dll.decode(errors="replace"),
                 "functions": [(i.name.decode(errors="replace") if i.name else f"ord({i.ordinal})") for i in e.imports][:60]}
                for e in pe.DIRECTORY_ENTRY_IMPORT[:20]
            ]
    except Exception:
        pass
    return json.dumps(result, indent=2, default=str)


@op("pe-strings", "PE / Binary Strings Extract", "Binary Analysis",
    "Extract ASCII + UTF-16LE printable strings ≥ min_len (default 4).",
    args=[{"name": "min_len", "type": "int", "required": False, "default": 4}])
def _pe_strings(data: str, min_len: int = 4, **_) -> str:
    b = _bin_from(data)
    n = max(int(min_len or 4), 3)
    ascii_re = re.compile(rb"[\x20-\x7e]{" + str(n).encode() + rb",}")
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(n).encode() + rb",}")
    out = []
    for m in ascii_re.finditer(b):
        out.append(m.group().decode("ascii", errors="replace"))
    for m in utf16_re.finditer(b):
        out.append(m.group().decode("utf-16-le", errors="replace").rstrip("\x00"))
    seen, unique = set(), []
    for s in out:
        if s not in seen:
            seen.add(s); unique.append(s)
    return "\n".join(unique[:1500])


@op("elf-header-parse", "ELF Header Parse (Linux)", "Binary Analysis",
    "Parse an ELF header — arch, entry point, sections.")
def _elf_parse(data: str) -> str:
    if not _HAS_ELFTOOLS:
        raise RuntimeError("pyelftools not installed")
    import io
    b = _bin_from(data)
    ef = _ELFFile(io.BytesIO(b))
    return json.dumps({
        "elf_class": ef.elfclass,
        "machine": ef.header["e_machine"],
        "entry": hex(ef.header["e_entry"]),
        "type": ef.header["e_type"],
        "num_sections": ef.num_sections(),
        "sections": [ef.get_section(i).name for i in range(min(ef.num_sections(), 40))],
    }, indent=2, default=str)


@op("pdf-header-parse", "PDF Header/Metadata", "Binary Analysis",
    "Show PDF header version + top-level structure markers (/Catalog, /JS, /OpenAction …).")
def _pdf_parse(data: str) -> str:
    b = _bin_from(data)
    header = b[:16].decode("latin-1", errors="replace")
    ver = re.match(r"%PDF-(\d\.\d)", header)
    markers = ["/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile",
               "/Encrypt", "/AcroForm", "/URI", "/XFA", "/RichMedia"]
    hits = {m: b.count(m.encode()) for m in markers if m.encode() in b}
    return json.dumps({
        "header": header, "version": ver.group(1) if ver else None,
        "size_bytes": len(b), "risky_markers": hits,
        "starts_with_pdf": b.startswith(b"%PDF-"),
    }, indent=2)


@op("file-magic", "File Magic Bytes / Type Sniff", "Binary Analysis",
    "Identify a file by its magic bytes (PE, ELF, PDF, PNG, ZIP, GZIP, MP4, JPG, RTF, class, etc).")
def _file_magic(data: str) -> str:
    b = _bin_from(data)
    sigs = [
        (b"MZ", "PE (Windows EXE/DLL)"),
        (b"\x7fELF", "ELF (Linux/Unix binary)"),
        (b"%PDF-", "PDF document"),
        (b"\x89PNG", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"),
        (b"PK\x03\x04", "ZIP archive / Office XML"),
        (b"\x1f\x8b", "GZIP compressed"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"{\\rtf", "RTF document"),
        (b"\xca\xfe\xba\xbe", "Java .class file"),
        (b"\xd0\xcf\x11\xe0", "OLE / legacy Office"),
        (b"BZh", "Bzip2"),
        (b"\xfd7zXZ", "XZ"),
        (b"OggS", "Ogg container"),
        (b"ID3", "MP3 (ID3)"),
        (b"\x00\x00\x00 ftyp", "MP4 (ftyp)"),
    ]
    hits = [name for sig, name in sigs if b.startswith(sig)]
    return json.dumps({
        "size_bytes": len(b),
        "hex_head": b[:32].hex(sep=" "),
        "ascii_head": "".join(chr(x) if 32 <= x < 127 else "." for x in b[:32]),
        "matches": hits or ["unknown / plain-text"],
    }, indent=2)


# =============================================================================
# JAVASCRIPT DEOBFUSCATION
# =============================================================================
@op("js-beautify", "JS Beautify", "JavaScript",
    "Reformat obfuscated/minified JavaScript into readable code.")
def _jsbeautify(data: str) -> str:
    if not _HAS_JSBEAUTIFIER:
        raise RuntimeError("jsbeautifier not installed")
    return _jsbeautifier.beautify(data)


@op("js-hex-strings-decode", "JS \\x-Escaped Strings Decode", "JavaScript",
    r"Decode all `\xHH` and `\uHHHH` escape sequences inline (common obfuscation).")
def _js_hex_decode(data: str) -> str:
    def _hx(m): return chr(int(m.group(1), 16))
    def _hu(m): return chr(int(m.group(1), 16))
    out = re.sub(r"\\x([0-9a-fA-F]{2})", _hx, data)
    out = re.sub(r"\\u([0-9a-fA-F]{4})", _hu, out)
    return out


@op("js-charcode-decode", "JS String.fromCharCode Decode", "JavaScript",
    "Reverse `String.fromCharCode(72, 101, ...)` blocks into their string form.")
def _js_charcode(data: str) -> str:
    def _decode(m):
        nums = re.findall(r"\d+", m.group(1))
        return "".join(chr(int(n)) for n in nums)
    return re.sub(r"String\.fromCharCode\(([^)]+)\)", _decode, data)


# =============================================================================
# UTILITIES
# =============================================================================
@op("printable-ratio", "Printable Ratio", "Utility",
    "Return the ratio of printable ASCII characters — used to score decode candidates.")
def _printable_ratio(data: str) -> str:
    b = data.encode("utf-8", errors="replace")
    if not b:
        return "0.0"
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return f"{printable / len(b):.4f}"


@op("entropy", "Shannon Entropy", "Utility",
    "Shannon entropy (0-8) — high values suggest compressed/encrypted content.")
def _entropy(data: str) -> str:
    import math
    b = data.encode("utf-8", errors="replace")
    if not b:
        return "0.0"
    freq: Dict[int, int] = {}
    for x in b:
        freq[x] = freq.get(x, 0) + 1
    h = -sum((c / len(b)) * math.log2(c / len(b)) for c in freq.values())
    return f"{h:.4f}"


@op("byte-frequency", "Byte Frequency Analysis", "Utility",
    "Top 10 most-frequent bytes, useful for XOR key hunting.")
def _byte_freq(data: str) -> str:
    b = data.encode("utf-8", errors="replace")
    freq: Dict[int, int] = {}
    for x in b:
        freq[x] = freq.get(x, 0) + 1
    top = sorted(freq.items(), key=lambda kv: -kv[1])[:10]
    return json.dumps([{"byte": hex(k), "chr": chr(k) if 32 <= k < 127 else ".",
                        "count": v, "pct": round(v * 100 / len(b), 2)} for k, v in top], indent=2)


# =============================================================================
# Environment variable expansion (SOC priority — resolves obfuscated paths)
# =============================================================================
#   %TEMP%\evil.exe       →  C:\Users\Public\AppData\Local\Temp\evil.exe
#   $env:APPDATA\stager   →  C:\Users\Public\AppData\Roaming\stager
#   ${HOME}/pwn           →  /home/user/pwn
#
# Uses canonical placeholder paths (not real host state) so decoded IOC paths
# render as human-readable strings analysts can pivot on.

_ENV_MAP: Dict[str, str] = {
    # Windows
    "TEMP":            r"C:\Users\Public\AppData\Local\Temp",
    "TMP":             r"C:\Users\Public\AppData\Local\Temp",
    "APPDATA":         r"C:\Users\Public\AppData\Roaming",
    "LOCALAPPDATA":    r"C:\Users\Public\AppData\Local",
    "SYSTEMROOT":      r"C:\Windows",
    "WINDIR":          r"C:\Windows",
    "SYSTEM32":        r"C:\Windows\System32",
    "PROGRAMDATA":     r"C:\ProgramData",
    "PROGRAMFILES":    r"C:\Program Files",
    "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
    "PROGRAMW6432":    r"C:\Program Files",
    "USERPROFILE":     r"C:\Users\Public",
    "PUBLIC":          r"C:\Users\Public",
    "ALLUSERSPROFILE": r"C:\ProgramData",
    "COMSPEC":         r"C:\Windows\System32\cmd.exe",
    "COMMONPROGRAMFILES": r"C:\Program Files\Common Files",
    "COMPUTERNAME":    "WIN-HOST",
    "USERNAME":        "public",
    "USERDOMAIN":      "WORKGROUP",
    # Unix
    "HOME":            "/home/user",
    "USER":            "user",
    "SHELL":           "/bin/bash",
    "PATH":            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PWD":             "/home/user",
    "XDG_CONFIG_HOME": "/home/user/.config",
    "XDG_CACHE_HOME":  "/home/user/.cache",
    "XDG_DATA_HOME":   "/home/user/.local/share",
    "TMPDIR":          "/tmp",
}

# %WINDIR% / %COMSPEC%
_ENV_PCT_RE   = re.compile(r"%([A-Za-z_][A-Za-z_0-9()]*)%")
# $env:APPDATA / ${env:APPDATA}
_ENV_PS_RE    = re.compile(r"\$(?:\{env:([A-Za-z_][A-Za-z_0-9]*)\}|env:([A-Za-z_][A-Za-z_0-9]*))", re.I)
# ${HOME} / $HOME
_ENV_BASH_RE  = re.compile(r"\$\{([A-Za-z_][A-Za-z_0-9]*)\}|\$([A-Za-z_][A-Za-z_0-9]*)")
# ~/ (Unix home)
_ENV_TILDE_RE = re.compile(r"~/")


def _lookup_env(name: str) -> Optional[str]:
    return _ENV_MAP.get((name or "").upper())


@op("env-expand", "Env-var Expand", "Utility",
    "Resolve %TEMP%, $env:APPDATA, ${HOME}, ~/ into canonical placeholder paths for readable IOCs.")
def _env_expand(data: str) -> str:
    if not data:
        return data
    def _pct(m):
        v = _lookup_env(m.group(1))
        return v if v is not None else m.group(0)
    def _ps(m):
        name = m.group(1) or m.group(2)
        v = _lookup_env(name)
        return v if v is not None else m.group(0)
    def _sh(m):
        name = m.group(1) or m.group(2)
        v = _lookup_env(name)
        return v if v is not None else m.group(0)
    out = _ENV_PCT_RE.sub(_pct, data)
    out = _ENV_PS_RE.sub(_ps, out)
    out = _ENV_BASH_RE.sub(_sh, out)
    out = _ENV_TILDE_RE.sub("/home/user/", out)
    return out


# =============================================================================
# Repeating-key XOR — Kasiski + Friedman based auto key-length + brute force
# =============================================================================
# Real-world coverage: Cobalt-Strike PROFILEs, Empire stagers, custom loaders
# often use 2–32 byte repeating XOR keys. Single-byte case is handled by the
# existing `xor` op — this op is specifically for the multi-byte case.

_XOR_MAX_KEY = 32


def _score_english(b: bytes) -> float:
    """Rough score in [0..1]: higher = more likely English/ASCII plaintext.

    Heuristic: printable-ratio × (letters+space) density × low-entropy bonus.
    Intentionally cheap — runs `_XOR_MAX_KEY` times per brute call.
    """
    if not b:
        return 0.0
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    letters   = sum(1 for x in b if (65 <= x < 91) or (97 <= x < 123) or x == 32)
    pr        = printable / len(b)
    lt        = letters / len(b)
    return round(pr * 0.55 + lt * 0.45, 4)


def _detect_xor_keylen(data: bytes, max_len: int = _XOR_MAX_KEY) -> List[int]:
    """Return candidate key lengths ranked by Kasiski-style repeat scoring.

    Slides windows of 3–4 bytes across the buffer, records inter-occurrence
    distances, then returns the GCD-of-distances-most-common divisors that
    fall within [2..max_len].
    """
    if len(data) < 40:
        return list(range(2, min(9, max_len + 1)))
    # Kasiski: count distances between repeats of short windows
    distances: Dict[int, int] = {}
    for w in (3, 4):
        seen: Dict[bytes, int] = {}
        for i in range(len(data) - w):
            chunk = bytes(data[i:i + w])
            if chunk in seen:
                d = i - seen[chunk]
                if 2 <= d <= max_len * 4:
                    distances[d] = distances.get(d, 0) + 1
            else:
                seen[chunk] = i
    # score each candidate keylen by how many distances are divisible by it
    scores: Dict[int, int] = {}
    for kl in range(2, max_len + 1):
        for d, c in distances.items():
            if d % kl == 0:
                scores[kl] = scores.get(kl, 0) + c
    if not scores:
        return list(range(2, min(9, max_len + 1)))
    # sort by score desc, keep the top 8 to keep brute-force fast
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])[:8]
    return [kl for kl, _ in ranked]


def _crack_key_of_length(data: bytes, keylen: int) -> tuple:
    """Given a fixed key length, find the byte-per-column that maximises the
    English-score of the decoded plaintext. Returns ``(key_bytes, score)``.
    """
    key = bytearray(keylen)
    for col in range(keylen):
        col_bytes = data[col::keylen]
        if not col_bytes:
            continue
        best_k, best_score = 0, -1.0
        for kbyte in range(256):
            decoded = bytes(b ^ kbyte for b in col_bytes)
            s = _score_english(decoded)
            if s > best_score:
                best_score, best_k = s, kbyte
        key[col] = best_k
    plain = bytes(b ^ key[i % keylen] for i, b in enumerate(data))
    return bytes(key), _score_english(plain), plain


@op("xor-brute", "XOR Brute (repeating-key)", "Cryptography",
    "Auto-detect 1–32 byte repeating XOR key from the ciphertext (Kasiski + English scoring).")
def _xor_brute(data: str, key_len: str = "auto") -> str:
    """Try every plausible repeating-key length and return the highest-scoring
    plaintext. Input can be hex, base64 or raw bytes; output is UTF-8 with
    replacement for any residual non-printables.
    """
    raw = _bin_from(data) if data else b""
    if not raw:
        return "(empty input)"
    if len(raw) < 8:
        return "(too short for repeating-key XOR analysis — try the plain `xor` op)"

    # Manual key-length override
    lens: List[int]
    if key_len and key_len != "auto":
        try:
            n = int(key_len, 0)
            lens = [n] if 1 <= n <= _XOR_MAX_KEY else _detect_xor_keylen(raw)
        except (TypeError, ValueError):
            lens = _detect_xor_keylen(raw)
    else:
        # Always try 1-byte first (fast path) then Kasiski ranking, then a
        # sweep of *all* plausible small key lengths as a safety net.
        lens = [1] + _detect_xor_keylen(raw) + list(range(2, _XOR_MAX_KEY + 1))
        # de-dupe while preserving order
        _seen = set(); _out = []
        for x in lens:
            if x in _seen: continue
            _seen.add(x); _out.append(x)
        lens = _out

    # Score all candidates, then apply an Occam-shave preferring shorter keys
    # unless a longer one *materially* outperforms them.
    candidates = []
    for kl in lens:
        try:
            k, s, plain = _crack_key_of_length(raw, kl)
            candidates.append((kl, k, s, plain))
        except Exception:
            continue
    if not candidates:
        return "(unable to recover XOR key with high confidence)"

    # sort by (length asc, score desc) — cheap way to enumerate short-first
    candidates.sort(key=lambda t: (t[0], -t[2]))
    best_kl, best_key, best_score, best_plain = candidates[0]
    for kl, k, s, plain in candidates[1:]:
        # Prefer a longer key ONLY if it beats the current champion by >=0.05.
        # This keeps single-byte keys from over-fitting into 30-byte ones, but
        # still lets a legitimate multi-byte key (score jumps ~0.15+) win.
        if s > best_score + 0.05:
            best_kl, best_key, best_score, best_plain = kl, k, s, plain

    if best_score <= 0:
        return "(unable to recover XOR key with high confidence)"
    header = (
        f"[xor-brute] recovered key = 0x{best_key.hex()} "
        f"(len={len(best_key)}, ascii='{best_key.decode('ascii', errors='replace')}', "
        f"english_score={best_score:.3f})\n\n"
    )
    return header + best_plain.decode("utf-8", errors="replace")
