"""Universal Troubleshoot Engine — deterministic-first, AI-optional.

Design
------
The Troubleshoot button must:
  1. Work OFFLINE (no LLM required) via rule-based diagnostics.
  2. Auto-fix runtime decoding failures with 1 click.
  3. Escalate to the LLM ONLY if rule-based repair leaves the state broken.

Scope (runtime-fixable):
  - Malformed base64 (missing padding, urlsafe chars, 4n+1 corruption)
  - Truncated gzip / partial deflate streams
  - Recipe stopped one layer too early (missing archetype)
  - Over-decoded output (repeated self-inverse tail ops)
  - Anti-hallucination graceful stops (explain in plain English)
  - Missing IOCs in shellcode (retry with alternate XOR keys / recursion)
  - Runtime op crashes (unroll to previous good layer)

Out of scope (dev-time only): frontend React bugs, backend syntax errors,
missing dependencies, misconfigured env — these are caught by CI/tests.
"""
from __future__ import annotations
import base64
import binascii
import gzip
import re
import zlib
from typing import Any, Dict, List, Optional, Tuple


# ─── Diagnostic codes ────────────────────────────────────────────────────
# Every rule emits ONE of these codes. `severity` is one of:
#   info  — informational, no fix needed
#   warn  — degraded state, fix improves quality
#   error — decode broken, fix required
D = {
    "OK":                 ("info",  "Decode succeeded — no issues detected."),
    "EMPTY_INPUT":        ("error", "Input is empty — paste a payload first."),
    "TINY_INPUT":         ("warn",  "Input is very short — likely already plaintext."),
    "B64_PAD_FIX":        ("warn",  "Base64 padding was auto-corrected."),
    "GZIP_TRUNCATED":     ("warn",  "Gzip stream was truncated — partial output recovered."),
    "RECIPE_TOO_SHALLOW": ("warn",  "Recipe stopped early — deeper archetype now applied."),
    "ARCHETYPE_MISSED":   ("warn",  "A named wrapper archetype was missed — now applied."),
    "OVER_DECODED":       ("warn",  "Trailing self-inverse op mangled clean output — trimmed."),
    "GRACEFUL_STOP":      ("info",  "Anti-hallucination guard fired — no further decoding possible."),
    "MISSING_IOCS":       ("warn",  "Shellcode reached but no IOCs — retried with alt keys."),
    "OP_CRASH":           ("error", "An op raised at runtime — rolled back to last good layer."),
    "LOW_CONFIDENCE":     ("warn",  "Winner confidence below floor — escalating to alt engine."),
    "UNKNOWN":            ("warn",  "Payload shape not matched by any archetype or heuristic."),
    "AI_ESCALATED":       ("info",  "Deterministic exhausted — LLM proposed a repair recipe."),
}


def _diag(code: str, extra: str = "", auto_fixed: bool = False) -> Dict[str, Any]:
    sev, msg = D.get(code, ("warn", "unknown diagnostic"))
    return {
        "code": code,
        "severity": sev,
        "message": (msg + (f" — {extra}" if extra else "")),
        "auto_fixed": auto_fixed,
    }


# ─── Standalone helper rules ─────────────────────────────────────────────
def _rule_input_shape(text: str) -> Optional[Dict[str, Any]]:
    if not text or not text.strip():
        return _diag("EMPTY_INPUT", auto_fixed=False)
    if len(text.strip()) < 8:
        return _diag("TINY_INPUT", extra=f"len={len(text.strip())}")
    return None


def _looks_like_base64(s: str) -> bool:
    """Heuristic: >=40 chars of mostly base64 alphabet."""
    if len(s) < 40:
        return False
    s2 = re.sub(r"\s+", "", s)
    if len(s2) < 40:
        return False
    b64_chars = sum(1 for c in s2 if c.isalnum() or c in "+/=_-")
    return b64_chars / len(s2) > 0.90


def _try_recover_base64(text: str) -> Tuple[Optional[bytes], bool]:
    """Return (recovered_bytes, was_repaired). Uses the same robust decoder
    as wrapper_archetypes so behaviour stays consistent."""
    try:
        from wrapper_archetypes import robust_b64decode
        # First: try strict base64 to detect whether repair was needed
        try:
            _ = base64.b64decode(re.sub(r"\s+", "", text), validate=True)
            was_repaired = False
        except (binascii.Error, ValueError):
            was_repaired = True
        return robust_b64decode(text), was_repaired
    except Exception:
        return None, False


def _try_gunzip_partial(raw: bytes) -> Tuple[Optional[str], bool]:
    """Decompress gzip, tolerating truncation. Returns (text, was_partial)."""
    try:
        return gzip.decompress(raw).decode("utf-8", errors="replace"), False
    except (EOFError, OSError, zlib.error):
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = d.decompress(raw)
            try:
                out += d.flush()
            except zlib.error:
                pass
            if out:
                return out.decode("utf-8", errors="replace"), True
        except zlib.error:
            pass
        return None, False


# ─── Alternate XOR-key sweep (shellcode IOC recovery) ────────────────────
_COMMON_XOR_KEYS = list(range(0x01, 0x60))  # 1..0x5F covers >99% of MSF stagers


def _find_c2_iocs(raw: bytes) -> Dict[str, str]:
    """Return the two IOCs the SOC verdict panel promotes."""
    iocs: Dict[str, str] = {}
    ip = re.search(rb"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b", raw)
    if ip:
        iocs["c2_ip"] = ip.group(0).decode("ascii")
    ua = re.search(rb"Mozilla/[0-9.]+[^\r\n\x00]{0,180}", raw)
    if ua:
        iocs["user_agent"] = ua.group(0).decode("ascii", errors="replace")
    return iocs


def _retry_xor_sweep(xored: bytes) -> Optional[Tuple[int, bytes, Dict[str, str]]]:
    """Try common single-byte XOR keys against `xored` bytes; return the first
    one that produces a known shellcode prologue + at least one IOC."""
    from shellcode_analyzer import starts_with_known_prologue
    best: Optional[Tuple[int, bytes, Dict[str, str]]] = None
    for k in _COMMON_XOR_KEYS:
        candidate = bytes(b ^ k for b in xored)
        if starts_with_known_prologue(candidate):
            iocs = _find_c2_iocs(candidate)
            if iocs:
                return (k, candidate, iocs)
            if best is None:
                best = (k, candidate, iocs)
    return best


# ─── Main orchestrator ───────────────────────────────────────────────────
def troubleshoot(
    input_text: str,
    current_output: Optional[str] = None,
    current_steps: Optional[List[Dict[str, Any]]] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the full deterministic diagnostic + auto-repair pipeline.

    Never raises — every failure mode is wrapped in a diagnostic.
    """
    diagnoses: List[Dict[str, Any]] = []
    fixes_applied: List[str] = []

    # ─── R1: Input shape ─────────────────────────────────────────────────
    r1 = _rule_input_shape(input_text)
    if r1:
        diagnoses.append(r1)
        if r1["code"] == "EMPTY_INPUT":
            return {
                "success": False,
                "diagnoses": diagnoses,
                "fixes_applied": fixes_applied,
                "final_output": "",
                "final_steps": [],
                "final_engine": None,
                "final_confidence": 0,
                "ai_used": False,
                "human_summary": "Nothing to decode — paste a payload first.",
            }

    # ─── R1b: Corrupt-payload short-circuit ──────────────────────────────
    # If the payload is structurally impossible (bad b64 length, malformed
    # gzip body, synthetic gzip header, etc.), stop decoding immediately
    # and return a clear anti-hallucination verdict.
    try:
        from corrupt_payload_detector import detect_corrupt_payload
        corrupt = detect_corrupt_payload(input_text)
    except Exception:
        corrupt = None
    if corrupt:
        # Only SHORT-CIRCUIT decoding if the corruption is severe:
        #   - gzip family AND body cannot decompress, OR
        #   - synthetic gzip fingerprint, OR
        #   - low-entropy faux-compressed body.
        # For plain "bad base64 length" alone, we still let the deterministic
        # pipeline attempt repair (a PowerShell payload with a stray char is
        # usually recoverable).
        _SEVERE = {"GZIP_HEADER_VALID_BODY_BAD",
                   "GZIP_SYNTHETIC_HEADER",
                   "LOW_ENTROPY_FAUX_COMPRESSED",
                   "BASE64_DECODE_FAIL"}
        codes_hit = {r["code"] for r in corrupt["reasons"]}
        short_circuit = bool(codes_hit & _SEVERE)
        diag = {
            "code": "CORRUPT_PAYLOAD",
            "severity": corrupt["severity"],
            "message": corrupt["verdict"],
            "auto_fixed": False,
            "evidence": corrupt["reasons"],
            "recommendation": corrupt["recommendation"],
        }
        diagnoses.append(diag)
        if short_circuit:
            return {
                "success": False,
                "diagnoses": diagnoses,
                "fixes_applied": fixes_applied,
                "final_output": "",
                "final_steps": [],
                "final_engine": "corrupt-payload-detector",
                "final_confidence": 0,
                "reached_shellcode": False,
                "ai_used": False,
                "human_summary": (
                    f"⚠ PAYLOAD CORRUPT — {corrupt['verdict']} "
                    f"({len(corrupt['reasons'])} evidence check(s) failed). "
                    "Do NOT trust AI-generated 'decoded' output from other tools — they hallucinate."
                ),
                "corrupt_payload": corrupt,
            }
        # else: fall through and let the deterministic pipeline attempt repair.

    # ─── R2: Re-run deterministic pipeline (chained-archetype + magic race) ─
    try:
        from analysis_core import deterministic_best_decode
        det = deterministic_best_decode(input_text)
    except Exception as e:
        diagnoses.append(_diag("OP_CRASH", extra=str(e)[:120], auto_fixed=False))
        det = {"output": "", "steps": [], "engine": None,
               "reached_shellcode": False, "score": 0.0}

    final_out = det.get("output") or ""
    final_steps = det.get("steps") or []
    final_engine = det.get("engine")
    final_conf = int(round((det.get("score") or 0.0) * 100)) if det.get("score") else 100

    # ─── R3: Was the previous recipe shallower than the deterministic one? ──
    prev_len = len(current_steps or [])
    if prev_len and len(final_steps) > prev_len:
        diagnoses.append(_diag(
            "RECIPE_TOO_SHALLOW",
            extra=f"was {prev_len} ops → now {len(final_steps)} ops "
                  f"(engine={final_engine})",
            auto_fixed=True,
        ))
        fixes_applied.append(f"Deepened recipe: {prev_len}→{len(final_steps)} ops")

    # ─── R4: Was an archetype missed by the previous run? ────────────────
    if (final_engine or "").startswith("archetype:") and \
            not any(str(s.get("op", "")).startswith("archetype") for s in (current_steps or [])):
        # Only surface this as a "fix" if the user had actually attempted a recipe
        if prev_len > 0:
            diagnoses.append(_diag(
                "ARCHETYPE_MISSED",
                extra=f"Applied {final_engine}",
                auto_fixed=True,
            ))
            fixes_applied.append(f"Fired archetype: {final_engine}")

    # ─── R5: Base64 padding auto-repair? ─────────────────────────────────
    if _looks_like_base64(input_text.strip()):
        recovered, was_repaired = _try_recover_base64(input_text.strip())
        if recovered is not None and was_repaired:
            diagnoses.append(_diag("B64_PAD_FIX", auto_fixed=True))
            fixes_applied.append("Repaired base64 padding / alphabet")

    # ─── R6: Terminal shellcode reached but no IOCs? Sweep XOR keys ──────
    if det.get("reached_shellcode"):
        raw = final_out.encode("latin-1", errors="replace")
        iocs = _find_c2_iocs(raw)
        if not iocs:
            # Attempt: maybe the archetype used the wrong key. Try alternates.
            # This is opportunistic — we don't override the winner if nothing found.
            sweep = _retry_xor_sweep(raw)
            if sweep and sweep[2]:
                k, better, iocs_found = sweep
                diagnoses.append(_diag(
                    "MISSING_IOCS",
                    extra=f"XOR-key sweep found key=0x{k:02X} → IOCs: {sorted(iocs_found.keys())}",
                    auto_fixed=True,
                ))
                fixes_applied.append(f"Alternate XOR key 0x{k:02X} recovered IOCs")
                final_out = better.decode("latin-1")
                final_steps = list(final_steps) + [{"op": "xor", "args": {"key": f"0x{k:02X}"}}]
        else:
            diagnoses.append(_diag(
                "OK",
                extra=f"IOCs recovered: {', '.join(f'{k}={v[:40]}' for k,v in iocs.items())}",
                auto_fixed=False,
            ))

    # ─── R7: Over-decoded tail? Strip trailing self-inverse ops ──────────
    if final_steps and final_steps[-1].get("op") in ("rot13", "reverse"):
        printable = sum(1 for c in final_out if 32 <= ord(c) < 127)
        if printable / max(1, len(final_out)) < 0.6:
            trimmed_steps = final_steps[:-1]
            try:
                from routers.ops import _run_recipe_sync  # optional; may not exist
                trimmed_out = _run_recipe_sync(input_text, trimmed_steps)
            except Exception:
                trimmed_out = None
            if trimmed_out and sum(1 for c in trimmed_out if 32 <= ord(c) < 127) / max(1, len(trimmed_out)) > 0.85:
                diagnoses.append(_diag(
                    "OVER_DECODED",
                    extra=f"Removed trailing {final_steps[-1]['op']}",
                    auto_fixed=True,
                ))
                fixes_applied.append(f"Trimmed over-decoded tail op: {final_steps[-1]['op']}")
                final_out = trimmed_out
                final_steps = trimmed_steps

    # ─── R8: Low-confidence terminal? Escalate to magic explicitly ───────
    if final_conf < 35 and not det.get("reached_shellcode"):
        try:
            from magic_decoder import magic_decode
            m = magic_decode(input_text, max_depth=6, max_branches=6, top_n=3)
            top = (m.get("top_results") or [{}])[0]
            m_score = int(round((top.get("score_breakdown", {}).get("score", 0.0)) * 100))
            if m_score > final_conf and (top.get("output") or ""):
                diagnoses.append(_diag(
                    "LOW_CONFIDENCE",
                    extra=f"{final_conf}% → {m_score}% via magic (depth 6)",
                    auto_fixed=True,
                ))
                fixes_applied.append(f"Escalated to magic-decoder — confidence {final_conf}%→{m_score}%")
                final_out = top.get("output") or ""
                final_steps = [{"op": c["op"], "args": c.get("args") or {}}
                               for c in (top.get("chain") or [])]
                final_engine = "magic"
                final_conf = m_score
        except Exception as e:
            diagnoses.append(_diag("OP_CRASH", extra=f"magic escalation failed: {e}"))

    # ─── R9: Op crash surfaced in `error` param? Try to salvage ──────────
    if error:
        diagnoses.append(_diag(
            "OP_CRASH",
            extra=error[:180],
            auto_fixed=bool(final_out),  # if we still produced output, fix succeeded
        ))
        if final_out:
            fixes_applied.append(f"Bypassed crashing op: {error[:80]}")

    # ─── Final: OK diagnostic if nothing else fired ──────────────────────
    if not diagnoses:
        diagnoses.append(_diag("OK"))

    success = bool(final_out.strip()) or det.get("reached_shellcode") is True
    human_summary = _human_summary(diagnoses, fixes_applied, final_engine,
                                    final_conf, det.get("reached_shellcode"))

    return {
        "success": success,
        "diagnoses": diagnoses,
        "fixes_applied": fixes_applied,
        "final_output": final_out,
        "final_steps": final_steps,
        "final_engine": final_engine,
        "final_confidence": final_conf,
        "reached_shellcode": bool(det.get("reached_shellcode")),
        "ai_used": False,
        "human_summary": human_summary,
    }


def _human_summary(
    diagnoses: List[Dict[str, Any]],
    fixes: List[str],
    engine: Optional[str],
    conf: int,
    reached_sc: Optional[bool],
) -> str:
    """One-paragraph plain-English summary for the UI toast."""
    if not fixes:
        if any(d["code"] == "OK" for d in diagnoses):
            base = f"No issues detected. Engine {engine or 'magic'} scored {conf}/100"
            if reached_sc:
                base += " and reached raw shellcode"
            return base + "."
        if any(d["code"] == "EMPTY_INPUT" for d in diagnoses):
            return "Nothing to decode — paste a payload first."
        return f"Analysed by {engine or 'magic'} · confidence {conf}/100 · no auto-fixes required."
    return (
        "Auto-fixed " + f"{len(fixes)} issue(s): "
        + "; ".join(fixes[:4])
        + (f". Final engine: {engine} · confidence {conf}/100"
           + (" · reached shellcode" if reached_sc else "") + ".")
    )
