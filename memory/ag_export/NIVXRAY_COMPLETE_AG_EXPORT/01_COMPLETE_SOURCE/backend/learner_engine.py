"""Auto-Archetype Learner Engine — Feb 2026.

Given a failed payload + expected decoded output, the engine:
  1. Extracts numerical features (length, entropy, charset class, alphabets)
  2. Fingerprints the payload for near-duplicate detection
  3. Clusters similar submissions by feature-hash
  4. Proposes a candidate archetype (regex + decode chain + Python code)
  5. Computes a 0-100 confidence with a component breakdown
  6. Runs the NXGEC regression suite as a hard merge gate

Pure deterministic — no LLM required. Every step is testable in isolation.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
import subprocess
import sys
import os
import textwrap
from typing import Any, Dict, List, Optional, Tuple


# ─── Feature extraction ──────────────────────────────────────────────────

_B64_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARSET = set("0123456789abcdefABCDEF")
_URL_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")
_BACKSLASH_X_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESC_RE = re.compile(r"\\u[0-9a-fA-F]{4}")
_HTML_ENT_RE = re.compile(r"&#(?:\d+|x[0-9a-fA-F]+);")
_LOLBAS_TOKENS = ("powershell", "cmd.exe", "certutil", "mshta", "regsvr32", "rundll32",
                  "bitsadmin", "wmic", "msiexec", "wscript", "cscript")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 3)


def extract_features(text: str) -> Dict[str, Any]:
    """Compute a stable feature dict for a raw payload string.

    All values are JSON-serialisable primitives so they can be persisted.
    """
    if not text:
        return {
            "length": 0, "entropy": 0.0, "charset": "empty",
            "b64_ratio": 0.0, "hex_ratio": 0.0, "printable_ratio": 0.0,
            "has_percent_esc": False, "has_backslash_x": False,
            "has_unicode_esc": False, "has_html_entity": False,
            "has_lolbas": False, "lolbas_tokens": [],
            "top_bigrams": [], "length_band": "empty",
        }

    length = len(text)
    charset_seen = set(text)
    b64_hits = sum(1 for c in text if c in _B64_CHARSET)
    hex_hits = sum(1 for c in text if c in _HEX_CHARSET)
    printable = sum(1 for c in text if 32 <= ord(c) < 127)

    # bigrams (top 5 most-common non-space)
    bigrams: Dict[str, int] = {}
    for i in range(length - 1):
        bg = text[i:i + 2]
        if " " in bg or "\n" in bg:
            continue
        bigrams[bg] = bigrams.get(bg, 0) + 1
    top_bigrams = [b for b, _ in sorted(bigrams.items(), key=lambda x: -x[1])[:5]]

    lolbas_hits = [t for t in _LOLBAS_TOKENS if t in text.lower()]

    if length < 32:
        band = "tiny"
    elif length < 128:
        band = "small"
    elif length < 512:
        band = "medium"
    elif length < 2048:
        band = "large"
    else:
        band = "huge"

    # Charset classification (rough)
    if hex_hits / length > 0.9:
        charset = "hex"
    elif b64_hits / length > 0.9:
        charset = "base64"
    elif printable / length > 0.95:
        charset = "printable"
    elif len(charset_seen) <= 20:
        charset = "narrow"
    else:
        charset = "mixed"

    return {
        "length": length,
        "entropy": _shannon_entropy(text),
        "charset": charset,
        "b64_ratio": round(b64_hits / length, 3),
        "hex_ratio": round(hex_hits / length, 3),
        "printable_ratio": round(printable / length, 3),
        "has_percent_esc": bool(_URL_ESCAPE_RE.search(text)),
        "has_backslash_x": bool(_BACKSLASH_X_RE.search(text)),
        "has_unicode_esc": bool(_UNICODE_ESC_RE.search(text)),
        "has_html_entity": bool(_HTML_ENT_RE.search(text)),
        "has_lolbas": bool(lolbas_hits),
        "lolbas_tokens": lolbas_hits,
        "top_bigrams": top_bigrams,
        "length_band": band,
    }


# ─── Similarity & duplicate detection ───────────────────────────────────

def similarity(a: Dict[str, Any], b: Dict[str, Any]) -> int:
    """Return an integer 0-100 similarity score between two feature dicts."""
    if not a or not b:
        return 0
    score = 0
    if a.get("charset") == b.get("charset"):        score += 25
    if a.get("length_band") == b.get("length_band"): score += 15
    # entropy within 0.5 bits
    if abs((a.get("entropy") or 0) - (b.get("entropy") or 0)) < 0.5: score += 10
    # ratio buckets close
    if abs((a.get("b64_ratio") or 0) - (b.get("b64_ratio") or 0)) < 0.15: score += 10
    if abs((a.get("hex_ratio") or 0) - (b.get("hex_ratio") or 0)) < 0.15: score += 10
    # boolean flag agreement
    for k in ("has_percent_esc", "has_backslash_x", "has_unicode_esc",
              "has_html_entity", "has_lolbas"):
        if a.get(k) == b.get(k):
            score += 3
    # bigram overlap
    a_bg = set(a.get("top_bigrams") or [])
    b_bg = set(b.get("top_bigrams") or [])
    if a_bg and b_bg:
        score += int(15 * len(a_bg & b_bg) / max(len(a_bg | b_bg), 1))
    return min(score, 100)


def cluster_key(features: Dict[str, Any]) -> str:
    """Coarse deterministic cluster label — payloads with the same key are
    in the same cluster. Used to group failures in the /clusters tab."""
    return "|".join([
        features.get("charset", "?"),
        features.get("length_band", "?"),
        "b64" if features.get("b64_ratio", 0) > 0.7 else
        "hex" if features.get("hex_ratio", 0) > 0.7 else "-",
        "esc" if features.get("has_backslash_x") or features.get("has_percent_esc")
              or features.get("has_unicode_esc") else "-",
        "lol" if features.get("has_lolbas") else "-",
    ])


# ─── Proposal generation ────────────────────────────────────────────────

def _guess_wrapper_regex(text: str) -> Optional[str]:
    """Heuristic: try to lift a stable wrapper prefix/suffix from the input."""
    # look for common LOLBAS invocation prefixes
    lower = text.lower()
    for tok in _LOLBAS_TOKENS:
        idx = lower.find(tok)
        if idx >= 0:
            return re.escape(text[idx: idx + len(tok)])
    # look for balanced quoted payload — pull the quote character
    m = re.search(r"""FromBase64String\(\s*(['"])(.+?)\1\s*\)""", text, re.I)
    if m:
        return r"FromBase64String\(\s*['\"](?P<b64>[A-Za-z0-9+/=]+)['\"]\s*\)"
    m = re.search(r"""(?:base64|b64)\s*(?:-d|--decode)""", text, re.I)
    if m:
        return re.escape(m.group(0))
    return None


def _guess_decode_chain(text: str, expected: str,
                       features: Dict[str, Any]) -> List[str]:
    chain: List[str] = []
    lower = text.lower()
    if features.get("has_backslash_x"):
        chain.append("backslash-x-decode")
    if features.get("has_percent_esc"):
        chain.append("url-decode")
    if features.get("has_unicode_esc"):
        chain.append("unicode-decode")
    if features.get("has_html_entity"):
        chain.append("html-entity-decode")
    if features.get("b64_ratio", 0) > 0.7 or "frombase64string" in lower or "base64" in lower:
        chain.append("base64-decode")
    if features.get("hex_ratio", 0) > 0.7:
        chain.append("hex-decode")
    if "gzip" in lower or "\x1f\x8b" in text:
        chain.append("gzip-decompress")
    if "utf-16" in lower or "unicode" in lower or _looks_utf16(text, expected):
        chain.append("utf16le-decode")
    if features.get("has_lolbas"):
        chain.append("lolbas-annotate")
    if not chain:
        chain.append("passthrough")
    return chain


def _looks_utf16(text: str, expected: str) -> bool:
    try:
        raw = base64.b64decode(text, validate=False)
        return b"\x00" in raw and raw[:32].count(b"\x00") > 2
    except Exception:
        return False


def _confidence_breakdown(text: str, expected: str,
                          features: Dict[str, Any],
                          chain: List[str],
                          wrapper_regex: Optional[str]) -> Dict[str, int]:
    """Sum to <= 100. Order matches the UI: Regex / Entropy / Charsets /
    Decode-path / Corpus."""
    regex_pts   = 35 if wrapper_regex else 5
    entropy_pts = 20 if 3.5 <= (features.get("entropy") or 0) <= 6.5 else 5
    charset_pts = 15 if features.get("charset") in ("base64", "hex", "printable") else 5
    path_pts    = min(20, len(chain) * 5) if chain and chain != ["passthrough"] else 0
    corpus_pts  = 10 if expected and expected.strip() else 0
    return {
        "regex":     regex_pts,
        "entropy":   entropy_pts,
        "charsets":  charset_pts,
        "decode_path": path_pts,
        "corpus_match": corpus_pts,
        "total":     regex_pts + entropy_pts + charset_pts + path_pts + corpus_pts,
    }


def _why_this_archetype(features: Dict[str, Any], chain: List[str],
                        wrapper_regex: Optional[str]) -> str:
    reasons: List[str] = []
    if wrapper_regex:
        reasons.append(f"wrapper regex candidate: `{wrapper_regex[:80]}`")
    if features.get("b64_ratio", 0) > 0.7:
        reasons.append(f"charset ~{int(features['b64_ratio']*100)}% base64 alphabet")
    if features.get("hex_ratio", 0) > 0.7:
        reasons.append(f"charset ~{int(features['hex_ratio']*100)}% hex alphabet")
    if features.get("has_backslash_x"):
        reasons.append("contains \\xHH byte escapes")
    if features.get("has_percent_esc"):
        reasons.append("URL %HH escapes present")
    if features.get("has_lolbas"):
        reasons.append(f"LOLBAS token(s): {', '.join(features.get('lolbas_tokens') or [])}")
    reasons.append(f"proposed decode chain: {' → '.join(chain)}")
    return "; ".join(reasons)


def _explain_why_not(features: Dict[str, Any], breakdown: Dict[str, int]) -> Dict[str, Any]:
    """If confidence is low, list what's missing so an analyst knows what
    kind of additional samples would push us over the line."""
    missing: List[str] = []
    if not features.get("has_percent_esc") and not features.get("has_backslash_x"):
        missing.append("no explicit byte-escape markers")
    if features.get("b64_ratio", 0) < 0.5 and features.get("hex_ratio", 0) < 0.5:
        missing.append("weak base64/hex signal")
    if features.get("entropy", 0) < 3.0:
        missing.append("entropy too low (may be plain text)")
    if breakdown.get("regex", 0) < 20:
        missing.append("no stable wrapper regex could be lifted")
    rec = "Need 2-3 more sibling samples to strengthen the pattern." \
          if missing else "Ready to promote."
    return {"missing": missing, "recommendation": rec}


def _emit_handler_code(archetype_id: str, chain: List[str],
                       wrapper_regex: Optional[str]) -> str:
    """Generate a candidate Python handler + match function as a string
    suitable for pasting into wrapper_archetypes_learned.py. This is the
    *proposal* — the human reviews before Approve writes it to staging."""
    rgx_literal = repr(wrapper_regex or r"^\s*$")
    chain_literal = repr(chain)
    return textwrap.dedent(f'''
        # ─── LEARNED · {archetype_id} ─────────────────────────────────
        import re as _re
        _RGX_{archetype_id} = _re.compile({rgx_literal}, _re.IGNORECASE)

        def _match_{archetype_id}(t: str) -> bool:
            return bool(_RGX_{archetype_id}.search(t or ""))

        def _handle_{archetype_id}(t: str) -> str:
            # NOTE: candidate scaffold — analyst should refine the decode
            # pipeline. Chain proposed: {chain}
            return t  # placeholder — replace with real decode logic

        _ARCHETYPE_{archetype_id} = {{
            "id": "{archetype_id}",
            "description": "learner-generated archetype (chain: " + " → ".join({chain_literal}) + ")",
            "chain":   {chain_literal},
            "handler": _handle_{archetype_id},
            "match":   _match_{archetype_id},
            "terminal": False,
        }}
        LEARNED_ARCHETYPES.append(_ARCHETYPE_{archetype_id})
    ''').strip()


def propose_archetype(raw_input: str, expected_output: str,
                      archetype_id: Optional[str] = None) -> Dict[str, Any]:
    """Full proposal pipeline. Deterministic.

    Returns a dict with:
        features, cluster_key, wrapper_regex, decode_chain,
        confidence_breakdown, why, why_not, code, archetype_id
    """
    features = extract_features(raw_input)
    wrapper_regex = _guess_wrapper_regex(raw_input)
    chain = _guess_decode_chain(raw_input, expected_output, features)
    breakdown = _confidence_breakdown(raw_input, expected_output,
                                      features, chain, wrapper_regex)
    aid = archetype_id or _mint_archetype_id(features)
    return {
        "archetype_id":         aid,
        "features":             features,
        "cluster_key":          cluster_key(features),
        "wrapper_regex":        wrapper_regex,
        "decode_chain":         chain,
        "confidence":           breakdown["total"],
        "confidence_breakdown": breakdown,
        "why":                  _why_this_archetype(features, chain, wrapper_regex),
        "why_not":              _explain_why_not(features, breakdown),
        "code":                 _emit_handler_code(aid, chain, wrapper_regex),
    }


def _mint_archetype_id(features: Dict[str, Any]) -> str:
    ck = cluster_key(features).replace("|", "_").replace("-", "N").upper()
    return f"LEARNED_{ck}"


# ─── Regression harness ─────────────────────────────────────────────────

_NXGEC_TEST = "backend/tests/test_nxgec_regression.py"


def run_regression(timeout_sec: int = 90) -> Dict[str, Any]:
    """Execute the NXGEC regression suite AND the User Golden Vault in a
    subprocess and return a machine-readable summary. Uses pytest -q --tb=no.

    The Golden Vault (backend/tests/test_user_golden_vault.py) locks every
    workspace case the analyst has saved — any archetype change that breaks
    a previously-validated payload is refused here, so /learner/approve can
    never merge a regression."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # __file__ is /app/backend/learner_engine.py → root = /app
    cwd = os.path.join(root, "backend")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=short",
             "tests/test_nxgec_regression.py",
             "tests/test_user_golden_vault.py",
             "tests/test_cjk_gibberish_regression.py"],
            cwd=cwd, capture_output=True, text=True, timeout=timeout_sec,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        passed, failed = _parse_pytest_summary(out)
        ok = proc.returncode == 0 and failed == 0
        return {
            "ok":       ok,
            "passed":   passed,
            "failed":   failed,
            "exit_code": proc.returncode,
            "log_tail": out[-4000:],
            "suites":   ["nxgec", "user_golden_vault", "cjk_gibberish"],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "passed": 0, "failed": 0,
                "exit_code": -1, "log_tail": "TIMEOUT"}
    except Exception as e:
        return {"ok": False, "passed": 0, "failed": 0,
                "exit_code": -2, "log_tail": f"ERROR: {e}"}


_PYTEST_SUMMARY_RE = re.compile(
    r"(?:(\d+)\s+passed)?(?:.*?(\d+)\s+failed)?", re.S
)


def _parse_pytest_summary(out: str) -> Tuple[int, int]:
    passed = failed = 0
    m = re.search(r"(\d+)\s+passed", out)
    if m: passed = int(m.group(1))
    m = re.search(r"(\d+)\s+failed", out)
    if m: failed = int(m.group(1))
    return passed, failed


# ─── Staging file writer ────────────────────────────────────────────────

_STAGING = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "wrapper_archetypes_learned.py")


def append_to_staging(code_block: str) -> Dict[str, Any]:
    """Idempotently append a code block to the staging file. Returns the
    file's line count after write. Callers should have already run the
    regression gate BEFORE calling this."""
    if not code_block or not code_block.strip():
        return {"ok": False, "error": "empty code block"}
    with open(_STAGING, "r", encoding="utf-8") as f:
        existing = f.read()
    if code_block.strip() in existing:
        return {"ok": True, "skipped": True, "reason": "already merged"}
    with open(_STAGING, "a", encoding="utf-8") as f:
        f.write("\n\n" + code_block.strip() + "\n")
    with open(_STAGING, "r", encoding="utf-8") as f:
        lines = len(f.readlines())
    return {"ok": True, "skipped": False, "lines": lines}


def remove_from_staging(archetype_id: str) -> Dict[str, Any]:
    """Roll back a merged archetype by stripping its block from staging."""
    with open(_STAGING, "r", encoding="utf-8") as f:
        text = f.read()
    marker = f"# ─── LEARNED · {archetype_id}"
    idx = text.find(marker)
    if idx < 0:
        return {"ok": False, "reason": "not found in staging"}
    # remove up to the next LEARNED block or EOF
    next_idx = text.find("# ─── LEARNED · ", idx + len(marker))
    if next_idx < 0:
        new_text = text[:idx].rstrip() + "\n"
    else:
        new_text = text[:idx] + text[next_idx:]
    with open(_STAGING, "w", encoding="utf-8") as f:
        f.write(new_text)
    return {"ok": True}
