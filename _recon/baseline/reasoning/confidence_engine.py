"""NivXRay Confidence Engine (Feb-2026 roadmap).

Weighted 4-dimension confidence scorer producing an explainable verdict
for any decode candidate. Each dimension returns a value in [0.0, 1.0]
plus a short reason. The final confidence is a weighted sum + reasons.

Dimensions (per user's Feb-2026 spec):

    1. Structural Validity  (weight 0.30)
       Does the output pass the decoder's own Validate()? E.g. gzip CRC
       verified, JSON parseable, base64 padding valid.

    2. Readability          (weight 0.30)
       Printable-ASCII ratio + English word density + PowerShell/shell
       keyword hits. Reuses reasoning.scorer.linguistic_score().

    3. Entropy Sanity       (weight 0.20)
       Natural text sits at 3.5-4.8 bits/byte. Base64/hex around 5.0-6.0.
       Compressed/encrypted 7.5+. Reward outputs that DROP entropy toward
       natural text; penalise ones that stay near-max entropy.

    4. Context Heuristics   (weight 0.20)
       Does the output make sense given the *input* context? E.g. if the
       input was clearly a PowerShell command wrapper and the output
       contains "Invoke-Expression", that's high context alignment.

The final confidence is: sum(dim * weight for dim in dimensions).

Explainability
--------------
The engine ALWAYS returns a `reasons: list[str]` explaining every
component that contributed positively or negatively. This is what the
UI's Verdict Card and the analyst's audit trail consume.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .scorer import linguistic_score, score_breakdown


# ------------------------------------------------------------------
# Dimension weights — tune here, not scattered through the codebase.
# ------------------------------------------------------------------
W_STRUCTURAL = 0.30
W_READABILITY = 0.30
W_ENTROPY = 0.20
W_CONTEXT = 0.20

# Confidence bands surfaced to the UI
BAND_HIGH = 0.75      # ≥ 0.75  → HIGH confidence  (green)
BAND_MEDIUM = 0.50    # ≥ 0.50  → MEDIUM           (yellow)
# < 0.50 → LOW (red / requires analyst review)


@dataclass
class ConfidenceBreakdown:
    """Explainable confidence verdict."""
    confidence: float
    band: str                           # "high" | "medium" | "low"
    structural: float
    readability: float
    entropy_sanity: float
    context: float
    reasons: List[str] = field(default_factory=list)
    dimensions: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "confidence": round(self.confidence, 4),
            "band": self.band,
            "structural": round(self.structural, 4),
            "readability": round(self.readability, 4),
            "entropy_sanity": round(self.entropy_sanity, 4),
            "context": round(self.context, 4),
            "weights": {
                "structural": W_STRUCTURAL,
                "readability": W_READABILITY,
                "entropy_sanity": W_ENTROPY,
                "context": W_CONTEXT,
            },
            "reasons": self.reasons,
            "dimensions": self.dimensions,
        }


# --- private helpers ------------------------------------------------

_PS_HINTS = re.compile(
    r"\b(?:powershell|pwsh|iex|invoke-expression|invoke-webrequest|"
    r"downloadstring|frombase64string|-enc(?:odedcommand)?|-nop|-noprofile|"
    r"new-object|net\.webclient|system\.reflection)\b",
    re.IGNORECASE,
)
_SHELL_HINTS = re.compile(
    r"\b(?:bash|sh|zsh|curl|wget|nc|netcat|whoami|hostname|"
    r"chmod|/bin/(?:bash|sh))\b",
    re.IGNORECASE,
)
_URL_HINT = re.compile(r"https?://[^\s\"'<>]+")
_HEX_ONLY = re.compile(r"^[0-9a-fA-F\s]+$")
_B64_ONLY = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    N = len(text)
    return -sum((c / N) * math.log2(c / N) for c in freq.values())


def _entropy_sanity(text: str) -> tuple:
    """Map entropy to a health score. Natural English = 4.0-4.8 (best).
    Base64/hex 5.0-6.0 (medium — still-encoded). Compressed/encrypted 7.0+.

    Returns (score, reason).
    """
    if not text:
        return 0.0, "empty"
    ent = _entropy(text)
    if ent <= 3.0:
        # Very repetitive — usually padding or tiny buffer. Not "bad" per se
        # but not confidently readable either. Neutral score.
        return 0.55, f"low-entropy={ent:.2f} (repetitive)"
    if 3.0 < ent <= 4.8:
        # Natural-language sweet spot.
        return 0.95, f"natural-text-entropy={ent:.2f}"
    if 4.8 < ent <= 5.8:
        # Mixed script/URL/JSON range — still very readable.
        return 0.80, f"mixed-content-entropy={ent:.2f}"
    if 5.8 < ent <= 6.8:
        # Base64/hex/blob range — likely still encoded.
        return 0.45, f"encoded-blob-entropy={ent:.2f}"
    if 6.8 < ent <= 7.5:
        # Compressed / encrypted range.
        return 0.25, f"high-entropy={ent:.2f} (compressed/encrypted?)"
    return 0.10, f"extreme-entropy={ent:.2f} (random/encrypted)"


def _readability(text: str) -> tuple:
    """Return (score, reason) from linguistic_score + printable ratio."""
    if not text:
        return 0.0, "empty"
    L = len(text)
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\r\n\t")
    pr = printable / max(L, 1)
    lscore = linguistic_score(text)
    # If it's still a pure hex/base64 blob, readability floors — no linguistic content.
    if _HEX_ONLY.match(text.strip()) and L >= 20:
        return round(0.10 * pr, 4), f"still-encoded (hex, printable={pr:.2f})"
    if _B64_ONLY.match(text.strip()) and L >= 20 and lscore < 0.10:
        return round(0.15 * pr, 4), f"still-encoded (base64, printable={pr:.2f})"
    combined = 0.55 * pr + 0.45 * lscore
    return round(min(combined, 1.0), 4), f"printable={pr:.2f}, linguistic={lscore:.2f}"


def _context_alignment(input_text: str, output_text: str) -> tuple:
    """Reward outputs that MATCH intent hints from the input.

    Rules:
      * Input has 'FromBase64String', 'atob(', '-EncodedCommand' → output
        should contain executable script tokens. Award +0.6.
      * Input has PowerShell markers → output containing PS keywords = +0.5.
      * Input has URL-like shape → output containing http:// = +0.4.
      * Neither hint → neutral 0.5.
    """
    if not output_text:
        return 0.0, "empty-output"

    lin = input_text.lower()
    lout = output_text.lower()

    # Wrappers that signal "the payload will decode to a command"
    wrapper_signals = (
        "frombase64string", "atob(", "-encodedcommand", "invoke-expression",
        "eval(", "iex(", "base64_decode", "convertfrom-",
    )
    input_wraps_payload = any(m in lin for m in wrapper_signals)

    score = 0.50   # neutral baseline
    reasons: List[str] = []

    if input_wraps_payload:
        # Output should reveal a command / URL / script
        hits = 0
        if _PS_HINTS.search(output_text):
            hits += 1; reasons.append("output-has-powershell-tokens")
        if _SHELL_HINTS.search(output_text):
            hits += 1; reasons.append("output-has-shell-tokens")
        if _URL_HINT.search(output_text):
            hits += 1; reasons.append("output-has-url")
        if hits >= 2:
            score = 0.95
        elif hits == 1:
            score = 0.80
        else:
            score = 0.30
            reasons.append("wrapper-implied-payload-but-no-command-tokens")

    else:
        # No wrapper — score by how "meaningful" the transformation was
        if _PS_HINTS.search(output_text) or _URL_HINT.search(output_text):
            score = 0.75
            reasons.append("output-has-actionable-tokens")
        elif output_text != input_text:
            score = 0.60
            reasons.append("output-differs-from-input")
        else:
            score = 0.40
            reasons.append("output-identical-to-input")

    return round(score, 4), "; ".join(reasons) or "no-context-hints"


# --- public API -----------------------------------------------------

def compute_confidence(
    output_text: str,
    input_text: str = "",
    structural_valid: Optional[bool] = None,
) -> ConfidenceBreakdown:
    """Return the weighted 4-dimension confidence for `output_text`.

    Args:
        output_text: The decoded output being evaluated.
        input_text: Original input (used for context alignment). Optional.
        structural_valid: If the decoder reports a hard validity result
            (e.g. gzip CRC verified), pass True/False. If None, we infer
            from output shape (non-empty, mostly-printable, no CRC-fail).

    Returns:
        ConfidenceBreakdown — final confidence + per-dimension explanation.
    """
    reasons: List[str] = []
    dims: Dict[str, Dict[str, Any]] = {}

    # ── Dim 1: Structural Validity ──────────────────────────────────
    if structural_valid is True:
        structural = 0.95
        s_reason = "structural-valid (decoder-verified)"
    elif structural_valid is False:
        structural = 0.10
        s_reason = "structural-invalid (decoder-rejected)"
    else:
        # Inference: non-empty + reasonable size + no obvious garbage
        if not output_text:
            structural = 0.0
            s_reason = "empty-output"
        else:
            L = len(output_text)
            if L < 3:
                structural = 0.15
                s_reason = f"too-short (L={L})"
            elif L > 200_000:
                structural = 0.30
                s_reason = f"output-too-large (L={L})"
            else:
                printable = sum(
                    1 for c in output_text
                    if 32 <= ord(c) < 127 or c in "\r\n\t"
                )
                pr = printable / max(L, 1)
                if pr < 0.30:
                    structural = 0.20
                    s_reason = f"low-printable-ratio={pr:.2f} (may be binary)"
                else:
                    structural = 0.70
                    s_reason = f"inferred-valid (printable={pr:.2f})"
    dims["structural"] = {"score": round(structural, 4), "reason": s_reason}
    reasons.append(f"structural: {s_reason}")

    # ── Dim 2: Readability ──────────────────────────────────────────
    readability, r_reason = _readability(output_text)
    dims["readability"] = {"score": readability, "reason": r_reason}
    reasons.append(f"readability: {r_reason}")

    # ── Dim 3: Entropy Sanity ───────────────────────────────────────
    entropy_sanity, e_reason = _entropy_sanity(output_text)
    dims["entropy_sanity"] = {"score": entropy_sanity, "reason": e_reason}
    reasons.append(f"entropy: {e_reason}")

    # ── Dim 4: Context Alignment ────────────────────────────────────
    context, c_reason = _context_alignment(input_text or "", output_text)
    dims["context"] = {"score": context, "reason": c_reason}
    reasons.append(f"context: {c_reason}")

    confidence = (
        W_STRUCTURAL * structural
        + W_READABILITY * readability
        + W_ENTROPY * entropy_sanity
        + W_CONTEXT * context
    )
    confidence = round(min(max(confidence, 0.0), 1.0), 4)

    if confidence >= BAND_HIGH:
        band = "high"
    elif confidence >= BAND_MEDIUM:
        band = "medium"
    else:
        band = "low"

    return ConfidenceBreakdown(
        confidence=confidence,
        band=band,
        structural=structural,
        readability=readability,
        entropy_sanity=entropy_sanity,
        context=context,
        reasons=reasons,
        dimensions=dims,
    )
