"""NivXRay LLM Tiebreaker (Feb-2026 roadmap — deep mode).

When the deterministic reasoning engine produces two or more candidates
whose linguistic deltas are within TIE_THRESHOLD of each other, we invoke
Claude Sonnet 4.5 as an arbitrator. Claude never gets to invent new
decoders; it only picks the winner from the candidates the deterministic
engine already produced.

Design rules:
    * OFF by default. Only invoked when `mode == "deep"` AND top two
      candidates are within TIE_THRESHOLD.
    * Deterministic first. Claude sees only the (input, candidates,
      scores) and returns a single op_id.
    * Failure-tolerant. If Claude times out / returns garbage / lacks a
      key, we fall back to the top deterministic candidate.
    * Budget-aware. One call per reasoning step, max 4 calls per decode
      request (matches MAX_DEPTH in engine.py).
    * Offline mode. If no LLM key is configured, `tiebreak_available()`
      returns False and callers skip the call cleanly.

Env keys consulted (first non-empty wins):
    EMERGENT_LLM_KEY    (universal Emergent key — supports Claude)
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class TiebreakerVerdict:
    winner_op: str
    rationale: str
    provider: str        # "emergent-claude" | "fallback-deterministic" | "no-key"
    used_llm: bool
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "winner_op": self.winner_op,
            "rationale": self.rationale,
            "provider": self.provider,
            "used_llm": self.used_llm,
            "error": self.error,
        }


def tiebreak_available() -> bool:
    """True iff at least one LLM key is present in the environment."""
    return bool(os.environ.get("EMERGENT_LLM_KEY"))


def _build_prompt(input_text: str, candidates: List[Dict[str, Any]]) -> str:
    """Build the LLM arbitration prompt.

    Candidates arrive as dicts with keys: op, output, delta, output_score.
    We keep the prompt terse — the LLM's only job is to pick ONE.
    """
    trimmed_input = input_text if len(input_text) <= 500 else input_text[:500] + "…"
    lines = [
        "You are the NivXRay decoder tiebreaker.",
        "The deterministic engine found multiple candidate decodings that scored within a tie threshold.",
        "Pick the SINGLE op_id whose output is MOST LIKELY to be the correct plaintext.",
        "",
        f"INPUT ({len(input_text)} chars):",
        trimmed_input,
        "",
        "CANDIDATES:",
    ]
    for i, c in enumerate(candidates, 1):
        out = c.get("output") or ""
        out_short = out if len(out) <= 200 else out[:200] + "…"
        lines.append(
            f"  [{i}] op={c.get('op')} score={c.get('output_score', 0):.3f} "
            f"delta={c.get('delta', 0):.3f}"
        )
        lines.append(f"      output: {out_short!r}")
    lines.append("")
    lines.append(
        'Reply with a JSON object exactly like: '
        '{"winner_op":"<op_id>","rationale":"<one sentence>"}'
    )
    lines.append("Do not include any other text. No markdown fences.")
    return "\n".join(lines)


async def arbitrate_async(
    input_text: str,
    candidates: List[Dict[str, Any]],
    session_id: str = "tiebreak",
) -> TiebreakerVerdict:
    """Async LLM arbitration. Returns TiebreakerVerdict.

    Falls back to the top deterministic candidate on any error.
    """
    if not candidates:
        return TiebreakerVerdict(
            winner_op="", rationale="no candidates", provider="fallback-deterministic",
            used_llm=False, error="empty-candidate-list",
        )

    top = candidates[0]

    if not tiebreak_available():
        return TiebreakerVerdict(
            winner_op=top.get("op") or "",
            rationale="LLM key not configured — fell back to top deterministic candidate",
            provider="no-key",
            used_llm=False,
        )

    try:
        # Emergent LLM key path — provider-agnostic Claude access.
        from emergentintegrations.llm.chat import LlmChat, UserMessage
    except Exception as e:
        return TiebreakerVerdict(
            winner_op=top.get("op") or "",
            rationale=(
                "emergentintegrations library not available — fell back to top "
                "deterministic candidate"
            ),
            provider="fallback-deterministic",
            used_llm=False,
            error=f"import-failed: {e}",
        )

    key = os.environ.get("EMERGENT_LLM_KEY", "")
    prompt = _build_prompt(input_text, candidates)
    try:
        chat = (
            LlmChat(
                api_key=key,
                session_id=session_id,
                system_message=(
                    "You arbitrate between candidate decoder outputs. Reply with "
                    "JSON only, no prose."
                ),
            )
            .with_model("anthropic", "claude-sonnet-4-5-20250929")
            .with_params(max_tokens=200)
        )
        reply = await chat.send_message(UserMessage(text=prompt))
        text = (reply or "").strip()

        import json, re as _re
        # Tolerate accidental code fences by stripping them
        text = _re.sub(r"^```(?:json)?|```$", "", text).strip()
        data = json.loads(text)
        winner = str(data.get("winner_op") or "").strip()
        rationale = str(data.get("rationale") or "").strip()
        # Winner MUST be one of the candidate op_ids we sent — never allow
        # the LLM to invent a new op.
        valid_ops = {c.get("op") for c in candidates}
        if winner not in valid_ops:
            return TiebreakerVerdict(
                winner_op=top.get("op") or "",
                rationale=(
                    f"LLM returned op_id={winner!r} not in candidate set — "
                    f"fell back to top deterministic candidate"
                ),
                provider="fallback-deterministic",
                used_llm=True,
                error="invalid-winner",
            )
        return TiebreakerVerdict(
            winner_op=winner,
            rationale=rationale or "LLM chose without rationale",
            provider="emergent-claude",
            used_llm=True,
        )
    except Exception as e:
        return TiebreakerVerdict(
            winner_op=top.get("op") or "",
            rationale=(
                "LLM arbitration failed — fell back to top deterministic "
                "candidate"
            ),
            provider="fallback-deterministic",
            used_llm=False,
            error=str(e),
        )


def arbitrate(
    input_text: str,
    candidates: List[Dict[str, Any]],
    session_id: str = "tiebreak",
) -> TiebreakerVerdict:
    """Sync wrapper — safe to call from non-async code paths.

    Uses asyncio.run to drive the coroutine.
    """
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If a loop is already running (e.g. inside FastAPI), spawn a
            # dedicated thread with its own loop so we don't deadlock.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(
                    lambda: asyncio.new_event_loop().run_until_complete(
                        arbitrate_async(input_text, candidates, session_id)
                    )
                )
                return fut.result(timeout=15)
    except RuntimeError:
        pass
    return asyncio.run(arbitrate_async(input_text, candidates, session_id))
