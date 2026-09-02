"""Top-level engine orchestrator.

Public entry: `decode(text, parent_canonical_id=None) -> ReconstructionResult`.

Behaviour:
  · Auto-detect the primary language (CMD / PowerShell / Bash) based on
    lightweight signals — never guess maliciously.
  · Dispatch to the appropriate sub-engine's `reconstruct()`.
  · If no signal fires (or the sub-engine makes no progress), return
    an empty ReconstructionResult with `final=raw_input` and an
    honest unresolved reason.

Gate 2A wires ONLY the CMD sub-engine.  PowerShell / Bash / Base /
Compression / Crypto / Recursive / Extraction sub-engines are
scaffold-placeholders for future gates — the engine registers them
as `IRRELEVANT` (rejected) placeholders would fail; instead we do
NOTHING for those languages here and record the honest gap.
"""
from __future__ import annotations

from typing import Optional
import uuid

from .types import ReconstructionResult, DecodedLayer
from .registry import get_registry
from . import cmd as _cmd
from . import powershell as _ps


ENGINE_VERSION = "0.3.0-gate2c"


def _looks_like_cmd(text: str) -> bool:
    low = text.lower()
    if any(sig in low for sig in (
        "cmd.exe", "cmd /c", "cmd /k", "cmd /v",
        "set ", "%comspec%", "%systemroot%",
        "^", " & ", " && ", "| ", "for /f",
    )):
        return True
    # Wildcard-exec pattern (e.g. `c*d.e?e`, `p*ell.exe`) → CMD.
    import re as _re
    if _re.search(r"[A-Za-z0-9]*[*?][A-Za-z0-9*?]*\.[A-Za-z0-9*?]+", text):
        return True
    return "!" in text and any(c in text for c in ("set ", "SET "))


def _looks_like_powershell(text: str) -> bool:
    low = text.lower()
    if any(sig in low for sig in (
        "powershell", "pwsh", "-encodedcommand", " -enc ", " -e ",
        "invoke-expression", "iex(", "iex ", "$env:",
        "new-object", "[system.", "[reflection.",
        "iwr ", "iwr(", "downloadstring", "invoke-webrequest",
        "frombase64string", "[char]", "-join", "-split",
        "-replace", "&$", "get-content",
    )):
        return True
    # Format-string function assembly: `'{n}{m}' -f 'a','b'`
    return "-f '" in text or "-f \"" in text or "'+'" in text or "\"+\"" in text


def _looks_like_bash(text: str) -> bool:
    low = text.lower()
    return any(sig in low for sig in (
        "bash -c", "sh -c", "#!/bin/", "$(", "curl ", "wget ",
        "chmod +x", "| sh", "|sh", "| bash", "|bash",
    ))


def _new_parent_id() -> str:
    return f"decoder:{uuid.uuid4().hex[:12]}"


class UniversalDecoderEngine:
    """Thin orchestrator over the language sub-engines."""

    def __init__(self) -> None:
        # Ensure registry is initialised (registers CMD capabilities).
        self.registry = get_registry()

    def decode(
        self,
        text: str,
        parent_canonical_id: Optional[str] = None,
    ) -> ReconstructionResult:
        if not isinstance(text, str) or not text:
            return ReconstructionResult(
                raw_input="", final="", engine_version=ENGINE_VERSION)
        pid = parent_canonical_id or _new_parent_id()

        # Gate 2A/2B: CMD path.
        cmd_result: Optional[ReconstructionResult] = None
        if _looks_like_cmd(text):
            cmd_result = _cmd.reconstruct(text, pid)

        # Gate 2C: PowerShell path — run on either the original text
        # (when no CMD signals) or on the CMD-reconstructed payload
        # (so nested PS-inside-CMD chains peel completely).
        ps_input = cmd_result.final if cmd_result else text
        ps_result: Optional[ReconstructionResult] = None
        if _looks_like_powershell(ps_input):
            ps_result = _ps.reconstruct(ps_input, pid)

        if cmd_result or ps_result:
            layers = []
            if cmd_result:
                layers.extend(cmd_result.layers)
            if ps_result and ps_result.layers:
                layers.extend(ps_result.layers)
            final = (ps_result.final if ps_result
                     else cmd_result.final if cmd_result else text)
            unresolved: list[str] = []
            if cmd_result:
                unresolved.extend(cmd_result.unresolved_reasons)
            if ps_result:
                unresolved.extend(ps_result.unresolved_reasons)
            return ReconstructionResult(
                raw_input          = text,
                final              = final,
                layers             = layers,
                unresolved_reasons = unresolved,
                partial            = any([
                    cmd_result and cmd_result.partial,
                    ps_result and ps_result.partial,
                ]),
                engine_version     = ENGINE_VERSION,
                static_only_verified = True,
            )

        # Nothing wired for Bash / Plane-A codec at this gate.
        reasons = []
        if _looks_like_bash(text):
            reasons.append(
                "bash surface detected — Bash sub-engine not yet "
                "wired (P0-1B Gate 2E).")
        if not reasons:
            reasons.append(
                "no CMD/PS/Bash surface detected by heuristic; "
                "Plane-A codec sub-engines not yet wired "
                "(P0-1B Gate 2D).")
        return ReconstructionResult(
            raw_input          = text,
            final              = text,
            layers             = [],
            unresolved_reasons = reasons,
            partial            = True,
            engine_version     = ENGINE_VERSION,
        )


_ENGINE: Optional[UniversalDecoderEngine] = None


def _engine() -> UniversalDecoderEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = UniversalDecoderEngine()
    return _ENGINE


def decode(
    text: str,
    parent_canonical_id: Optional[str] = None,
) -> ReconstructionResult:
    """Module-level public entry.  Idempotent.  Deterministic."""
    return _engine().decode(text, parent_canonical_id)


__all__ = ["UniversalDecoderEngine", "decode", "ENGINE_VERSION"]
