"""Command Reconstruction Engine.

`reconstruct(cmdline)` recursively peels every wrapper the registry
knows about until the effective payload is bare, then classifies the
result so downstream analyzers know which dispatch target to use.

Guarantees:
    · Deterministic  — no randomness, no clocks, no external calls
    · Bounded        — hard recursion cap (`MAX_DEPTH`) prevents
                        pathological chains
    · Evidence-first — every peel emits a WrapperChainStep the
                        analyst can audit
    · Extensible     — new wrappers register in `wrappers/__init__.py`;
                        this engine never needs to change
"""
from __future__ import annotations

import hashlib
import json
import re

from .models import CommandReconstruction, DispatchHint, WrapperChainStep
from .wrappers import WRAPPER_REGISTRY

MAX_DEPTH = 8


# ── Effective-payload classifier ────────────────────────────────
# Maps the FIRST-token of the effective payload to the dispatch hint
# every downstream engine will honour. This is deliberately kept as a
# table so adding a new dispatch target is a one-line change.
_DISPATCH_TABLE: list[tuple[re.Pattern[str], DispatchHint]] = [
    (re.compile(r"(?i)^\s*(?:c:\\[^\s]*\\)?(?:powershell|pwsh)(?:\.exe)?\b"),
     DispatchHint.POWERSHELL),
    (re.compile(r"(?i)^\s*(?:c:\\[^\s]*\\)?"
                 r"(?:mshta|rundll32|regsvr32|certutil|bitsadmin|"
                 r"msiexec|installutil|regasm|regsvcs|msbuild)"
                 r"(?:\.exe)?\b"), DispatchHint.LOLBAS),
    (re.compile(r"(?i)^\s*(?:c:\\[^\s]*\\)?wscript(?:\.exe)?\b"),
     DispatchHint.WSCRIPT),
    (re.compile(r"(?i)^\s*(?:c:\\[^\s]*\\)?cscript(?:\.exe)?\b"),
     DispatchHint.CSCRIPT),
    (re.compile(r"(?i)^\s*(?:c:\\[^\s]*\\)?cmd(?:\.exe)?\b"),
     DispatchHint.CMD_BATCH),
    (re.compile(r"(?i)^\s*(?:/[^\s]*/)?bash\b"),  DispatchHint.BASH),
    (re.compile(r"(?i)^\s*(?:/[^\s]*/)?python[23]?\b"), DispatchHint.PYTHON),
]


def _classify(effective_payload: str) -> DispatchHint:
    """Map an effective payload to a dispatch hint via the table."""
    if not effective_payload:
        return DispatchHint.UNKNOWN
    for pat, hint in _DISPATCH_TABLE:
        if pat.search(effective_payload):
            return hint
    # Fallback: PowerShell-shaped payloads without an explicit
    # `powershell.exe` prefix (naked scripts, .NET-static-method calls,
    # Verb-Noun cmdlets, WebClient chains). Kept in one place so the
    # CRE dispatch hint stays aligned with the semantic engine's own
    # `_PS_MARKER_RE` detector.
    if re.search(
        r"(?ix)"
        r"\b(?:iex|invoke-expression|invoke-webrequest|invoke-restmethod)\b"
        r"|\[net\.webclient\]|\[system\.net\.webclient\]"
        r"|\bnew-object\b|\bwrite-host\b|\bwrite-output\b"
        r"|\[string\]::(?:join|format)\b"
        r"|\[convert\]::(?:toint16|toint32|frombase64string)\b"
        r"|\b(?:Get|Set|New|Add|Remove|Where|ForEach|Start|Stop|Test|Import|"
        r"Export|Select|Sort|Format|Invoke|Register)-[A-Z][A-Za-z0-9]+\b",
        effective_payload,
    ):
        return DispatchHint.POWERSHELL
    return DispatchHint.UNKNOWN


def _determinism_hash(steps: list[WrapperChainStep], effective: str) -> str:
    """SHA-256 of the canonical step dicts + effective payload. The
    regression harness compares this hash across runs to prove the
    reconstruction is truly deterministic (no clock, no PID, no
    ordering wobble)."""
    payload = {
        "chain":     [s.to_dict() for s in steps],
        "effective": effective,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


def reconstruct(cmdline: str) -> CommandReconstruction:
    """Public entrypoint — reconstruct the effective executable
    payload for any nested command-line invocation."""
    original = cmdline or ""
    current = original
    chain: list[WrapperChainStep] = []
    stopped = ""

    for _ in range(MAX_DEPTH):
        candidate: WrapperChainStep | None = None
        for parser in WRAPPER_REGISTRY:
            try:
                if not parser.match(current):
                    continue
                step = parser.extract(current)
            except Exception as exc:  # noqa: BLE001
                # A wrapper parser must not raise on well-formed input
                # — but even if one does, the engine keeps trying other
                # parsers so the reconstruction is never lost.
                stopped = f"parser_error:{parser.NAME}:{type(exc).__name__}"
                continue
            if step is None:
                continue
            candidate = step
            break

        if candidate is None:
            # No parser matched this layer — we've reached the effective
            # payload OR encountered an unknown wrapper. Either way the
            # loop terminates cleanly.
            break

        chain.append(candidate)
        next_layer = candidate.normalized_command or candidate.inner_command
        if next_layer == current:
            # Sanity guard — a parser that returns its own input is
            # buggy; bail out before we infinite-loop.
            stopped = f"noop_parser:{candidate.wrapper}"
            break
        current = next_layer
    else:
        stopped = "max_depth_reached"

    reconstruction = CommandReconstruction(
        original=original,
        effective_payload=current.strip(),
        chain=chain,
        dispatch_hint=_classify(current),
        stopped_reason=stopped,
    )
    reconstruction.determinism_hash = _determinism_hash(
        chain, reconstruction.effective_payload
    )
    return reconstruction
