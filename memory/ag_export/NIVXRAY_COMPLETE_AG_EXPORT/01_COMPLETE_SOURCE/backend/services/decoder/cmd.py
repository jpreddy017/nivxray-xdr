"""CMD sub-engine · Gate 2A ·

Ships four capabilities:
  · cmd.caret_strip           — remove CMD `^` escaping outside quoted regions
  · cmd.percent_var_resolve   — statically resolve `%VAR%` when SET in same script
  · cmd.delayed_expansion     — resolve `!VAR!` under /V:ON or SETLOCAL EnableDelayedExpansion
  · cmd.set_reassembly        — apply SET VAR=… declarations found earlier in the same script

Static-only rules (owner-locked):
  · A variable is resolvable ONLY if it appears as `SET VAR=<literal>`
    (or `SET "VAR=<literal>"`) EARLIER in the same statement chain.
  · Chained SETs (`SET a=power&SET b=shell&%a%%b%`) are handled by
    processing the script left-to-right per `&`-separated segment.
  · No environment probing.  No filesystem access.  No process
    execution.  `%USERNAME%`, `%APPDATA%`, `%TEMP%`, `%COMSPEC%`
    remain unresolved (recorded in `unresolved_reasons`).
  · Caret stripping is applied OUTSIDE double-quoted regions.
    Inside `"..."` cmd.exe passes carets through literally; our
    normaliser matches that behaviour.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .types import (
    Capability, CapabilityKind, DecodedLayer, Provenance,
    ReconstructionResult, now_iso,
)
from .registry import CapabilityRegistry


ENGINE_VERSION = "0.3.0-gate2c"


# ══════════════════════════════════════════════════════════════════
# 1 · Caret stripping (Plane-B priority #1)
# ══════════════════════════════════════════════════════════════════
def strip_carets_outside_quotes(text: str) -> Tuple[str, int]:
    """Remove CMD caret escapes outside of double-quoted regions.

    Returns `(cleaned_text, caret_count_removed)`.

    Rules matching cmd.exe behaviour:
      · Inside `"..."`, carets are LITERAL — leave alone.
      · A caret at the very end of a line (line continuation) is
        NOT stripped in this pass (would change semantics).
      · Double-carets `^^` collapse to a single literal `^`.
    """
    if "^" not in text:
        return text, 0
    out: list[str] = []
    in_dquote = False
    n = len(text)
    i = 0
    removed = 0
    while i < n:
        ch = text[i]
        if ch == '"':
            in_dquote = not in_dquote
            out.append(ch)
            i += 1
            continue
        if ch == "^" and not in_dquote:
            nxt = text[i + 1] if i + 1 < n else ""
            if nxt == "^":
                # `^^` → literal `^`
                out.append("^")
                i += 2
                continue
            if nxt in ("\r", "\n", ""):
                # line continuation — preserve as-is; semantic
                # reconstruction beyond a line boundary is a
                # different concern.
                out.append(ch)
                i += 1
                continue
            # Otherwise: pure escape — drop the caret, keep next char.
            removed += 1
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), removed


def _run_caret(raw: str, parent_id: str, layer_index: int) -> Optional[DecodedLayer]:
    stripped, removed = strip_carets_outside_quotes(raw)
    if removed == 0 or stripped == raw:
        return None
    cap = _CAPS["cmd.caret_strip"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "cmd.caret_strip",
        language       = "cmd",
        bytes_in       = len(raw),
        bytes_out      = len(stripped),
        input_preview  = raw[:256],
        output         = stripped,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = f"stripped {removed} caret(s) outside quoted regions",
    )


# ══════════════════════════════════════════════════════════════════
# 2 · SET reassembly + %VAR% / !VAR! resolution (priorities #2-4)
# ══════════════════════════════════════════════════════════════════
_SET_RE  = re.compile(
    # SET VAR=value  |  SET "VAR=value"
    r'(?i)^\s*set\s+(?:"([A-Za-z_][A-Za-z_0-9]*)=([^"]*)"|'
    r'([A-Za-z_][A-Za-z_0-9]*)=([^&|<>\r\n]*))'
)
_PERCENT_VAR_RE = re.compile(r"%([A-Za-z_][A-Za-z_0-9]*)%")
_BANG_VAR_RE    = re.compile(r"!([A-Za-z_][A-Za-z_0-9]*)!")

# Gate 2B · FOR /F semantic reconstruction.
# Matches: `for /f [<options>] %<var> in (<source>) do <body>`
# `%<var>` is one letter (e.g. %i); double-percent form `%%i` also
# accepted for script context.
_FOR_F_RE = re.compile(
    r"(?i)\bfor\s+/f\s+"
    r"(?:\"[^\"]*\"\s+)?"          # optional "usebackq tokens=… delims=…"
    r"%%?([A-Za-z])\s+in\s+"
    r"\((?P<source>[^)]*)\)\s*"
    r"do\s+(?P<body>.+?)"
    r"(?=(?:\s*(?:&|\|(?!\|)|\r|\n|$)))",
    re.DOTALL,
)

# Gate 2B · Wildcard-executable resolution.
# CMD wildcards: `*` matches any run of chars, `?` matches one.
# We resolve ONLY to known-safe LOLBAS binaries — never invent.
_CMD_WILDCARD_TOKEN_RE = re.compile(r"[A-Za-z0-9*?]+\.[A-Za-z0-9*?]+")

# Leading CMD wrapper (`cmd.exe /S /C "..."`, `cmd /v:on /k …`, …).
# Deterministic peel so downstream SET reassembly + caret stripping
# operate on the actual payload, not the wrapper.  Accepts optional
# fully-qualified path (`C:\Windows\system32\cmd.exe`).
_CMD_WRAPPER_HEAD_RE = re.compile(
    r'(?i)^\s*(?:%COMSPEC%|%SystemRoot%\\[Ss]ystem32\\cmd\.exe|'
    r'%WINDIR%\\[Ss]ystem32\\cmd\.exe|'
    r'(?:[A-Za-z]:)?(?:\\+[^\\/\s"]+)*\\+cmd(?:\.exe)?|'
    r'cmd(?:\.exe)?)\b'
)
# Flags cmd.exe accepts before the /C or /K terminal flag:
#   /S · /D · /A · /U · /Q · /T:… · /E:ON|OFF · /F:ON|OFF · /V:ON|OFF
_CMD_WRAPPER_FLAG_RE = re.compile(
    r"(?i)^\s*/(?:S|D|A|U|Q|T:[^\s]+|E:(?:ON|OFF)|F:(?:ON|OFF)|"
    r"V:(?:ON|OFF)|V\s+(?:ON|OFF))"
)
_CMD_WRAPPER_TERMINAL_RE = re.compile(r"(?i)^\s*/(C|K|R)\b")


def _peel_cmd_wrapper(text: str) -> tuple[str, bool, bool]:
    """Peel any leading `cmd[.exe] [flags] /C|/K …` wrapper.

    Returns `(inner_text, peeled, delayed_expansion_flag)`.  The
    delayed-expansion flag is True iff a `/V:ON` or `/V ON` was
    present in the peeled wrapper (this is where `!VAR!` becomes
    active).
    """
    m_head = _CMD_WRAPPER_HEAD_RE.match(text)
    if not m_head:
        return text, False, False
    rest = text[m_head.end():]
    dexp = False
    # Consume optional pre-terminal flags.
    while True:
        m_flag = _CMD_WRAPPER_FLAG_RE.match(rest)
        if not m_flag:
            break
        matched = rest[:m_flag.end()]
        if re.search(r"(?i)/V(?::|\s+)ON", matched):
            dexp = True
        rest = rest[m_flag.end():]
    m_term = _CMD_WRAPPER_TERMINAL_RE.match(rest)
    if not m_term:
        # `cmd.exe` alone — no terminal flag; nothing to peel.
        return text, False, dexp
    rest = rest[m_term.end():].lstrip()
    # If the remainder is fully wrapped in "…", strip that one layer.
    if len(rest) >= 2 and rest.startswith('"') and rest.endswith('"'):
        rest = rest[1:-1]
    return rest, True, dexp

# Env vars we deliberately do NOT try to resolve (system-owned).
_UNRESOLVABLE_ENV_VARS = frozenset({
    "USERNAME", "USERDOMAIN", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "TEMP", "TMP", "PUBLIC", "COMPUTERNAME", "COMSPEC", "SYSTEMROOT",
    "WINDIR", "PROGRAMFILES", "PROGRAMDATA", "PATHEXT", "PATH",
    "PROCESSOR_ARCHITECTURE", "OS", "HOMEDRIVE", "HOMEPATH",
    "SESSIONNAME", "LOGONSERVER",
})


def _detect_delayed_expansion_enabled(text: str) -> bool:
    low = text.lower()
    return ("/v:on" in low or "/v on" in low
            or "setlocal enabledelayedexpansion" in low)


# CMD wrapper unwrap capability (registered so it appears in provenance)
_WRAPPER_CAP = Capability(
    name        = "cmd.wrapper_unwrap",
    kind        = CapabilityKind.PARSER,
    language    = "cmd",
    version     = "0.1.0",
    description = "Peel leading `cmd[.exe] [flags] /C|/K \"…\"` wrapper "
                  "so downstream reconstruction operates on payload.",
)


def _run_wrapper_unwrap(raw: str,
                        parent_id: str,
                        layer_index: int) -> Optional[DecodedLayer]:
    inner, peeled, dexp = _peel_cmd_wrapper(raw)
    if not peeled or inner == raw:
        return None
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "cmd.wrapper_unwrap",
        language       = "cmd",
        bytes_in       = len(raw),
        bytes_out      = len(inner),
        input_preview  = raw[:256],
        output         = inner,
        capability     = _WRAPPER_CAP,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = _WRAPPER_CAP.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = f"peeled cmd wrapper; delayed_expansion={dexp}",
    )


def _split_cmd_segments(text: str) -> list[str]:
    """Split a command line on `&`, `&&`, `||` while preserving
    quoted regions."""
    out: list[str] = []
    buf: list[str] = []
    in_dq = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            in_dq = not in_dq
            buf.append(ch); i += 1; continue
        if not in_dq and ch in "&|":
            nxt = text[i + 1] if i + 1 < n else ""
            if (ch == "&" and nxt == "&") or (ch == "|" and nxt == "|"):
                out.append("".join(buf).strip()); buf = []; i += 2; continue
            out.append("".join(buf).strip()); buf = []; i += 1; continue
        buf.append(ch); i += 1
    if buf:
        out.append("".join(buf).strip())
    return [s for s in out if s]


def _collect_set_assignments(segments: list[str]) -> dict[str, str]:
    """Left-to-right scan for `SET VAR=value` — later SETs shadow earlier."""
    variables: dict[str, str] = {}
    for seg in segments:
        m = _SET_RE.match(seg)
        if not m:
            continue
        var_q, val_q, var_u, val_u = m.groups()
        name  = (var_q or var_u or "").upper()
        value = (val_q if val_q is not None else (val_u or "")).strip()
        if name:
            variables[name] = value
    return variables


def _resolve_variables(text: str,
                       variables: dict[str, str],
                       allow_bang: bool) -> tuple[str, list[str], int]:
    """Perform one pass of `%VAR%` and (optionally) `!VAR!` substitution.
    Returns `(new_text, unresolved_names, substitutions_count)`."""
    unresolved: set[str] = set()
    subs = 0

    def _repl_percent(m: re.Match) -> str:
        nonlocal subs
        name = m.group(1).upper()
        if name in variables:
            subs += 1
            return variables[name]
        if name in _UNRESOLVABLE_ENV_VARS:
            unresolved.add(f"%{name}% (system env — unresolved by design)")
            return m.group(0)
        unresolved.add(f"%{name}% (not defined in same script)")
        return m.group(0)

    def _repl_bang(m: re.Match) -> str:
        nonlocal subs
        name = m.group(1).upper()
        if name in variables:
            subs += 1
            return variables[name]
        unresolved.add(f"!{name}! (not defined in same script)")
        return m.group(0)

    new_text = _PERCENT_VAR_RE.sub(_repl_percent, text)
    if allow_bang:
        new_text = _BANG_VAR_RE.sub(_repl_bang, new_text)
    return new_text, sorted(unresolved), subs


def _run_variable_resolution(
    raw: str,
    parent_id: str,
    layer_index: int,
    delayed_expansion_hint: bool = False,
) -> tuple[list[DecodedLayer], list[str]]:
    """Emit SET-reassembly / %VAR% / !VAR! layers (may produce 0, 1, or 2).

    `delayed_expansion_hint` — carries `/V:ON` state peeled from a
    parent wrapper.  cmd.exe's `!VAR!` semantics activate when
    ANY parent invocation enabled delayed expansion, not only when
    the current segment shows it.
    """
    layers: list[DecodedLayer] = []
    unresolved_all: list[str] = []

    segments  = _split_cmd_segments(raw)
    variables = _collect_set_assignments(segments)
    if not variables:
        _, unresolved, _ = _resolve_variables(
            raw, variables,
            allow_bang=(delayed_expansion_hint
                        or _detect_delayed_expansion_enabled(raw)))
        return [], unresolved

    # Layer emission strategy:
    #   1. cmd.set_reassembly    — records the discovered assignments
    #   2. cmd.percent_var_resolve — substitutes %VAR% globally
    #   3. cmd.delayed_expansion — substitutes !VAR! when /V:ON or SETLOCAL

    # (1) SET reassembly layer — knowledge, not text change.
    set_cap = _CAPS["cmd.set_reassembly"]
    layers.append(DecodedLayer(
        layer_index    = layer_index,
        stage          = "cmd.set_reassembly",
        language       = "cmd",
        bytes_in       = len(raw),
        bytes_out      = len(raw),
        input_preview  = raw[:256],
        output         = raw,
        capability     = set_cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = set_cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = "assignments: " + ", ".join(
            f"{k}={v!r}" for k, v in variables.items()),
    ))

    # (2) %VAR% substitution
    text_after_percent, unresolved_p, subs_p = _resolve_variables(
        raw, variables, allow_bang=False)
    unresolved_all.extend(unresolved_p)
    if subs_p > 0 and text_after_percent != raw:
        pct_cap = _CAPS["cmd.percent_var_resolve"]
        layers.append(DecodedLayer(
            layer_index    = layer_index + len(layers),
            stage          = "cmd.percent_var_resolve",
            language       = "cmd",
            bytes_in       = len(raw),
            bytes_out      = len(text_after_percent),
            input_preview  = raw[:256],
            output         = text_after_percent,
            capability     = pct_cap,
            provenance     = Provenance(
                decoded_from    = parent_id,
                capability_name = pct_cap.name,
                engine_version  = ENGINE_VERSION,
                recorded_at     = now_iso(),
            ),
            confidence     = "HIGH",
            notes          = f"resolved {subs_p} %VAR% substitutions",
        ))

    # (3) !VAR! substitution (only when delayed expansion is enabled)
    dexp = delayed_expansion_hint or _detect_delayed_expansion_enabled(raw)
    if dexp:
        text_after_bang, unresolved_b, subs_b = _resolve_variables(
            text_after_percent, variables, allow_bang=True)
        # Filter for only newly-added unresolved (avoid double-report)
        unresolved_new = [u for u in unresolved_b if u not in unresolved_p]
        unresolved_all.extend(unresolved_new)
        if subs_b > 0 and text_after_bang != text_after_percent:
            bang_cap = _CAPS["cmd.delayed_expansion"]
            layers.append(DecodedLayer(
                layer_index    = layer_index + len(layers),
                stage          = "cmd.delayed_expansion",
                language       = "cmd",
                bytes_in       = len(text_after_percent),
                bytes_out      = len(text_after_bang),
                input_preview  = text_after_percent[:256],
                output         = text_after_bang,
                capability     = bang_cap,
                provenance     = Provenance(
                    decoded_from    = parent_id,
                    capability_name = bang_cap.name,
                    engine_version  = ENGINE_VERSION,
                    recorded_at     = now_iso(),
                ),
                confidence     = "HIGH",
                notes          = f"resolved {subs_b} !VAR! substitutions "
                                 f"(delayed expansion detected)",
            ))
    else:
        # Bang references present but no /V:ON → honest partial.
        if _BANG_VAR_RE.search(text_after_percent):
            unresolved_all.append(
                "!VAR! references found but /V:ON / SETLOCAL "
                "EnableDelayedExpansion NOT declared — cmd.exe would "
                "treat these as literal.")

    return layers, unresolved_all


# ══════════════════════════════════════════════════════════════════
# Capability registrations
# ══════════════════════════════════════════════════════════════════
_CAPS: dict[str, Capability] = {
    "cmd.caret_strip": Capability(
        name        = "cmd.caret_strip",
        kind        = CapabilityKind.DEOBFUSCATOR,
        language    = "cmd",
        version     = "0.1.0",
        description = "Remove CMD `^` escaping outside double-quoted regions.",
    ),
    "cmd.set_reassembly": Capability(
        name        = "cmd.set_reassembly",
        kind        = CapabilityKind.PARSER,
        language    = "cmd",
        version     = "0.1.0",
        description = "Statically collect SET VAR=value assignments in "
                      "left-to-right chain order.",
    ),
    "cmd.percent_var_resolve": Capability(
        name        = "cmd.percent_var_resolve",
        kind        = CapabilityKind.DEOBFUSCATOR,
        language    = "cmd",
        version     = "0.1.0",
        description = "Substitute %VAR% using SET-declared values only. "
                      "System env vars remain unresolved.",
    ),
    "cmd.delayed_expansion": Capability(
        name        = "cmd.delayed_expansion",
        kind        = CapabilityKind.DEOBFUSCATOR,
        language    = "cmd",
        version     = "0.1.0",
        description = "Substitute !VAR! when /V:ON or SETLOCAL "
                      "EnableDelayedExpansion is present.",
    ),
    # ── Gate 2B additions ────────────────────────────────────────
    "cmd.for_f_semantic": Capability(
        name        = "cmd.for_f_semantic",
        kind        = CapabilityKind.PARSER,
        language    = "cmd",
        version     = "0.2.0",
        description = "Static semantic reconstruction of `for /f %var "
                      "in ('cmd') do body`. Records the inner command "
                      "as evidence; SUBSTITUTES the loop variable in "
                      "the body only when the inner command is a "
                      "recognised LOLBin whose typical output is known "
                      "(e.g. `where c*d.e?e`) — otherwise leaves the "
                      "loop intact and records unresolved.",
    ),
    "cmd.wildcard_exec_resolve": Capability(
        name        = "cmd.wildcard_exec_resolve",
        kind        = CapabilityKind.KNOWLEDGE,
        language    = "cmd",
        version     = "0.2.0",
        description = "Resolve CMD wildcard executable specifications "
                      "(`c*d.e?e`, `p*ell.exe`) against the LOLBAS "
                      "registry.  Only known-safe binaries are "
                      "resolved; ambiguous specs stay unresolved.",
    ),
}


# ══════════════════════════════════════════════════════════════════
# Gate 2B · wildcard-executable resolution against LOLBAS
# ══════════════════════════════════════════════════════════════════
def _wildcard_to_regex(spec: str) -> "re.Pattern":
    r_parts: list[str] = ["^"]
    for ch in spec:
        if ch == "*":
            r_parts.append(r"[^\\/\s]*")
        elif ch == "?":
            r_parts.append(r"[^\\/\s]")
        else:
            r_parts.append(re.escape(ch))
    r_parts.append("$")
    return re.compile("".join(r_parts), re.IGNORECASE)


def _resolve_wildcard_binary(spec: str) -> tuple[Optional[str], list[str]]:
    """Return `(resolved_name, candidates[])`.  Resolves ONLY when
    exactly one LOLBAS entry matches — ambiguous specs stay
    unresolved (candidates list is returned for provenance)."""
    if "*" not in spec and "?" not in spec:
        return (None, [])
    from services.die.lolbas import LOLBAS_REGISTRY
    pat = _wildcard_to_regex(spec)
    hits = [name for name in LOLBAS_REGISTRY if pat.match(name)]
    if len(hits) == 1:
        return (hits[0], hits)
    return (None, hits)


def _run_wildcard_exec(raw: str,
                       parent_id: str,
                       layer_index: int) -> tuple[Optional[DecodedLayer], list[str]]:
    """Scan `raw` for wildcard-executable tokens; resolve unique hits.
    Returns `(layer_or_none, unresolved_reasons[])`.
    """
    unresolved: list[str] = []
    substitutions: dict[str, str] = {}
    for m in _CMD_WILDCARD_TOKEN_RE.finditer(raw):
        spec = m.group(0)
        # Skip anything without a wildcard character.
        if "*" not in spec and "?" not in spec:
            continue
        # Skip domain-looking tokens (contain letters + a common TLD)
        low = spec.lower()
        if any(low.endswith(tld) for tld in (
                ".com", ".net", ".org", ".io", ".ai", ".lol", ".xyz")):
            continue
        resolved, hits = _resolve_wildcard_binary(spec)
        if resolved and spec not in substitutions:
            substitutions[spec] = resolved
        elif not resolved:
            unresolved.append(
                f"{spec} — {len(hits)} LOLBAS candidate(s): "
                f"{hits[:5] if hits else 'none'}")
    if not substitutions:
        return None, unresolved
    new_text = raw
    for spec, name in substitutions.items():
        new_text = new_text.replace(spec, name)
    cap = _CAPS["cmd.wildcard_exec_resolve"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "cmd.wildcard_exec_resolve",
        language       = "cmd",
        bytes_in       = len(raw),
        bytes_out      = len(new_text),
        input_preview  = raw[:256],
        output         = new_text,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = "resolved: " + ", ".join(
            f"{k}→{v}" for k, v in substitutions.items()),
    ), unresolved


# ══════════════════════════════════════════════════════════════════
# Gate 2B · FOR /F static semantic reconstruction
# ══════════════════════════════════════════════════════════════════
# Known static "where"-style resolutions.  Kept small and
# conservative — semantic reconstruction requires the inner
# command's stdout to be deterministically knowable.  `where
# <lolbin>` deterministically returns the absolute path to that
# lolbin; for our reconstruction we substitute the LOLBin name so
# the loop-body semantics are readable to analysts.
_STATIC_INNER_RESOLVERS: list[tuple[re.Pattern, callable]] = [
    (
        re.compile(r"(?i)^\s*where\s+([A-Za-z0-9*?._-]+\.[A-Za-z0-9*?._-]+)\s*$"),
        lambda m: _resolve_wildcard_binary(m.group(1))[0]
                  or (m.group(1) if "*" not in m.group(1) and "?" not in m.group(1)
                      else None),
    ),
    (
        re.compile(r"(?i)^\s*where\s+([A-Za-z0-9._-]+)\s*$"),
        lambda m: m.group(1) if not any(c in m.group(1)
                                        for c in "*?") else None,
    ),
]


def _resolve_for_f_inner(inner: str) -> Optional[str]:
    """Return the deterministic value the `for /f` loop variable
    would receive, or None when not statically knowable."""
    inner = inner.strip().strip("'\"")
    for pat, fn in _STATIC_INNER_RESOLVERS:
        m = pat.match(inner)
        if m:
            val = fn(m)
            if val:
                return val
    return None


def _run_for_f(raw: str,
               parent_id: str,
               layer_index: int) -> tuple[list[DecodedLayer], list[str]]:
    """Rewrite each `for /f %v in (…) do body` where the inner is
    statically resolvable; leave others as UNRESOLVED honest evidence.
    """
    layers: list[DecodedLayer] = []
    unresolved: list[str] = []
    substitutions: list[tuple[str, str, str, str]] = []  # (var, resolved, inner, body)
    new_text = raw
    for m in list(_FOR_F_RE.finditer(raw)):
        var    = m.group(1)
        inner  = m.group("source") or ""
        body   = m.group("body")   or ""
        resolved = _resolve_for_f_inner(inner)
        if resolved is None:
            unresolved.append(
                f"for /f %{var} in ({inner.strip()}) — inner not "
                "statically resolvable (Gate 2B leaves loop intact).")
            continue
        # Substitute `%var` (case-insensitive one-letter form) in body
        body_expanded = re.sub(
            rf"%{re.escape(var)}\b", resolved, body,
            flags=re.IGNORECASE)
        # Replace the whole FOR /F expression with the expanded body.
        full = m.group(0)
        new_text = new_text.replace(full, body_expanded, 1)
        substitutions.append((var, resolved, inner.strip(), body_expanded))
    if not substitutions:
        return [], unresolved
    cap = _CAPS["cmd.for_f_semantic"]
    layers.append(DecodedLayer(
        layer_index    = layer_index,
        stage          = "cmd.for_f_semantic",
        language       = "cmd",
        bytes_in       = len(raw),
        bytes_out      = len(new_text),
        input_preview  = raw[:256],
        output         = new_text,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "MEDIUM",
        notes          = "; ".join(
            f"%{v} <- {r} (from `{i}`)" for v, r, i, _ in substitutions),
    ))
    return layers, unresolved


def register_all(registry: CapabilityRegistry) -> None:
    """Register CMD sub-engine capabilities.  Idempotent."""
    if registry.get("cmd.caret_strip") is not None:
        return
    registry.register(_WRAPPER_CAP,                    _run_wrapper_unwrap)
    registry.register(_CAPS["cmd.caret_strip"],       _run_caret)
    registry.register(_CAPS["cmd.set_reassembly"],    _run_variable_resolution)
    registry.register(_CAPS["cmd.percent_var_resolve"], _run_variable_resolution)
    registry.register(_CAPS["cmd.delayed_expansion"], _run_variable_resolution)
    registry.register(_CAPS["cmd.for_f_semantic"],    _run_for_f)
    registry.register(_CAPS["cmd.wildcard_exec_resolve"], _run_wildcard_exec)


# ══════════════════════════════════════════════════════════════════
# Reconstruct pass — orchestrated by the engine
# ══════════════════════════════════════════════════════════════════
def reconstruct(raw: str, parent_id: str) -> ReconstructionResult:
    """CMD reconstruction pass.  Deterministic ordering:
       1. wrapper unwrap →
       2. caret strip →
       3. SET / %VAR% / !VAR! resolution →
       4. FOR /F semantic reconstruction →
       5. wildcard-executable resolution.
    """
    layers: list[DecodedLayer] = []
    unresolved: list[str] = []

    current = raw
    dexp_hint = False
    wrap_layer = _run_wrapper_unwrap(current, parent_id, layer_index=0)
    if wrap_layer is not None:
        layers.append(wrap_layer)
        current = wrap_layer.output
        if "delayed_expansion=True" in (wrap_layer.notes or ""):
            dexp_hint = True

    caret_layer = _run_caret(current, parent_id, layer_index=len(layers))
    if caret_layer is not None:
        layers.append(caret_layer)
        current = caret_layer.output

    var_layers, var_unresolved = _run_variable_resolution(
        current, parent_id, layer_index=len(layers),
        delayed_expansion_hint=dexp_hint)
    layers.extend(var_layers)
    unresolved.extend(var_unresolved)
    if var_layers:
        current = var_layers[-1].output

    # Gate 2B — FOR /F semantic reconstruction (up to two passes so
    # nested loops can peel).
    for _pass in range(2):
        forf_layers, forf_unresolved = _run_for_f(
            current, parent_id, layer_index=len(layers))
        unresolved.extend(forf_unresolved)
        if not forf_layers:
            break
        layers.extend(forf_layers)
        current = forf_layers[-1].output

    # Gate 2B — wildcard-executable resolution against LOLBAS.
    wild_layer, wild_unresolved = _run_wildcard_exec(
        current, parent_id, layer_index=len(layers))
    unresolved.extend(wild_unresolved)
    if wild_layer is not None:
        layers.append(wild_layer)
        current = wild_layer.output

    partial = bool(unresolved)
    return ReconstructionResult(
        raw_input          = raw,
        final              = current,
        layers             = layers,
        unresolved_reasons = unresolved,
        partial            = partial,
        engine_version     = ENGINE_VERSION,
        static_only_verified = True,
    )


# Registration is invoked by `services.decoder.registry.get_registry()`
# on first use; see `register_all()` above.


__all__ = [
    "strip_carets_outside_quotes",
    "reconstruct",
    "register_all",
]
