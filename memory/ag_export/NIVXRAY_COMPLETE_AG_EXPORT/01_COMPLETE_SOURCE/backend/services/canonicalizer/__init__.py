"""
NivXRay · Evidence Canonicalizer (P0.15A · ADR-002)
────────────────────────────────────────────────────

Pure, deterministic. Takes a raw command string in the shape
threat-report vendors publish (with launcher wrappers such as
``cmd.exe /S /C "…"`` or ``powershell -EncodedCommand …``) and
returns the canonical form the Behavior Classifier consumes:

    { launcher_chain:    ["cmd.exe", "powershell.exe"],
      effective_command: "mshta",
      effective_head:    "mshta.exe",
      payload:           "http://…",
      unwrap_depth:      2,
      canonicalizer_version: "1.0" }

Every classifier call site routes through here so the classifier
no longer cares HOW the command was wrapped — only WHAT it does.

Architectural boundary (ADR-002 §8):
  · This module NEVER emits Behaviors, MITRE tids, or
    Recommendations.  It converts syntax; semantic interpretation
    happens downstream.
"""
from __future__ import annotations

import base64
import shlex
from dataclasses  import dataclass, field, asdict
from typing       import Any, Dict, List, Optional, Tuple


CANONICALIZER_VERSION = "1.0"

# Hard cap · protects against pathological nested wrappers.  ADR-002 §8.
_MAX_UNWRAP_DEPTH = 4


# ══════════════════════════════════════════════════════════════════
# Launcher rules  (extension point per ADR-002 §7)
# ══════════════════════════════════════════════════════════════════
# Each entry declares:
#   heads      · set of executable names that identify this launcher
#                (case-insensitive, with or without ``.exe``)
#   unwrap     · flag arguments after which the *next* token is the
#                inner command payload.  Order matters — first match wins.
#   base64     · optional flag whose argument is base64-encoded (e.g.
#                PowerShell ``-EncodedCommand``).  When present, the
#                canonicalizer decodes the payload before recursing.
_LAUNCHER_RULES: Tuple[Dict[str, Any], ...] = (
    {
        "name":    "cmd",
        "heads":   ("cmd", "cmd.exe"),
        "unwrap":  ("/c", "/r", "/k"),   # /c is the common one; /s /c collapses to /c after tokenising
        "base64":  (),
    },
    {
        # Windows `start` wrapper — real-world telemetry chains this as
        # `%COMSPEC% /c start /b /min powershell -EncodedCommand …`.
        # `start` isn't an executable; it's a cmd builtin, but for
        # canonicalization purposes it's another wrapper we must peel.
        # Every token after the last `start`-flag is the inner command.
        "name":         "start",
        "heads":        ("start", "start.exe"),
        "unwrap":       (),
        "base64":       (),
        "start_wrapper": True,
    },
    {
        "name":    "powershell",
        "heads":   ("powershell", "powershell.exe"),
        "unwrap":  ("-command", "-c"),
        "base64":  ("-encodedcommand", "-enc", "-e"),
    },
    {
        "name":    "pwsh",
        "heads":   ("pwsh", "pwsh.exe"),
        "unwrap":  ("-command", "-c"),
        "base64":  ("-encodedcommand", "-enc", "-e"),
    },
    {
        "name":    "mshta",
        "heads":   ("mshta", "mshta.exe"),
        # mshta payload is the URL/JS itself — not behind a flag.
        # Handled via ``inline_after_head=True`` below.
        "unwrap":  (),
        "base64":  (),
        "inline_after_head": True,
    },
    {
        "name":    "rundll32",
        "heads":   ("rundll32", "rundll32.exe"),
        "unwrap":  (),
        "base64":  (),
        "inline_after_head": True,
    },
    {
        "name":    "regsvr32",
        "heads":   ("regsvr32", "regsvr32.exe"),
        "unwrap":  (),
        "base64":  (),
        "inline_after_head": True,
    },
    {
        "name":    "wscript",
        "heads":   ("wscript", "wscript.exe"),
        "unwrap":  (),
        "base64":  (),
        "inline_after_head": True,
    },
    {
        "name":    "cscript",
        "heads":   ("cscript", "cscript.exe"),
        "unwrap":  (),
        "base64":  (),
        "inline_after_head": True,
    },
    {
        "name":    "bash",
        "heads":   ("bash", "sh"),
        "unwrap":  ("-c",),
        "base64":  (),
    },
)


@dataclass
class CanonicalCommand:
    """The single shape every downstream consumer must accept."""
    raw:                str
    launcher_chain:     List[str] = field(default_factory=list)
    effective_command:  str        = ""
    effective_head:     str        = ""
    payload:            str        = ""
    unwrap_depth:       int        = 0
    canonicalizer_version: str     = CANONICALIZER_VERSION
    # P0-0 Decoder-in-Pipeline plumbing (2026-09-02).  Additive
    # fields — every previous consumer continues to work unchanged.
    #
    # `decoded_layers[]` — each layer is a canonical CHILD of this
    #   command with `provenance.decoded_from` pointing back at the
    #   parent evidence id (owner invariant: technique claim →
    #   supporting evidence required).
    # `decoded_iocs[]`   — IOCs surfaced from decoded layers, each
    #   stamped with the decoded_layer_id + decoded_from provenance.
    # `decoded_final`    — fully-peeled payload (single string).
    decoded_layers:     List[Dict[str, Any]] = field(default_factory=list)
    decoded_iocs:       List[Dict[str, Any]] = field(default_factory=list)
    decoded_final:        str                  = ""
    decoded_intelligence: Dict[str, Any]       = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════
def canonicalize(raw: str,
                                 *,
                                 parent_canonical_id: str | None = None,
                                 with_decoder: bool = True) -> CanonicalCommand:
    """Return a ``CanonicalCommand`` for ``raw``.

    When ``with_decoder=True`` (default), the fully-peeled payload
    is ALSO run through the existing recursive decoder engine via
    ``services.decoder_bridge.decode_commandline``.  Each decoded
    layer is attached as a canonical CHILD, and decoded IOCs are
    projected onto the parent so downstream ATT&CK / Verdict /
    Narration surfaces can consume them.

    ``parent_canonical_id`` is the id of the raw evidence this
    canonical command was derived from — becomes the
    ``provenance.decoded_from`` for every child layer.  When None,
    a stable synthetic id is used.

    Never raises; on any parse error returns a canonical form where
    ``effective_command == raw`` and ``launcher_chain == []`` so the
    caller can always trust the shape."""
    if not raw or not isinstance(raw, str):
        return CanonicalCommand(raw=raw or "")
    current = _expand_windows_envvars(raw.strip())
    chain: List[str] = []
    depth = 0
    while depth < _MAX_UNWRAP_DEPTH:
        rule, inner = _peel_one_launcher(current)
        if rule is None:
            break
        chain.append(rule["name"] + ".exe")
        current = inner
        depth += 1
    head = _head_of(current)

    decoded_layers: List[Dict[str, Any]] = []
    decoded_iocs:   List[Dict[str, Any]] = []
    decoded_final = current
    if with_decoder:
        # P0-0 plumbing — delegate to the existing recursive engine
        # for Plane-A codec projection (Base64, GZIP, UTF-16LE, XOR,
        # RC4, AES, PE detection, …).  This path calls the XDR-owned
        # `services/die/preprocessor/recursive_decoder` — an internal
        # module, NOT an external bridge.  Slated to collapse into
        # `services/decoder/` at Gate 2D.
        try:
            from services.decoder_bridge import (      # noqa: WPS433
                decode_commandline, project_iocs,
            )
            pid = parent_canonical_id or f"canonical:{abs(hash(raw)) & 0xffffffff:x}"
            final_text, layers = decode_commandline(raw, pid)
            decoded_final  = final_text or current
            decoded_layers = [l.to_dict() for l in layers]
            decoded_iocs   = project_iocs(layers)
        except Exception:      # decoder must NEVER break canonicalisation
            decoded_layers, decoded_iocs, decoded_final = [], [], current

        # P0-1B Gate 2A/2B · call the XDR-owned Universal Decoder
        # Engine for CMD Plane-B semantic reconstruction (caret,
        # SET reassembly, %VAR%/!VAR!, FOR /F, wildcard-exec).
        # Runs on the ORIGINAL raw so wrapper unwrap can see the
        # `cmd.exe /c "..."` shape.  Its layers are appended AFTER
        # the codec layers so analysts see codec-then-semantic order.
        try:
            from services.decoder import decode_universal    # noqa: WPS433
            pid_b = parent_canonical_id or f"canonical:{abs(hash(raw)) & 0xffffffff:x}"
            ureq = decode_universal(raw, pid_b)
            if ureq.layers:
                for l in ureq.layers:
                    d = l.to_dict()
                    d["source"] = "universal_decoder"
                    decoded_layers.append(d)
                # Promote the universal-decoder final when the codec
                # bridge produced NO layers (its decoded_final would
                # then be the original raw, i.e. no progress).  When
                # the codec bridge DID produce layers, keep its final
                # (Plane-A peel outranks Plane-B for downstream IOC
                # projection until Gate 2D absorbs codecs).
                if not any(l.get("source") != "universal_decoder"
                           for l in decoded_layers) \
                   and ureq.final and ureq.final != raw:
                    decoded_final = ureq.final
                    # Re-scan the semantically-reconstructed text so
                    # IOCs (URLs, IPs, hashes) that only surface post-
                    # reconstruction are surfaced honestly.  Uses the
                    # existing DIE extractor — no new IOC logic.
                    try:
                        from services.die.ioc_semantic import extract_iocs
                        for ioc in extract_iocs(ureq.final,
                                                source="universal_decoder") or []:
                            decoded_iocs.append(ioc)
                    except Exception:
                        pass
        except Exception:      # engine must NEVER break canonicalisation
            pass

        # P0-1B Gate 2D-B2 · MANDATORY Deterministic Decode
        # Orchestrator (DDO) integration.  Runs on the decoded_final
        # so Plane-A encodings inside a peeled payload also fold.
        # Signature-driven and bounded — cannot false-reconstruct
        # plain English text.
        try:
            from services.decoder.orchestrator import orchestrate     # noqa: WPS433
            ddo_input = decoded_final or raw
            ddo_pid   = f"ddo:{parent_canonical_id or 'root'}"
            ddo_res   = orchestrate(ddo_input, parent_id=ddo_pid)
            if ddo_res.layers:
                for l in ddo_res.layers:
                    d = l.to_dict()
                    d["source"] = "ddo"
                    decoded_layers.append(d)
                if ddo_res.final and ddo_res.final != ddo_input:
                    decoded_final = ddo_res.final
                    try:
                        from services.die.ioc_semantic import extract_iocs
                        for ioc in extract_iocs(ddo_res.final,
                                                source="ddo") or []:
                            decoded_iocs.append(ioc)
                    except Exception:
                        pass
        except Exception:
            pass

    # Build authoritative decoded_intelligence bundle
    if not decoded_layers:
        stop_reason = "already_plaintext"
    else:
        stop_reason = "terminal_plaintext_reached"
        for lyr in reversed(decoded_layers):
            if isinstance(lyr, dict):
                r = lyr.get("stop_reason") or (lyr.get("meta") or {}).get("stop_reason")
                if r:
                    stop_reason = r
                    break

    valid_stop_tokens = {
        "already_plaintext",
        "no_transformation_identified",
        "terminal_plaintext_reached",
        "no_further_transformation",
        "max_depth_reached",
        "size_limit_exceeded",
    }
    if stop_reason not in valid_stop_tokens:
        if not decoded_layers:
            stop_reason = "already_plaintext"
        elif decoded_final and decoded_final != raw:
            stop_reason = "terminal_plaintext_reached"
        else:
            stop_reason = "no_further_transformation"

    semantic_understanding: Dict[str, Any] = {}
    security_controls: Dict[str, Any] = {"tampering_detected": False, "findings": [], "mitre_techniques": []}
    try:
        from services.analyzers.security_controls import analyze_security_controls
        security_controls = analyze_security_controls(decoded_final or raw)
    except Exception:
        pass

    if with_decoder and decoded_final and decoded_final != raw:
        try:
            from services.die.api import analyze as die_analyze
            sem = die_analyze(decoded_final)
            techniques = list(sem.get("techniques", []))
            for t in security_controls.get("mitre_techniques", []):
                if t not in techniques:
                    techniques.append(t)

            semantic_understanding = {
                "language": sem.get("language", "unknown"),
                "techniques": techniques,
                "lolbins": sem.get("lolbins", []),
                "attack_intent": sem.get("attack_intent", {}),
                "summary": (
                    f"Decoded {sem.get('language', 'command')} payload"
                    + (f" utilizing LOLBAS: {', '.join(b.get('name', '') for b in sem.get('lolbins', []))}" if sem.get('lolbins') else "")
                ),
            }
        except Exception:
            pass

    # Build authoritative structured IOC bundle matching downstream contract
    ioc_bundle: Dict[str, Any] = {
        "ips": [],
        "urls": [],
        "domains": [],
        "hashes": {"md5": [], "sha1": [], "sha256": []},
        "emails": [],
        "files": [],
        "raw_iocs": decoded_iocs,
    }

    all_extracted_iocs = list(decoded_iocs)
    if decoded_final and decoded_final != raw:
        try:
            from services.die.ioc_semantic import extract_iocs
            final_extracted = extract_iocs(decoded_final, source="decoded_final") or []
            for item in final_extracted:
                if not any(d.get("value") == item.get("value") for d in all_extracted_iocs):
                    all_extracted_iocs.append(item)
        except Exception:
            pass

    import re as _re_canon
    for ioc in all_extracted_iocs:
        if not isinstance(ioc, dict):
            continue
        val = str(ioc.get("value") or "").strip()
        if not val:
            continue
        kind = str(ioc.get("kind") or ioc.get("type") or "").lower()
        if kind in ("ip", "ipv4", "ipv6") or (not kind and _re_canon.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", val)):
            if val not in ioc_bundle["ips"]:
                ioc_bundle["ips"].append(val)
        elif kind == "url" or (not kind and val.startswith(("http://", "https://"))):
            if val not in ioc_bundle["urls"]:
                ioc_bundle["urls"].append(val)
        elif kind == "domain":
            if val not in ioc_bundle["domains"]:
                ioc_bundle["domains"].append(val)
        elif kind == "email":
            if val not in ioc_bundle["emails"]:
                ioc_bundle["emails"].append(val)
        elif kind in ("md5", "sha1", "sha256"):
            if val not in ioc_bundle["hashes"].get(kind, []):
                ioc_bundle["hashes"][kind].append(val)
        else:
            if _re_canon.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", val):
                if val not in ioc_bundle["ips"]:
                    ioc_bundle["ips"].append(val)
            elif val.startswith(("http://", "https://")):
                if val not in ioc_bundle["urls"]:
                    ioc_bundle["urls"].append(val)

    decoded_intel = {
        "raw_command": raw,
        "effective_payload": decoded_final or current,
        "stages": decoded_layers,
        "stage_count": len(decoded_layers),
        "stop_reason": stop_reason,
        "iocs": ioc_bundle,
        "semantic_understanding": semantic_understanding,
        "security_controls": security_controls,
    }

    return CanonicalCommand(
        raw                  = raw,
        launcher_chain       = chain,
        effective_command    = _canonical_name(head),
        effective_head       = head,
        payload              = current,
        unwrap_depth         = depth,
        decoded_layers       = decoded_layers,
        decoded_iocs         = decoded_iocs,
        decoded_final        = decoded_final,
        decoded_intelligence = decoded_intel,
    )


def _expand_windows_envvars(cmd: str) -> str:
    """Expand the two Windows environment variables real-world EDR
    telemetry uses to launch cmd.exe.  Deterministic — no OS lookup.

    * ``%COMSPEC%``                        → ``cmd.exe``
    * ``%SystemRoot%\\system32\\cmd.exe``    → ``cmd.exe``
    * ``%WINDIR%\\system32\\cmd.exe``        → ``cmd.exe``

    Case-insensitive; only applied when the env-var is the very first
    token so we never rewrite argument payloads.
    """
    import re as _re
    # Only touch the leading token — never rewrite the middle of a payload.
    return _re.sub(
        r"^(?:"
        r"%COMSPEC%"
        r"|%SystemRoot%\\[Ss]ystem32\\cmd\.exe"
        r"|%WINDIR%\\[Ss]ystem32\\cmd\.exe"
        r")",
        "cmd.exe",
        cmd,
        flags=_re.IGNORECASE,
    )


# ══════════════════════════════════════════════════════════════════
# Internals
# ══════════════════════════════════════════════════════════════════
def _head_of(cmd: str) -> str:
    """Return the first token of ``cmd`` — the executable name."""
    cmd = (cmd or "").lstrip('"').lstrip("'").strip()
    if not cmd:
        return ""
    # Fast-path: split on the first whitespace, then strip surrounding
    # quotes.  shlex is heavy for a hot path and we only need the head.
    head = cmd.split(None, 1)[0]
    head = head.strip('"').strip("'")
    # If head is a path (C:\...\foo.exe or /usr/bin/foo), keep the leaf.
    for sep in ("\\", "/"):
        if sep in head:
            head = head.rsplit(sep, 1)[-1]
    return head


def _canonical_name(head: str) -> str:
    """Strip the ``.exe`` suffix so downstream matches on family."""
    if not head:
        return ""
    h = head.lower()
    if h.endswith(".exe"):
        h = h[:-4]
    return h


def _peel_one_launcher(cmd: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Try to unwrap ``cmd`` by exactly one launcher.  Returns
    ``(rule, inner)`` on success or ``(None, cmd)`` if ``cmd`` doesn't
    start with any known launcher."""
    head = _head_of(cmd)
    if not head:
        return (None, cmd)
    head_lc = head.lower()
    rule = None
    for r in _LAUNCHER_RULES:
        if head_lc in r["heads"] or (
                head_lc + ".exe" in r["heads"]):
            rule = r
            break
    if rule is None:
        return (None, cmd)

    # Tokenise the argument list after the head.  shlex handles
    # nested quotes cleanly which matters for `cmd /S /C "..."`.
    try:
        tokens = shlex.split(cmd, posix=False)
    except ValueError:
        # unbalanced quotes — give up gracefully.
        return (None, cmd)
    if not tokens:
        return (None, cmd)
    args = tokens[1:]

    # 1. base64 flag → decode → recurse.
    for flag in rule.get("base64", ()):
        for i, tok in enumerate(args):
            if tok.lower() == flag and i + 1 < len(args):
                b64_payload = args[i + 1].strip('"').strip("'")
                decoded = _try_b64_decode(b64_payload)
                if decoded:
                    return (rule, decoded)

    # 2. unwrap flag → next token(s) are the inner command string.
    for flag in rule.get("unwrap", ()):
        for i, tok in enumerate(args):
            if tok.lower() == flag and i + 1 < len(args):
                # Windows quirk: `cmd /S /C "…"` uses /S as a wrapper
                # flag before /C.  shlex keeps them as sibling tokens
                # so we don't need to special-case /S — /C or /c is
                # still the marker.
                #
                # Two payload shapes appear in real telemetry:
                #   (a) fully quoted:   cmd /c "powershell -enc XYZ"
                #       shlex de-quotes so args[i+1] IS the full inner.
                #   (b) unquoted:       cmd /c start /b /min powershell …
                #       every token from i+1 to end is the inner command.
                # We prefer (a) if the next token itself parses as a
                # multi-word command; otherwise we join the remainder.
                remainder = args[i + 1:]
                next_tok  = remainder[0].strip()
                if len(remainder) == 1 or " " in next_tok:
                    inner = next_tok
                else:
                    inner = " ".join(remainder).strip()
                return (rule, inner)

    # 3. Inline launchers (mshta / rundll32 / regsvr32 / wscript / cscript)
    # — every token after the head is the payload as a single string.
    if rule.get("inline_after_head") and args:
        inner = " ".join(args).strip()
        return (rule, inner)

    # 4. Windows `start` wrapper — `start /b /min <cmd> <args…>`.
    # Skip leading /flags (single letter or slash-key options) until we
    # hit the first non-flag token, which is the wrapped executable.
    if rule.get("start_wrapper"):
        i = 0
        while i < len(args) and args[i].startswith("/"):
            i += 1
        # Some `start` invocations use a quoted title as the first
        # positional arg: `start "" /b powershell …`.  If the first
        # positional token is a bare pair of quotes (or an empty
        # string after shlex de-quoting), skip it.
        if i < len(args) and args[i] in ('""', "''", ""):
            i += 1
        if i < len(args):
            inner = " ".join(args[i:]).strip()
            if inner:
                return (rule, inner)

    return (None, cmd)


def _try_b64_decode(s: str) -> Optional[str]:
    """Best-effort base64 decode.  PowerShell ``-EncodedCommand``
    payloads are UTF-16-LE.  Returns None on any failure."""
    try:
        raw = base64.b64decode(s, validate=False)
    except Exception:
        return None
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            decoded = raw.decode(enc).strip("\x00")
        except UnicodeDecodeError:
            continue
        # Sanity — only accept decodes that look like commands.
        if decoded and any(ch.isprintable() for ch in decoded[:32]):
            return decoded
    return None


__all__ = [
    "canonicalize",
    "CanonicalCommand",
    "CANONICALIZER_VERSION",
]
