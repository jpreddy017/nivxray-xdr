"""
DIE · Stage-0 · Input Health Check
──────────────────────────────────
Frozen 2026-03-01 as part of IUE v2.0 (Layer 0).

Before the Input Understanding Engine even attempts to classify a
paste, we ask a simpler question:

    "Can I even process this?"

If the answer is *no*, we explain *why* so the analyst never sees a
silent failure or a cryptic 500.  The IUE pipeline still runs, but
the workspace surfaces the health notices alongside the classifier
result so trust is built the moment the paste lands.

Rules
-----
· Deterministic.  Same paste → same health verdict.
· Non-blocking.  A ``fatal`` verdict does NOT stop the pipeline — the
  analyst still gets a partial investigation for whatever content
  the IUE / preprocessor was able to salvage.
· Adds only *evidence*, never opinion.  Every issue includes the
  concrete signal that produced it.
"""
from __future__ import annotations
import base64
import binascii
import re
import string
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


# ── Public model ──────────────────────────────────────────────────
@dataclass
class HealthIssue:
    """A single health warning attached to the input."""
    id:        str                      # stable identifier (test-friendly)
    severity:  str                      # "info" | "warn" | "error"
    label:     str                      # short display label
    detail:    str                      # analyst-facing explanation
    evidence:  Optional[str] = None     # short excerpt / signal


@dataclass
class InputHealth:
    """Aggregate health verdict for a paste."""
    ok:         bool                    # True iff no error-level issues
    ready:      bool                    # True iff the pipeline should run
    bytes:      int                     # length of the paste (chars)
    issues:     List[HealthIssue] = field(default_factory=list)
    checks:     List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# ── Signals ───────────────────────────────────────────────────────
_B64_ONLY_RE   = re.compile(r"^[A-Za-z0-9+/=\r\n\s]+$")
_HEX_ONLY_RE   = re.compile(r"^[0-9a-fA-F\r\n\s]+$")
_PDF_MAGIC     = b"%PDF-"
_ZIP_MAGIC     = b"PK\x03\x04"
_GZIP_MAGIC    = b"\x1f\x8b"
_MZ_MAGIC      = b"MZ"                  # EXE / DLL
_ELF_MAGIC     = b"\x7fELF"
_PNG_MAGIC     = b"\x89PNG"
_JPG_MAGIC     = b"\xff\xd8\xff"
_OFFICE_ZIP_RE = re.compile(rb"^(PK\x03\x04)")   # DOCX / XLSX / PPTX are ZIP


def _looks_like_base64(text: str) -> bool:
    stripped = text.strip()
    return len(stripped) >= 24 and bool(_B64_ONLY_RE.match(stripped))


def _looks_like_hex(text: str) -> bool:
    stripped = text.strip()
    return len(stripped) >= 32 and bool(_HEX_ONLY_RE.match(stripped))


# ── Individual checks ─────────────────────────────────────────────
def _check_empty(text: str) -> List[HealthIssue]:
    if text is None or not text.strip():
        return [HealthIssue(
            id="empty-input",
            severity="error",
            label="Empty Input",
            detail="No content was provided.  Paste an artifact into the input pane.",
        )]
    return []


def _check_oversize(text: str, limit: int = 4_000_000) -> List[HealthIssue]:
    if len(text) > limit:
        return [HealthIssue(
            id="oversized-input",
            severity="warn",
            label="Oversized Input",
            detail=f"Input is {len(text):,} chars — exceeds soft cap of {limit:,}. "
                    "The pipeline will still run but may be truncated for downstream engines.",
            evidence=f"length = {len(text):,}",
        )]
    return []


def _check_binary_signature(text: str) -> List[HealthIssue]:
    """Detect obvious binary payload magic bytes appearing as literal
    ASCII in the paste (e.g. someone pastes an EXE header)."""
    issues: List[HealthIssue] = []
    head = text[:16].encode("latin-1", errors="ignore")
    if head.startswith(_PDF_MAGIC):
        issues.append(HealthIssue(
            id="binary-pdf",
            severity="warn",
            label="Binary PDF Detected",
            detail="Input starts with the PDF magic bytes `%PDF-` — this "
                   "appears to be a binary PDF pasted as text.  The IUE will "
                   "route this to the IDA (document) pipeline once available; "
                   "for now, extract embedded scripts/URLs separately.",
            evidence=head[:16].decode("latin-1", errors="replace"),
        ))
    if head.startswith(_ZIP_MAGIC):
        issues.append(HealthIssue(
            id="binary-zip",
            severity="warn",
            label="Binary Archive Detected",
            detail="Input starts with the ZIP magic bytes `PK\\x03\\x04` — "
                   "this appears to be a ZIP / DOCX / XLSX / PPTX archive "
                   "pasted as text.  Extract and re-submit its contents "
                   "individually until archive support lands.",
            evidence="PK\\x03\\x04",
        ))
    if head.startswith(_MZ_MAGIC) and len(text) > 64:
        issues.append(HealthIssue(
            id="binary-pe",
            severity="warn",
            label="Windows Binary Detected",
            detail="Input starts with the DOS/PE `MZ` header — this appears "
                   "to be a Windows EXE / DLL pasted as text.  The IUE will "
                   "route this to the binary artifact pipeline once available.",
            evidence="MZ",
        ))
    if head.startswith(_ELF_MAGIC):
        issues.append(HealthIssue(
            id="binary-elf",
            severity="warn",
            label="Linux Binary Detected",
            detail="Input starts with the ELF magic bytes — this appears to "
                   "be a Linux executable pasted as text.  Route through the "
                   "binary artifact pipeline (planned).",
            evidence="\\x7fELF",
        ))
    if head.startswith(_PNG_MAGIC) or head.startswith(_JPG_MAGIC):
        issues.append(HealthIssue(
            id="binary-image",
            severity="warn",
            label="Image Payload Detected",
            detail="Input starts with an image magic header (PNG / JPEG).  "
                   "OCR / IDA integration is required to extract text — planned.",
            evidence=head[:6].decode("latin-1", errors="replace"),
        ))
    return issues


def _check_base64_integrity(text: str) -> List[HealthIssue]:
    """When the paste looks like a bare base64 blob, verify padding &
    charset so the analyst learns *early* that the payload is truncated."""
    issues: List[HealthIssue] = []
    if not _looks_like_base64(text):
        return issues
    stripped = re.sub(r"\s+", "", text)
    # Padding check
    if len(stripped) % 4 != 0:
        issues.append(HealthIssue(
            id="b64-truncated",
            severity="warn",
            label="Truncated Base64",
            detail=(f"Base64 length {len(stripped):,} chars is not a multiple "
                    f"of 4 — the payload may be truncated.  Missing "
                    f"{(-len(stripped)) % 4} padding character(s); the decoder "
                    f"will attempt lenient padding but the tail may be lost."),
            evidence=stripped[-24:],
        ))
    # Charset check
    illegal = set(stripped) - set(string.ascii_letters + string.digits + "+/=")
    if illegal:
        issues.append(HealthIssue(
            id="b64-illegal-chars",
            severity="warn",
            label="Malformed Base64",
            detail=f"Base64 payload contains non-standard characters "
                    f"({', '.join(sorted(illegal))!r}).  The decoder will "
                    f"substitute a best-effort charset (URL-safe / Base64Std).",
            evidence=str(sorted(illegal))[:60],
        ))
    return issues


_ENC_CMD_RE = re.compile(
    r"(?i)-(?:e(?:c|n|nc(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?)\s+([A-Za-z0-9+/=]{16,})"
)


def _check_encoded_command_integrity(text: str) -> List[HealthIssue]:
    """Verify -EncodedCommand payloads decode cleanly as UTF-16LE."""
    m = _ENC_CMD_RE.search(text or "")
    if not m:
        return []
    b64 = m.group(1)
    if len(b64) % 4 != 0:
        return [HealthIssue(
            id="enc-b64-truncated",
            severity="warn",
            label="Truncated -EncodedCommand",
            detail=(f"PowerShell -EncodedCommand payload is {len(b64):,} chars — "
                    f"not a multiple of 4.  The decoder pads leniently, but "
                    f"the recovered script may miss its final tokens."),
            evidence=b64[-24:],
        )]
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as e:
        return [HealthIssue(
            id="enc-b64-invalid",
            severity="error",
            label="Invalid -EncodedCommand",
            detail=f"Base64 decoder rejected the payload: {e!s}. "
                    "The recovered PowerShell script will be unusable.",
            evidence=b64[:32],
        )]
    try:
        raw.decode("utf-16-le")
        return []
    except UnicodeDecodeError:
        return [HealthIssue(
            id="enc-utf16-invalid",
            severity="warn",
            label="Non-UTF-16LE -EncodedCommand",
            detail="PowerShell -EncodedCommand payload does not decode as "
                    "UTF-16LE.  The decoder will fall back to UTF-8; if the "
                    "recovered text looks garbled, the payload is corrupt.",
            evidence=b64[:32],
        )]


def _check_control_char_ratio(text: str) -> List[HealthIssue]:
    """Detect large blocks of non-printable bytes that suggest a
    corrupted paste (e.g. raw bytes copy/pasted through a terminal)."""
    if len(text) < 32:
        return []
    ctrl = sum(1 for c in text if ord(c) < 32 and c not in ("\r", "\n", "\t"))
    ratio = ctrl / max(1, len(text))
    if ratio >= 0.05:
        return [HealthIssue(
            id="high-control-chars",
            severity="warn",
            label="High Control-Char Ratio",
            detail=(f"{ratio:.0%} of the paste is non-printable control bytes "
                    f"({ctrl} of {len(text):,} chars).  The paste may be "
                    "corrupted, binary, or the terminal ate escape sequences."),
            evidence=f"control_ratio = {ratio:.3f}",
        )]
    return []


def _check_password_hint(text: str) -> List[HealthIssue]:
    """Heuristic: paste mentions a password / passphrase — likely a
    password-protected artifact.  Analyst-visible reminder."""
    if re.search(r"(?i)\b(?:password\s*[:=]|passphrase\s*[:=]|infected\s*/?\s*infected)", text or ""):
        return [HealthIssue(
            id="password-protected",
            severity="info",
            label="Password Reference Detected",
            detail="Paste mentions a password / passphrase — the underlying "
                    "artifact may be a password-protected archive.  Extract "
                    "and re-submit its contents after unlocking.",
        )]
    return []


# ── Orchestrator ──────────────────────────────────────────────────
_CHECKS = (
    ("empty",               _check_empty),
    ("oversize",            _check_oversize),
    ("binary-magic",        _check_binary_signature),
    ("base64",              _check_base64_integrity),
    ("encoded-command",     _check_encoded_command_integrity),
    ("control-chars",       _check_control_char_ratio),
    ("password-hint",       _check_password_hint),
)


def check_health(text: str) -> InputHealth:
    """Run every Stage-0 check against ``text`` and return an
    aggregate ``InputHealth``.

    Deterministic — same input → same verdict.
    """
    src = text or ""
    issues: List[HealthIssue] = []
    checks_run: List[Dict[str, Any]] = []
    for name, fn in _CHECKS:
        try:
            found = fn(src)
        except Exception as e:                                 # never fatal
            found = [HealthIssue(
                id=f"{name}-crash",
                severity="warn",
                label="Health Check Crashed",
                detail=f"{name}: {e!s}",
            )]
        checks_run.append({
            "id":       name,
            "issues":   [i.id for i in found],
            "passed":   not any(i.severity == "error" for i in found),
        })
        issues.extend(found)
    has_error = any(i.severity == "error" for i in issues)
    return InputHealth(
        ok=not has_error,
        ready=not has_error,
        bytes=len(src),
        issues=issues,
        checks=checks_run,
    )
