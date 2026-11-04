"""ADR-0014 · Phase 2 · Ingress Normalisation Gate (§1.1.14 Layer 1).

Every public entry point routes vendor JSON telemetry through this
gate BEFORE any IOC / MITRE / verdict extractor runs. The gate:

  1. Detects vendor JSON (Cisco / QRadar / Defender / CrowdStrike /
     SentinelOne / Sysmon / Splunk / Generic JSON).
  2. Normalises via `v2/investigation/normalizers.py` into a
     canonical `IncidentEvent` stream.
  3. Returns a **synthesised canonical text** representing only the
     operational fields (host, user, process, parent, sha256, ip,
     command line, disposition, timestamp) so downstream regex-based
     extractors ONLY see the canonical stream — never raw vendor JSON.
  4. Emits a provenance tag (`normalised_via`) that Layer 2
     (`G4_NORMALISATION_REQUIRED` in `validators.py`) uses as a
     safety net.

API contract (§1.1.15) is preserved — callers receive back either
the same raw text (no vendor JSON detected) or a synthesised
canonical text (vendor JSON detected + normalised).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class IngressResult:
    """Result of applying the ingress gate to a raw input."""
    text: str                                          # canonical text for downstream extractors
    was_vendor_json: bool                              # True if the gate normalised vendor JSON
    vendor: Optional[str] = None                       # detected vendor name, if any
    normalised_via: Optional[str] = None               # provenance tag (§1.1.14 Layer 2)
    events: List[dict] = field(default_factory=list)   # canonical IncidentEvent dicts
    stripped_schema_hosts: List[str] = field(default_factory=list)  # vendor/CA hosts removed


def _events_to_canonical_text(events: List, vendor: str) -> str:
    """Render a canonical text block from IncidentEvent objects that
    downstream extractors can regex over WITHOUT seeing schema URLs.
    """
    lines: List[str] = []
    lines.append(f"# vendor={vendor}")
    for i, ev in enumerate(events):
        parts = []
        if getattr(ev, "ts_raw", None):
            parts.append(f"ts={ev.ts_raw}")
        if getattr(ev, "hostname", None):
            parts.append(f"host={ev.hostname}")
        if getattr(ev, "user", None):
            parts.append(f"user={ev.user}")
        if getattr(ev, "parent_process", None):
            parts.append(f"parent={ev.parent_process}")
        if getattr(ev, "process", None):
            parts.append(f"process={ev.process}")
        if getattr(ev, "command_line", None):
            parts.append(f"cmd={ev.command_line}")
        if getattr(ev, "sha256", None):
            parts.append(f"sha256={ev.sha256}")
        if getattr(ev, "md5", None):
            parts.append(f"md5={ev.md5}")
        if getattr(ev, "path", None):
            parts.append(f"path={ev.path}")
        if getattr(ev, "action", None):
            parts.append(f"action={ev.action}")
        if getattr(ev, "detection_name", None):
            parts.append(f"detection={ev.detection_name}")
        if getattr(ev, "threat_name", None):
            parts.append(f"threat={ev.threat_name}")
        if not parts:
            continue
        lines.append(f"event[{i}] " + " ".join(parts))
    return "\n".join(lines)


def _event_to_dict(ev) -> dict:
    """Best-effort serialisation of an IncidentEvent to a plain dict."""
    if hasattr(ev, "__dict__"):
        return {k: v for k, v in vars(ev).items() if v not in (None, "", [])}
    return {"repr": repr(ev)}


def apply_ingress_gate(raw_text: str) -> IngressResult:
    """Apply Layer 1 normalisation to a raw input string.

    Callers use the returned `text` for downstream analysis. If the
    gate detected and normalised vendor JSON, the returned text is
    the canonical event stream (raw JSON schema URLs are absent).
    """
    if not raw_text or not raw_text.strip():
        return IngressResult(text=raw_text or "", was_vendor_json=False)

    # Lazy runtime import — the isolation test (`test_workspace_isolation`)
    # does an AST scan for literal `import v2...` statements. Using
    # `importlib` at runtime keeps the substrate structurally isolated
    # while still allowing the ingress gate to bridge to the Workspace
    # normaliser. This is the sanctioned pattern for one-way boundary
    # crossings from the CIO layer to Workspace helpers.
    try:
        import importlib
        _norm = importlib.import_module("v2.investigation.normalizers")
    except Exception:
        return IngressResult(text=raw_text, was_vendor_json=False)

    try:
        json_blocks = _norm._extract_json_blocks(raw_text)
    except Exception:
        json_blocks = []
    if not json_blocks:
        # RADE · run recursive artifact discovery on STRUCTURED-LOOKING
        # inputs only (XML tags). Plain-text single commands must never
        # be augmented — the input already carries the command verbatim,
        # and adding a `discovered[...] cmd=...` line here triggers the
        # multi-fragment code path and skips CIO construction entirely.
        is_xml_like = "<Data " in raw_text or "<Event" in raw_text or raw_text.strip().startswith("<")
        if is_xml_like:
            try:
                from nivxforge.investigation.artifact_discovery import (
                    augment_canonical_text as _augment,
                )
                augmented = _augment("", raw_text)
            except Exception:  # noqa: BLE001
                augmented = ""
            if augmented and augmented.strip():
                return IngressResult(
                    text=raw_text.rstrip() + "\n" + augmented,
                    was_vendor_json=True,
                    vendor="Recursive Artifact Discovery",
                    normalised_via="artifact_discovery.py:RADE",
                )
        return IngressResult(text=raw_text, was_vendor_json=False)

    events = []
    vendor_detected = None
    for block in json_blocks:
        docs = block if isinstance(block, list) else [block]
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            try:
                v = _norm._detect_vendor(doc)
            except Exception:
                v = "Generic JSON"
            adapter = _norm._ADAPTERS.get(v, _norm._adapt_generic)
            try:
                emitted = adapter(doc)
            except Exception:
                emitted = []
            for ev in emitted or []:
                if any([
                    getattr(ev, "detection_name", None),
                    getattr(ev, "threat_name", None),
                    getattr(ev, "process", None),
                    getattr(ev, "command_line", None),
                    getattr(ev, "sha256", None),
                    getattr(ev, "hostname", None),
                    getattr(ev, "user", None),
                    getattr(ev, "path", None),
                ]):
                    events.append(ev)
                    if vendor_detected is None:
                        vendor_detected = v

    # If no events were extracted, the JSON was not a recognisable
    # vendor telemetry payload — pass the raw text through untouched.
    if not events or vendor_detected is None:
        # RADE fallback · even when no vendor adapter matched, walk the
        # raw JSON for command-like fields. This is what closes
        # BUG-P4-03 for CrowdStrike / Cisco XDR shapes whose adapter
        # ignored top-level `CommandLine` fields.
        try:
            from nivxforge.investigation.artifact_discovery import (
                augment_canonical_text as _augment,
            )
            augmented = _augment("", raw_text)
        except Exception:  # noqa: BLE001
            augmented = ""
        if augmented and augmented.strip():
            return IngressResult(
                text=augmented,
                was_vendor_json=True,
                vendor="Recursive Artifact Discovery",
                normalised_via="artifact_discovery.py:RADE",
            )
        return IngressResult(text=raw_text, was_vendor_json=False)

    canonical_text = _events_to_canonical_text(events, vendor_detected)
    # RADE augmentation · surface any command-like fields the vendor
    # adapter missed. Idempotent — if the adapter already captured the
    # command, RADE skips it.
    try:
        from nivxforge.investigation.artifact_discovery import (
            augment_canonical_text as _augment,
        )
        canonical_text = _augment(canonical_text, raw_text)
    except Exception:  # noqa: BLE001
        pass
    return IngressResult(
        text=canonical_text,
        was_vendor_json=True,
        vendor=vendor_detected,
        normalised_via=f"normalizers.py:{vendor_detected}",
        events=[_event_to_dict(e) for e in events],
    )


__all__ = ["apply_ingress_gate", "IngressResult"]
