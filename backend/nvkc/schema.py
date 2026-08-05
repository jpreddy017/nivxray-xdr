"""NVKC sample metadata schema (v1.0) + loader.

Master architecture reference: /app/memory/ARCHITECTURE.md v1.1 (FROZEN)
NVKC governance: /app/backend/nvkc/README.md

A sample descriptor is a YAML file next to (or containing) its
payload. This module defines the schema, validates it, and produces
a `NvkcSample` object that the harness can replay.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

NVKC_SCHEMA_VERSION = "1.0"


class NvkcSchemaError(Exception):
    """Raised when a sample descriptor violates the schema."""


@dataclass(frozen=True)
class ExpectedOutputs:
    terminal_state:          str
    artifact_types:          List[str]
    mitre:                   List[str]
    attack_fingerprint_hash: Optional[str]
    behavior_codes:          List[str]        = field(default_factory=list)
    ioc_kinds:               List[str]        = field(default_factory=list)
    benign:                  bool             = False


@dataclass(frozen=True)
class NvkcSample:
    slug:        str
    version:     str
    track:       str          # command_line | artifact | investigation | ...
    description: str
    tags:        List[str]
    input_kind:  str          # text | file | b64 | hex
    input_path:  Optional[Path]
    input_inline: Optional[str]
    expected:    ExpectedOutputs
    descriptor_path: Path

    # ── payload loader ────────────────────────────────────────────────
    def load_payload(self) -> bytes:
        """Return the raw payload bytes exactly as it enters the
        pipeline. Text samples are UTF-8 encoded; binary samples are
        returned verbatim."""
        if self.input_kind == "text":
            return (self.input_inline or "").encode("utf-8")
        if self.input_kind == "b64":
            import base64
            return base64.b64decode(self.input_inline or "")
        if self.input_kind == "hex":
            return bytes.fromhex((self.input_inline or "").replace(" ", ""))
        if self.input_kind == "file":
            if not self.input_path:
                raise NvkcSchemaError(f"[{self.slug}] input.kind=file but no path")
            return self.input_path.read_bytes()
        raise NvkcSchemaError(f"[{self.slug}] unknown input.kind={self.input_kind!r}")


# ─────────────────────────────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────────────────────────────
_ALLOWED_TRACKS = {"command_line", "artifact", "investigation", "image",
                   "malware_family", "benign_enterprise"}
_ALLOWED_INPUT_KINDS = {"text", "file", "b64", "hex"}


def load_sample(descriptor_path: Path) -> NvkcSample:
    with descriptor_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    def req(key: str, ty: type = str) -> Any:
        if key not in data:
            raise NvkcSchemaError(f"[{descriptor_path}] missing required '{key}'")
        v = data[key]
        if ty is str and not isinstance(v, str):
            raise NvkcSchemaError(f"[{descriptor_path}] '{key}' must be str, got {type(v).__name__}")
        return v

    version = req("version")
    if version != NVKC_SCHEMA_VERSION:
        raise NvkcSchemaError(
            f"[{descriptor_path}] unsupported NVKC schema version {version!r} "
            f"(expected {NVKC_SCHEMA_VERSION!r})")

    track = req("track")
    if track not in _ALLOWED_TRACKS:
        raise NvkcSchemaError(f"[{descriptor_path}] unknown track {track!r}")

    inp = data.get("input") or {}
    kind = inp.get("kind")
    if kind not in _ALLOWED_INPUT_KINDS:
        raise NvkcSchemaError(f"[{descriptor_path}] input.kind must be one of "
                              f"{sorted(_ALLOWED_INPUT_KINDS)}, got {kind!r}")

    input_path: Optional[Path] = None
    input_inline: Optional[str] = None
    if kind == "file":
        rel = inp.get("path")
        if not rel:
            raise NvkcSchemaError(f"[{descriptor_path}] input.path required for kind=file")
        input_path = (descriptor_path.parent / rel).resolve()
        if not input_path.exists():
            raise NvkcSchemaError(f"[{descriptor_path}] input file missing: {input_path}")
    else:
        input_inline = inp.get("inline")
        if input_inline is None:
            raise NvkcSchemaError(f"[{descriptor_path}] input.inline required for kind={kind!r}")

    exp = data.get("expected") or {}
    expected = ExpectedOutputs(
        terminal_state          = str(exp.get("terminal_state") or ""),
        artifact_types          = sorted([str(t) for t in exp.get("artifact_types") or []]),
        mitre                   = sorted([str(m).upper() for m in exp.get("mitre") or []]),
        attack_fingerprint_hash = (str(exp["attack_fingerprint_hash"])
                                   if exp.get("attack_fingerprint_hash") else None),
        behavior_codes          = sorted([str(c) for c in exp.get("behavior_codes") or []]),
        ioc_kinds               = sorted([str(k) for k in exp.get("ioc_kinds") or []]),
        benign                  = bool(exp.get("benign") or False),
    )

    return NvkcSample(
        slug            = req("slug"),
        version         = version,
        track           = track,
        description     = req("description"),
        tags            = [str(t) for t in (data.get("tags") or [])],
        input_kind      = kind,
        input_path      = input_path,
        input_inline    = input_inline,
        expected        = expected,
        descriptor_path = descriptor_path,
    )


def discover_samples(corpus_root: Path) -> List[NvkcSample]:
    """Load every `*.nvkc.yaml` under `corpus_root` (recursively).
    Sorted by slug for determinism."""
    out: List[NvkcSample] = []
    for p in sorted(corpus_root.rglob("*.nvkc.yaml")):
        out.append(load_sample(p))
    out.sort(key=lambda s: s.slug)
    return out


__all__ = [
    "NVKC_SCHEMA_VERSION",
    "NvkcSample",
    "ExpectedOutputs",
    "NvkcSchemaError",
    "load_sample",
    "discover_samples",
]
