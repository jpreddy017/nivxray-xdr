"""NivXRay Engine — Phase A scaffold.

Layered plugin-based deterministic engine. Each layer is a plug-in registry
governed by an AnalysisContext + Budget shared across the whole pipeline.

Layers
------
L0  fingerprint/       encoding, entropy, file-type, wrapper detection
L1  archetypes/        PowerShell, CMD, JS/VBS/HTA/WMI/Office wrappers
L2  decoders/          atomic codec plugins (base64, hex, xor, ascii85, ...)
L3  threat_intel/      IOC, MITRE, family heuristics, kill-chain, similarity

Public API surface (Phase A)
----------------------------
    from engine import (
        Budget, AnalysisContext, TraceBuffer, TraceStep,
        Fingerprint, DetectResult, DecodeResult,
        BaseDecoder, DecoderRegistry,
        Orchestrator, DecodeOutcome,
    )
"""
from __future__ import annotations

from .models import (
    Budget,
    AnalysisContext,
    TraceBuffer,
    TraceStep,
    Fingerprint,
    DetectResult,
    DecodeResult,
    DecodeOutcome,
)
from .decoder_base import BaseDecoder
from .registry import DecoderRegistry
from .orchestrator import Orchestrator

__all__ = [
    "Budget",
    "AnalysisContext",
    "TraceBuffer",
    "TraceStep",
    "Fingerprint",
    "DetectResult",
    "DecodeResult",
    "DecodeOutcome",
    "BaseDecoder",
    "DecoderRegistry",
    "Orchestrator",
]

SCHEMA_VERSION = "1.0"
