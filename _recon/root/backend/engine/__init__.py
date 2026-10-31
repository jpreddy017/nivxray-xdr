"""NivXRay Engine — Phase A (vision-aligned MCIP scaffold).

Layered plugin-based deterministic engine. Every layer is a plug-in registry
governed by an AnalysisContext + Budget shared across the whole pipeline.

Layers
------
L0  fingerprint/       encoding, entropy, file-type, wrapper detection
L1  archetypes/        PowerShell, CMD, JS/VBS/HTA/WMI/Office wrappers
L2  decoders/          atomic codec plugins (base64, hex, xor, ...)
L3  intelligence/      family detectors, LOLBAS matchers, tradecraft flags,
                       IOC extractors, MITRE mappers, kill-chain, similarity

Public API surface (Phase A)
----------------------------
    from engine import (
        Budget, AnalysisContext, TraceBuffer, TraceStep, Fingerprint,
        DetectResult, PluginResult, DecodeResult,        # DecodeResult = alias
        AnalystReport, DecodeOutcome,                    # DecodeOutcome = alias
        Findings, IOCBundle,
        MitreHint, FamilyHint, LolbasHit, TradecraftFlag,
        InvestigationRecommendation, SigmaRuleStub, YaraRuleStub,
        FamilyMatch, SimilarCase,
        BaseDecoder, DecoderRegistry, Orchestrator,
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
    PluginResult,
    DecodeResult,        # backwards-compat alias for PluginResult
    AnalystReport,
    DecodeOutcome,       # backwards-compat alias for AnalystReport
    Findings,
    IOCBundle,
    MitreHint,
    FamilyHint,
    LolbasHit,
    TradecraftFlag,
    InvestigationRecommendation,
    SigmaRuleStub,
    YaraRuleStub,
    FamilyMatch,
    SimilarCase,
    ConfidenceBreakdown,
    RiskContribution,
    PluginExecutionReport,
    PluginExecutionEntry,
)
from .decoder_base import BaseDecoder
from .registry import DecoderRegistry
from .orchestrator import Orchestrator
from .config import engine_mode, new_budget, EngineMode

__all__ = [
    "Budget", "AnalysisContext", "TraceBuffer", "TraceStep", "Fingerprint",
    "DetectResult", "PluginResult", "DecodeResult",
    "AnalystReport", "DecodeOutcome",
    "Findings", "IOCBundle",
    "MitreHint", "FamilyHint", "LolbasHit", "TradecraftFlag",
    "InvestigationRecommendation", "SigmaRuleStub", "YaraRuleStub",
    "FamilyMatch", "SimilarCase",
    "ConfidenceBreakdown", "RiskContribution",
    "PluginExecutionReport", "PluginExecutionEntry",
    "BaseDecoder", "DecoderRegistry", "Orchestrator",
    "engine_mode", "new_budget", "EngineMode",
]

SCHEMA_VERSION = "1.0"
