"""
NivXRay Engine Registry · canonical model.

Records every discovered NivXRay implementation with its ACTUAL
role — not "all are detection engines".  Roles are derived from
source-code inspection, never guessed from acronyms.
"""
from __future__ import annotations
from enum import Enum


COLLECTION = "xdr_engines"


class EngineRole(str, Enum):
    DETECTION_ENGINE      = "DETECTION_ENGINE"
    CORRELATION_ENGINE    = "CORRELATION_ENGINE"
    VERDICT_ENGINE        = "VERDICT_ENGINE"
    EVIDENCE_ENGINE       = "EVIDENCE_ENGINE"
    ANALYZER              = "ANALYZER"
    PARSER                = "PARSER"
    NORMALIZER            = "NORMALIZER"
    DECODER               = "DECODER"
    INTERPRETER           = "INTERPRETER"
    ORCHESTRATOR          = "ORCHESTRATOR"
    PLANNER               = "PLANNER"
    GRAPH_ENGINE          = "GRAPH_ENGINE"
    INTELLIGENCE_ENGINE   = "INTELLIGENCE_ENGINE"
    UTILITY               = "UTILITY"
    LIBRARY               = "LIBRARY"
    PROTOCOL              = "PROTOCOL"
    OTHER                 = "OTHER"


class EngineState(str, Enum):
    DISCOVERED             = "DISCOVERED"
    REGISTERED             = "REGISTERED"
    CONFIGURATION_REQUIRED = "CONFIGURATION_REQUIRED"
    CONFIGURED             = "CONFIGURED"
    DEPENDENCY_BLOCKED     = "DEPENDENCY_BLOCKED"
    READY                  = "READY"
    CONNECTED              = "CONNECTED"
    DEGRADED               = "DEGRADED"
    ERROR                  = "ERROR"
    DISABLED               = "DISABLED"
