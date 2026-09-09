"""Process Tree schema — canonical Pydantic models for NivXRay LLM training.

This is the SINGLE SOURCE OF TRUTH for how a NivXRay process-tree is shaped —
used by the seed dataset, the LLM predictor, the validator, and every exporter.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid


def _short_id() -> str:
    return uuid.uuid4().hex[:10]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProcessEvidence(BaseModel):
    """Where in the decoded payload this process was derived from."""
    citation: str = ""                 # exact substring from decoded/raw
    layer_index: Optional[int] = None  # which decode layer produced this
    inferred: bool = False             # true = LLM inferred (e.g. downstream of IEX)
    confidence: float = Field(0.85, ge=0.0, le=1.0)


class ProcessNode(BaseModel):
    """One process in the reconstructed execution tree.

    Every field either comes from decoded evidence or is explicitly marked
    inferred with confidence — never hallucinated silently.
    """
    node_id: str = Field(default_factory=_short_id)
    parent_node_id: Optional[str] = None

    # --- Identity -------------------------------------------------------- #
    process: str                           # e.g. "powershell.exe"
    command_line: Optional[str] = None
    executable_path: Optional[str] = None
    hashes: Dict[str, str] = Field(default_factory=dict)  # md5/sha1/sha256
    signer: Optional[str] = None           # code-signing subject

    # --- Runtime context ------------------------------------------------- #
    pid: Optional[int] = None
    ppid: Optional[int] = None
    user: Optional[str] = None
    integrity_level: Optional[str] = None  # low | medium | high | system

    # --- Analyst semantics ---------------------------------------------- #
    action: str = ""                       # short human-readable purpose
    lolbin: bool = False
    mitre_ids: List[str] = Field(default_factory=list)
    tactic: Optional[str] = None           # execution | persistence | c2 …

    # --- Timing ---------------------------------------------------------- #
    ts_delta_ms: int = 0                   # ms after parent spawn
    timestamp: Optional[str] = None        # optional absolute ISO ts

    # --- Provenance ------------------------------------------------------ #
    evidence: ProcessEvidence = Field(default_factory=ProcessEvidence)

    children: List["ProcessNode"] = Field(default_factory=list)


ProcessNode.model_rebuild()


class SocRationale(BaseModel):
    """Full SOC rationale attached to a predicted tree."""
    verdict: str = ""                                            # one-liner
    severity: str = "unknown"                                    # info|low|medium|high|critical
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    iocs: Dict[str, List[str]] = Field(default_factory=dict)     # urls/ips/domains/hashes/files
    lolbins: List[str] = Field(default_factory=list)
    mitre_ids: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    sigma_opportunities: List[str] = Field(default_factory=list)
    yara_opportunities: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)       # substrings from decoded
    analyst_summary: str = ""                                    # 3–5 sentence brief


class ProcessTree(BaseModel):
    """Root object — a full predicted execution tree + SOC rationale."""
    tree_id: str = Field(default_factory=_short_id)
    platform: str = "windows"       # windows | linux | macos | container
    root: ProcessNode
    rationale: SocRationale = Field(default_factory=SocRationale)
    evidence_source: str = "decoded"  # decoded | raw | insufficient
    warnings: List[str] = Field(default_factory=list)
    generated_ts: str = Field(default_factory=_now_iso)


class TrainingRecord(BaseModel):
    """A single row of the fine-tuning dataset (JSONL)."""
    training_id: str
    platform: str
    category: str
    input_raw_command: str
    decoded_script_analysis: str
    predicted_process_tree: ProcessTree
    tags: List[str] = Field(default_factory=list)
    difficulty: str = "medium"      # easy | medium | hard | expert
    source: str = "nivxray-archetype"
