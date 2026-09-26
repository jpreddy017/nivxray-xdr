"""Knowledge Base — Pydantic schema.

A KB entry is a distilled, evidence-backed archetype derived from one or more
past investigations that share a common fingerprint (MITRE + verdict + engine).
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class KBSampleRef(BaseModel):
    """Compact reference to a source investigation (never the full doc)."""
    investigation_id: str
    input_preview: str
    engine: Optional[str] = None
    confidence: int = 0
    verdict: Optional[str] = None
    ts: Optional[str] = None


class KBIocRollup(BaseModel):
    """Aggregated IOC counts across all investigations in the cluster."""
    urls: Dict[str, int] = Field(default_factory=dict)     # url → occurrence count
    ips: Dict[str, int] = Field(default_factory=dict)
    domains: Dict[str, int] = Field(default_factory=dict)
    hashes: Dict[str, int] = Field(default_factory=dict)   # any-algo hash → count
    files: Dict[str, int] = Field(default_factory=dict)


class KBEntry(BaseModel):
    """A single Knowledge Base archetype entry."""
    slug: str                                          # url-safe stable id
    fingerprint: str                                   # deterministic hash
    title: str                                         # short human title
    summary: str                                       # 1-2 sentence blurb
    severity: str = "unknown"                          # info|low|medium|high|critical
    verdict: str = ""                                  # Malicious|Suspicious|Benign|unknown
    mitre_ids: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    engines: Dict[str, int] = Field(default_factory=dict)   # smart/magic/ai → count
    common_chains: List[str] = Field(default_factory=list)  # decoder op sequences
    iocs: KBIocRollup = Field(default_factory=KBIocRollup)
    lolbins: List[str] = Field(default_factory=list)
    samples: List[KBSampleRef] = Field(default_factory=list)   # top N sample refs
    investigation_ids: List[str] = Field(default_factory=list) # all source ids
    investigation_count: int = 0
    playbook_steps: List[str] = Field(default_factory=list)    # LLM-synthesised triage steps
    hunt_queries: List[str] = Field(default_factory=list)      # Sigma/YARA hunt ideas
    evidence_refs: List[str] = Field(default_factory=list)     # cited substrings
    warnings: List[str] = Field(default_factory=list)          # e.g. "synthesis fell back to deterministic"
    first_seen: str = Field(default_factory=_now_iso)
    last_seen: str = Field(default_factory=_now_iso)
    refreshed_at: str = Field(default_factory=_now_iso)
    user_email: Optional[str] = None                            # KB is user-scoped
