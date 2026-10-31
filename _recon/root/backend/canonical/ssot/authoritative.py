"""AuthoritativeSSOT — the canonical investigation object (D2-d).

Structural rules (enforced at runtime):
    - Append-only for authoritative buckets (ADR-005 §4.2).
    - Every appended entry MUST carry Provenance (D3-z).
    - Projection buckets exist but MUST remain empty in Phase 2.
    - fingerprint() is deterministic canonical-JSON sha256.
    - freeze() locks the object; further appends raise.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, is_dataclass, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

from .models import (
    ActivityProjection,
    Artifact,
    AttckProjection,
    ContextBucket,
    EvidenceGraph,
    ExecutionStep,
    GraphEdge,
    GraphNode,
    HistoricalItem,
    IOCProjection,
    Provenance,
    ReasoningStep,
    ReportsProjection,
    Source,
    ThreatIntelProjection,
    VerdictProjection,
)
from .ssot_ref import SSOTRef, make_ssot_ref


SCHEMA_VERSION = "2.0.0-phase2"


APPENDABLE_BUCKETS = frozenset({
    "evidence_graph.nodes",
    "evidence_graph.edges",
    "reasoning_steps",
    "artifacts",
    "execution_trace",
    "context.historical",
})


PROJECTION_BUCKETS = frozenset({
    "activity", "iocs", "threat_intel", "attck", "attack_chain",
    "attack_story", "verdict", "recommendations", "analyst_summary",
    "executive_summary", "reports", "timeline",
})


# ── canonical JSON + fingerprint ────────────────────────────────────────
def _default(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, bytes):
        # Bytes are represented by their hex + length so fingerprints are
        # stable across encodings. Fingerprint-critical.
        return {"__bytes_hex__": obj.hex(), "__len__": len(obj)}
    raise TypeError(f"non-serialisable: {type(obj).__name__}")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, default=_default, sort_keys=True,
                      ensure_ascii=False, separators=(",", ":"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── AuthoritativeSSOT ───────────────────────────────────────────────────
@dataclass
class AuthoritativeSSOT:
    """Canonical investigation object.

    See ADR-005 §4.1 for the required buckets. Append-only via `.append(...)`.
    """
    # ── Identity ─────────────────────────────────────────────────────────
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = SCHEMA_VERSION
    created_at: str = ""
    updated_at: str = ""
    source: Source = field(default_factory=Source)

    # ── Authoritative tier ───────────────────────────────────────────────
    input_raw: Any = None                          # bytes | str
    input_profile: Dict[str, Any] = field(default_factory=dict)
    input_health: Dict[str, Any] = field(default_factory=dict)
    iue_decision: Dict[str, Any] = field(default_factory=dict)
    plan: List[Dict[str, Any]] = field(default_factory=list)
    execution_trace: List[ExecutionStep] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    evidence_graph: EvidenceGraph = field(default_factory=EvidenceGraph)
    reasoning_steps: List[ReasoningStep] = field(default_factory=list)
    context: ContextBucket = field(default_factory=ContextBucket)

    # ── Provenance of the SSOT itself ────────────────────────────────────
    provenance: Optional[Provenance] = None

    # ── Misc ─────────────────────────────────────────────────────────────
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ── Projection tier (EMPTY in Phase 2) ───────────────────────────────
    activity: ActivityProjection = field(default_factory=ActivityProjection)
    iocs: IOCProjection = field(default_factory=IOCProjection)
    threat_intel: ThreatIntelProjection = field(default_factory=ThreatIntelProjection)
    attck: AttckProjection = field(default_factory=AttckProjection)
    attack_chain: List[Dict[str, Any]] = field(default_factory=list)
    attack_story: Optional[Dict[str, Any]] = None
    verdict: VerdictProjection = field(default_factory=VerdictProjection)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    analyst_summary: Optional[Dict[str, Any]] = None
    executive_summary: Optional[Dict[str, Any]] = None
    reports: ReportsProjection = field(default_factory=ReportsProjection)
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    # ── Freeze flag (not part of persisted state) ────────────────────────
    _frozen: bool = field(default=False, repr=False, compare=False)

    # ─────────────────────────────────────────────────────────────────────
    #                         APPEND-ONLY API
    # ─────────────────────────────────────────────────────────────────────
    def append(self, bucket: str, entry: Any, provenance: Optional[Provenance] = None) -> Any:
        """Append `entry` to `bucket`. Provenance MANDATORY.

        `bucket` must be one of APPENDABLE_BUCKETS. Every entry must
        carry Provenance either via its own `provenance` attribute OR
        via the `provenance=` argument (used to stamp the entry).
        """
        if self._frozen:
            raise ValueError("AuthoritativeSSOT is frozen; further appends forbidden")

        if bucket not in APPENDABLE_BUCKETS:
            raise ValueError(
                f"bucket {bucket!r} not appendable; allowed: {sorted(APPENDABLE_BUCKETS)}"
            )

        # Stamp provenance if not carried by entry.
        entry_prov = getattr(entry, "provenance", None)
        if entry_prov is None and provenance is None:
            raise ValueError(
                f"append({bucket!r}) requires Provenance; provide via entry.provenance "
                "or the provenance= argument (D3-z)"
            )
        if entry_prov is None and provenance is not None:
            try:
                entry.provenance = provenance                       # type: ignore[attr-defined]
            except Exception as exc:                                # noqa: BLE001
                raise ValueError(
                    f"cannot stamp provenance on entry of type {type(entry).__name__}: {exc}"
                )

        # Route to the correct list.
        target_list = self._resolve_bucket(bucket)
        target_list.append(entry)
        return entry

    def _resolve_bucket(self, bucket: str) -> List[Any]:
        if bucket == "evidence_graph.nodes":
            return self.evidence_graph.nodes
        if bucket == "evidence_graph.edges":
            return self.evidence_graph.edges
        if bucket == "reasoning_steps":
            return self.reasoning_steps
        if bucket == "artifacts":
            return self.artifacts
        if bucket == "execution_trace":
            return self.execution_trace
        if bucket == "context.historical":
            return self.context.historical
        raise ValueError(f"unknown bucket {bucket!r}")

    # ─────────────────────────────────────────────────────────────────────
    #                     PROJECTION-BOUNDARY GUARD
    # ─────────────────────────────────────────────────────────────────────
    def assert_projections_empty(self) -> None:
        """Phase 2 invariant: projections must remain empty. Phase 4 lifts."""
        errors: List[str] = []
        if any([self.activity.processes, self.activity.files,
                self.activity.network, self.activity.registry, self.activity.auth]):
            errors.append("activity.*")
        if any([self.iocs.urls, self.iocs.ips, self.iocs.domains, self.iocs.emails,
                self.iocs.hashes, self.iocs.files, self.iocs.registry,
                self.iocs.user_agents, self.iocs.bitcoin_addresses]):
            errors.append("iocs.*")
        if self.threat_intel.hits or self.threat_intel.sources:
            errors.append("threat_intel.*")
        if self.attck.techniques or self.attck.tactics or self.attck.kill_chain:
            errors.append("attck.*")
        if self.attack_chain:
            errors.append("attack_chain")
        if self.attack_story is not None:
            errors.append("attack_story")
        if self.verdict.label or self.verdict.confidence or self.verdict.contributors:
            errors.append("verdict")
        if self.recommendations:
            errors.append("recommendations")
        if self.analyst_summary is not None:
            errors.append("analyst_summary")
        if self.executive_summary is not None:
            errors.append("executive_summary")
        if any([self.reports.stix, self.reports.sigma, self.reports.yara,
                self.reports.navigator, self.reports.mdr]):
            errors.append("reports.*")
        if self.timeline:
            errors.append("timeline")
        if errors:
            raise AssertionError(
                f"Phase 2 invariant violated — projection buckets non-empty: {errors}"
            )

    # ─────────────────────────────────────────────────────────────────────
    #                         FINGERPRINT + FREEZE
    # ─────────────────────────────────────────────────────────────────────
    def to_canonical_json(self) -> str:
        """Deterministic canonical JSON. Excludes _frozen."""
        d = asdict(self)
        d.pop("_frozen", None)
        return canonical_json(d)

    def fingerprint(self) -> str:
        return sha256_hex(self.to_canonical_json())

    def freeze(self) -> None:
        """Freeze the SSOT — further appends will raise."""
        object.__setattr__(self, "_frozen", True)

    def is_frozen(self) -> bool:
        return bool(self._frozen)

    def to_ssot_ref(self) -> SSOTRef:
        """Compute the SSOT reference (D6-r) from the fingerprint."""
        return make_ssot_ref(self.fingerprint())

    # ─────────────────────────────────────────────────────────────────────
    #                         SERIALISATION
    # ─────────────────────────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("_frozen", None)
        return d

    @staticmethod
    def _rebuild_provenance(d: Optional[Dict[str, Any]]) -> Optional[Provenance]:
        if d is None:
            return None
        return Provenance(
            engine=d.get("engine", ""),
            version=d.get("version", ""),
            at=d.get("at", ""),
            upstream_evidence_ids=list(d.get("upstream_evidence_ids", [])),
        )

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthoritativeSSOT":
        """Rebuild an AuthoritativeSSOT from a to_dict() output."""
        d = dict(d)
        d.pop("_frozen", None)

        # Rebuild nested dataclasses conservatively (Phase 2 minimum).
        src = d.get("source", {}) or {}
        d["source"] = Source(
            surface=src.get("surface", ""),
            endpoint=src.get("endpoint", ""),
            correlation_id=src.get("correlation_id", ""),
            session_id=src.get("session_id"),
            channel=src.get("channel", ""),
        )

        eg = d.get("evidence_graph", {}) or {}
        nodes = [
            GraphNode(
                id=n["id"], kind=n["kind"], label=n["label"],
                attrs=dict(n.get("attrs", {})),
                provenance=cls._rebuild_provenance(n.get("provenance")),
            )
            for n in (eg.get("nodes") or [])
        ]
        edges = [
            GraphEdge(
                id=e["id"], from_node_id=e["from_node_id"],
                to_node_id=e["to_node_id"], kind=e["kind"],
                attrs=dict(e.get("attrs", {})),
                provenance=cls._rebuild_provenance(e.get("provenance")),
            )
            for e in (eg.get("edges") or [])
        ]
        d["evidence_graph"] = EvidenceGraph(nodes=nodes, edges=edges)

        d["reasoning_steps"] = [
            ReasoningStep(
                id=r["id"], rule=r["rule"], rationale=r["rationale"],
                input_evidence_ids=list(r.get("input_evidence_ids", [])),
                output_evidence_ids=list(r.get("output_evidence_ids", [])),
                provenance=cls._rebuild_provenance(r.get("provenance")),
            )
            for r in (d.get("reasoning_steps") or [])
        ]

        d["artifacts"] = [
            Artifact(
                id=a["id"], kind=a["kind"], label=a["label"],
                parent_evidence_id=a.get("parent_evidence_id"),
                investigation_ref=a.get("investigation_ref"),
                attrs=dict(a.get("attrs", {})),
                provenance=cls._rebuild_provenance(a.get("provenance")),
            )
            for a in (d.get("artifacts") or [])
        ]

        d["execution_trace"] = [
            ExecutionStep(
                step_id=x["step_id"], capability=x["capability"],
                engine=x["engine"], status=x["status"],
                started_at=x.get("started_at"), finished_at=x.get("finished_at"),
                output_evidence_ids=list(x.get("output_evidence_ids", [])),
                notes=x.get("notes", ""),
                provenance=cls._rebuild_provenance(x.get("provenance")),
            )
            for x in (d.get("execution_trace") or [])
        ]

        ctx = d.get("context", {}) or {}
        d["context"] = ContextBucket(
            historical=[
                HistoricalItem(
                    kind=h["kind"], ref=h["ref"],
                    matched_at=h.get("matched_at", ""),
                    attrs=dict(h.get("attrs", {})),
                    provenance=cls._rebuild_provenance(h.get("provenance")),
                )
                for h in (ctx.get("historical") or [])
            ]
        )

        d["provenance"] = cls._rebuild_provenance(d.get("provenance"))

        # Projections — rebuild scaffolds (must be empty in Phase 2).
        pd = d.get("activity", {}) or {}
        d["activity"] = ActivityProjection(**{k: list(pd.get(k, [])) for k in
                                              ("processes", "files", "network", "registry", "auth")})
        pd = d.get("iocs", {}) or {}
        d["iocs"] = IOCProjection(
            urls=list(pd.get("urls", [])), ips=list(pd.get("ips", [])),
            domains=list(pd.get("domains", [])), emails=list(pd.get("emails", [])),
            hashes=dict(pd.get("hashes", {})),
            files=list(pd.get("files", [])), registry=list(pd.get("registry", [])),
            user_agents=list(pd.get("user_agents", [])),
            bitcoin_addresses=list(pd.get("bitcoin_addresses", [])),
        )
        pd = d.get("threat_intel", {}) or {}
        d["threat_intel"] = ThreatIntelProjection(
            hits=list(pd.get("hits", [])),
            sources=list(pd.get("sources", [])),
            enrichment_status=pd.get("enrichment_status", "not_run"),
        )
        pd = d.get("attck", {}) or {}
        d["attck"] = AttckProjection(
            techniques=list(pd.get("techniques", [])),
            tactics=list(pd.get("tactics", [])),
            kill_chain=list(pd.get("kill_chain", [])),
        )
        pd = d.get("verdict", {}) or {}
        d["verdict"] = VerdictProjection(
            label=pd.get("label", ""), confidence=int(pd.get("confidence", 0)),
            reason=pd.get("reason", ""),
            contributors=list(pd.get("contributors", [])),
            input_completeness=dict(pd.get("input_completeness", {})),
        )
        pd = d.get("reports", {}) or {}
        d["reports"] = ReportsProjection(
            stix=pd.get("stix"), sigma=pd.get("sigma"), yara=pd.get("yara"),
            navigator=pd.get("navigator"), mdr=pd.get("mdr"),
        )
        # attack_chain, recommendations, timeline, attack_story, analyst_summary,
        # executive_summary keep their raw types.

        return cls(**d)
