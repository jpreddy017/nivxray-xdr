"""ADR-0014 · Slice-A release-gate validators.

Three gates (ADR-0014 §7.1):

    G1 · CIO schema validation
        - schema_version pinned to "0.1"
        - Pydantic model rejects unknown fields
        - required fields present

    G2 · Evidence Graph integrity
        - node ids unique
        - no dangling edges (every source/target refers to a node)
        - edge kinds within the typed enum
        - every non-artifact node reachable from at least one artifact
          (transitively through `produces` / `references` /
           `contributes_to` / `derived_from` / `supports` / `contradicts`
           / `escalates_to`).

    G3 · Legacy response parity
        - given a `legacy` response dict, this validator checks that
          every key present in the pre-CIO baseline is preserved
          byte-identically in the post-CIO response. Callers invoke
          this with the response *before* and *after* CIO injection.

Any failure raises `CIOValidationError` with a machine-readable
`.code`; endpoints catch and log — Slice-A never propagates a raw
exception to a caller (additive-only, principle §1.1.6).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from nivxforge.investigation.models import CIO
from nivxforge.investigation.graph import EvidenceGraph


class CIOValidationError(ValueError):
    """Raised when a CIO fails a §7.1 release gate."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ─── G1 · schema ────────────────────────────────────────────────────────

def _gate_schema(cio: CIO) -> None:
    if cio.schema_version != "0.1":
        raise CIOValidationError(
            "G1_SCHEMA_VERSION",
            f"schema_version must be '0.1', got {cio.schema_version!r}",
        )
    # Pydantic model_config extra="forbid" already blocks unknown fields;
    # here we only assert that the roots we care about are present.
    if cio.cio_id is None or not cio.cio_id:
        raise CIOValidationError("G1_MISSING_CIO_ID", "cio_id must be non-empty")
    if cio.source is None:
        raise CIOValidationError("G1_MISSING_SOURCE", "source must be present")


# ─── G2 · graph integrity ───────────────────────────────────────────────

def _gate_graph(graph: EvidenceGraph) -> None:
    # unique node ids
    seen: Dict[str, int] = {}
    for n in graph.nodes:
        seen[n.id] = seen.get(n.id, 0) + 1
    dupes = [k for k, v in seen.items() if v > 1]
    if dupes:
        raise CIOValidationError(
            "G2_DUPLICATE_NODE_ID",
            f"Duplicate node ids: {sorted(dupes)}",
        )
    # no dangling edges
    ids = set(seen.keys())
    for e in graph.edges:
        if e.source not in ids:
            raise CIOValidationError(
                "G2_DANGLING_EDGE_SOURCE",
                f"Edge source not in nodes: {e.source} → {e.target} ({e.kind})",
            )
        if e.target not in ids:
            raise CIOValidationError(
                "G2_DANGLING_EDGE_TARGET",
                f"Edge target not in nodes: {e.source} → {e.target} ({e.kind})",
            )
    # every non-artifact node reachable from some artifact
    if graph.nodes:
        artifacts = [n.id for n in graph.nodes if n.kind == "artifact"]
        if not artifacts:
            raise CIOValidationError(
                "G2_NO_ARTIFACT_ROOT",
                "Evidence Graph has nodes but no artifact root",
            )
        # BFS reachability from all artifacts
        reachable = set(artifacts)
        frontier = list(artifacts)
        while frontier:
            nxt: List[str] = []
            for src in frontier:
                for tgt in graph.neighbours(src):
                    if tgt not in reachable:
                        reachable.add(tgt)
                        nxt.append(tgt)
            frontier = nxt
        orphans = [n.id for n in graph.nodes if n.kind != "artifact" and n.id not in reachable]
        if orphans:
            raise CIOValidationError(
                "G2_ORPHAN_NODES",
                f"Non-artifact nodes not reachable from any artifact: {sorted(orphans)}",
            )


# ─── G3 · legacy response parity ────────────────────────────────────────

def _gate_legacy_parity(
    legacy: Optional[Dict[str, Any]],
    post: Optional[Dict[str, Any]],
    *,
    added_keys: Optional[List[str]] = None,
) -> None:
    """Assert that every key in `legacy` is present and equal in `post`.

    `added_keys` are the CIO/graph fields we are *permitted* to add
    (Slice-A: `cio`). Everything else must be byte-identical.
    """
    if legacy is None or post is None:
        return
    added = set(added_keys or [])
    for key, value in legacy.items():
        if key not in post:
            raise CIOValidationError(
                "G3_LEGACY_KEY_REMOVED",
                f"Legacy response key removed: {key!r}",
            )
        if post[key] != value:
            raise CIOValidationError(
                "G3_LEGACY_VALUE_CHANGED",
                f"Legacy response value changed for key: {key!r}",
            )
    # Confirm new keys are limited to the sanctioned set
    new_keys = set(post.keys()) - set(legacy.keys())
    illegal = new_keys - added
    if illegal:
        raise CIOValidationError(
            "G3_UNSANCTIONED_KEY_ADDED",
            f"Post-CIO response added keys outside the sanctioned set {sorted(added)}: {sorted(illegal)}",
        )


def _gate_normalisation(cio: CIO) -> None:
    """G4 · ADR-0014 §1.1.14 Layer 2 safety net.

    If the CIO's input_text looks like a raw vendor-JSON telemetry
    payload but the metadata does not carry a `normalised_via` tag,
    reject the CIO. Ingress-side normalisation (Layer 1) MUST run
    before analysis on every entry point.
    """
    txt = (cio.input_text or "").strip()
    if not txt:
        return
    # Heuristic: JSON envelope that carries vendor-schema signals.
    looks_like_json = (txt.startswith("{") or txt.startswith("[")) and (
        txt.endswith("}") or txt.endswith("]")
    )
    if not looks_like_json:
        return
    vendor_markers = (
        '"connector_guid"', '"falcon_host_link"', '"event_simpleName"',
        '"AlertId"', '"detectionSource"', '"agentDetectionInfo"',
        '"threatInfo"', '"EventID"', '"qid"', '"sourcetype"',
        '"observables"', '"incident_ref"',
    )
    is_vendor_json = any(marker in txt for marker in vendor_markers)
    if not is_vendor_json:
        return
    if not (cio.metadata or {}).get("normalised_via"):
        raise CIOValidationError(
            "G4_NORMALISATION_REQUIRED",
            "Vendor-JSON input reached the CIO builder without a "
            "`normalised_via` provenance tag. Ingress gate (Layer 1) "
            "MUST normalise vendor telemetry before analysis "
            "(ADR-0014 §1.1.14).",
        )


# ─── Public entry ───────────────────────────────────────────────────────

def validate_cio(
    cio: CIO,
    *,
    legacy: Optional[Dict[str, Any]] = None,
    post: Optional[Dict[str, Any]] = None,
    added_keys: Optional[List[str]] = None,
) -> None:
    """Run G1 + G2 + G4 (+ G3 if legacy/post supplied).

    Raises `CIOValidationError` on the first failure.
    """
    _gate_schema(cio)
    _gate_graph(cio.evidence_graph)
    _gate_normalisation(cio)
    if legacy is not None and post is not None:
        _gate_legacy_parity(legacy, post, added_keys=added_keys)


__all__ = ["validate_cio", "CIOValidationError"]
