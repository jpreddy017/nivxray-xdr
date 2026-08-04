"""Correlation Engine — Phase 4 · P1 · Cross-Artifact Correlation.

Owner directive (2026-02-15):
    "An Investigation is a first-class entity, not a collection of linked
    cases. Cases remain atomic records; the Investigation becomes the
    analyst's primary working object."

This module implements the first-class Correlation Investigation entity.
Terminology map:
    DB collection: `correlations`
    URL prefix:    `/api/correlations`
    Case field:    `correlation_id`   (back-reference on the existing
                                        `investigations` collection, which
                                        stores individual decode cases)
    UI label:      "Investigations"    (analyst-facing)

Deterministic-first: NO LLM in this pipeline. Every correlation edge is
backed by concrete evidence (hash equality, URL/domain/IP overlap, MITRE
technique overlap ≥ threshold, or shared decoded payload signature).

Two correlation sources:
    1. `inline_recursive` — child artifacts discovered *during a single
       decode* (e.g. .eml → attached .docm → PowerShell → PE). Always
       auto-attached. Provenance captured at decode time.
    2. `auto_correlated`  — deterministic evidence overlap detected across
       independent History cases. Emits confidence-scored *suggestions*
       the analyst confirms or dismisses.

Public surface:
    - build_evidence_signature(case)      → dict fingerprint for matching
    - compute_correlation(caseA, caseB)   → (score, shared_evidence)
    - scan_correlations(user_email, case) → list[dict] suggestions
    - build_attack_chain(correlation)     → linear chain view payload
    - build_evidence_graph(correlation)   → nodes + edges payload
    - build_unified_timeline(correlation) → chronological event list
    - build_threat_summary(correlation)   → consolidated verdict/risk
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("nivxray.correlation")

# ---------------------------------------------------------------------
# Scoring weights — tuned so a single strong signal (shared hash) yields
# a "high-confidence" suggestion (>= 80) on its own, while soft signals
# (single overlapping URL) sit in the "review" band (40-70).
# ---------------------------------------------------------------------
W_HASH_SHA256      = 60
W_HASH_SHA1        = 45
W_HASH_MD5         = 40
W_URL              = 12
W_DOMAIN           = 10
W_IP               = 14
W_C2_INDICATOR     = 25
W_MITRE_TECHNIQUE  = 6      # per shared technique, capped
W_MITRE_CAP        = 24     # cap MITRE contribution
W_INTERPRETER      = 4
W_CHAIN_OVERLAP    = 8      # >=3 shared recipe ops
W_ARTIFACT_TYPE    = 5      # both PE / both ELF / both Office / …

# Buckets to name confidence externally (UI treats > 80 as "auto-suggest",
# 50-80 as "review", <50 as "weak — do not surface unless explicit").
SUGGESTION_MIN_SCORE = 50


# ---------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_URL_RE  = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _norm_url(u: str) -> str:
    u = (u or "").strip().rstrip("/").lower()
    return u


def _norm_domain(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


def build_evidence_signature(case: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a deterministic evidence fingerprint from a History case.

    Consumes the persisted case doc (as returned by the history router).
    Never mutates. Missing fields degrade to empty sets — nothing here
    raises.
    """
    iocs = case.get("iocs") or {}
    mitre = case.get("mitre") or []

    def _set(key: str) -> set:
        v = iocs.get(key) or []
        if isinstance(v, list):
            return {str(x).strip() for x in v if x}
        if isinstance(v, str):
            return {v.strip()} if v.strip() else set()
        return set()

    urls   = {_norm_url(u) for u in _set("urls")}
    urls.discard("")
    ips    = _set("ips")
    domains = {_norm_domain(d) for d in _set("domains")}
    domains.discard("")
    md5    = {h.lower() for h in _set("md5")}
    sha1   = {h.lower() for h in _set("sha1")}
    sha256 = {h.lower() for h in _set("sha256")}

    techniques: set = set()
    for m in mitre:
        if isinstance(m, dict):
            tid = m.get("id") or m.get("technique_id")
            if tid:
                techniques.add(str(tid).strip().upper())

    chain = case.get("chain") or []
    if not isinstance(chain, list):
        chain = []
    interpreter = None
    # Prefer the explicit final_interpreter from the verdict card / iedde
    verdict = case.get("verdict") or {}
    if isinstance(verdict, dict):
        interpreter = verdict.get("interpreter") or verdict.get("final_interpreter")
    if not interpreter:
        vc = case.get("verdict_card") or {}
        if isinstance(vc, dict):
            interpreter = vc.get("interpreter") or vc.get("final_interpreter")

    # Artifact type comes from the routed_analysis when a binary artifact
    # was recovered (PE / PDF / Office / ELF). Fall back to None.
    artifact_type = None
    iedde = case.get("iedde") or {}
    if isinstance(iedde, dict):
        ba = iedde.get("binary_artifact") or {}
        ra = (ba.get("routed_analysis") or {}) if isinstance(ba, dict) else {}
        if isinstance(ra, dict):
            artifact_type = ra.get("artifact_type")

    # C2 indicators — a URL/domain/IP flagged in the verdict card
    c2: set = set()
    vc = case.get("verdict_card") or {}
    if isinstance(vc, dict):
        for item in (vc.get("c2") or vc.get("c2_indicators") or []):
            if isinstance(item, str):
                c2.add(item.strip().lower())
            elif isinstance(item, dict):
                v = item.get("value") or item.get("indicator")
                if v:
                    c2.add(str(v).strip().lower())

    return {
        "case_id":     str(case.get("id") or case.get("_id") or ""),
        "user_email":  case.get("user_email"),
        "input_hash":  case.get("input_hash"),
        "urls":        urls,
        "ips":         ips,
        "domains":     domains,
        "md5":         md5,
        "sha1":        sha1,
        "sha256":      sha256,
        "techniques":  techniques,
        "chain":       chain,
        "interpreter": interpreter,
        "artifact_type": artifact_type,
        "c2":          c2,
        "verdict":     (verdict.get("verdict") if isinstance(verdict, dict) else None),
        "ts":          case.get("ts") or case.get("last_seen") or case.get("first_seen"),
    }


# ---------------------------------------------------------------------
# Pairwise correlation
# ---------------------------------------------------------------------
def compute_correlation(sig_a: Dict[str, Any], sig_b: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Return (score 0-100, shared_evidence dict). Deterministic."""
    if sig_a.get("case_id") == sig_b.get("case_id"):
        return 0, {}

    score = 0
    shared: Dict[str, Any] = {}

    # Hash overlaps — the strongest signals
    s_sha256 = sig_a["sha256"] & sig_b["sha256"]
    if s_sha256:
        score += W_HASH_SHA256
        shared["sha256"] = sorted(s_sha256)
    s_sha1 = sig_a["sha1"] & sig_b["sha1"]
    if s_sha1:
        score += W_HASH_SHA1
        shared["sha1"] = sorted(s_sha1)
    s_md5 = sig_a["md5"] & sig_b["md5"]
    if s_md5:
        score += W_HASH_MD5
        shared["md5"] = sorted(s_md5)

    # Network indicators
    s_urls = sig_a["urls"] & sig_b["urls"]
    if s_urls:
        score += min(W_URL * len(s_urls), 24)
        shared["urls"] = sorted(s_urls)
    s_domains = sig_a["domains"] & sig_b["domains"]
    if s_domains:
        score += min(W_DOMAIN * len(s_domains), 20)
        shared["domains"] = sorted(s_domains)
    s_ips = sig_a["ips"] & sig_b["ips"]
    if s_ips:
        score += min(W_IP * len(s_ips), 28)
        shared["ips"] = sorted(s_ips)

    # C2 indicators — high signal
    s_c2 = sig_a["c2"] & sig_b["c2"]
    if s_c2:
        score += min(W_C2_INDICATOR * len(s_c2), 40)
        shared["c2"] = sorted(s_c2)

    # MITRE technique overlap — soft signal
    s_tech = sig_a["techniques"] & sig_b["techniques"]
    if s_tech:
        score += min(W_MITRE_TECHNIQUE * len(s_tech), W_MITRE_CAP)
        shared["techniques"] = sorted(s_tech)

    # Interpreter match — very soft signal
    if (sig_a.get("interpreter")
            and sig_a["interpreter"] == sig_b.get("interpreter")):
        score += W_INTERPRETER
        shared["interpreter"] = sig_a["interpreter"]

    # Same artifact type (PE/ELF/Office/PDF) — soft signal
    if (sig_a.get("artifact_type")
            and sig_a["artifact_type"] == sig_b.get("artifact_type")):
        score += W_ARTIFACT_TYPE
        shared["artifact_type"] = sig_a["artifact_type"]

    # Recipe-op chain overlap (≥3 shared ops in order-agnostic set)
    ch_a = set(sig_a.get("chain") or [])
    ch_b = set(sig_b.get("chain") or [])
    shared_chain = ch_a & ch_b
    if len(shared_chain) >= 3:
        score += W_CHAIN_OVERLAP
        shared["chain_ops"] = sorted(shared_chain)

    return min(score, 100), shared


def score_to_confidence(score: int) -> str:
    if score >= 80:  return "high"
    if score >= 65:  return "medium"
    if score >= SUGGESTION_MIN_SCORE: return "low"
    return "weak"


# ---------------------------------------------------------------------
# Cross-case scan
# ---------------------------------------------------------------------
async def scan_correlations(
    db,
    user_email: str,
    seed_case: Dict[str, Any],
    limit_candidates: int = 200,
) -> List[Dict[str, Any]]:
    """Scan the user's History for cases that correlate with `seed_case`.

    Returns a list of suggestion dicts sorted by score desc:
        [{ "case_id", "score", "confidence", "shared", "case_preview" }]

    Only cases owned by `user_email` are considered (Feb-2026 SEC-003).
    Cases already in the same correlation as the seed are skipped.
    Non-blocking: caller decides whether to await or fire-and-forget.
    """
    seed_sig = build_evidence_signature(seed_case)
    seed_correlation = seed_case.get("correlation_id")

    # Only bother querying if we have SOMETHING to match. If a case has no
    # IOCs, no hashes, no MITRE, correlation is unreliable — return [].
    has_signals = bool(
        seed_sig["urls"] or seed_sig["ips"] or seed_sig["domains"]
        or seed_sig["md5"] or seed_sig["sha1"] or seed_sig["sha256"]
        or seed_sig["techniques"] or seed_sig["c2"]
    )
    if not has_signals:
        return []

    # Narrow the candidate window: most recent 200 cases for the user.
    # Any deterministic hit here is worth surfacing; scoring filters the rest.
    query = {
        "user_email": user_email,
        "_id": {"$ne": _bson_oid(seed_case.get("id") or seed_case.get("_id"))},
    }
    if seed_correlation:
        # Skip cases already correlated to the same group
        query["$or"] = [
            {"correlation_id": {"$exists": False}},
            {"correlation_id": None},
            {"correlation_id": {"$ne": seed_correlation}},
        ]
    cursor = db.investigations.find(query).sort("ts", -1).limit(limit_candidates)

    suggestions: List[Dict[str, Any]] = []
    async for cand in cursor:
        cand_sig = build_evidence_signature(cand)
        score, shared = compute_correlation(seed_sig, cand_sig)
        if score < SUGGESTION_MIN_SCORE:
            continue
        suggestions.append({
            "case_id":    str(cand.get("_id")),
            "score":      score,
            "confidence": score_to_confidence(score),
            "shared":     shared,
            "case_preview": {
                "input_preview": (cand.get("input_preview") or "")[:200],
                "case_name":     cand.get("case_name"),
                "interpreter":   cand_sig.get("interpreter"),
                "artifact_type": cand_sig.get("artifact_type"),
                "verdict":       cand_sig.get("verdict"),
                "ts":            _iso(cand.get("ts") or cand.get("last_seen")),
            },
        })
    suggestions.sort(key=lambda x: x["score"], reverse=True)
    return suggestions


def _bson_oid(v):
    from bson import ObjectId
    try:
        return ObjectId(str(v))
    except Exception:
        return None


def _iso(v):
    if isinstance(v, datetime):
        return v.isoformat()
    return v


# ---------------------------------------------------------------------
# Correlation entity — construction + view builders
# ---------------------------------------------------------------------
def new_correlation_doc(user_email: str, root_case: Dict[str, Any],
                        name: Optional[str] = None) -> Dict[str, Any]:
    """Materialise a fresh correlation doc anchored on `root_case`."""
    now = datetime.now(timezone.utc)
    root_id = str(root_case.get("id") or root_case.get("_id") or "")
    return {
        "user_email":   user_email,
        "name":         name or _derive_name(root_case),
        "description":  "",
        "root_case_id": root_id,
        "case_ids":     [root_id] if root_id else [],
        "artifact_nodes": [_node_from_case(root_case, source="root", parent=None)],
        "edges":        [],
        "dismissed_case_ids": [],
        "tags":         [],
        "created_at":   now,
        "updated_at":   now,
        "ts":           now,
    }


def _derive_name(case: Dict[str, Any]) -> str:
    n = (case.get("case_name") or "").strip()
    if n:
        return f"Investigation · {n}"
    ip = (case.get("input_preview") or "").strip().split("\n", 1)[0]
    if ip:
        return f"Investigation · {ip[:60]}"
    return f"Investigation · {(case.get('id') or 'new')[:8]}"


def _node_from_case(case: Dict[str, Any], *, source: str, parent: Optional[str]) -> Dict[str, Any]:
    sig = build_evidence_signature(case)
    return {
        "node_id":     f"case:{sig['case_id']}",
        "kind":        "case",
        "case_id":     sig["case_id"],
        "case_name":   case.get("case_name"),
        "input_preview": (case.get("input_preview") or "")[:180],
        "interpreter": sig.get("interpreter"),
        "artifact_type": sig.get("artifact_type"),
        "verdict":     sig.get("verdict"),
        "iocs_summary": {
            "urls":    sorted(sig["urls"])[:5],
            "domains": sorted(sig["domains"])[:5],
            "ips":     sorted(sig["ips"])[:5],
            "sha256":  sorted(sig["sha256"])[:3],
        },
        "techniques":  sorted(sig["techniques"]),
        "source":      source,               # root | manual | auto_correlated | inline_recursive
        "parent_node": parent,               # for inline chains
        "ts":          _iso(case.get("ts") or case.get("last_seen")),
    }


def _artifact_node(*, node_id: str, artifact_type: str,
                   label: str, parent: str, source: str,
                   extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    d = {
        "node_id":     node_id,
        "kind":        "artifact",
        "artifact_type": artifact_type,
        "label":       label,
        "parent_node": parent,
        "source":      source,
    }
    if extra:
        d.update(extra)
    return d


def merge_case_into_correlation(correlation: Dict[str, Any],
                                case: Dict[str, Any],
                                *, source: str,
                                parent_node_id: Optional[str] = None,
                                shared_evidence: Optional[Dict[str, Any]] = None
                                ) -> Dict[str, Any]:
    """Attach `case` to `correlation` in-place and return the updated doc.

    `source` ∈ {"manual", "auto_correlated", "inline_recursive"}.
    Creates a new node for the case + an edge from parent (or root) with
    the evidence bundle that justified the link.
    """
    case_id = str(case.get("id") or case.get("_id") or "")
    if not case_id:
        return correlation
    if case_id in correlation.get("case_ids", []):
        return correlation

    parent_node_id = parent_node_id or f"case:{correlation['root_case_id']}"
    node = _node_from_case(case, source=source, parent=parent_node_id)
    correlation.setdefault("artifact_nodes", []).append(node)
    correlation.setdefault("case_ids", []).append(case_id)
    correlation.setdefault("edges", []).append({
        "from":     parent_node_id,
        "to":       node["node_id"],
        "relationship": _edge_relationship(source),
        "evidence": shared_evidence or {},
        "source":   source,
        "ts":       _iso(datetime.now(timezone.utc)),
    })
    correlation["updated_at"] = datetime.now(timezone.utc)
    return correlation


def _edge_relationship(source: str) -> str:
    return {
        "inline_recursive": "contains",
        "manual":           "linked_by_analyst",
        "auto_correlated":  "shared_evidence",
        "root":             "root",
    }.get(source, "linked")


def attach_inline_children(correlation: Dict[str, Any],
                           parent_case_id: str,
                           child_declarations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Given a case's declared child artifacts (e.g. Office analyzer surfacing
    a PowerShell + a PE) attach them as *artifact nodes* under the case node.

    child_declarations items shape:
        { "type": "powershell"|"pe"|"office"|"pdf"|"elf"|...,
          "label": str,
          "hash": {"sha256": "...", "md5": "..."} | None,
          "snippet": str | None,
          "case_id": str | None,   # if this child has itself become a case
        }
    """
    parent_node_id = f"case:{parent_case_id}"
    nodes = correlation.setdefault("artifact_nodes", [])
    edges = correlation.setdefault("edges", [])
    for i, child in enumerate(child_declarations or []):
        atype = child.get("type") or "artifact"
        node_id = child.get("case_id")
        if node_id:
            node_id = f"case:{node_id}"
        else:
            # Deterministic id — parent case + index + type
            node_id = f"artifact:{parent_case_id}:{i}:{atype}"
        # Skip if we already have this node
        if any(n.get("node_id") == node_id for n in nodes):
            continue
        nodes.append(_artifact_node(
            node_id=node_id,
            artifact_type=atype,
            label=(child.get("label") or f"{atype} artifact"),
            parent=parent_node_id,
            source="inline_recursive",
            extra={
                "hash":    child.get("hash"),
                "snippet": (child.get("snippet") or "")[:400],
                "case_id": child.get("case_id"),
            },
        ))
        edges.append({
            "from":         parent_node_id,
            "to":           node_id,
            "relationship": "contains",
            "evidence":     {"provenance": "inline_recursive"},
            "source":       "inline_recursive",
            "ts":           _iso(datetime.now(timezone.utc)),
        })
    correlation["updated_at"] = datetime.now(timezone.utc)
    return correlation


# ---------------------------------------------------------------------
# View builders
# ---------------------------------------------------------------------
def build_attack_chain(correlation: Dict[str, Any]) -> Dict[str, Any]:
    """Linearise nodes into a top-to-bottom attack chain.

    Uses a topological walk from the root node; nodes without a parent
    edge get bucketed as parallel branches attached to the root.
    """
    nodes = {n["node_id"]: n for n in correlation.get("artifact_nodes", [])}
    root_id = f"case:{correlation.get('root_case_id','')}"
    if root_id not in nodes and nodes:
        root_id = next(iter(nodes))

    edges = correlation.get("edges", [])
    children_of: Dict[str, List[str]] = {}
    for e in edges:
        children_of.setdefault(e["from"], []).append(e["to"])

    chain: List[Dict[str, Any]] = []
    seen = set()

    def walk(node_id: str, depth: int):
        if node_id in seen:
            return
        seen.add(node_id)
        n = nodes.get(node_id)
        if not n:
            return
        chain.append({**n, "depth": depth})
        for child in children_of.get(node_id, []):
            walk(child, depth + 1)

    walk(root_id, 0)
    # Orphan nodes (no incoming edge but present in the correlation)
    for nid in nodes:
        if nid not in seen:
            walk(nid, 0)

    return {"root": root_id, "steps": chain, "total": len(chain)}


def build_evidence_graph(correlation: Dict[str, Any]) -> Dict[str, Any]:
    """Return {nodes, edges} in a Cytoscape/react-flow-friendly shape.

    IOC values become secondary nodes attached to their owning case node
    so the analyst can see WHAT connects two cases at a glance.
    """
    graph_nodes: List[Dict[str, Any]] = []
    graph_edges: List[Dict[str, Any]] = []
    seen_ioc_ids: set = set()

    for n in correlation.get("artifact_nodes", []):
        graph_nodes.append({
            "id":    n["node_id"],
            "kind":  n.get("kind", "case"),
            "label": (n.get("case_name") or n.get("label")
                      or (n.get("input_preview") or "")[:40] or n["node_id"]),
            "artifact_type": n.get("artifact_type"),
            "verdict": n.get("verdict"),
            "source":  n.get("source"),
        })
        # Attach top IOCs as satellite nodes
        iocs = n.get("iocs_summary") or {}
        for kind, values in [("url","urls"),("domain","domains"),
                             ("ip","ips"),("sha256","sha256")]:
            for v in (iocs.get(values) or [])[:3]:
                if not v:
                    continue
                ioc_id = f"ioc:{kind}:{v}"
                if ioc_id not in seen_ioc_ids:
                    seen_ioc_ids.add(ioc_id)
                    graph_nodes.append({
                        "id": ioc_id, "kind": "ioc",
                        "ioc_kind": kind, "label": v[:60],
                    })
                graph_edges.append({
                    "from": n["node_id"], "to": ioc_id,
                    "kind": "has_ioc", "ioc_kind": kind,
                })

    for e in correlation.get("edges", []):
        graph_edges.append({
            "from": e["from"], "to": e["to"],
            "kind": "chain",
            "relationship": e.get("relationship"),
            "source": e.get("source"),
            "evidence": e.get("evidence") or {},
        })

    return {"nodes": graph_nodes, "edges": graph_edges,
            "node_count": len(graph_nodes), "edge_count": len(graph_edges)}


def build_unified_timeline(correlation: Dict[str, Any],
                           cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge each case's ts + IOC-first-seen + verdict events into one
    chronological timeline."""
    events: List[Dict[str, Any]] = []
    case_by_id = {str(c.get("id") or c.get("_id")): c for c in cases}
    for n in correlation.get("artifact_nodes", []):
        if n.get("kind") != "case":
            continue
        cid = n.get("case_id")
        c = case_by_id.get(cid)
        if not c:
            continue
        ts = c.get("ts") or c.get("last_seen") or c.get("first_seen")
        events.append({
            "ts":     _iso(ts),
            "case_id": cid,
            "kind":   "case_analyzed",
            "label":  n.get("case_name") or (c.get("input_preview") or "")[:60],
            "artifact_type": n.get("artifact_type"),
            "verdict": n.get("verdict"),
            "interpreter": n.get("interpreter"),
        })
    for e in correlation.get("edges", []):
        events.append({
            "ts":     e.get("ts"),
            "kind":   "correlation_link",
            "from":   e.get("from"), "to": e.get("to"),
            "source": e.get("source"),
            "relationship": e.get("relationship"),
        })
    events.sort(key=lambda ev: ev.get("ts") or "")
    return {"events": events, "count": len(events)}


def build_investigation_threat_summary(correlation: Dict[str, Any],
                                       cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate verdict / risk / IOCs / MITRE across all member cases."""
    verdicts = []
    mitre_union: Dict[str, Dict[str, Any]] = {}
    iocs_union: Dict[str, set] = {
        "urls": set(), "ips": set(), "domains": set(),
        "sha256": set(), "sha1": set(), "md5": set(),
    }
    artifact_types: List[str] = []
    interpreters: List[str] = []
    max_risk = 0
    for c in cases:
        v = (c.get("verdict") or {})
        if isinstance(v, dict) and v.get("verdict"):
            verdicts.append(v["verdict"])
        vc = c.get("verdict_card") or {}
        if isinstance(vc, dict):
            r = vc.get("risk_score") or vc.get("risk")
            if isinstance(r, (int, float)) and r > max_risk:
                max_risk = int(r)
        for m in (c.get("mitre") or []):
            if isinstance(m, dict) and m.get("id"):
                tid = str(m["id"]).upper()
                if tid not in mitre_union:
                    mitre_union[tid] = {
                        "id": tid,
                        "technique": m.get("technique"),
                        "tactic": m.get("tactic"),
                        "sources": [],
                    }
                cid = str(c.get("id") or c.get("_id") or "")
                if cid:
                    mitre_union[tid]["sources"].append(cid)
        iocs = c.get("iocs") or {}
        for k in iocs_union.keys():
            for v in (iocs.get(k) or []):
                if v:
                    iocs_union[k].add(str(v))
        sig = build_evidence_signature(c)
        if sig.get("artifact_type"):
            artifact_types.append(sig["artifact_type"])
        if sig.get("interpreter"):
            interpreters.append(sig["interpreter"])

    def _worst(vs: List[str]) -> str:
        rank = {"malicious": 4, "suspicious": 3, "partial": 2, "benign": 1, "unknown": 0}
        return max(vs, key=lambda v: rank.get(str(v).lower(), 0), default="unknown")

    return {
        "verdict":        _worst(verdicts),
        "risk_score":     max_risk,
        "case_count":     len(cases),
        "artifact_types": sorted(set(artifact_types)),
        "interpreters":   sorted(set(interpreters)),
        "iocs": {k: sorted(v) for k, v in iocs_union.items()},
        "mitre": sorted(mitre_union.values(), key=lambda x: x["id"]),
        "mitre_count": len(mitre_union),
    }


# ---------------------------------------------------------------------
# Signature helper for external hooks (recipe_planner integration)
# ---------------------------------------------------------------------
def declare_inline_children_from_routed_analysis(routed_analysis: Dict[str, Any]
                                                 ) -> List[Dict[str, Any]]:
    """Introspect a routed_analysis payload and extract child artifact
    declarations. Used at record-time to seed inline chains without
    forcing the recipe_planner to know about correlations.

    Returns [] for artifact types with no observed children.
    """
    if not isinstance(routed_analysis, dict):
        return []
    atype = routed_analysis.get("artifact_type")
    analysis = routed_analysis.get("analysis") or {}
    children: List[Dict[str, Any]] = []

    if atype == "office" and isinstance(analysis, dict):
        # Office analyzer surfaces embedded macros / DDE / OLE / URLs
        macros = analysis.get("macros") or []
        if isinstance(macros, list) and macros:
            for m in macros[:5]:
                children.append({
                    "type": "powershell" if _looks_like_ps(m) else "vba_macro",
                    "label": _short_label(m, "VBA / macro"),
                    "snippet": _snippet(m),
                })
        for k, kind in [("dde", "dde"), ("ole_objects", "ole"),
                        ("embedded_files", "embedded_file")]:
            v = analysis.get(k) or []
            if not isinstance(v, list):
                continue
            for it in v[:5]:
                children.append({
                    "type":  kind,
                    "label": _short_label(it, kind),
                    "snippet": _snippet(it),
                })
    if atype == "pdf" and isinstance(analysis, dict):
        pdf_list = analysis.get("javascript") or analysis.get("actions") or []
        if isinstance(pdf_list, list):
            for act in pdf_list[:5]:
                children.append({
                    "type": "pdf_javascript",
                    "label": _short_label(act, "PDF JavaScript"),
                    "snippet": _snippet(act),
                })
        emb_list = analysis.get("embedded_files") or []
        if isinstance(emb_list, list):
            for emb in emb_list[:5]:
                children.append({
                    "type": "embedded_file",
                    "label": _short_label(emb, "PDF embedded"),
                    "snippet": _snippet(emb),
                })
    if atype in ("pe", "elf") and isinstance(analysis, dict):
        # Not a child artifact per-se, but preserve top-level metadata as a
        # single anchor node so the chain visualization has structure.
        pass
    return children


def _looks_like_ps(v) -> bool:
    s = str(v).lower()
    return any(t in s for t in [
        "powershell", "iex ", "invoke-expression", "downloadstring",
        "webclient", "-encodedcommand", "frombase64string",
    ])


def _short_label(v, default: str) -> str:
    if isinstance(v, dict):
        for k in ("name", "label", "value", "title"):
            if v.get(k):
                return str(v[k])[:80]
    s = str(v).strip().replace("\n", " ")
    return (s[:80] or default) if s else default


def _snippet(v) -> str:
    return str(v)[:400] if v else ""
