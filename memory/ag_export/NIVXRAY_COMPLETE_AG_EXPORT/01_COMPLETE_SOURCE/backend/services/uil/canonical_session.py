"""Phase 5.1 · Canonical session envelope builder.

Owner directive 2026-08-10:
  - Direct canonical envelope (Q1=b) — do NOT call legacy
    `services.die.investigation_results.render` or legacy
    `services.session.adapter.build_session`.
  - Values are derived from AuthoritativeSSOT + Phase 4 projections.
  - Envelope keys remain session-v1-compatible for frontend contract.
  - Wave-N labels added: `wave`, `lifecycle`, `canonical_ssot_ref`.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from canonical.projections import (
    project_activity,
    project_analyst_summary,
    project_attack_chain,
    project_attack_story,
    project_attck,
    project_canonical,
    project_evidence_bundle,
    project_evidence_graph_view,
    project_executive_summary,
    project_iocs,
    project_lolbas,
    project_recommendations,
    project_reports,
    project_timeline,
    project_verdict,
)
from canonical.ssot import AuthoritativeSSOT

_SCHEMA = "session-v1"
_WAVE   = "5.1"
_LIFECYCLE = "canonical"


# ── Input-type label table (parity with legacy adapter) ─────────────────
_ARTIFACT_TYPE_LABEL: dict[str, str] = {
    "url":         "URL",
    "ip":          "IP Address",
    "domain":      "Domain",
    "hash":        "File Hash",
    "email":       "Email",
    "file":        "File Path",
    "registry":    "Registry Key",
    "command":     "Command Line",
    "lolbas":      "LOLBAS Binary",
    "mitre":       "MITRE ATT&CK",
}


def _short_id(prefix: str, key: str) -> str:
    """Deterministic short id (matches legacy adapter behaviour)."""
    h = hashlib.sha1(key.encode("utf-8", "ignore")).hexdigest()[:12]
    return f"{prefix}_{h}"


def _investigation_inputs(ssot: AuthoritativeSSOT,
                          iocs, lolbas: dict[str, Any],
                          attck) -> list[dict[str, Any]]:
    """Build the session's `investigation_inputs` list from canonical
    projections. Deterministic ordering: URLs → IPs → Domains → Emails
    → Hashes → Files → Registry → LOLBAS → MITRE."""
    out: list[dict[str, Any]] = []
    idx = 0

    def _add(kind: str, section: str, values, status: str = "correlated"):
        nonlocal idx
        for v in values:
            if not v:
                continue
            idx += 1
            out.append({
                "id":         _short_id("inp", f"{kind}:{v}"),
                "index":      idx,
                "type":       kind,
                "type_label": _ARTIFACT_TYPE_LABEL.get(kind, kind.title()),
                "value":      v,
                "preview":    v,
                "source":     "canonical.ioc_extractor" if kind not in ("lolbas", "mitre") else f"canonical.{kind}",
                "section":    section,
                "status":     status,
                "investigation": None,
            })

    _add("url",      "IOCs · URLs",      iocs.urls)
    _add("ip",       "IOCs · IPs",       iocs.ips)
    _add("domain",   "IOCs · Domains",   iocs.domains)
    _add("email",    "IOCs · Emails",    iocs.emails)
    for hkind, values in sorted(iocs.hashes.items()):
        _add("hash", f"IOCs · Hashes ({hkind})", values)
    _add("file",     "IOCs · Files",     iocs.files)
    _add("registry", "IOCs · Registry",  iocs.registry)
    _add("lolbas",   "LOLBAS",           lolbas.get("binaries", []))

    # MITRE techniques as referenced descriptors.
    for t in attck.techniques:
        idx += 1
        out.append({
            "id":         _short_id("inp", f"mitre:{t['id']}"),
            "index":      idx,
            "type":       "mitre",
            "type_label": _ARTIFACT_TYPE_LABEL["mitre"],
            "value":      t["id"],
            "preview":    f"{t['id']}: {t['name']}",
            "source":     "canonical.mitre_map",
            "section":    "MITRE ATT&CK",
            "status":     "referenced",
            "investigation": None,
            "detail":     t,
        })

    return out


def _incident(ssot: AuthoritativeSSOT, verdict, attck, story,
              recs: dict[str, Any]) -> dict[str, Any]:
    """Canonical incident envelope (session-v1 compatible)."""
    severity_map = {
        "MALICIOUS":    "critical",
        "SUSPICIOUS":   "high",
        "LIKELY_BENIGN": "low",
        "INCONCLUSIVE": "unknown",
    }
    incident = {
        "verdict": {
            "label":       verdict.label,
            "confidence":  verdict.confidence,
            "reason":      verdict.reason,
            "contributors": list(verdict.contributors),
        },
        "severity": severity_map.get(verdict.label, "unknown"),
        "kill_chain": attck.kill_chain,
        "tactics":    attck.tactics,
        "techniques": [t["id"] for t in attck.techniques],
        "attack_story": story,
        "recommendations": recs["items"],
        "recommendation_notes": recs["notes"],
        "readiness": {
            "input_completeness": verdict.input_completeness,
            "executed_capabilities": sorted({t.capability for t in ssot.execution_trace
                                             if t.status == "executed"}),
        },
    }
    return incident


def _gateway_summary(ssot: AuthoritativeSSOT, inputs, verdict, attck, iocs) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    for inp in inputs:
        t = inp["type"]
        by_type[t] = by_type.get(t, 0) + 1

    checks: list[dict[str, Any]] = [
        {"label": "Canonical IUE",
         "state": "ok" if ssot.iue_decision else "pending"},
        {"label": "Canonical SSOT",
         "state": "ok"},
        {"label": "MITRE evidence",
         "state": "ok" if attck.techniques else "empty"},
        {"label": "IOC evidence",
         "state": "ok" if (iocs.urls or iocs.ips or iocs.domains or iocs.hashes)
                  else "empty"},
    ]
    total_iocs = (len(iocs.urls) + len(iocs.ips) + len(iocs.domains)
                  + len(iocs.emails)
                  + sum(len(v) for v in iocs.hashes.values())
                  + len(iocs.files) + len(iocs.registry))
    return {
        "counters": {
            "investigation_inputs": len(inputs),
            "iocs_total":           total_iocs,
            "techniques":           len(attck.techniques),
            "by_type":              dict(sorted(by_type.items())),
        },
        "verdict": {
            "label":      verdict.label,
            "confidence": verdict.confidence,
        },
        "checks": checks,
    }


def _collect_children(ssot: AuthoritativeSSOT, store) -> list:
    """Depth-first walk of D6-r child_ssot_ref artifacts. Returns the
    list of child SSOTs (deduped by ssot_ref, preserving discovery order).

    Pure function of `ssot` + `store`; no I/O beyond the in-memory store
    (which is content-addressed).
    """
    if store is None:
        return []
    seen: set = set()
    ordered: list = []
    stack: list = [ssot]
    while stack:
        current = stack.pop(0)
        for a in current.artifacts:
            if a.kind != "child_ssot_ref" or not a.investigation_ref:
                continue
            ref = a.investigation_ref
            if ref in seen:
                continue
            seen.add(ref)
            child = store.get(ref) if hasattr(store, "get") else None
            if child is None:
                continue
            ordered.append(child)
            stack.append(child)
    return ordered


def _aggregate(parent, children):
    """Merge parent + children Phase 4 projections into a single union
    view. Deterministic: sorted / de-duped throughout.

    Returns a dict with the union projections used by the session envelope:
      iocs, attck, attack_chain, attack_story, recommendations,
      lolbas, verdict (best confidence), analyst_summary,
      executive_summary, timeline (concatenated).
    """
    from collections import OrderedDict

    all_ssots = [parent] + list(children)

    # ── Union IOCs ─────────────────────────────────────────────────────
    urls: OrderedDict = OrderedDict()
    ips: OrderedDict = OrderedDict()
    domains: OrderedDict = OrderedDict()
    emails: OrderedDict = OrderedDict()
    hashes: dict = {}
    files: OrderedDict = OrderedDict()
    registry: OrderedDict = OrderedDict()
    for s in all_ssots:
        p = project_iocs(s)
        for v in p.urls:    urls[v] = None
        for v in p.ips:     ips[v] = None
        for v in p.domains: domains[v] = None
        for v in p.emails:  emails[v] = None
        for k, vs in p.hashes.items():
            bucket = hashes.setdefault(k, OrderedDict())
            for v in vs:
                bucket[v] = None
        for v in p.files:    files[v] = None
        for v in p.registry: registry[v] = None

    class _UnionIocs:
        pass
    ui = _UnionIocs()
    ui.urls     = list(urls.keys())
    ui.ips      = list(ips.keys())
    ui.domains  = list(domains.keys())
    ui.emails   = list(emails.keys())
    ui.hashes   = {k: list(v.keys()) for k, v in hashes.items()}
    ui.files    = list(files.keys())
    ui.registry = list(registry.keys())
    ui.user_agents = []
    ui.bitcoin_addresses = []

    # ── Union MITRE techniques (dedup by id, keep first-seen order) ────
    seen_tids: set = set()
    merged_techniques: list = []
    for s in all_ssots:
        for t in project_attck(s).techniques:
            if t["id"] in seen_tids:
                continue
            seen_tids.add(t["id"])
            merged_techniques.append(t)
    merged_techniques.sort(key=lambda t: t["id"])

    class _UnionAttck:
        pass
    ua = _UnionAttck()
    ua.techniques = merged_techniques
    ua.tactics    = sorted({t["tactic"] for t in merged_techniques} - {"unknown"})
    ua.kill_chain = sorted({t["kill_chain"] for t in merged_techniques} - {"unknown"})

    # ── Union attack chain, story, recommendations, lolbas ─────────────
    from canonical.projections.attack_chain import _STAGE_INDEX

    stage_map: dict = {}
    for s in all_ssots:
        for stage in project_attack_chain(s):
            existing = stage_map.setdefault(stage["stage"], set())
            existing.update(stage["techniques"])
    merged_chain: list = []
    for stage_name in sorted(stage_map.keys(),
                             key=lambda x: _STAGE_INDEX.get(x, len(_STAGE_INDEX))):
        merged_chain.append({
            "stage": stage_name,
            "order": _STAGE_INDEX.get(stage_name, len(_STAGE_INDEX)),
            "title": stage_name.replace("_", " ").title(),
            "techniques": sorted(stage_map[stage_name]),
        })

    # Story: union of chapters from all SSOTs that produced any.
    merged_story_chapters: list = []
    seen_stages: set = set()
    for s in all_ssots:
        st = project_attack_story(s)
        if not st:
            continue
        for ch in st.get("chapters", []):
            if ch["stage"] in seen_stages:
                continue
            seen_stages.add(ch["stage"])
            merged_story_chapters.append(ch)
    merged_story = None
    if merged_story_chapters:
        merged_story = {
            "opening": f"Aggregated canonical narrative over {len(all_ssots)} "
                       f"SSOT(s) (parent + children).",
            "chapters": merged_story_chapters,
            "closing":  f"End of aggregated canonical narrative. "
                        f"{len(merged_story_chapters)} stage(s) reconstructed "
                        f"from evidence across the SSOT tree.",
        }

    # Recommendations: union, dedup by (technique_id, action).
    seen_recs: set = set()
    merged_rec_items: list = []
    all_notes: list = []
    for s in all_ssots:
        rr = project_recommendations(s)
        for item in rr["items"]:
            key = (item["technique_id"], item["action"])
            if key in seen_recs:
                continue
            seen_recs.add(key)
            merged_rec_items.append(item)
        all_notes.extend(rr["notes"])
    merged_rec_items.sort(key=lambda x: (x["technique_id"], x["action"]))
    # Only emit notes when there are NO items — matches P4-FW3 shape.
    merged_recs = {
        "items": merged_rec_items,
        "notes": [] if merged_rec_items else all_notes[:1],
    }

    # LOLBAS union.
    lb_bins: set = set()
    lb_matches: list = []
    for s in all_ssots:
        p = project_lolbas(s)
        lb_bins.update(p.get("binaries", []))
        lb_matches.extend(p.get("matches", []))
    merged_lolbas = {
        "binaries": sorted(lb_bins),
        "matches":  lb_matches,
    }

    # Verdict: pick the highest-confidence label across the tree.
    best_verdict = project_verdict(parent)
    for s in children:
        cv = project_verdict(s)
        if cv.confidence > best_verdict.confidence:
            best_verdict = cv

    # Analyst / executive summaries: prefer child summary if it has
    # techniques AND parent has none (typical DOCX case).
    analyst = project_analyst_summary(parent)
    executive = project_executive_summary(parent)
    for s in children:
        ca = project_analyst_summary(s)
        ce = project_executive_summary(s)
        if analyst is None and ca is not None:
            analyst = ca
        if executive is None and ce is not None:
            executive = ce

    # Timeline: parent then children (deterministic ordering).
    merged_timeline: list = list(project_timeline(parent))
    for s in children:
        merged_timeline.extend(project_timeline(s))

    return {
        "iocs":              ui,
        "attck":             ua,
        "attack_chain":      merged_chain,
        "attack_story":      merged_story,
        "recommendations":   merged_recs,
        "lolbas":            merged_lolbas,
        "verdict":           best_verdict,
        "analyst_summary":   analyst,
        "executive_summary": executive,
        "timeline":          merged_timeline,
    }


def build_canonical_session(*,
                             ssot: AuthoritativeSSOT,
                             ssot_ref: str,
                             input_text: str,
                             uil_meta: dict[str, Any],
                             session_id: str | None = None,
                             store=None,
                             ) -> dict[str, Any]:
    """Direct canonical → session-v1 envelope (Phase 5.1).

    NEVER calls `services.die.investigation_results.render()`.
    NEVER calls `services.session.adapter.build_session()`.
    NEVER mutates any SSOT.

    When `store` is provided, aggregates child-SSOT projections (D6-r)
    into the envelope so DOCX / archive inputs surface their inner
    evidence (fixes empty attack_chain / recommendations for DOCX).
    """
    # Collect the child SSOTs (D6-r recursion, deterministic order).
    children = _collect_children(ssot, store)

    # Aggregate projections across parent + children.
    agg = _aggregate(ssot, children)
    verdict  = agg["verdict"]
    iocs     = agg["iocs"]
    attck    = agg["attck"]
    story    = agg["attack_story"]
    recs     = agg["recommendations"]
    lolbas   = agg["lolbas"]
    analyst_sum   = agg["analyst_summary"]
    executive_sum = agg["executive_summary"]
    timeline      = agg["timeline"]
    merged_chain  = agg["attack_chain"]

    # Parent-only projections for the deep object view.
    activity = project_activity(ssot)
    canonical_view = project_canonical(ssot)
    ebundle = project_evidence_bundle(ssot)
    egview  = project_evidence_graph_view(ssot)
    reports = project_reports(ssot)

    inputs = _investigation_inputs(ssot, iocs, lolbas, attck)
    incident = _incident(ssot, verdict, attck, story, recs)
    # Attach the aggregated chain to the incident too (frontend uses it).
    incident["attack_chain"] = merged_chain
    summary  = _gateway_summary(ssot, inputs, verdict, attck, iocs)

    # session_id: deterministic short-id from ssot_ref (10 chars is enough).
    if session_id is None:
        session_id = _short_id("ses", ssot_ref)

    created_at = datetime.now(timezone.utc).isoformat()

    envelope: dict[str, Any] = {
        "session_id":   session_id,
        "created_at":   created_at,
        "schema":       _SCHEMA,
        "original_input": {
            "raw":         input_text or "",
            "kind":        (uil_meta or {}).get("kind"),
            "label":       (uil_meta or {}).get("kind_label"),
            "confidence":  None,       # canonical IUE doesn't expose UIL-style score
        },
        "document_profile":  dict(ssot.input_profile),
        "acquired_document": {},
        "investigation_inputs": inputs,
        "incident":         incident,
        "readiness":        incident["readiness"],
        "summary":          summary,
        "raw_investigation": {
            "schema":      "canonical.projection.canonical/1.0.0-phase4",
            "ssot_ref":    ssot_ref,
            "fingerprint": ssot.fingerprint(),
            "canonical":   canonical_view,
            "activity":    {
                "processes": activity.processes,
                "files":     activity.files,
                "network":   activity.network,
                "registry":  activity.registry,
                "auth":      activity.auth,
            },
            "attack_chain":     merged_chain,
            "attack_story":     story,
            "analyst_summary":  analyst_sum,
            "executive_summary": executive_sum,
            "reports":           {"stix": reports.stix, "sigma": reports.sigma,
                                  "yara": reports.yara, "navigator": reports.navigator,
                                  "mdr": reports.mdr},
            "timeline":          timeline,
            "evidence_bundle":   ebundle,
            "evidence_graph":    egview,
        },
        "summary_narrative": None,      # deferred per spec §Envelope contract
        "uil":               uil_meta or {},
        # ── Phase 5.1 Wave-N labels (Q3=a) ─────────────────────────────
        "wave":      _WAVE,
        "lifecycle": _LIFECYCLE,
        "canonical_ssot_ref": ssot_ref,
    }
    return envelope


__all__ = ["build_canonical_session"]
