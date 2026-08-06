"""
Deterministic Paste-Only Synthesis · Rule R22 · Architecture v1.0
──────────────────────────────────────────────────────────────────
When the analyst pastes raw text (a PowerShell script, a command
chain, a bare payload — anything that has no acquirable source URL
or document), we owe the workspace the SAME canonical shape it
gets for EML / PDF / URL / DOCX / ZIP / Image cases.

The frontend must NOT special-case paste-only investigations.  This
module projects the deterministic *behavior graph* already extracted
by ``services.reasoning.behavior_extractor`` into:

    · ``ssot.acquired_document``     — synthetic ``ok=true`` envelope
                                         (source_kind ``"analyst_paste"``)
    · ``ssot.acquisition_plan``      — synthetic paste-only pipeline
    · ``ssot.incident.behaviors``    — behavior_clusters (paste form)
    · ``ssot.incident.timeline``     — behavior-driven events with
                                         stable ``evt-####`` ids
    · ``ssot.incident.evidence``     — commands + behavior evidence
                                         list (each with an ``ev-####`` id
                                         linking back to ``bhv-<id>``)

Rule alignment
──────────────
· R14 — Adapters extract; only reasoning composes.  Behavior
        extraction runs deterministically on the raw input.
· R21 — Every projection reads ``incident{}``.  This module ONLY
        writes into ``incident`` when the corresponding slot is empty
        (no acquired source produced a real timeline / behaviors).
· R22 — Every promoted piece carries stable ids so the frontend can
        deep-link (``evt-0001``, ``ev-0001``, ``bhv-<id>``).

Deterministic.  No LLM.  No randomness.  Identical input → identical
synthesis every time.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from services.reasoning.behavior_extractor import (
    Behavior, BehaviorEvidence, correlate_behaviors, extract_behaviors,
)


# ══════════════════════════════════════════════════════════════════
# 0. Preprocessor-stage → Behavior promotion
# ══════════════════════════════════════════════════════════════════
# The DIE preprocessor recognises hundreds of attack techniques the
# 27-rule regex behavior_extractor doesn't cover (Reverse SSH Tunnel,
# AD Enumeration, MSI Installer Execution, Shadow Copy Removal,
# Registry Modification, WMIC Software Removal, …).  Every recognised
# stage already carries a canonical MITRE tactic + technique list
# upstream.  This promoter wraps every such stage into a full-fledged
# Behavior so the 14-lane trajectory / attack-lifecycle panel picks
# up the correct MITRE tactic — no separate stage-vs-behavior data
# path in the frontend.
#
# Deterministic.  No LLM.  Stage `.tactic` maps 1:1 to the MITRE
# lane; empty / uncategorised stages are skipped so we never
# hallucinate a lane.

# Preprocessor tactic strings → canonical MITRE ATT&CK lane label.
_TACTIC_LANE_LABEL: Dict[str, str] = {
    "Reconnaissance":         "Reconnaissance",
    "Resource Development":   "Resource Development",
    "Initial Access":         "Initial Access",
    "Execution":              "Execution",
    "Persistence":            "Persistence",
    "Privilege Escalation":   "Privilege Escalation",
    "Defense Evasion":        "Defense Evasion",
    "Credential Access":      "Credential Access",
    "Discovery":              "Discovery",
    "Lateral Movement":       "Lateral Movement",
    "Collection":             "Collection",
    "Command and Control":    "Command and Control",
    "Command & Control":      "Command and Control",
    "Exfiltration":           "Exfiltration",
    "Impact":                 "Impact",
}

# Tactic → kill-chain phase list (Cyber Kill Chain projection).
_TACTIC_KILLCHAIN: Dict[str, List[str]] = {
    "Reconnaissance":         ["Reconnaissance"],
    "Resource Development":   ["Reconnaissance"],
    "Initial Access":         ["Delivery"],
    "Execution":              ["Execution"],
    "Persistence":            ["Persistence"],
    "Privilege Escalation":   ["Privilege Escalation"],
    "Defense Evasion":        ["Defense Evasion"],
    "Credential Access":      ["Credential Access"],
    "Discovery":              ["Discovery"],
    "Lateral Movement":       ["Lateral Movement"],
    "Collection":             ["Collection"],
    "Command and Control":    ["Command and Control"],
    "Exfiltration":           ["Exfiltration"],
    "Impact":                 ["Impact"],
}


def _stage_slug(text: str) -> str:
    if not text:
        return "stage"
    slug = "".join(ch.lower() if ch.isalnum() else "_"
                    for ch in text.strip())
    return "_".join(p for p in slug.split("_") if p)[:48] or "stage"


def _behaviors_from_stages(ssot: Dict[str, Any]) -> List[Behavior]:
    """Promote every preprocessor stage that carries a MITRE tactic
    to a full Behavior.  Deterministic; skips stages without a
    recognised tactic so we never hallucinate a lane.

    The SSOT emits preprocessor stages under ``ssot.commands[]``
    (see ``_command_to_ssot`` in ``investigation_results.py``).
    Each stage carries ``title``, ``objective``, ``tactic``,
    ``mitre[]``, ``family``, ``normalized_command``, ``raw_excerpt``,
    ``confidence``, and ``index``.
    """
    out: List[Behavior] = []
    for i, stage in enumerate(ssot.get("commands") or []):
        if not isinstance(stage, dict):
            continue
        tactic_raw = (stage.get("tactic") or "").strip()
        canonical_tactic = _TACTIC_LANE_LABEL.get(tactic_raw)
        mitre_ids = [m for m in (stage.get("mitre") or []) if m]
        if not canonical_tactic and not mitre_ids:
            # Nothing to project — skip rather than dumping into a
            # bogus lane.  The stage still appears in the timeline
            # via the deterministic stage timeline.
            continue
        # If we have MITRE but no tactic, we still need SOMETHING to
        # place the node — use "Execution" as the neutral default.
        canonical_tactic = canonical_tactic or "Execution"
        title = (stage.get("title")
                  or stage.get("family")
                  or stage.get("objective") or f"Stage {i + 1}")
        description = (stage.get("objective")
                        or stage.get("family")
                        or f"Preprocessor stage {i + 1}.")
        confidence = float(stage.get("confidence") or 0.9)
        # Deterministic severity tier.
        if   confidence >= 0.95: sev = "critical"
        elif confidence >= 0.85: sev = "high"
        elif confidence >= 0.70: sev = "medium"
        else:                    sev = "low"
        # Evidence citation — normalized command first, raw excerpt fallback.
        evidence_text = (stage.get("normalized_command")
                          or stage.get("raw_excerpt") or "").strip()
        evidence = [BehaviorEvidence(text=evidence_text,
                                      location=f"stage.{i + 1}")] if evidence_text else []
        # Stable Behavior id.  Preserve the family slug when
        # available so re-runs against the same input produce
        # byte-identical ids.
        bid = "stage_" + (stage.get("family")
                           or _stage_slug(title))
        out.append(Behavior(
            id=f"{bid}_{i:02d}",
            title=title,
            kill_chain=_TACTIC_KILLCHAIN.get(canonical_tactic, [canonical_tactic]),
            mitre_techniques=mitre_ids,
            mitre_tactics=[canonical_tactic],
            confidence=min(0.99, confidence),
            description=description,
            category=(stage.get("family") or "execution"),
            severity=sev,
            order=100 + i,       # keep stage-derived behaviors AFTER regex ones
            evidence=evidence,
        ))
    return out


# ══════════════════════════════════════════════════════════════════
# 1. Detection — when should the synthesizer run?
# ══════════════════════════════════════════════════════════════════
def _needs_synthesis(ssot: Dict[str, Any]) -> bool:
    """Return True iff this SSOT is a paste-only investigation.

    A paste-only investigation has:
      · no successful acquisition (``acquired_document.ok`` falsy),
      · no acquisition attempt (no ``url`` and no ``error_code`` on
        the acquired_document — otherwise IDA-3 tried and failed and
        we must NOT mask that failure), and
      · no article-extractor commands (``report_extraction.commands``
        empty).

    The incident block emitted by ICE is otherwise fine (behaviors /
    timeline both derived from the article extractors).
    """
    acq = (ssot or {}).get("acquired_document") or {}
    if acq.get("ok"):
        return False
    # If IDA-3 actually attempted a fetch, respect the failure signal.
    if acq.get("url") or acq.get("final_url") or acq.get("error_code"):
        return False
    ext = (ssot or {}).get("report_extraction") or {}
    if ext.get("commands"):
        return False
    return True


# ══════════════════════════════════════════════════════════════════
# 2. Behavior → Timeline / Evidence projection
# ══════════════════════════════════════════════════════════════════
_KILLCHAIN_ORDER = {
    "Reconnaissance":         0,
    "Resource Development":   1,
    "Initial Access":         2,
    "Delivery":               3,
    "Execution":              4,
    "Persistence":            5,
    "Privilege Escalation":   6,
    "Defense Evasion":        7,
    "Credential Access":      8,
    "Discovery":              9,
    "Lateral Movement":      10,
    "Collection":            11,
    "Command and Control":   12,
    "Exfiltration":          13,
    "Impact":                14,
}


def _tactic_slug(tactic: str) -> str:
    """MITRE tactic → the snake_case slug the frontend AttackLifecyclePanel
    keys off (see `_TACTIC_ORDER` in InvestigationSessionPage.jsx)."""
    if not tactic:
        return "execution"
    return tactic.strip().lower().replace("&", "and").replace(" ", "_")


def _behavior_sort_key(b: Behavior) -> Tuple[int, int, str]:
    """Deterministic order — kill-chain phase, then insertion order,
    then behavior id.  Guarantees paste-only cases replay identically
    across restarts and become byte-identical to their canonical
    representation."""
    first_phase = b.kill_chain[0] if b.kill_chain else "zzz"
    phase_rank = _KILLCHAIN_ORDER.get(first_phase, 99)
    return (phase_rank, b.order, b.id)


def _behaviors_from_input(text: str) -> List[Behavior]:
    """Line-level extraction so evidence carries a stable location.
    Falls back to a single ``cmd.1`` chunk when the paste has no
    newlines (single-shot ``powershell -c "..."`` cases).
    """
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        lines = [text or ""]
    per_line = [
        extract_behaviors(ln, location_prefix=f"cmd.{i+1}")
        for i, ln in enumerate(lines)
    ]
    merged = correlate_behaviors(per_line)
    return sorted(merged, key=_behavior_sort_key)


# ── Behavior → cluster (ICE-compatible shape) ─────────────────────
def _behaviors_to_clusters(behaviors: List[Behavior]) -> List[Dict[str, Any]]:
    """Emit ICE-compatible behavior_clusters so the frontend
    AttackLifecyclePanel and NIST projection render identically to
    the URL / PDF / EML cases.

    Every cluster carries a stable ``bhv_id`` (``bhv-<behavior.id>``)
    the timeline events reference back to.
    """
    out: List[Dict[str, Any]] = []
    for b in behaviors:
        primary_tactic = _tactic_slug(b.mitre_tactics[0]) if b.mitre_tactics else "execution"
        conf_label = ("high"   if b.confidence >= 0.90
                       else "medium" if b.confidence >= 0.75
                       else "low")
        out.append({
            "bhv_id":         f"bhv-{b.id}",
            "label":          b.title,
            "description":    b.description,
            "commands":       [
                {"command": e.text, "source": e.location or "paste"}
                for e in b.evidence
            ],
            "command_count":  len(b.evidence),
            "mitre":          [{"id": tid, "name": "", "tactic": primary_tactic}
                                for tid in b.mitre_techniques],
            "mitre_tactics":  list(b.mitre_tactics),
            "kill_chain":     list(b.kill_chain),
            "lolbins":        [],
            "languages":      ["powershell"],
            "primary_tactic": primary_tactic,
            "confidence":     conf_label,
            "severity":       b.severity,
            "category":       b.category,
            "order":          b.order,
            "sources":        ["analyst_paste"],
            "evidence_strength": "moderate" if len(b.evidence) >= 2 else "weak",
            "evidence_sources":  ["commands"] + (["mitre"] if b.mitre_techniques else []),
        })
    return out


# ── Behavior → timeline (deterministic evt-#### ids) ──────────────
def _behaviors_to_timeline(behaviors: List[Behavior]) -> List[Dict[str, Any]]:
    """Behavior-driven timeline.  ONE event per behavior, ordered by
    kill-chain phase then insertion order.  Each event carries:

        · ``id``                — stable ``evt-####``
        · ``kind``              — ``"behavior"``
        · ``step``              — 1-based position
        · ``event``             — behavior title (analyst-facing)
        · ``description``       — behavior description
        · ``behavior_id``       — matches the cluster's ``bhv_id``
        · ``category``          — canonical behavior category
        · ``severity``          — deterministic severity tier
        · ``confidence``        — 0.0–0.99
        · ``kill_chain``        — list of kill-chain phases
        · ``mitre_tactics``     — plural
        · ``mitre_techniques``  — T-ids
        · ``command``           — a representative evidence sample
        · ``evidence_refs``     — list of ``ev-####`` ids
    """
    out: List[Dict[str, Any]] = []
    ev_counter = 0
    for step, b in enumerate(behaviors, start=1):
        sample = b.evidence[0].text if b.evidence else ""
        refs: List[str] = []
        for _ in b.evidence:
            ev_counter += 1
            refs.append(f"ev-{ev_counter:04d}")
        out.append({
            "id":                f"evt-{step:04d}",
            "kind":              "behavior",
            "step":              step,
            "event":             b.title,
            "description":       b.description,
            "behavior_id":       f"bhv-{b.id}",
            "category":          b.category,
            "severity":          b.severity,
            "confidence":        b.confidence,
            "kill_chain":        list(b.kill_chain),
            "mitre_tactics":     list(b.mitre_tactics),
            "mitre_techniques":  list(b.mitre_techniques),
            "command":           sample,
            "evidence_refs":     refs,
            "source":            "analyst_paste",
        })
    return out


# ── Behavior → evidence list (flat, id-addressable) ───────────────
def _behaviors_to_evidence_list(behaviors: List[Behavior]) -> List[Dict[str, Any]]:
    """Flat evidence records — one row per BehaviorEvidence.  Each
    row carries a stable ``ev-####`` id so timeline events + IEP
    projections can cross-reference the exact substring that fired
    the behavior."""
    out: List[Dict[str, Any]] = []
    counter = 0
    for b in behaviors:
        for e in b.evidence:
            counter += 1
            out.append({
                "id":               f"ev-{counter:04d}",
                "text":             e.text,
                "location":         e.location or "",
                "behavior_id":      f"bhv-{b.id}",
                "behavior_title":   b.title,
                "mitre_techniques": list(b.mitre_techniques),
                "mitre_tactics":    list(b.mitre_tactics),
                "kill_chain":       list(b.kill_chain),
                "category":         b.category,
                "severity":         b.severity,
                "confidence":       b.confidence,
                "source":           "analyst_paste",
            })
    return out


# ══════════════════════════════════════════════════════════════════
# 3. Synthetic acquired_document / acquisition_plan
# ══════════════════════════════════════════════════════════════════
def _synthetic_acquired_document(text: str, behaviors: List[Behavior]) -> Dict[str, Any]:
    """Synthetic ``acquired_document{}`` for paste-only inputs.

    We set ``ok=true`` and ``source_kind="analyst_paste"`` so the
    Evidence Explorer tab and downstream projections render exactly
    the same UI regardless of whether the source was a URL / PDF or
    a raw paste.  The ``article_text`` mirrors the raw input so
    downstream extractors that read this field see the same data
    (unchanged) as if it were an article body."""
    line_count = sum(1 for _ in (text or "").splitlines() if _.strip()) or (1 if text else 0)
    return {
        "ok":              True,
        "url":             "",
        "final_url":       "",
        "status_code":     0,
        "content_type":    "text/plain",
        "fetched_bytes":   len((text or "").encode("utf-8", "replace")),
        "truncated":       False,
        "duration_ms":     0,
        "title":           "Analyst Paste",
        "sitename":        "Analyst Paste",
        "language":        "",
        "article_text":    text or "",
        "article_chars":   len(text or ""),
        "outbound_links":  [],
        "structured_blocks": [text or ""] if text else [],
        "engine":          "paste_synthesis",
        "source_kind":     "analyst_paste",
        "fallback_chain":  [],
        "error_code":      "",
        "error_detail":    "",
        "synthetic":       True,
        "line_count":      line_count,
        "behavior_count":  len(behaviors),
    }


def _synthetic_acquisition_plan(behaviors: List[Behavior]) -> List[Dict[str, Any]]:
    """Synthetic acquisition plan — matches the ``_ACQ_STEP_TEMPLATES``
    shape in ``investigation_results.py`` so the Evidence Explorer
    AcquisitionPlanPanel renders without changes.  Every step is
    ``done`` because the paste itself IS the acquired content."""
    return [
        {"id": "ida-1",     "title": "Identify Input",
         "engine": "IDA-1 Input Classifier",
         "detail": "Classify the paste as raw analyst-provided text.",
         "status": "done"},
        {"id": "ida-2",     "title": "Determine Resource Type",
         "engine": "IDA-2 Artifact Splitter",
         "detail": "Split the paste into command / IOC artifacts.",
         "status": "done"},
        {"id": "ida-3",     "title": "Acquire Resource",
         "engine": "Paste Synthesis",
         "detail": "Paste is already the acquired content — no network fetch.",
         "status": "done"},
        {"id": "ida-4",     "title": "Extract Commands",
         "engine": "Behavior Extractor",
         "detail": f"Deterministic behavior extraction yielded {len(behaviors)} behavior(s).",
         "status": "done"},
        {"id": "die",       "title": "Decode / Deobfuscate",
         "engine": "DIE",
         "detail": "PowerShell constant folding + recursive base64 decode applied.",
         "status": "done"},
        {"id": "ssot",      "title": "Assemble SSOT",
         "engine": "SSOT",
         "detail": "Unified Canonical Investigation Object with synthetic evidence.",
         "status": "done"},
        {"id": "report",    "title": "Generate Investigation Report",
         "engine": "IVE",
         "detail": "Project the NIST IR sections + Evidence Completeness surface.",
         "status": "done"},
    ]


# ══════════════════════════════════════════════════════════════════
# 4. Public entry point
# ══════════════════════════════════════════════════════════════════
def synthesize(ssot: Dict[str, Any]) -> Dict[str, Any]:
    """Mutate ``ssot`` in place: add synthetic acquired_document /
    acquisition_plan / incident.behaviors / incident.timeline /
    incident.evidence for paste-only investigations.  No-op when
    the SSOT already has a real acquired document or article
    extractors produced commands.

    Returns the same ``ssot`` reference for chaining convenience.
    """
    if not isinstance(ssot, dict) or not _needs_synthesis(ssot):
        return ssot

    raw = ((ssot.get("input") or {}).get("raw") or "") if isinstance(ssot.get("input"), dict) \
          else (ssot.get("input") or "")
    if not isinstance(raw, str):
        raw = str(raw or "")

    behaviors = _behaviors_from_input(raw)

    # ── Merge in preprocessor-stage behaviors ─────────────────────
    # DIE recognises hundreds of attack techniques the 27-rule
    # behavior_extractor doesn't cover (Reverse SSH Tunnel, AD
    # Enumeration, MSI Installer, Shadow Copy Removal, WMIC Software
    # Removal, Registry Modification, …).  Every stage already
    # carries a canonical MITRE tactic + technique id upstream, so
    # promoting them to behaviors makes the 14-lane trajectory a
    # complete picture instead of a regex-limited slice.
    stage_behaviors = _behaviors_from_stages(ssot)
    if stage_behaviors:
        # Dedupe by MITRE technique + tactic first (stages that name
        # the same technique should collapse), falling back to title
        # dedupe for stages that have no MITRE id.
        seen_keys: set = set()
        for b in behaviors:
            for tid in b.mitre_techniques:
                for t in b.mitre_tactics:
                    seen_keys.add((tid, t))
            seen_keys.add(("title", b.title.lower()))
        for sb in stage_behaviors:
            key_hit = any((tid, t) in seen_keys
                            for tid in sb.mitre_techniques
                            for t   in sb.mitre_tactics)
            if key_hit:
                continue
            if ("title", sb.title.lower()) in seen_keys:
                continue
            behaviors.append(sb)
            for tid in sb.mitre_techniques:
                for t in sb.mitre_tactics:
                    seen_keys.add((tid, t))
            seen_keys.add(("title", sb.title.lower()))
        behaviors = sorted(behaviors, key=_behavior_sort_key)

    if not behaviors:
        # No behaviors detected — still emit a synthetic acquired_document
        # + acquisition_plan so the Evidence Explorer isn't empty, but
        # skip the incident synthesis (nothing to project).
        ssot["acquired_document"] = _synthetic_acquired_document(raw, behaviors)
        ssot["acquisition_plan"]  = _synthetic_acquisition_plan(behaviors)
        return ssot

    clusters   = _behaviors_to_clusters(behaviors)
    timeline   = _behaviors_to_timeline(behaviors)
    evidence   = _behaviors_to_evidence_list(behaviors)

    # ── Enrich SSOT top-level ─────────────────────────────────────
    ssot["acquired_document"] = _synthetic_acquired_document(raw, behaviors)
    ssot["acquisition_plan"]  = _synthetic_acquisition_plan(behaviors)

    # ── Enrich incident{} — only touch empty slots (R21). ─────────
    incident = ssot.get("incident") or {}
    # Never overwrite article-extractor output if it exists.
    if not incident.get("behaviors"):
        incident["behaviors"] = clusters
    if not incident.get("timeline"):
        incident["timeline"] = timeline
    ev = incident.get("evidence") or {}
    if not ev.get("behaviors"):
        ev["behaviors"] = evidence
    if not ev.get("commands"):
        # Best-effort per-line command sampling so the Evidence
        # Explorer commands list mirrors the paste — deterministic.
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if not lines and raw:
            lines = [raw]
        ev["commands"] = [
            {"command": ln, "source": "analyst_paste", "purpose": ""}
            for ln in lines
        ]
    incident["evidence"] = ev
    # Add a small provenance breadcrumb so downstream projections know
    # the incident was synthesized from behaviors rather than from
    # article extractors.
    incident["synthetic"] = True
    incident["synthetic_source"] = "paste_synthesis.v1"
    ssot["incident"] = incident

    # ── Mirror onto legacy `ice{}` block so any consumer still
    # reading the raw per-piece surface picks up the same data.
    ice = ssot.get("ice") or {}
    if not ice.get("behavior_clusters"):
        ice["behavior_clusters"] = clusters
    if not ice.get("timeline"):
        ice["timeline"] = timeline
    ssot["ice"] = ice

    return ssot
