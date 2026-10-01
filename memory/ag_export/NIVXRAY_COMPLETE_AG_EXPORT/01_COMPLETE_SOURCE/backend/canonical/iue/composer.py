"""Canonical IUE Composer — Phase 1.

Public entry point: `classify(raw, context=None) -> IUEDecision`.

Composition order (ADR-005 §3.3):
    InputHealth -> BytesMagic -> TextStructure -> Language+MultiArtefact
    -> ArtefactDecomposition -> Intent
    -> PlanBuilder (deterministic plan + dispatch + policy)

Tie-breaking (see /app/memory/adr/0005-phase1-spec.md §5):
    1. blocking health short-circuits
    2. highest confidence wins primary_type
    3. fixed sub-classifier priority on confidence tie
    4. non-winners with conf >= 40 join embedded[]

Determinism: no clock reads, no random, no network, no environment
lookups. Provenance envelope on every emitted evidence.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from .adapters.artefact_decomp import artefact_decomp_evidence
from .adapters.bytes_magic import bytes_magic_evidence
from .adapters.input_health import health_evidence
from .adapters.intent import intent_evidence
from .adapters.language_multi_artefact import language_multi_artefact_evidence
from .adapters.text_structure import text_structure_evidence
from .determinism import fingerprint
from .models import (
    Capability,
    ConfidenceMatrix,
    DispatchPolicy,
    IUEDecision,
    IUEEvidence,
    InputProfile,
    Intent,
    Provenance,
    RawInput,
)
from .plan_builder import build_plan_and_dispatch


COMPOSER_VERSION = "1.0.0"

_COMPOSER_PROV = Provenance(
    engine="canonical.iue.composer",
    version=COMPOSER_VERSION,
    at="phase1",
    upstream_evidence_ids=[],
)


# Tie-break priority: bytes_magic > text_structure > language_multi > multi_artefact
# See /app/memory/adr/0005-phase1-spec.md §5.
_TIE_BREAK_ORDER: Dict[str, int] = {
    "bytes_magic":              0,
    "text_structure":           1,
    "language_multi_artefact":  2,
    "artefact_decomp":          3,
    "input_health":             4,
    "intent":                   5,
}


def _normalise_raw(inp: Union[RawInput, bytes, str, Dict[str, Any]]) -> RawInput:
    if isinstance(inp, RawInput):
        return inp
    if isinstance(inp, dict):
        return RawInput(**inp)
    return RawInput(payload=inp)


def _pick_primary(candidates: List[tuple]) -> str:
    """(source_name, type_str, confidence) -> winning type_str."""
    if not candidates:
        return "unknown"

    # Filter Nones
    filtered = [(s, t, c) for (s, t, c) in candidates if t]
    if not filtered:
        return "unknown"

    # Sort: descending confidence, then ascending tie-break priority.
    filtered.sort(key=lambda x: (-int(x[2]), _TIE_BREAK_ORDER.get(x[0], 99)))
    return filtered[0][1].lower()


def _binary_taxonomy_mapping(uil_kind: Optional[str]) -> Optional[str]:
    """Map UIL InputKind values into the canonical primary_type taxonomy.
    In Phase 1 the taxonomy is the UIL value itself, lowercased. This
    function exists so Phase 2/3 can extend the mapping without changing
    the composer.
    """
    return uil_kind.lower() if uil_kind else None


def classify(
    raw: Union[RawInput, bytes, str, Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> IUEDecision:
    """Canonical IUE entry point.

    Phase 1 composer. Deterministic. No I/O. See ADR-005 §3.2 for the
    IUEDecision contract.
    """
    r = _normalise_raw(raw)

    all_evidence: List[IUEEvidence] = []

    # 1. Input health
    health, ev_health = health_evidence(r)
    all_evidence.extend(ev_health)

    # 2. Bytes magic (IUE-4)
    bytes_kind, ev_bytes = bytes_magic_evidence(r)
    all_evidence.extend(ev_bytes)

    # If health is blocking, short-circuit to a MANUAL_REVIEW plan.
    if health.blocking:
        profile = InputProfile(
            primary_type="blocked_by_health",
            embedded=[],
            input_kind=(bytes_kind or ""),
            encoding=health.encoding,
            size_bytes=r.size(),
            byte_signature=r.as_bytes()[:16].hex(),
            filename=r.filename,
            mime_hint=r.mime_hint,
        )
        intent = Intent(label="blocked_by_health", confidence=0,
                        evidence_ids=[e.id for e in ev_health if "issue" in e.meta or e.id == "ev.input_health.ok"][:3])
        plan, caps, policy = build_plan_and_dispatch(
            "blocked_by_health", [], None, 0, [], "blocked_by_health", blocking_health=True
        )
        matrix = ConfidenceMatrix(0, 0, 0, 0, 0, 0)
        decision = IUEDecision(
            input_health=health,
            input_profile=profile,
            intent=intent,
            capabilities=caps,
            plan=plan,
            confidence_matrix=matrix,
            dispatch_policy=policy,
            provenance=_COMPOSER_PROV,
            next_engine_hint="Input failed pre-IUE health checks; manual review required.",
            evidence=all_evidence,
        )
        _stamp_hash(decision)
        return decision

    # 3. Text-structure classification (IUE-2)
    text_type, next_hint_text, ev_text = text_structure_evidence(r)
    all_evidence.extend(ev_text)

    # 4. Language + multi-artefact (IUE-3)
    lang_type, embedded_v2, dispatch_hints_v2, ev_lang = language_multi_artefact_evidence(r)
    all_evidence.extend(ev_lang)

    # 5. Artefact decomposition (IUE-5)
    ida_result, ev_ida = artefact_decomp_evidence(r)
    all_evidence.extend(ev_ida)

    # Consolidate candidates for primary_type tie-breaking.
    # Each entry: (source_name, canonical_type_string, confidence 0..100)
    candidates: List[tuple] = []
    if bytes_kind:
        # Prefer bytes_magic when it's a genuine binary/rich type;
        # for plain_text/command/powershell the text-side classifiers
        # are more precise, so bytes_magic confidence reported by the
        # adapter (55 for text kinds, 95 for binary kinds) already
        # encodes this.
        bytes_conf = int(ev_bytes[0].confidence) if ev_bytes else 0
        candidates.append(("bytes_magic",
                           _binary_taxonomy_mapping(bytes_kind),
                           bytes_conf))
    if text_type:
        text_conf = int(ev_text[0].confidence) if ev_text and ev_text[0].source == "text_structure" else 0
        candidates.append(("text_structure", text_type, text_conf))
    if lang_type:
        lang_conf = int(ev_lang[0].confidence) if ev_lang else 0
        candidates.append(("language_multi_artefact", lang_type, lang_conf))

    primary_type = _pick_primary(candidates)

    # Assemble embedded[] — everything non-winning with conf >= 40.
    embedded: List[str] = []
    for src, t, c in candidates:
        if not t:
            continue
        if t.lower() == primary_type:
            continue
        if int(c) < 40:
            continue
        if t.lower() not in embedded:
            embedded.append(t.lower())
    # Add v2 embedded artefact types (`javascript`, `wmic`, etc.).
    for t in embedded_v2:
        tl = t.lower()
        if tl != primary_type and tl not in embedded:
            embedded.append(tl)

    # 6. Intent (upstream — D1-D)
    class_conf = 0
    for src, t, c in candidates:
        if t and t.lower() == primary_type:
            class_conf = max(class_conf, int(c))
    intent_obj, ev_intent = intent_evidence(r, primary_type, class_conf)
    all_evidence.extend(ev_intent)

    # 7. Plan / dispatch / policy
    ida_class = (ida_result or {}).get("ida_class")
    ida_hint = 0
    summary = (ida_result or {}).get("summary") or {}
    if isinstance(summary, dict):
        ida_hint = sum(int(v) for v in summary.values())
    plan, caps, policy = build_plan_and_dispatch(
        primary_type=primary_type,
        embedded=embedded,
        ida_class=ida_class,
        ida_artifact_hint=ida_hint,
        dispatch_hints_from_v2=dispatch_hints_v2,
        intent_label=intent_obj.label,
        blocking_health=False,
    )

    # 8. Confidence matrix — 6 axes.
    matrix = ConfidenceMatrix(
        input_classification=class_conf,
        decode_path=(80 if any(c is Capability.DECODER for c in caps) else 40),
        language_detection=(int(ev_lang[0].confidence) if ev_lang else 0),
        estimated_recovery=(70 if any(c is Capability.DECODER for c in caps) else 90),
        artifact_completeness=(min(100, 50 + 10 * len(embedded))),
        telemetry_richness=(100 if any(c is Capability.VENDOR_NORMALISER for c in caps) else 30),
    )

    profile = InputProfile(
        primary_type=primary_type,
        embedded=embedded,
        input_kind=(bytes_kind or ""),
        encoding=health.encoding,
        size_bytes=r.size(),
        byte_signature=r.as_bytes()[:16].hex(),
        filename=r.filename,
        mime_hint=r.mime_hint,
    )

    next_hint = (next_hint_text
                 or f"Input classified as {primary_type} "
                    f"(embedded={embedded or 'none'}); intent={intent_obj.label}.")

    # Deterministic sort of evidence for stability.
    all_evidence.sort(
        key=lambda e: (
            _TIE_BREAK_ORDER.get(e.source, 99),
            e.id,
        )
    )

    decision = IUEDecision(
        input_health=health,
        input_profile=profile,
        intent=intent_obj,
        capabilities=caps,
        plan=plan,
        confidence_matrix=matrix,
        dispatch_policy=policy,
        provenance=_COMPOSER_PROV,
        next_engine_hint=next_hint,
        evidence=all_evidence,
    )
    _stamp_hash(decision)
    return decision


def _stamp_hash(decision: IUEDecision) -> None:
    """Compute + assign determinism_hash. Hash excludes the field itself."""
    tmp = decision.determinism_hash
    decision.determinism_hash = ""
    h = fingerprint(decision)
    decision.determinism_hash = h
    # If callers ever re-hash without clearing, we still get the same
    # value because canonical_json is order-stable and the tmp above
    # was already ignored.
    del tmp
