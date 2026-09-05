"""
P0.4 · Round 11 · XDR IUE (Investigation & Understanding of Evidence)
─────────────────────────────────────────────────────────────────────

Boundary (Round 10 §36, reaffirmed Round 11):

  DSM  = vendor/product semantics (parser selection)
  IUE  = **security-investigation understanding** of already-canonical
         evidence.  Extracts *entities*, *attack-lifecycle hints*,
         *severity_hint*, and a *capability profile* — nothing more.
         Never fabricates verdicts, never decodes bytes, never joins
         to external intel.

Determinism contract (§3):
  * Pure function of the canonical evidence + optional detection
    result.  No clock reads, no random UUIDs (uses `evidence_hash`
    for stable IDs), no I/O, no network.
  * Same canonical evidence → byte-identical IUEEvidence output.

Honest-state contract (§37/§42):
  * If the evidence contains no security signal, we honestly return
    `severity_hint = "INFORMATIONAL"` and confidence = 0.
  * If the detection result is missing, `detection_supported = False`.
    We *never* mark the evidence as "detected" without upstream proof.
"""
from __future__ import annotations
import hashlib
from typing import Any


IUE_ENGINE_ID = "nivxray::xdr::iue"
IUE_ENGINE_VERSION = "1.0.0"


# Deterministic severity ladder (§37: numeric, allow-listed).
_SEV_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Suricata numeric severity → canonical band (1=high alert in Suricata).
_SURICATA_SEV_MAP = {
    1: "HIGH",
    2: "MEDIUM",
    3: "LOW",
    4: "INFORMATIONAL",
}


def _stable_id(prefix: str, seed: str) -> str:
    return f"{prefix}_{hashlib.sha256(seed.encode()).hexdigest()[:20]}"


def _extract_entities(canonical: dict) -> list[dict]:
    """
    Emit deterministic entity records straight from canonical evidence.
    Every entity carries its *origin path* so provenance is traceable.
    """
    ents: list[dict] = []
    net = canonical.get("network") or {}
    src = (net.get("src") or {})
    dst = (net.get("dst") or {})
    if src.get("ip"):
        ents.append({
            "kind":       "ipv4" if "." in src["ip"] else "ipv6",
            "value":      src["ip"],
            "role":       "source",
            "origin":     "network.src.ip",
        })
    if dst.get("ip"):
        ents.append({
            "kind":       "ipv4" if "." in dst["ip"] else "ipv6",
            "value":      dst["ip"],
            "role":       "destination",
            "origin":     "network.dst.ip",
        })
    proto = net.get("protocol")
    if proto:
        ents.append({
            "kind":       "protocol",
            "value":      str(proto).upper(),
            "role":       "context",
            "origin":     "network.protocol",
        })
    sig = (canonical.get("security") or {}).get("signature") or {}
    if sig.get("id") is not None:
        ents.append({
            "kind":       "signature",
            "value":      str(sig.get("id")),
            "name":       sig.get("name"),
            "role":       "trigger",
            "origin":     "security.signature.id",
        })

    # ── Derived Content Intelligence Entities (from decoded payloads) ──
    intel = canonical.get("decoded_intelligence") or {}
    iocs = intel.get("iocs") or {}
    if isinstance(iocs, dict):
        for ip in iocs.get("ips") or []:
            ents.append({
                "kind":       "ipv4" if "." in str(ip) else "ipv6",
                "value":      str(ip),
                "role":       "c2_indicator",
                "origin":     "decoded_intelligence.iocs.ips",
            })
        for url in iocs.get("urls") or []:
            ents.append({
                "kind":       "url",
                "value":      str(url),
                "role":       "download_cradle",
                "origin":     "decoded_intelligence.iocs.urls",
            })
        for dom in iocs.get("domains") or []:
            ents.append({
                "kind":       "domain",
                "value":      str(dom),
                "role":       "c2_domain",
                "origin":     "decoded_intelligence.iocs.domains",
            })
    sem = intel.get("semantic_understanding") or {}
    for lb in sem.get("lolbins") or []:
        lb_name = lb.get("name") if isinstance(lb, dict) else str(lb)
        if lb_name:
            ents.append({
                "kind":       "lolbas",
                "value":      lb_name,
                "role":       "execution_tool",
                "origin":     "decoded_intelligence.semantic_understanding.lolbins",
            })

    return ents


def _capability_tags(canonical: dict, detection: dict | None) -> list[str]:
    """
    A capability tag is a *declaration* that this evidence can support
    a downstream capability (correlation, verdict, response).  It is
    not a verdict.  Round 8 §1: `capability ≠ verdict`.
    """
    tags: list[str] = []
    if canonical.get("event_type") == "network_alert":
        tags.append("CORRELATION_CANDIDATE:NETWORK")
    if detection and detection.get("matched"):
        tags.append("VERDICT_INPUT:RULE_MATCH")
    if (canonical.get("security") or {}).get("category"):
        tags.append("ATTACK_CATEGORY_PRESENT")
    if canonical.get("decoded_intelligence"):
        tags.append("DERIVED_EVIDENCE:DECODED_CONTENT")
        intel = canonical["decoded_intelligence"]
        if (intel.get("iocs") or {}).get("ips") or (intel.get("iocs") or {}).get("urls"):
            tags.append("CORRELATION_CANDIDATE:DECODED_NETWORK_IOC")
        if (intel.get("security_controls") or {}).get("tampering_detected"):
            tags.append("VERDICT_INPUT:DEFENSE_EVASION_TAMPERING")
    return tags


def _severity_hint(canonical: dict) -> str:
    sev = (canonical.get("security") or {}).get("severity")
    try:
        band = _SURICATA_SEV_MAP.get(int(sev)) if sev is not None else None
    except (TypeError, ValueError):
        band = None
    return band or "INFORMATIONAL"


def _confidence(entities: list[dict], detection: dict | None) -> int:
    """
    Bounded 0..100.  A single alert with a matched detection carries
    moderate confidence.  We deliberately never claim >70 from a
    single event — correlation must lift it.
    """
    score = 20 if entities else 0
    if detection and detection.get("matched"):
        score += 40
    if any(e["kind"] == "signature" for e in entities):
        score += 10
    return max(0, min(score, 70))


def understand(canonical: dict, detection: dict | None = None) -> dict:
    """
    Round 11 · XDR IUE entry point.

    Args:
      canonical:  the Round 10 canonical-evidence dict (must carry a
                  `provenance` block + `event_id`).
      detection:  optional Round 10 detection result.

    Returns a deterministic IUEEvidence dict.  Every field can be
    reproduced from the inputs; nothing is fabricated.
    """
    ev_id = canonical.get("event_id") or "no-event-id"
    entities = _extract_entities(canonical)
    tags     = _capability_tags(canonical, detection)
    sev      = _severity_hint(canonical)
    conf     = _confidence(entities, detection)

    iue_id = _stable_id("iue", f"{ev_id}|{sev}|{','.join(tags)}")

    return {
        "iue_id":              iue_id,
        "engine_id":           IUE_ENGINE_ID,
        "engine_version":      IUE_ENGINE_VERSION,
        "input_event_id":      ev_id,
        "entities":            entities,
        "capability_tags":     tags,
        "severity_hint":       sev,
        "confidence":          conf,
        "detection_supported": bool(detection and detection.get("matched")),
        "honesty_note":
            "IUE never fabricates verdicts; capability_tags are inputs "
            "to VEEE, not conclusions.  confidence is capped at 70 for "
            "single-event evidence — correlation lifts it.",
        "provenance": {
            "trace_id":       (canonical.get("provenance") or {}).get("trace_id"),
            "canonical_id":   ev_id,
            "iue_engine_id":  IUE_ENGINE_ID,
        },
    }
