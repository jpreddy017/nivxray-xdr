"""
P0.7.3 · Round 16 · Threat Family Classifier
────────────────────────────────────────────

Deterministic, evidence-driven classifier that reads IUE entities +
canonical evidence + intelligence observations + ICE matches and
emits ONE of the enumerated families with `confidence` and
`evidence_refs`.

**Golden rule (§2, §11 · owner-locked):**
    A family is NEVER forced.  If evidence is insufficient the
    classifier honestly reports `UNKNOWN` with `reason`.
    "PCAppStore" is a *specific manifestation* of `PUA_ADWARE`,
    NOT a family of its own.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


CLASSIFIER_ID      = "nivxray::xdr::threat_family_classifier"
CLASSIFIER_VERSION = "1.0.0"

FAMILIES = [
    "PUA_ADWARE", "MALWARE", "RANSOMWARE",
    "CREDENTIAL_THEFT", "PHISHING", "INFOSTEALER",
    "LOADER", "C2", "LATERAL_MOVEMENT", "PERSISTENCE",
    "EXPLOITATION", "DATA_EXFILTRATION", "WORM", "BOTNET",
    "SUSPICIOUS_APPLICATION", "BENIGN_ADMINISTRATIVE",
    "UNKNOWN",
]


# ── Signal predicates ────────────────────────────────────────
#
# Each predicate is a pure function of the composed feature bag
# `feats`.  A predicate returning a list of matched reasons
# contributes to that family's score.

def _score(feats: dict) -> dict[str, tuple[int, list[str]]]:
    scores: dict[str, tuple[int, list[str]]] = {}

    def bump(fam: str, pts: int, reason: str):
        cur = scores.get(fam, (0, []))
        scores[fam] = (cur[0] + pts, cur[1] + [reason])

    sig_name = (feats.get("signature_name") or "").lower()
    proto    = (feats.get("protocol") or "").upper()
    sev      = (feats.get("severity_hint") or "INFORMATIONAL")
    ips      = feats.get("ips") or []
    domains  = feats.get("domains") or []
    obs      = feats.get("observations") or []
    ice_n    = feats.get("ice_matches") or 0
    veee     = (feats.get("verdict_label") or "").upper()

    # ── C2 signals ──────────────────────────────
    if any(k in sig_name for k in ("c2", "beacon", "cobalt", "discord",
                                                    "asymmetric cryptography", "tls sni",
                                                    "observed dns")):
        bump("C2", 30, f"signature suggests C2 pattern ({sig_name})")
    if proto in ("HTTP", "HTTPS", "DNS", "TLS") and domains:
        bump("C2", 5, f"protocol={proto} + domain observed")

    # ── PUA / Adware ─────────────────────────────
    pua_needles = ("pua", "adware", "unwanted", "onestart",
                          "pcapp", "wave browser", "toolbar")
    if any(n in sig_name for n in pua_needles):
        bump("PUA_ADWARE", 45, f"signature declares PUA/adware ({sig_name})")
    if feats.get("startup_persistence"):
        bump("PUA_ADWARE", 10, "startup persistence artefact observed")

    # ── Ransomware ─────────────────────────────
    if any(k in sig_name for k in ("ransom", "lockbit", "conti",
                                                    "blackcat", "encrypt")):
        bump("RANSOMWARE", 50, f"signature suggests ransomware ({sig_name})")

    # ── Credential theft ───────────────────────
    if any(k in sig_name for k in ("mimikatz", "lsass", "credential",
                                                    "kerberoast", "ntds")):
        bump("CREDENTIAL_THEFT", 45,
              f"credential-access signature ({sig_name})")

    # ── Phishing ───────────────────────────────
    if "phish" in sig_name or "mail" in sig_name:
        bump("PHISHING", 40, f"phishing signature ({sig_name})")

    # ── Loader / infostealer ───────────────────
    if any(k in sig_name for k in ("stealer", "info stealer", "amatera")):
        bump("INFOSTEALER", 45, f"stealer signature ({sig_name})")
    if any(k in sig_name for k in ("loader", "downloader", "dropper")):
        bump("LOADER", 35, f"loader signature ({sig_name})")

    # ── OSINT observation escalation ───────────
    mal_obs = [o for o in obs
                    if (o.get("verdict") or "").lower() == "malicious"]
    if len(mal_obs) >= 2:
        bump("C2", 10, f"{len(mal_obs)} OSINT providers confirmed malicious")
        bump("MALWARE", 5, "corroborated malicious intelligence")

    # ── Correlation lift ───────────────────────
    if ice_n >= 2:
        bump("MALWARE", 8, f"{ice_n} correlation matches lift signal")

    # ── VEEE gating ────────────────────────────
    if veee == "MALICIOUS":
        # Amplify any established family; do not INVENT a family here.
        for k, (pts, _) in list(scores.items()):
            if pts >= 20:
                bump(k, 5, "VEEE label MALICIOUS")
    elif veee == "LIKELY_BENIGN":
        bump("BENIGN_ADMINISTRATIVE", 20, "VEEE label LIKELY_BENIGN")

    return scores


def _collect_feats(canonical: dict | None, iue: dict | None,
                          ice_matches: list[dict],
                          observations: list[dict],
                          verdict: dict | None) -> dict:
    sig = ((canonical or {}).get("security") or {}).get("signature") or {}
    net = ((canonical or {}).get("network")   or {})
    src = (net.get("src") or {}).get("ip")
    dst = (net.get("dst") or {}).get("ip")
    return {
        "signature_name":  sig.get("name"),
        "signature_id":    sig.get("id"),
        "protocol":        net.get("protocol"),
        "ips":             [i for i in (src, dst) if i],
        "domains":         [],   # canonical schema doesn't carry domains yet
        "severity_hint":   (iue or {}).get("severity_hint"),
        "capability_tags": (iue or {}).get("capability_tags") or [],
        "ice_matches":     len(ice_matches),
        "observations":    observations,
        "verdict_label":   (verdict or {}).get("label"),
        "startup_persistence": False,  # future EDR telemetry lane
    }


async def classify(db, incident_id: str) -> dict:
    """
    Round 16 classifier entry point.  Pure projection over persisted
    state; deterministic and idempotent.  Never forces a family.
    """
    inc = await db["workspace_cases"].find_one({"id": incident_id},
                                                             {"_id": 0})
    if not inc:
        return {"engine_id": CLASSIFIER_ID,
                    "state": "MISSING",
                    "reason": f"incident {incident_id} not found"}

    prov = inc.get("xdr_pipeline") or {}
    canonical = None
    ce_id = prov.get("canonical_event_id")
    if ce_id:
        canonical = await db["xdr_canonical_evidence"].find_one(
            {"event_id": ce_id}, {"_id": 0})

    ice_matches: list[dict] = []
    for mid in (prov.get("ice_matches") or []):
        m = await db["xdr_correlation_matches"].find_one(
            {"match_id": mid}, {"_id": 0})
        if m:
            ice_matches.append(m)

    observations: list[dict] = []
    async for o in db["xdr_intelligence_observations"].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        observations.append(o)

    feats = _collect_feats(canonical, prov.get("iue"),
                                    ice_matches, observations,
                                    prov.get("veee"))
    scores = _score(feats)

    if not scores:
        return {"engine_id":      CLASSIFIER_ID,
                    "engine_version": CLASSIFIER_VERSION,
                    "state":         "READY",
                    "incident_id":   incident_id,
                    "family":        "UNKNOWN",
                    "confidence":    "N/A",
                    "reason":        "insufficient evidence for classification",
                    "candidates":    [],
                    "feats":         feats,
                    "honesty_note":
                        "No signal reached the classification threshold. "
                        "UNKNOWN is preserved to avoid template-driven "
                        "recommendations."}

    ordered = sorted(scores.items(), key=lambda kv: kv[1][0], reverse=True)
    top_fam, (top_pts, top_reasons) = ordered[0]
    confidence = ("HIGH"   if top_pts >= 40
                       else "MEDIUM" if top_pts >= 20
                       else "LOW")
    return {
        "engine_id":      CLASSIFIER_ID,
        "engine_version": CLASSIFIER_VERSION,
        "state":          "READY",
        "incident_id":    incident_id,
        "family":         top_fam,
        "confidence":     confidence,
        "score":          top_pts,
        "reasons":        top_reasons,
        "candidates": [
            {"family": f, "score": pts, "reasons": rs}
            for f, (pts, rs) in ordered
        ],
        "feats":          feats,
        "computed_at":    datetime.now(timezone.utc).isoformat(),
        "honesty_note":
            "Family selection is deterministic + compositional.  A specific "
            "malware/application (e.g. PCAppStore) is a manifestation of a "
            "family, never a family itself.",
    }
