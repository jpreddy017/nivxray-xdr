"""NivXRay Explainable Verdict (Phase 9.4).

Splits the raw `Malicious 70` score into four analyst-facing sub-scores
plus a human-readable rationale.

Sub-scores (each 0-100):
    • risk_score          — final banded overall (composite)
    • behavior_score      — sum of behavior severities × confidences
    • ioc_score           — external endpoints, hashes, C2 infra weight
    • obfuscation_score   — encoding depth, string reconstruction, decompression

Verdict bands:
    ≥ 75    malicious
    ≥ 40    suspicious
    ≥ 15    needs_review
    ≥  1    informational
    else    benign
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


SEVERITY_WEIGHT = {"critical": 45, "high": 30, "medium": 18, "low": 8, "info": 2}


@dataclass
class VerdictBreakdown:
    verdict: str
    risk_score: int
    behavior_score: int
    ioc_score: int
    obfuscation_score: int
    confidence: int
    rationale: list[str] = field(default_factory=list)
    top_signals: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _bucket(x: int) -> int:
    return max(0, min(100, int(round(x))))


def compute_verdict(behaviors: list, ioc_stats: dict, decode_trace_steps: list,
                    encoded_present: bool = False) -> VerdictBreakdown:
    """Deterministic scoring — every reason lands in `rationale`."""
    behavior_raw = 0
    top_signals: list[dict] = []
    critical_count = 0
    high_count = 0
    for b in behaviors:
        sev = getattr(b, "severity", None) or (isinstance(b, dict) and b.get("severity")) or "info"
        conf = getattr(b, "confidence", None) or (isinstance(b, dict) and b.get("confidence")) or 0
        name = getattr(b, "name", None) or (isinstance(b, dict) and b.get("name")) or ""
        bid = getattr(b, "id", None) or (isinstance(b, dict) and b.get("id")) or ""
        weight = SEVERITY_WEIGHT.get(sev, 5) * (conf / 100.0)
        behavior_raw += weight
        if sev == "critical":
            critical_count += 1
        elif sev == "high":
            high_count += 1
        top_signals.append({"id": bid, "name": name, "severity": sev,
                            "confidence": conf, "weight": round(weight, 1)})
    top_signals.sort(key=lambda s: -s["weight"])
    behavior_score = _bucket(behavior_raw)

    # IOC score — external endpoints and threat-intel hits weigh most
    ext_urls  = int(ioc_stats.get("external_urls", 0) or 0)
    ext_ips   = int(ioc_stats.get("external_ips", 0) or 0)
    ti_hits   = int(ioc_stats.get("ti_hits", 0) or 0)
    file_hashes = int(ioc_stats.get("hashes", 0) or 0)
    ioc_raw = ext_urls * 12 + ext_ips * 12 + ti_hits * 25 + file_hashes * 5
    ioc_score = _bucket(ioc_raw)

    # Obfuscation score — encoded command + decoder depth + reconstruction tricks
    ob_layers = int(ioc_stats.get("decoder_layers", 0) or 0)
    ob_raw = 0
    if encoded_present:
        ob_raw += 20
    ob_raw += min(30, ob_layers * 8)
    # Any string reconstruction / char-array / decompression
    reconstruction_ids = {"string_reconstruction", "char_array_join",
                          "payload_decompression", "payload_decode"}
    if any((getattr(b, "id", None) or (isinstance(b, dict) and b.get("id"))) in reconstruction_ids
           for b in behaviors):
        ob_raw += 25
    obfuscation_score = _bucket(ob_raw)

    # Composite risk score
    composite = int(round(0.55 * behavior_score + 0.25 * ioc_score + 0.20 * obfuscation_score))
    # If we have a critical behavior, floor the risk at 75 (malicious band)
    if critical_count > 0:
        composite = max(composite, 75)
    if high_count >= 2:
        composite = max(composite, 55)
    risk_score = _bucket(composite)

    # Verdict banding
    if risk_score >= 75:
        verdict = "malicious"
    elif risk_score >= 40:
        verdict = "suspicious"
    elif risk_score >= 15 or encoded_present:
        verdict = "needs_review" if risk_score >= 15 else "informational"
    elif risk_score >= 1:
        verdict = "informational"
    else:
        verdict = "benign"

    # Analyst rationale
    rationale: list[str] = []
    if behaviors:
        rationale.append(
            f"Behavior score {behavior_score}/100 driven by "
            f"{len(behaviors)} tag(s) — "
            f"{critical_count} critical, {high_count} high.")
    else:
        rationale.append("No behavior tags emitted from the AST.")
    if ext_urls or ext_ips:
        rationale.append(
            f"IOC score {ioc_score}/100 — {ext_urls} external URL(s), "
            f"{ext_ips} external IP(s), {ti_hits} threat-intel hit(s).")
    else:
        rationale.append("IOC score is low — no external network endpoints observed.")
    if encoded_present or ob_layers or obfuscation_score:
        rationale.append(
            f"Obfuscation score {obfuscation_score}/100 — "
            f"{'EncodedCommand present' if encoded_present else 'no encoded command'}, "
            f"{ob_layers} decoder layer(s).")
    rationale.append(f"Composite risk {risk_score}/100 → verdict: {verdict}.")

    # Confidence — how many decoder steps ended in `applied`
    if decode_trace_steps:
        applied = sum(1 for s in decode_trace_steps if s.get("status") == "applied")
        conf = int(round(60 + 40 * applied / max(1, len(decode_trace_steps))))
    else:
        conf = 50 + min(45, len(behaviors) * 10)
    conf = max(50, min(99, conf))

    return VerdictBreakdown(
        verdict=verdict,
        risk_score=risk_score,
        behavior_score=behavior_score,
        ioc_score=ioc_score,
        obfuscation_score=obfuscation_score,
        confidence=conf,
        rationale=rationale,
        top_signals=top_signals[:8],
    )
