"""
P0.4 · Round 11 · XDR ICE (Investigation Correlation Engine)
────────────────────────────────────────────────────────────

**Boundary**:
  IUE tells us WHAT this evidence *is*.
  ICE tells us HOW this evidence *relates to other evidence*.

Round 11 scope is deliberately narrow (§35 · dependency order):
  * Consume IUE output for the current event.
  * Consult the ENABLED correlation-rule catalog stored in
    `xdr_correlation_rules` (already the SSOT — see
    `routers/xdr_correlation.py`).
  * Evaluate single-signal rules on this event and emit
    correlation-evidence records into `xdr_correlation_matches`.
  * Return a per-invocation summary with an honest state:
      MATCHED        — at least one rule matched
      NO_RULES_ENABLED — the enabled catalog is empty
      NO_MATCH       — rules exist but none matched this evidence

**HONEST STATE**: If there are zero enabled correlation rules the
engine reports `state=NO_RULES_ENABLED` and executed=0.  It never
manufactures a synthetic match to look busy.

Multi-signal / temporal / SEQUENCE evaluation remains the domain of
the existing stateful engine in `routers/xdr_correlation.py`; this
adapter deliberately restricts itself to what can be evaluated
deterministically on a single event to satisfy the Round 11
dependency order without duplicating the stateful engine.
"""
from __future__ import annotations
import re
import uuid
from datetime import datetime, timezone
from typing import Any


ICE_ENGINE_ID = "nivxray::xdr::ice"
ICE_ENGINE_VERSION = "1.0.0"

CORRELATION_RULES_COLLECTION   = "xdr_correlation_rules"
CORRELATION_MATCHES_COLLECTION = "xdr_correlation_matches"


def _get_field(signal: dict, key: str) -> Any:
    """Look up a field on the flattened signal, checking both top-
    level keys and the free-form ``fields`` bag (compat with the
    stateful engine's Signal model)."""
    if key in signal and signal[key] is not None:
        return signal[key]
    return (signal.get("fields") or {}).get(key)


def _scalar_match(actual: Any, expected: Any) -> bool:
    if isinstance(expected, str):
        if expected.startswith("contains:"):
            return expected[9:].lower() in str(actual).lower()
        if expected.startswith("endswith:"):
            return str(actual).lower().endswith(expected[9:].lower())
        if expected.startswith("startswith:"):
            return str(actual).lower().startswith(expected[11:].lower())
        if expected.startswith("regex:"):
            try:
                return re.search(expected[6:], str(actual)) is not None
            except re.error:
                return False
    return actual == expected


def _match_condition(cond: dict, signal: dict) -> bool:
    m = cond.get("match") or {}
    if not m:
        return False
    for k, expected in m.items():
        actual = _get_field(signal, k)
        if actual is None:
            return False
        if isinstance(expected, list):
            if not any(_scalar_match(actual, ev) for ev in expected):
                return False
        else:
            if not _scalar_match(actual, expected):
                return False
    return True


def _signal_from_canonical(canonical: dict, iue: dict) -> dict:
    """Flatten canonical + IUE into the Signal shape consumed by
    `xdr_correlation`.  Deterministic — no clock, no uuid."""
    net = canonical.get("network") or {}
    src = net.get("src") or {}
    dst = net.get("dst") or {}
    intel = canonical.get("decoded_intelligence") or {}
    iocs = intel.get("iocs") or {}
    sig = (canonical.get("security") or {}).get("signature") or {}
    fields = {
        "signature_id":   sig.get("id"),
        "signature_name": sig.get("name"),
        "protocol":       net.get("protocol"),
        "severity_hint":  iue.get("severity_hint"),
        "src_ip":         src.get("ip"),
        "dst_ip":         dst.get("ip"),
    }
    if isinstance(iocs, dict):
        ips = iocs.get("ips") or []
        if ips:
            fields["decoded_c2_ip"] = str(ips[0])
            fields["decoded_c2_ips"] = [str(ip) for ip in ips]
        urls = iocs.get("urls") or []
        if urls:
            fields["decoded_url"] = str(urls[0])
            fields["decoded_urls"] = [str(u) for u in urls]
    if intel.get("effective_payload"):
        fields["effective_command"] = intel["effective_payload"]
    sec_ctrl = intel.get("security_controls") or {}
    if sec_ctrl.get("tampering_detected"):
        fields["defense_evasion_tampering"] = True

    return {
        "signal_id":      f"sig_{canonical.get('event_id', '')}",
        "signal_kind":    "detection",
        "at":             canonical.get("timestamp"),
        "event_kind":     canonical.get("event_type"),
        "host_id":        src.get("ip"),           # network-alert host proxy
        "dst_ip":         dst.get("ip"),
        "source_event_id": canonical.get("event_id"),
        "detection_id":   sig.get("id"),
        "fields":         fields,
    }


async def correlate(db, canonical: dict, iue: dict, trace_id: str) -> dict:
    """
    Round 11 · XDR ICE entry point.

    Args:
      db:         motor async db (uses `xdr_correlation_rules` + `..._matches`).
      canonical:  Round 10 canonical evidence.
      iue:        Round 11 IUE output.
      trace_id:   pipeline trace id (mandatory for provenance).

    Returns a summary dict.  Persists match documents when applicable.
    """
    signal = _signal_from_canonical(canonical, iue)

    # Only ENABLED single-signal (EVENT_MATCH) rules are safe to
    # evaluate here.  Multi-signal windows live in the stateful
    # engine and are not re-implemented (§4 · no duplication).
    enabled_count = await db[CORRELATION_RULES_COLLECTION].count_documents(
        {"enabled": True}
    )
    if enabled_count == 0:
        return {
            "engine_id":      ICE_ENGINE_ID,
            "engine_version": ICE_ENGINE_VERSION,
            "state":          "NO_RULES_ENABLED",
            "rules_evaluated": 0,
            "matches":        [],
            "honesty_note":
                "xdr_correlation_rules has zero ENABLED rules — no "
                "correlation is fabricated.  Load rules via "
                "/api/xdr/correlation/rules to activate this stage.",
        }

    matches: list[dict] = []
    rules_evaluated = 0
    async for rule in db[CORRELATION_RULES_COLLECTION].find(
        {"enabled": True,
          "operators.type": "EVENT_MATCH"},
        {"_id": 0}
    ):
        rules_evaluated += 1
        conds = rule.get("conditions") or []
        # EVENT_MATCH requires every condition to match this signal.
        if conds and all(_match_condition(c, signal) for c in conds):
            match_id = f"cm_{uuid.uuid4().hex[:20]}"
            match_doc = {
                "match_id":         match_id,
                "rule_id":          rule.get("rule_id") or rule.get("id"),
                "rule_name":        rule.get("name"),
                "signal_id":        signal["signal_id"],
                "source_event_id":  signal["source_event_id"],
                "trace_id":         trace_id,
                "emitted_at":       datetime.now(timezone.utc).isoformat(),
                "evidence_level":   "CORRELATION_OBSERVED",
                "severity_hint":    rule.get("severity_hint")
                                        or iue.get("severity_hint"),
                "attack_techniques": rule.get("attack_techniques") or [],
                "engine_id":        ICE_ENGINE_ID,
            }
            await db[CORRELATION_MATCHES_COLLECTION].insert_one(dict(match_doc))
            matches.append(match_doc)

    return {
        "engine_id":      ICE_ENGINE_ID,
        "engine_version": ICE_ENGINE_VERSION,
        "state":          "MATCHED" if matches else "NO_MATCH",
        "rules_evaluated": rules_evaluated,
        "enabled_rules_total": enabled_count,
        "matches":        matches,
        "honesty_note":
            "ICE Round-11 evaluates single-signal EVENT_MATCH rules "
            "only.  Multi-signal / temporal correlation remains in "
            "routers/xdr_correlation.py (stateful, not duplicated).",
    }
