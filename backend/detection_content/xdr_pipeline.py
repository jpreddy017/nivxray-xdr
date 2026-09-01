"""
P0.3 · DSM + Snort Parser + Snort Normalizer + Canonical Evidence
+ Sigma Detection (Round 10 unblock).

Boundaries preserved (Round 10 §36):
  DSM        = vendor/product/source semantics + parser selection
  Parser     = source-format interpretation
  Normalizer = canonical schema mapping
  Detection  = existing P0.2e Sigma harness (no new engine)
"""
from __future__ import annotations
import re, uuid
from datetime import datetime, timezone
from typing import Any

from .sigma_strict import strict_parse
from .nivxray_native_sigma import evaluate as nx_evaluate
from .xdr_iue import understand as iue_understand
from .xdr_ice import correlate as ice_correlate
from .xdr_veee import compute_verdict as veee_compute
from .xdr_incident import materialise_incident
from .xdr_investigation import project_investigation
from .xdr_response_fabric import orchestrate as response_orchestrate
from .xdr_closed_loop import recompute as closed_loop_recompute
from .xdr_framework_mapping import resolve_mappings as framework_resolve


# ── DSM Registry ────────────────────────────────────────────────

class SnortEveDSM:
    id       = "snort-eve"
    vendor   = "Snort"
    product  = "Snort / Suricata EVE"
    version  = "1"
    source_type = "NETWORK_IDS"

    def supports(self, ev: dict) -> bool:
        if not isinstance(ev, dict): return False
        # Suricata-EVE alerts carry event_type and an alert sub-object.
        return "event_type" in ev and "src_ip" in ev

    def select_parser(self): return SnortEveParser()
    def select_normalizer(self): return SnortNormalizer()

    def identity(self) -> dict:
        return {"id": self.id, "vendor": self.vendor,
                    "product": self.product, "version": self.version,
                    "source_type": self.source_type}


class DSMRegistry:
    def __init__(self):
        self._dsms: list = [SnortEveDSM()]

    def resolve(self, ev: dict):
        for d in self._dsms:
            if d.supports(ev): return d
        return None

    def list(self):
        return [d.identity() for d in self._dsms]


DSM_REGISTRY = DSMRegistry()


# ── Parser ──────────────────────────────────────────────────────

_IP_RX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$")


class ParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code; self.message = message
        super().__init__(f"{code}: {message}")


class SnortEveParser:
    id = "snort-eve-parser"

    def parse(self, ev: dict) -> dict:
        if not isinstance(ev, dict):
            raise ParserError("INVALID_JSON", "event is not a JSON object")
        for k in ("event_type", "timestamp", "src_ip", "dest_ip"):
            if k not in ev:
                raise ParserError("MISSING_REQUIRED_FIELD",
                                        f"required field '{k}' missing")
        for k in ("src_ip", "dest_ip"):
            if not _IP_RX.match(str(ev[k])):
                raise ParserError("INVALID_IP",
                                        f"{k}={ev[k]!r} is not a valid IP")
        try:
            datetime.fromisoformat(str(ev["timestamp"]).replace("Z", "+00:00"))
        except Exception:
            raise ParserError("INVALID_TIMESTAMP", str(ev["timestamp"]))
        alert = ev.get("alert") or {}
        if ev["event_type"] == "alert" and "signature_id" not in alert:
            raise ParserError("INVALID_ALERT",
                                    "event_type=alert but alert.signature_id missing")
        return {
            "parser_id":   self.id,
            "raw":         ev,
            "event_type":  ev["event_type"],
            "timestamp":   ev["timestamp"],
            "src_ip":      ev["src_ip"],
            "src_port":    ev.get("src_port"),
            "dest_ip":     ev["dest_ip"],
            "dest_port":   ev.get("dest_port"),
            "proto":       ev.get("proto"),
            "alert":       alert,
        }


# ── Normalizer ──────────────────────────────────────────────────

class SnortNormalizer:
    id = "snort-normalizer"

    def normalize(self, parsed: dict, dsm_id: str,
                        collector_id: str, integration_id: str,
                        trace_id: str) -> dict:
        alert = parsed.get("alert") or {}
        return {
            "event_id":   str(uuid.uuid4()),
            "event_type": "network_alert",
            "timestamp":  parsed["timestamp"],
            "source": {
                "vendor":  "Snort",
                "product": "Snort / Suricata",
            },
            "network": {
                "src": {"ip": parsed["src_ip"], "port": parsed.get("src_port")},
                "dst": {"ip": parsed["dest_ip"], "port": parsed.get("dest_port")},
                "protocol": parsed.get("proto"),
            },
            "security": {
                "signature": {
                    "id":   alert.get("signature_id"),
                    "name": alert.get("signature"),
                },
                "category": alert.get("category"),
                "severity": alert.get("severity"),
            },
            "raw_ref": parsed["raw"],
            "provenance": {
                "trace_id":         trace_id,
                "integration_id":   integration_id,
                "collector_id":     collector_id,
                "dsm_id":           dsm_id,
                "parser_id":        SnortEveParser.id,
                "normalizer_id":    SnortNormalizer.id,
            },
        }


# ── Detection via P0.2e harness ──────────────────────────────────

# One deterministic Sigma rule that matches the golden signature.
_GOLDEN_RULE = """
title: Snort golden alert
id: 00000000-0000-0000-0000-9999abcdef99
logsource: {product: snort, category: network_alert}
detection:
    selection:
        security_signature_id: 2027865
    condition: selection
"""

def evaluate_detection(canonical: dict) -> dict:
    """
    Run the golden rule against the canonical evidence.  Uses the same
    Sigma evaluator proven in Round 6 (P0.2e).
    """
    parsed = strict_parse(_GOLDEN_RULE)
    if parsed.status != "PARSED":
        return {"status": "EXECUTION_FAILED",
                    "error": parsed.error_message}
    # Flatten the canonical fields the rule references
    sec = (canonical.get("security") or {}).get("signature") or {}
    ev_flat = {"security_signature_id": sec.get("id")}
    try:
        matched = bool(nx_evaluate(parsed.rule, ev_flat))
    except Exception as e:
        return {"status": "EXECUTION_FAILED",
                    "error_type": type(e).__name__,
                    "error": str(e)}
    return {
        "status":       "RULE_MATCH" if matched else "RULE_NO_MATCH",
        "rule_id":      "00000000-0000-0000-0000-9999abcdef99",
        "engine_id":    "nivxray::detection_content::nivxray_native_sigma",
        "matched":      matched,
        "execution_id": str(uuid.uuid4()),
    }


# ── Persistence + full pipeline runner ──────────────────────────

CANONICAL_COLLECTION = "xdr_canonical_evidence"


async def process_event_through_pipeline(db, raw_event: dict,
                                                       trace_id: str,
                                                       integration_id: str,
                                                       collector_id: str) -> dict:
    """
    Drive one raw event through DSM → Parser → Normalizer →
    Canonical Evidence → Sigma Detection.  Halts honestly at first
    failure with the exact reason recorded.
    """
    stages: list[dict] = []
    def _s(name, status, **detail):
        stages.append({"stage": name, "status": status, **detail})

    dsm = DSM_REGISTRY.resolve(raw_event)
    if not dsm:
        _s("dsm", "BLOCKED", reason="no DSM in registry supports this event")
        return {"stages": stages, "blocker": "dsm"}
    _s("dsm", "EXECUTED", dsm_id=dsm.id, vendor=dsm.vendor,
                product=dsm.product)

    parser = dsm.select_parser()
    try:
        parsed = parser.parse(raw_event)
    except ParserError as pe:
        _s("parser", "FAILED", code=pe.code, error=pe.message,
                    parser_id=parser.id)
        return {"stages": stages, "blocker": "parser"}
    _s("parser", "EXECUTED", parser_id=parser.id,
                fields=len(parsed))

    normalizer = dsm.select_normalizer()
    canonical = normalizer.normalize(
        parsed, dsm.id, collector_id, integration_id, trace_id)
    _s("normalizer", "EXECUTED", normalizer_id=normalizer.id)

    await db[CANONICAL_COLLECTION].insert_one(dict(canonical))
    _s("canonical_evidence", "EXECUTED",
                event_id=canonical["event_id"],
                collection=CANONICAL_COLLECTION)
    _s("ssot", "EXECUTED", note="canonical evidence persisted")

    # ── Detection first (needed by IUE for capability_tags) ──────
    detection = evaluate_detection(canonical)
    if detection.get("status") == "EXECUTION_FAILED":
        _s("detection", "FAILED", detection_error=detection.get("error"))
        return {"stages": stages, "blocker": "detection",
                    "canonical": canonical}
    _s("detection", "EXECUTED", detection_status=detection.get("status"),
            matched=detection.get("matched"),
            engine_id=detection.get("engine_id"),
            rule_id=detection.get("rule_id"))

    # ── Round 11 · IUE (understanding) ──────────────────────────
    iue = iue_understand(canonical, detection)
    _s("iue", "EXECUTED",
            iue_id=iue["iue_id"],
            entities=len(iue["entities"]),
            capability_tags=iue["capability_tags"],
            severity_hint=iue["severity_hint"],
            confidence=iue["confidence"],
            engine_id=iue["engine_id"])

    # ── Round 11 · ICE (correlation) ────────────────────────────
    ice = await ice_correlate(db, canonical, iue, trace_id)
    _s("correlation", "EXECUTED",
            state=ice["state"],
            rules_evaluated=ice["rules_evaluated"],
            matches=len(ice.get("matches") or []),
            engine_id=ice["engine_id"])

    # ── Round 11 · VEEE (verdict) ───────────────────────────────
    verdict = veee_compute(canonical, detection, iue, ice)
    _s("verdict", "EXECUTED",
            label=verdict["label"],
            score=verdict["score"],
            engine_id=verdict["engine_id"],
            reason=verdict["reason"])

    # ── Round 11 · Incident (gated materialisation) ─────────────
    incident = await materialise_incident(
        db, canonical, iue, ice, detection, verdict, trace_id)
    if incident.get("created"):
        _s("incident", "EXECUTED",
                incident_id=incident["incident_id"],
                priority=incident["priority"],
                state=incident["state"],
                engine_id=incident["engine_id"])
    else:
        _s("incident", "NOT_CREATED",
                reason=incident.get("reason"),
                engine_id=incident.get("engine_id"))

    # Investigation Fabric — Round 12 · P0.6 · projection over
    # existing evidence + provenance (§37: no second engine).
    investigation = None
    response = None
    loop = None
    framework = None
    if incident.get("created"):
        investigation = await project_investigation(
            db, incident["incident_id"])
        _s("investigation", "EXECUTED",
                incident_id=incident["incident_id"],
                lanes_ready=investigation["lanes_ready"],
                lanes_total=investigation["lanes_total"],
                engine_id=investigation["engine_id"])

        # Response Fabric — Round 13 · P0.7 · Context → Recommendation
        # → Decision → Approval → Executor (with real OSINT adapter).
        response = await response_orchestrate(db, incident["incident_id"])
        decision  = (response.get("decision") or {})
        execution = (response.get("execution") or {})
        _s("response", "EXECUTED",
                decision=decision.get("decision"),
                required_action=decision.get("required_action"),
                execution_state=(execution or {}).get("state"),
                engine_id=response.get("engine_id"),
                recommendations=len(response.get("recommendations") or []))

        # Closed-Loop Recompute — Round 14 · P0.7.1 · Action result
        # becomes provenance-bearing observation, Investigation and
        # Recommendations recompute idempotently.
        loop = await closed_loop_recompute(db, incident["incident_id"])
        _s("closed_loop", "EXECUTED",
                engine_id=loop.get("engine_id"),
                changed=loop.get("changed"),
                new_observations=loop.get("new_observations"),
                created_recos=len((loop.get("recommendations") or {}).get("created") or []),
                superseded_recos=len((loop.get("recommendations") or {}).get("superseded") or []),
                decision=loop.get("decision"))

        # Framework Mapping Fabric — Round 15 · P0.7.2 · knowledge
        # mapping above the engines.  Pure Fabric composer.
        framework = await framework_resolve(db, incident["incident_id"])
        _s("framework_mapping", "EXECUTED",
                engine_id=framework.get("engine_id"),
                frameworks_active=[fw for fw, c in (framework.get("counts") or {}).items() if c > 0],
                counts=framework.get("counts") or {})

        # Round 16 · Threat Family classification — deterministic
        # projection over IUE / ICE / observations / VEEE.
        from detection_content.xdr_threat_family import classify as _cf
        family = await _cf(db, incident["incident_id"])
        _s("threat_family", "EXECUTED",
                family=family.get("family"),
                confidence=family.get("confidence"),
                score=family.get("score"),
                engine_id=family.get("engine_id"))
    else:
        _s("investigation", "NOT_CREATED",
                reason="upstream incident not created — no synthetic "
                        "investigation is fabricated (§37/§42)")
        _s("response", "NOT_CREATED",
                reason="upstream incident not created — response fabric "
                        "requires a materialised incident (§37)")
        _s("closed_loop", "NOT_CREATED",
                reason="upstream incident not created — closed-loop "
                        "recompute requires materialised evidence")
        _s("framework_mapping", "NOT_CREATED",
                reason="upstream incident not created — framework "
                        "mapping requires incident context")

    blocker = None if incident.get("created") else "incident_gate"
    return {"stages":         stages,
            "blocker":        blocker,
            "canonical":      canonical,
            "detection":      detection,
            "iue":            iue,
            "ice":            ice,
            "verdict":        verdict,
            "incident":       incident,
            "investigation":  investigation,
            "response":       response,
            "closed_loop":    loop if incident.get("created") else None,
            "framework":      framework if incident.get("created") else None}
