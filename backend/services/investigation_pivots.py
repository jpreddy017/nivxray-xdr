"""Investigation pivots · the SERVER is the authority.

Task 3A. Three questions are answered here, and only from facts the
platform already holds:

  1. **Telemetry & detection origin** — which collector / DSM / parser /
     canonical evidence / detection actually produced this incident.
  2. **IOC investigation** — for each observable the incident records, which
     providers can be used, and in which state.
  3. **Recommended investigation pivots** — deterministic, artifact-derived:
     `Reason → supporting artifact → available action`. No model.

## Provider capability model (owner decision, Task 3A)

A provider declares up to **two independent capabilities**:

  * ``AUTO_ENRICHMENT`` — server-side, event-driven enrichment of an
    observed IOC (target architecture: observed IOC → async enrichment →
    cache/dedupe → provider API → normalized intelligence + provenance).
    **No enrichment adapter is implemented in this build**, so every
    provider that *could* support it reports ``NOT_IMPLEMENTED``. That is a
    statement about NivXRay, not about the provider.
  * ``EXTERNAL_PIVOT`` — an analyst-initiated deep link into the provider's
    own verification surface. No credential is used and nothing is sent
    server-side.

A later enrichment adapter registers against the SAME provider entry; the
Investigation Pivots surface does not change shape when it does.

## Fail-closed rules

  * A native vendor console pivot is offered ONLY when the tenant's own
    integration record supplies a ``console_url`` AND a declared console
    path for the target, AND the incident carries the required identifier.
    NivXRay never guesses a vendor console route.
  * States are kept distinct and are never collapsed into "unavailable":
    ``AVAILABLE · NOT_CONFIGURED · NOT_AUTHORIZED ·
    REQUIRED_IDENTIFIER_MISSING · UNSUPPORTED · TEMPORARILY_UNAVAILABLE``.
  * Tenancy: every lookup is constrained to the incident's own tenant. The
    caller's authorization to address the incident is enforced by the
    route, not here.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import quote

# ── States (kept distinct — never collapsed) ─────────────────────────
AVAILABLE = "AVAILABLE"
NOT_CONFIGURED = "NOT_CONFIGURED"
NOT_AUTHORIZED = "NOT_AUTHORIZED"
IDENTIFIER_MISSING = "REQUIRED_IDENTIFIER_MISSING"
UNSUPPORTED = "UNSUPPORTED"
TEMPORARILY_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
NOT_RECORDED = "NOT_RECORDED"
OBSERVED = "OBSERVED"

# ── Capabilities ────────────────────────────────────────────────────
AUTO_ENRICHMENT = "AUTO_ENRICHMENT"
EXTERNAL_PIVOT = "EXTERNAL_PIVOT"

_ENRICHMENT_PENDING = {
    "supported": True,
    "state": NOT_IMPLEMENTED,
    "reason": "NivXRay has no enrichment adapter registered for this "
              "provider yet · event-driven enrichment is the declared "
              "target architecture, not a shipped capability",
}


def _enrichment_absent(reason: str) -> Dict[str, Any]:
    return {"supported": False, "state": UNSUPPORTED, "reason": reason}


def _pivot_open() -> Dict[str, Any]:
    return {
        "supported": True,
        "state": AVAILABLE,
        "reason": "analyst-initiated deep link · no credential is used and "
                  "NivXRay sends nothing on the analyst's behalf",
    }


# ── OSINT / verification providers ──────────────────────────────────
# `pivot_templates` are the providers' own documented lookup routes.
OSINT_PROVIDERS: List[Dict[str, Any]] = [
    {
        "key": "virustotal",
        "name": "VirusTotal",
        "vendor": "Google · VirusTotal",
        "classification": "EXTERNAL_OSINT",
        "requires_integration": None,
        "capabilities": {AUTO_ENRICHMENT: _ENRICHMENT_PENDING,
                         EXTERNAL_PIVOT: _pivot_open()},
        "pivot_templates": {
            "ip": "https://www.virustotal.com/gui/ip-address/{v}",
            "domain": "https://www.virustotal.com/gui/domain/{v}",
            "url": "https://www.virustotal.com/gui/search/{v}",
            "hash": "https://www.virustotal.com/gui/file/{v}",
        },
    },
    {
        "key": "cisco_talos",
        "name": "Cisco Talos",
        "vendor": "Cisco · Talos Reputation Center",
        "classification": "EXTERNAL_OSINT",
        "requires_integration": None,
        "capabilities": {
            AUTO_ENRICHMENT: _enrichment_absent(
                "the Talos Reputation Center publishes no documented "
                "programmatic lookup API for this use"),
            EXTERNAL_PIVOT: _pivot_open(),
        },
        "pivot_templates": {
            "ip": "https://talosintelligence.com/reputation_center/lookup?search={v}",
            "domain": "https://talosintelligence.com/reputation_center/lookup?search={v}",
        },
    },
    {
        "key": "abuseipdb",
        "name": "AbuseIPDB",
        "vendor": "AbuseIPDB",
        "classification": "EXTERNAL_OSINT",
        "requires_integration": None,
        "capabilities": {AUTO_ENRICHMENT: _ENRICHMENT_PENDING,
                         EXTERNAL_PIVOT: _pivot_open()},
        "pivot_templates": {"ip": "https://www.abuseipdb.com/check/{v}"},
    },
    {
        "key": "urlhaus",
        "name": "URLhaus",
        "vendor": "abuse.ch",
        "classification": "EXTERNAL_OSINT",
        "requires_integration": None,
        "capabilities": {AUTO_ENRICHMENT: _ENRICHMENT_PENDING,
                         EXTERNAL_PIVOT: _pivot_open()},
        "pivot_templates": {
            "url": "https://urlhaus.abuse.ch/browse.php?search={v}",
            "domain": "https://urlhaus.abuse.ch/browse.php?search={v}",
        },
    },
    {
        "key": "threatfox",
        "name": "ThreatFox",
        "vendor": "abuse.ch",
        "classification": "EXTERNAL_OSINT",
        "requires_integration": None,
        "capabilities": {AUTO_ENRICHMENT: _ENRICHMENT_PENDING,
                         EXTERNAL_PIVOT: _pivot_open()},
        "pivot_templates": {
            "ip": "https://threatfox.abuse.ch/browse.php?search=ioc%3A{v}",
            "domain": "https://threatfox.abuse.ch/browse.php?search=ioc%3A{v}",
            "url": "https://threatfox.abuse.ch/browse.php?search=ioc%3A{v}",
            "hash": "https://threatfox.abuse.ch/browse.php?search=ioc%3A{v}",
        },
    },
    {
        "key": "malwarebazaar",
        "name": "MalwareBazaar",
        "vendor": "abuse.ch",
        "classification": "EXTERNAL_OSINT",
        "requires_integration": None,
        "capabilities": {AUTO_ENRICHMENT: _ENRICHMENT_PENDING,
                         EXTERNAL_PIVOT: _pivot_open()},
        "pivot_templates": {
            "hash": "https://bazaar.abuse.ch/browse.php?search=sha256%3A{v}",
        },
    },
    {
        # Licensed Cisco surface — gated on the tenant's own integration.
        "key": "umbrella_investigate",
        "name": "Cisco Umbrella Investigate",
        "vendor": "Cisco",
        "classification": "EXTERNAL_LICENSED",
        "requires_integration": "umbrella",
        "capabilities": {AUTO_ENRICHMENT: _ENRICHMENT_PENDING,
                         EXTERNAL_PIVOT: _pivot_open()},
        "pivot_templates": {
            "domain": "https://investigate.umbrella.com/domain-view/name/{v}/view",
            "ip": "https://investigate.umbrella.com/ip-view/{v}",
        },
    },
]

# ── Native security-console targets (integration-gated) ─────────────
# `identifier` names the incident fact the console route needs, and
# `console_path_key` is the path the tenant's integration record must
# declare in `console_pivot_paths`. NivXRay never invents the path.
NATIVE_CONSOLES: List[Dict[str, Any]] = [
    {"vendor_key": "cortex", "name": "Palo Alto Cortex XDR",
     "identifier": "endpoint_id", "console_path_key": "endpoint"},
    {"vendor_key": "falcon", "name": "CrowdStrike Falcon",
     "identifier": "endpoint_id", "console_path_key": "endpoint"},
    {"vendor_key": "mde", "name": "Microsoft Defender XDR",
     "identifier": "endpoint_id", "console_path_key": "endpoint"},
    {"vendor_key": "sentinelone", "name": "SentinelOne Singularity",
     "identifier": "endpoint_id", "console_path_key": "endpoint"},
    {"vendor_key": "umbrella", "name": "Cisco Umbrella",
     "identifier": "domain", "console_path_key": "domain"},
    {"vendor_key": "cisco_secure_endpoint", "name": "Cisco Secure Endpoint",
     "identifier": "endpoint_id", "console_path_key": "endpoint"},
]

OBSERVABLE_KINDS = ("ip", "domain", "url", "hash")

_IOC_FIELDS = {
    "ip": ("ip", "ips"),
    "domain": ("domain", "domains"),
    "url": ("url", "urls"),
    "hash": ("hash", "hashes", "sha256"),
    "user": ("user", "users"),
    "host": ("host", "hosts"),
    "process": ("process", "processes"),
}


# ── Observables ─────────────────────────────────────────────────────
def observables_of(incident_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every observable the incident record itself carries, with the field
    it was read from. Nothing is inferred and nothing is de-duplicated
    across kinds."""
    iocs = incident_doc.get("iocs") or {}
    out: List[Dict[str, Any]] = []
    seen = set()
    for kind, fields in _IOC_FIELDS.items():
        for field in fields:
            values = iocs.get(field)
            if values is None:
                continue
            if not isinstance(values, list):
                values = [values]
            for v in values:
                if not isinstance(v, str) or not v.strip():
                    continue
                key = (kind, v)
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "kind": kind,
                    "value": v,
                    "source_field": f"iocs.{field}",
                    "externally_verifiable": kind in OBSERVABLE_KINDS,
                })
    return out


# ── Telemetry & detection origin ────────────────────────────────────
def telemetry_origin(incident_doc: Dict[str, Any], db) -> Dict[str, Any]:
    """Where this incident's belief physically came from.

    Every row is a recorded fact with the field it was read from. A stage
    the incident cannot prove is reported ``NOT_RECORDED`` with the reason —
    never drawn as complete.
    """
    tenant = incident_doc.get("tenant_id")
    pipeline = incident_doc.get("xdr_pipeline") or {}
    prov = pipeline.get("source_provenance") or {}
    sources: List[Dict[str, Any]] = []

    canonical_event_id = pipeline.get("canonical_event_id")
    evidence_doc = None
    if canonical_event_id:
        evidence_doc = db["xdr_canonical_evidence"].find_one(
            {"event_id": canonical_event_id}, {"_id": 0}) or None

    ev_prov = (evidence_doc or {}).get("provenance") or {}
    ev_src = (evidence_doc or {}).get("source") or {}

    # 1 · the producing security tool, as the canonical evidence recorded it
    if ev_src.get("vendor") or ev_src.get("product"):
        sources.append({
            "origin_kind": "PRODUCT",
            "state": OBSERVED,
            "label": " · ".join(
                [x for x in (ev_src.get("vendor"), ev_src.get("product")) if x]),
            "detail": f"recorded on canonical evidence {canonical_event_id}",
            "read_from": "xdr_canonical_evidence.source",
            "evidence_ref": canonical_event_id,
        })
    else:
        sources.append({
            "origin_kind": "PRODUCT",
            "state": NOT_RECORDED,
            "label": "Producing product",
            "detail": "no canonical evidence row records a source vendor or "
                      "product for this incident"
                      if canonical_event_id else
                      "this incident carries no canonical event id",
            "read_from": "xdr_canonical_evidence.source",
            "evidence_ref": canonical_event_id,
        })

    # 2 · the declared source model (DSM) + parser + normalizer
    dsm = ev_prov.get("dsm_id") or prov.get("dsm_id")
    sources.append({
        "origin_kind": "DSM",
        "state": OBSERVED if dsm else NOT_RECORDED,
        "label": dsm or "Declared source model",
        "detail": " · ".join([x for x in (
            f"parser {ev_prov.get('parser_id') or prov.get('parser_id')}"
            if (ev_prov.get("parser_id") or prov.get("parser_id")) else None,
            f"normalizer {ev_prov.get('normalizer_id') or prov.get('normalizer_id')}"
            if (ev_prov.get("normalizer_id") or prov.get("normalizer_id")) else None,
        ) if x]) or "no parser or normalizer identity is recorded",
        "read_from": "xdr_canonical_evidence.provenance / "
                     "xdr_pipeline.source_provenance",
        "evidence_ref": dsm,
    })

    # 3 · the collector that delivered it — with its own recorded counters
    collector_id = ev_prov.get("collector_id") or prov.get("collector_id")
    collector = None
    if collector_id and tenant:
        collector = db["xdr_collectors"].find_one(
            {"id": collector_id, "tenant_id": tenant}, {"_id": 0})
    if collector:
        sources.append({
            "origin_kind": "COLLECTOR",
            "state": OBSERVED,
            "label": f"{collector.get('name')} · {collector_id}",
            "detail": f"{collector.get('state') or 'STATE_NOT_RECORDED'} · "
                      f"received/parsed/normalized "
                      f"{collector.get('events_received')}/"
                      f"{collector.get('events_parsed')}/"
                      f"{collector.get('events_normalized')} · "
                      f"last event {collector.get('last_event_at') or 'NOT RECORDED'}",
            "read_from": "xdr_collectors",
            "evidence_ref": collector_id,
        })
    else:
        sources.append({
            "origin_kind": "COLLECTOR",
            "state": NOT_RECORDED,
            "label": collector_id or "Delivering collector",
            "detail": (f"collector {collector_id} is not registered in this "
                       f"tenant" if collector_id else
                       "no collector identity is recorded on this incident's "
                       "provenance"),
            "read_from": "xdr_collectors",
            "evidence_ref": collector_id,
        })

    # 4 · the detection that raised it
    rule_id = pipeline.get("detection_rule_id")
    sources.append({
        "origin_kind": "DETECTION",
        "state": OBSERVED if rule_id else NOT_RECORDED,
        "label": rule_id or "Raising detection",
        "detail": f"trace {pipeline.get('trace_id')}" if pipeline.get("trace_id")
                  else "no detection rule id is recorded on the pipeline record",
        "read_from": "xdr_pipeline.detection_rule_id",
        "evidence_ref": rule_id,
    })

    # 5 · the endpoint sensor identity, when the campaign recorded one
    campaign = incident_doc.get("endpoint_campaign") or {}
    endpoint_id = campaign.get("endpoint_id")
    sources.append({
        "origin_kind": "ENDPOINT_SENSOR",
        "state": OBSERVED if endpoint_id else NOT_RECORDED,
        "label": endpoint_id or "Endpoint sensor",
        "detail": (f"hostname {campaign.get('hostname') or 'NOT RECORDED'} · "
                   f"rules {', '.join(campaign.get('rule_ids') or []) or 'NOT RECORDED'}")
                  if endpoint_id else
                  "this incident records no endpoint campaign",
        "read_from": "endpoint_campaign.endpoint_id",
        "evidence_ref": endpoint_id,
    })

    observed = [s for s in sources if s["state"] == OBSERVED]
    return {
        "state": OBSERVED if observed else NOT_RECORDED,
        "observed_count": len(observed),
        "sources": sources,
        "integration_id": ev_prov.get("integration_id")
                          or prov.get("integration_id"),
        "note": "Origin is read from the incident's own pipeline record and "
                "the canonical evidence it cites. A stage with nothing "
                "recorded reads NOT RECORDED rather than being drawn as "
                "complete.",
    }


# ── Integrations (tenant-scoped, fail-closed) ───────────────────────
def _tenant_integrations(db, tenant: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """vendor_key → the tenant's own integration record. Fail closed: no
    tenant means no integration is visible."""
    if not tenant:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for doc in db["xdr_integrations"].find({"tenant_id": tenant}, {"_id": 0}):
        key = doc.get("vendor_key") or doc.get("vendor")
        if key and key not in out:
            out[key] = doc
    return out


def _console_pivot(target: Dict[str, Any], integ: Optional[Dict[str, Any]],
                   identifiers: Dict[str, Optional[str]]) -> Dict[str, Any]:
    """Resolve ONE native console target into a single honest state."""
    base = {
        "vendor_key": target["vendor_key"],
        "name": target["name"],
        "capability": EXTERNAL_PIVOT,
        "required_identifier": target["identifier"],
        "url": None,
        "integration_id": (integ or {}).get("integration_id"),
    }
    if not integ:
        return {**base, "state": NOT_CONFIGURED,
                "reason": "this tenant has no integration record for "
                          f"{target['name']}"}
    if integ.get("active") is False or integ.get("revoked_at"):
        return {**base, "state": NOT_AUTHORIZED,
                "reason": "the integration record for this tenant is revoked "
                          "or deactivated"}
    console_url = integ.get("console_url") or (integ.get("config") or {}).get("console_url")
    if not console_url:
        return {**base, "state": UNSUPPORTED,
                "reason": "the integration record declares no console URL · "
                          "NivXRay does not guess a vendor console address"}
    paths = integ.get("console_pivot_paths") or \
        (integ.get("config") or {}).get("console_pivot_paths") or {}
    path = paths.get(target["console_path_key"])
    if not path:
        return {**base, "state": UNSUPPORTED,
                "reason": "the integration record declares no console path for "
                          f"a {target['console_path_key']} · NivXRay does not "
                          "guess a vendor console route"}
    value = identifiers.get(target["identifier"])
    if not value:
        return {**base, "state": IDENTIFIER_MISSING,
                "reason": f"this incident records no {target['identifier']}, "
                          "so the console route cannot be addressed"}
    if integ.get("connected") is False:
        return {**base, "state": TEMPORARILY_UNAVAILABLE,
                "reason": "the last probe of this integration did not connect · "
                          + str(integ.get("connect_detail")
                                or "no probe detail recorded")}
    try:
        suffix = path.format(**{target["identifier"]: quote(value, safe="")})
    except (KeyError, IndexError):
        return {**base, "state": UNSUPPORTED,
                "reason": "the declared console path does not accept the "
                          f"{target['identifier']} placeholder"}
    return {**base, "state": AVAILABLE,
            "url": console_url.rstrip("/") + suffix,
            "reason": "the tenant's integration record declares this console "
                      "route and the incident carries the identifier"}


def provider_view(db, incident_doc: Dict[str, Any]) -> Dict[str, Any]:
    """The provider registry, resolved for THIS tenant."""
    tenant = incident_doc.get("tenant_id")
    integrations = _tenant_integrations(db, tenant)
    providers = []
    for p in OSINT_PROVIDERS:
        caps = {k: dict(v) for k, v in p["capabilities"].items()}
        req = p.get("requires_integration")
        if req and req not in integrations:
            caps[EXTERNAL_PIVOT] = {
                "supported": True, "state": NOT_CONFIGURED,
                "reason": "this provider is licensed and requires an "
                          f"integration record for {req} in this tenant",
            }
        providers.append({
            "key": p["key"], "name": p["name"], "vendor": p["vendor"],
            "classification": p["classification"],
            "requires_integration": req,
            "observables": sorted(p["pivot_templates"].keys()),
            "capabilities": caps,
        })
    return {"providers": providers,
            "tenant_integrations": sorted(integrations.keys())}


def _external_actions(observable: Dict[str, Any], providers: List[Dict[str, Any]]
                      ) -> List[Dict[str, Any]]:
    """External verification actions valid for ONE observable."""
    out = []
    by_key = {p["key"]: p for p in OSINT_PROVIDERS}
    for resolved in providers:
        p = by_key[resolved["key"]]
        template = p["pivot_templates"].get(observable["kind"])
        cap = resolved["capabilities"][EXTERNAL_PIVOT]
        if not template:
            continue
        if cap["state"] != AVAILABLE:
            out.append({"kind": "EXTERNAL", "provider": p["key"],
                        "label": p["name"], "url": None,
                        "state": cap["state"], "reason": cap["reason"]})
            continue
        out.append({
            "kind": "EXTERNAL", "provider": p["key"], "label": p["name"],
            "url": template.format(v=quote(observable["value"], safe="")),
            "state": AVAILABLE, "reason": cap["reason"],
            "egress": "the analyst opens this in a new tab · the observable "
                      "leaves NivXRay only on that click",
        })
    return out


def _internal_action(observable: Dict[str, Any], incident_id: str) -> Dict[str, Any]:
    qs = f"q={quote(observable['value'], safe='')}&incident_id={quote(incident_id or '', safe='')}"
    return {
        "kind": "INTERNAL", "provider": "nivx_intelligence",
        "label": "NivX Intelligence",
        "to": f"/xdr/intelligence/iocs?{qs}",
        "state": AVAILABLE,
        "reason": "NivXRay's own indicator record for this observable",
    }


def recommendations(db, incident_doc: Dict[str, Any],
                    resolved_providers: List[Dict[str, Any]],
                    consoles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deterministic, strictly artifact-derived.

    Every recommendation carries `reason → evidence → actions`, and an
    action is only offered when it is valid for that observable AND the
    provider capability is AVAILABLE. An empty list is a true statement
    about this incident.
    """
    incident_id = incident_doc.get("id") or ""
    canonical = [r.get("canonical_event_id")
                 for r in ((incident_doc.get("endpoint_campaign") or {})
                           .get("detections") or [])
                 if r.get("canonical_event_id")]
    pipeline_event = (incident_doc.get("xdr_pipeline") or {}).get("canonical_event_id")
    if pipeline_event:
        canonical = [pipeline_event] + [c for c in canonical if c != pipeline_event]

    out: List[Dict[str, Any]] = []
    for ob in observables_of(incident_doc):
        if not ob["externally_verifiable"]:
            continue
        actions = [_internal_action(ob, incident_id)]
        actions += [a for a in _external_actions(ob, resolved_providers)
                    if a["state"] == AVAILABLE]
        out.append({
            "id": f"verify-{ob['kind']}-{ob['value']}",
            "title": f"Verify {ob['kind']} reputation",
            "reason": f"{ob['value']} is recorded on this incident in "
                      f"{ob['source_field']}",
            "evidence": ([{"kind": "CANONICAL_EVENT", "ref": canonical[0]}]
                         if canonical else
                         [{"kind": "INCIDENT_FIELD", "ref": ob["source_field"]}]),
            "observable": {"kind": ob["kind"], "value": ob["value"]},
            "actions": actions,
        })

    # Endpoint recommendation — only when a native console can really serve it.
    available_consoles = [c for c in consoles if c["state"] == AVAILABLE]
    endpoint_id = (incident_doc.get("endpoint_campaign") or {}).get("endpoint_id")
    if endpoint_id and available_consoles:
        out.append({
            "id": f"native-endpoint-{endpoint_id}",
            "title": "Review this endpoint in its native console",
            "reason": f"the incident's endpoint campaign records {endpoint_id}",
            "evidence": [{"kind": "ENDPOINT_CAMPAIGN", "ref": endpoint_id}],
            "observable": {"kind": "endpoint", "value": endpoint_id},
            "actions": [{"kind": "NATIVE_CONSOLE", "provider": c["vendor_key"],
                         "label": c["name"], "url": c["url"],
                         "state": AVAILABLE, "reason": c["reason"]}
                        for c in available_consoles],
        })
    return out


def build_pivots(db, incident_doc: Dict[str, Any]) -> Dict[str, Any]:
    """The whole Investigation Pivots payload for one incident."""
    tenant = incident_doc.get("tenant_id")
    integrations = _tenant_integrations(db, tenant)
    identifiers = {
        "endpoint_id": (incident_doc.get("endpoint_campaign") or {}).get("endpoint_id"),
        "domain": next((o["value"] for o in observables_of(incident_doc)
                        if o["kind"] == "domain"), None),
    }
    consoles = [_console_pivot(t, integrations.get(t["vendor_key"]), identifiers)
                for t in NATIVE_CONSOLES]
    pv = provider_view(db, incident_doc)
    obs = []
    for ob in observables_of(incident_doc):
        obs.append({**ob,
                    "actions": ([_internal_action(ob, incident_doc.get("id") or "")]
                                + _external_actions(ob, pv["providers"]))
                    if ob["externally_verifiable"] else []})
    return {
        "incident_id": incident_doc.get("id"),
        "telemetry_origin": telemetry_origin(incident_doc, db),
        "observables": obs,
        "providers": pv["providers"],
        "tenant_integrations": pv["tenant_integrations"],
        "native_consoles": consoles,
        "recommendations": recommendations(db, incident_doc, pv["providers"], consoles),
        "capability_model": {
            AUTO_ENRICHMENT: "server-side event-driven enrichment of an "
                             "observed IOC · no adapter is implemented in "
                             "this build",
            EXTERNAL_PIVOT: "analyst-initiated deep link into the provider's "
                            "own verification surface",
        },
    }
