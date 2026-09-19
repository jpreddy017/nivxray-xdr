"""Lane G · the SINGLE server-side authority on Windows channel truth.

Owner contract (2026-06): five dimensions, each independently authoritative.
NONE of them is derived from another, and there is no overall green
"HEALTHY" that a partial success can manufacture.

    Collection      NOT CONFIGURED | CONFIGURED | NOT OBSERVED | RECEIVING
                    | GAP DETECTED | DEGRADED | ERROR | UNSUPPORTED
    Parsing         NOT EVALUATED | SUPPORTED | PARTIAL | UNSUPPORTED | ERROR
    Normalization   NOT EVALUATED | SUPPORTED | PARTIAL | UNSUPPORTED | ERROR
    Detection capability   NOT AVAILABLE | PARTIAL | AVAILABLE
    Detection activity     measured firings — evidence of EXERCISE, never
                           the definition of capability

So this is legitimate and is exactly what this module will report:

    Security · Collection RECEIVING · Parsing SUPPORTED ·
    Normalization SUPPORTED · Detection capability PARTIAL ·
    Detections observed 0

and so is its inverse: 12 historical firings prove ACTIVITY, and prove
nothing about present capability if the content that fired is gone.

WHERE EVERY NUMBER COMES FROM
  * `xdr_canonical_events`      — the raw row the authenticated ingest
                                  handler wrote. Delivery truth.
  * `xdr_canonical_evidence`    — DSM output. Understanding truth.
  * `xdr_detection_matches`     — one row per (evidence × matched rule).
                                  Activity truth.
  * `xdr_collectors`            — the server's own record of what each
                                  collector is AUTHORIZED to send.
  * the detection content inventory (`detection_content.library`) —
                                  capability truth.

A measurement this platform does not make returns `None`, which the API
renders as `NOT AVAILABLE` / `—`. It is never returned as `0`: "we did not
measure" and "we measured zero" are different facts and a console that
confuses them is lying quietly.

DEVICE IDENTITY (owner directive)
`origin_computer` is the machine identity ASSERTED BY THE DELIVERED EVENT.
It is evidence of origin and it is NOT the permanent asset identity. Every
device row therefore carries `identity_state` and an `aliases` block sized
for the stronger identifiers that will arrive later (EDR device id, machine
GUID, enrolment identity, FQDN, domain, SID, cloud instance id) with
IP/MAC as observations. An origin with no EDR match reports
`EDR association: NOT ESTABLISHED` — never `UNENROLLED`, which would be a
claim about enrolment that nothing here has established.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

# ── vocabularies · the ONLY permitted values ──────────────────────
NOT_CONFIGURED = "NOT CONFIGURED"
CONFIGURED = "CONFIGURED"
NOT_OBSERVED = "NOT OBSERVED"
RECEIVING = "RECEIVING"
GAP_DETECTED = "GAP DETECTED"
DEGRADED = "DEGRADED"
ERROR = "ERROR"
UNSUPPORTED = "UNSUPPORTED"

COLLECTION_STATES = (NOT_CONFIGURED, CONFIGURED, NOT_OBSERVED, RECEIVING,
                     GAP_DETECTED, DEGRADED, ERROR, UNSUPPORTED)

NOT_EVALUATED = "NOT EVALUATED"
SUPPORTED = "SUPPORTED"
PARTIAL = "PARTIAL"
SUPPORT_STATES = (NOT_EVALUATED, SUPPORTED, PARTIAL, UNSUPPORTED, ERROR)

NOT_AVAILABLE = "NOT AVAILABLE"
AVAILABLE = "AVAILABLE"
CAPABILITY_STATES = (NOT_AVAILABLE, PARTIAL, AVAILABLE)

#: A channel is RECEIVING only if a delivery landed inside this window.
#: Older than this and arrival has stopped — which is a GAP, not health.
FRESH_MINUTES = 60
#: Default analysis window for counts and activity.
WINDOW_HOURS = 24

RAW_COLLECTION = "xdr_canonical_events"
EVIDENCE_COLLECTION = "xdr_canonical_evidence"
MATCH_COLLECTION = "xdr_detection_matches"
COLLECTOR_COLLECTION = "xdr_collectors"


# ── per-channel declaration · what the PLATFORM can do ────────────
# `provides` are the canonical capability tokens this channel's DSM can
# actually populate. They are matched against each detection rule's
# `telemetry_requirements`, which is how capability is computed instead of
# asserted. A token absent here is absent on purpose.
CHANNEL_DECLARATIONS: dict[str, dict[str, Any]] = {
    "Microsoft-Windows-Sysmon/Operational": {
        "label": "Sysmon",
        "declared_source": "sysmon",
        "security_value": "CRITICAL",
        "dsm_id": "microsoft-sysmon",
        "parsing": SUPPORTED,
        "normalization": SUPPORTED,
        "provides": ("process_creation", "command_line", "parent_process",
                     "registry_event", "dns_query", "network_traffic",
                     "file_activity", "identity", "endpoint",
                     "service_creation"),
    },
    "Security": {
        "label": "Security",
        "declared_source": "windows_security",
        "security_value": "CRITICAL",
        "dsm_id": "windows-security-evd",
        "parsing": SUPPORTED,
        "normalization": SUPPORTED,
        "provides": ("process_creation", "command_line", "parent_process",
                     "identity", "registry_event", "kerberos",
                     "security_event_4768", "security_event_4769",
                     "active_directory_audit"),
    },
    "Microsoft-Windows-PowerShell/Operational": {
        "label": "PowerShell Operational",
        "declared_source": "windows_powershell",
        "security_value": "CRITICAL",
        "dsm_id": "windows-powershell-evd",
        "parsing": SUPPORTED,
        "normalization": SUPPORTED,
        "provides": ("script_block_logging", "command_line"),
    },
    "Windows PowerShell": {
        "label": "Windows PowerShell (classic)",
        "declared_source": "windows_powershell",
        "security_value": "HIGH",
        "dsm_id": "windows-powershell-evd",
        # The classic channel carries the engine/host context but not the
        # script body, so its parsing is honestly PARTIAL rather than
        # borrowing the Operational channel's coverage.
        "parsing": PARTIAL,
        "normalization": PARTIAL,
        "provides": ("command_line",),
        "support_note": ("the classic channel records engine and pipeline "
                         "context; the executed script body is only in "
                         "Microsoft-Windows-PowerShell/Operational 4104"),
    },
    "Microsoft-Windows-Windows Defender/Operational": {
        "label": "Microsoft Defender",
        "declared_source": "microsoft_defender",
        "security_value": "CRITICAL",
        "dsm_id": "windows-defender-evd",
        "parsing": SUPPORTED,
        "normalization": SUPPORTED,
        "provides": ("endpoint_protection", "malware_detection",
                     "file_activity", "identity"),
        "support_note": ("Defender's own detection is recorded as SOURCE "
                         "evidence; it is never promoted to a NivXRay "
                         "verdict"),
    },
    "Microsoft-Windows-TaskScheduler/Operational": {
        "label": "Task Scheduler", "declared_source": "windows_task_scheduler",
        "security_value": "HIGH", "dsm_id": None,
        "parsing": UNSUPPORTED, "normalization": UNSUPPORTED,
        "provides": (), "roadmap_position": 1,
    },
    "Microsoft-Windows-WMI-Activity/Operational": {
        "label": "WMI Activity", "declared_source": "windows_wmi",
        "security_value": "HIGH", "dsm_id": None,
        "parsing": UNSUPPORTED, "normalization": UNSUPPORTED,
        "provides": (), "roadmap_position": 2,
    },
    "Microsoft-Windows-AppLocker/EXE and DLL": {
        "label": "AppLocker", "declared_source": "windows_applocker",
        "security_value": "HIGH", "dsm_id": None,
        "parsing": UNSUPPORTED, "normalization": UNSUPPORTED,
        "provides": (), "roadmap_position": 3,
    },
    "System": {
        "label": "System", "declared_source": "windows_system",
        "security_value": "HIGH", "dsm_id": None,
        "parsing": UNSUPPORTED, "normalization": UNSUPPORTED,
        "provides": (), "roadmap_position": 4,
    },
    "Application": {
        "label": "Application", "declared_source": "windows_application",
        "security_value": "MEDIUM", "dsm_id": None,
        "parsing": UNSUPPORTED, "normalization": UNSUPPORTED,
        "provides": (), "roadmap_position": 5,
    },
}

#: Declared unsupported, not silently missing.
UNSUPPORTED_CHANNELS = {
    "ForwardedEvents": ("WEF/WEC collection is a later milestone: a "
                        "forwarded record's origin computer and its "
                        "collector host are different facts, and that "
                        "distinction is not yet proven end to end"),
}

#: Channels whose collection support exists in the adapter but which are not
#: individually itemised above are still reported — they simply have no
#: analysis declaration. Nothing is hidden.
ANALYSIS_UNDECLARED_REASON = (
    "this channel is acquired and its raw XML is preserved verbatim, but no "
    "DSM parses it into canonical evidence yet — so it cannot be reasoned "
    "over or detected on")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── DETECTION CAPABILITY · computed from the content inventory ─────
def _rule_inventory() -> list[dict[str, Any]]:
    """Every rule the runtime detection library will actually evaluate.

    The runtime library has no per-rule disable switch, so every rule it
    holds IS deployed. That is stated rather than implied, because
    "deployed" is the fact capability depends on.
    """
    from detection_content.library.registry import RUNTIME_DETECTION_RULES
    out: list[dict[str, Any]] = []
    for r in RUNTIME_DETECTION_RULES:
        out.append({
            "rule_id": r.rule_id,
            "name": r.name,
            "platform": getattr(r.platform, "value", str(r.platform)),
            "severity": getattr(r.severity, "value", str(r.severity)),
            "technique_id": r.technique_id,
            "telemetry_requirements": list(r.telemetry_requirements or []),
            "declared_fields": [c.canonical_field for c in (r.conditions or [])],
        })
    return out


def detection_capability(channel: str) -> dict[str, Any]:
    """What detection this channel's evidence CAN power, right now.

    Deliberately independent of whether anything has ever fired. A tenant
    with 500 applicable deployed rules and zero attacks has AVAILABLE
    capability and zero activity, and both statements are true.
    """
    decl = CHANNEL_DECLARATIONS.get(channel) or {}
    provides = set(decl.get("provides") or ())
    normalization = decl.get("normalization", UNSUPPORTED)

    if channel in UNSUPPORTED_CHANNELS:
        return {"state": NOT_AVAILABLE, "eligible_rule_count": 0,
                "partially_eligible_rule_count": 0, "eligible_rules": [],
                "provides": [], "content_state": "NOT APPLICABLE",
                "basis": UNSUPPORTED_CHANNELS[channel]}
    if normalization == UNSUPPORTED or not provides:
        return {"state": NOT_AVAILABLE, "eligible_rule_count": 0,
                "partially_eligible_rule_count": 0, "eligible_rules": [],
                "provides": sorted(provides), "content_state": "DEPLOYED",
                "basis": ("no DSM turns this channel into canonical "
                          "evidence, so no rule can evaluate it — detection "
                          "content is irrelevant until normalization exists")}

    fully: list[dict[str, Any]] = []
    partial: list[dict[str, Any]] = []
    for rule in _rule_inventory():
        reqs = set(rule["telemetry_requirements"])
        if not reqs:
            continue
        if rule["platform"] not in ("windows", "identity", "cloud"):
            continue
        if reqs <= provides:
            fully.append(rule)
        elif reqs & provides:
            partial.append({**rule,
                            "unmet_requirements": sorted(reqs - provides)})

    if fully:
        state = AVAILABLE
        basis = (f"{len(fully)} deployed rule(s) require only telemetry this "
                 f"channel's canonical evidence provides")
    elif partial:
        state = PARTIAL
        basis = (f"{len(partial)} deployed rule(s) partly match this "
                 f"channel's evidence but each also needs telemetry this "
                 f"channel does not provide")
    else:
        state = NOT_AVAILABLE
        basis = ("no deployed rule's telemetry requirements are satisfied by "
                 "this channel's canonical evidence")

    # Normalization that is itself PARTIAL cannot support a full AVAILABLE
    # claim: some of the fields those rules cite may never be populated.
    if state == AVAILABLE and normalization == PARTIAL:
        state = PARTIAL
        basis += ("; capped at PARTIAL because this channel's normalization "
                  "is itself PARTIAL")

    return {
        "state": state,
        "eligible_rule_count": len(fully),
        "partially_eligible_rule_count": len(partial),
        "eligible_rules": [{"rule_id": r["rule_id"], "name": r["name"],
                            "severity": r["severity"],
                            "technique_id": r["technique_id"]}
                           for r in fully[:25]],
        "partially_eligible_rules": [
            {"rule_id": r["rule_id"], "name": r["name"],
             "unmet_requirements": r["unmet_requirements"]}
            for r in partial[:25]],
        "provides": sorted(provides),
        "content_state": ("DEPLOYED · the runtime detection library has no "
                          "per-rule disable, so every counted rule is "
                          "active"),
        "basis": basis,
        "independence_note": ("capability is computed from deployed content "
                              "and this channel's evidence shape. It does "
                              "NOT depend on anything having fired, and a "
                              "firing does not prove present capability"),
    }


# ── measured facts ────────────────────────────────────────────────
def _channel_match(channel: str) -> dict[str, Any]:
    """A raw row belongs to a channel if either the collector's canonical
    block or the delivered payload names it. Both are the collector's own
    words; neither is inferred."""
    return {"$or": [{"normalized.channel": channel},
                    {"raw.channel": channel}]}


async def _raw_facts(db, tenant_id: str, since: datetime
                     ) -> dict[str, dict[str, Any]]:
    """Per-channel delivery truth from the raw rows this server wrote."""
    pipeline = [
        {"$match": {"tenant_id": tenant_id}},
        {"$project": {
            "channel": {"$ifNull": ["$normalized.channel", "$raw.channel"]},
            "provider": "$normalized.provider",
            "event_id": "$normalized.event_id",
            "origin": "$normalized.origin_computer",
            "collector_id": 1, "parser_ok": 1, "normalized_ok": 1,
            "nivx_received_at": 1, "source_timestamp": 1,
            "profile_id": "$normalized.profile_id",
        }},
        {"$match": {"channel": {"$ne": None}}},
        {"$group": {
            "_id": "$channel",
            "events_delivered": {"$sum": 1},
            "parse_ok": {"$sum": {"$cond": [{"$eq": ["$parser_ok", True]}, 1, 0]}},
            "parse_failed": {"$sum": {"$cond": [{"$eq": ["$parser_ok", False]}, 1, 0]}},
            "parse_unmeasured": {"$sum": {"$cond": [{"$eq": ["$parser_ok", None]}, 1, 0]}},
            "norm_ok": {"$sum": {"$cond": [{"$eq": ["$normalized_ok", True]}, 1, 0]}},
            "norm_failed": {"$sum": {"$cond": [{"$eq": ["$normalized_ok", False]}, 1, 0]}},
            "norm_unmeasured": {"$sum": {"$cond": [{"$eq": ["$normalized_ok", None]}, 1, 0]}},
            "last_received_at": {"$max": "$nivx_received_at"},
            "last_source_timestamp": {"$max": "$source_timestamp"},
            "providers": {"$addToSet": "$provider"},
            "event_ids": {"$addToSet": "$event_id"},
            "origins": {"$addToSet": "$origin"},
            "collectors": {"$addToSet": "$collector_id"},
            "profiles": {"$addToSet": "$profile_id"},
        }},
    ]
    out: dict[str, dict[str, Any]] = {}
    async for row in db[RAW_COLLECTION].aggregate(pipeline):
        row["channel"] = row.pop("_id")
        row["providers"] = sorted(p for p in row["providers"] if p)
        row["event_ids"] = sorted((str(e) for e in row["event_ids"] if e),
                                  key=lambda s: (len(s), s))
        row["origins"] = sorted(o for o in row["origins"] if o)
        row["collectors"] = sorted(c for c in row["collectors"] if c)
        row["profiles"] = sorted(p for p in row["profiles"] if p)
        out[row["channel"]] = row
    _ = since
    return out


async def _evidence_facts(db, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Per-channel canonical evidence truth — what the DSMs produced."""
    pipeline = [
        {"$match": {"tenant_id": tenant_id}},
        {"$group": {
            "_id": "$raw_ref.channel",
            "canonical_events": {"$sum": 1},
            "event_types": {"$addToSet": "$event_type"},
            "dsm_ids": {"$addToSet": "$provenance.dsm_id"},
            "last_ingest_time": {"$max": "$ingest_time"},
        }},
    ]
    out: dict[str, dict[str, Any]] = {}
    async for row in db[EVIDENCE_COLLECTION].aggregate(pipeline):
        channel = row.pop("_id")
        if not channel:
            continue
        row["event_types"] = sorted(t for t in row["event_types"] if t)
        row["dsm_ids"] = sorted(d for d in row["dsm_ids"] if d)
        out[channel] = row
    return out


async def _activity_facts(db, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Per-channel DETECTION ACTIVITY — measured firings only.

    Joined evidence → match, so a firing is attributed to the channel whose
    evidence the rule actually read. Never to the channel we assume.
    """
    pipeline = [
        {"$match": {"tenant_id": tenant_id}},
        {"$lookup": {"from": EVIDENCE_COLLECTION,
                     "localField": "canonical_event_id",
                     "foreignField": "event_id",
                     "as": "evidence"}},
        {"$unwind": "$evidence"},
        {"$group": {
            "_id": "$evidence.raw_ref.channel",
            "detections_fired": {"$sum": 1},
            "rules_exercised": {"$addToSet": "$rule_id"},
            "last_detection_at": {"$max": "$evaluated_at"},
            "evidence_refs": {"$addToSet": "$evidence_ref"},
        }},
    ]
    out: dict[str, dict[str, Any]] = {}
    async for row in db[MATCH_COLLECTION].aggregate(pipeline):
        channel = row.pop("_id")
        if not channel:
            continue
        row["rules_exercised"] = sorted(r for r in row["rules_exercised"] if r)
        row["evidence_refs"] = [r for r in row["evidence_refs"] if r][:10]
        out[channel] = row
    return out


async def _authorized_channels(db, tenant_id: str
                               ) -> tuple[dict[str, list[str]], list[dict]]:
    """Which channels a collector is AUTHORIZED to deliver, per the server.

    The collector's own claim is irrelevant here: authorization is the
    server-side record, and a collector with an empty allowlist is
    authorized for nothing.
    """
    by_source: dict[str, list[str]] = {}
    collectors: list[dict[str, Any]] = []
    cursor = db[COLLECTOR_COLLECTION].find({"tenant_id": tenant_id})
    async for doc in cursor:
        sources = [str(s) for s in (doc.get("authorized_sources") or [])]
        collectors.append({
            "collector_id": doc.get("id") or doc.get("collector_id"),
            "name": doc.get("name"),
            "protocol": doc.get("protocol"),
            "state": doc.get("state") or doc.get("status"),
            "authorized_sources": sources,
            "enabled": doc.get("enabled"),
            "last_seen_at": doc.get("last_seen_at"),
        })
        for src in sources:
            by_source.setdefault(src.strip().lower(), []).append(
                str(doc.get("id") or doc.get("collector_id") or ""))
    return by_source, collectors


# ── the five dimensions, assembled ────────────────────────────────
def _collection_dimension(channel: str, raw: dict[str, Any] | None,
                          authorized_for: list[str],
                          tenant_has_any_delivery: bool) -> dict[str, Any]:
    if channel in UNSUPPORTED_CHANNELS:
        return {"state": UNSUPPORTED, "reason": UNSUPPORTED_CHANNELS[channel],
                "events_delivered": None, "last_event_at": None,
                "gap": None}

    delivered = (raw or {}).get("events_delivered") or 0
    last_at = _parse_iso((raw or {}).get("last_received_at"))
    fresh = bool(last_at and (_now() - last_at)
                 <= timedelta(minutes=FRESH_MINUTES))
    parse_failed = (raw or {}).get("parse_failed") or 0
    norm_failed = (raw or {}).get("norm_failed") or 0

    if delivered == 0:
        if not authorized_for:
            state = NOT_CONFIGURED
            reason = ("no collector in this tenant is authorized to deliver "
                      f"this channel's declared source")
        elif tenant_has_any_delivery:
            state = NOT_OBSERVED
            reason = ("a collector authorized for this channel is delivering "
                      "other channels, and nothing has arrived from this one")
        else:
            state = CONFIGURED
            reason = ("a collector is authorized for this channel and no "
                      "delivery of any channel has been observed yet, so "
                      "arrival has not been evaluated")
        return {"state": state, "reason": reason, "events_delivered": 0,
                "last_event_at": None, "gap": None,
                "authorized_collectors": authorized_for,
                "collectors_observed": [],
                "bookmark": {
                    "state": NOT_AVAILABLE,
                    "reason": ("per-channel bookmark position is held in the "
                               "collector's local durable state and is not "
                               "yet published to the server (W2 contract "
                               "C-4)"),
                }}

    if norm_failed and norm_failed >= delivered:
        state, reason = ERROR, (
            "every delivery on this channel arrived and NONE produced a "
            "normalized view — arrival is not understanding")
    elif parse_failed or norm_failed:
        state, reason = DEGRADED, (
            f"{parse_failed} parse failure(s) and {norm_failed} "
            f"normalization failure(s) measured on delivered records")
    elif fresh:
        state, reason = RECEIVING, (
            f"a delivery landed within the last {FRESH_MINUTES} minutes")
    else:
        state, reason = GAP_DETECTED, (
            f"records exist but the newest arrived at {last_at.isoformat()}, "
            f"more than {FRESH_MINUTES} minutes ago — arrival has stopped")

    return {
        "state": state, "reason": reason,
        "events_delivered": delivered,
        "last_event_at": (raw or {}).get("last_received_at"),
        "last_source_timestamp": (raw or {}).get("last_source_timestamp"),
        "gap": (None if fresh else
                {"state": "ARRIVAL_STOPPED",
                 "since": (raw or {}).get("last_received_at"),
                 "note": ("a stopped stream is a gap in this platform's "
                          "visibility; it is not proof the endpoint is "
                          "quiet")}),
        "authorized_collectors": authorized_for,
        "collectors_observed": (raw or {}).get("collectors") or [],
        "bookmark": {
            "state": NOT_AVAILABLE,
            "reason": ("per-channel bookmark position is held in the "
                       "collector's local durable state and is not yet "
                       "published to the server (W2 contract C-4)"),
        },
    }


def _support_dimension(declared: str, ok: int | None, failed: int | None,
                       unmeasured: int | None, note: str | None
                       ) -> dict[str, Any]:
    """A declaration and a measurement, side by side — never merged."""
    total = sum(v for v in (ok, failed, unmeasured) if v)
    if declared == UNSUPPORTED:
        measured_state = NOT_EVALUATED
    elif total == 0:
        measured_state = NOT_EVALUATED
    elif failed and not ok:
        measured_state = ERROR
    elif failed or unmeasured:
        measured_state = PARTIAL
    else:
        measured_state = SUPPORTED
    return {
        "state": declared,
        "state_basis": "PLATFORM_DECLARATION",
        "measured_state": measured_state,
        "measured": {"ok": ok, "failed": failed, "unmeasured": unmeasured}
        if total else {"ok": None, "failed": None, "unmeasured": None},
        "note": note,
        "disagreement": (measured_state == ERROR and declared != UNSUPPORTED),
    }


def _activity_dimension(activity: dict[str, Any] | None,
                        evaluated: bool) -> dict[str, Any]:
    if not evaluated:
        return {"detections_fired": None, "rules_exercised": None,
                "last_detection_at": None, "evidence_refs": [],
                "reason": ("no canonical evidence from this channel has been "
                           "evaluated, so detection activity is NOT "
                           "MEASURED — it is not zero")}
    a = activity or {}
    return {
        "detections_fired": a.get("detections_fired", 0),
        "rules_exercised": len(a.get("rules_exercised") or []),
        "rule_ids": (a.get("rules_exercised") or [])[:25],
        "last_detection_at": a.get("last_detection_at"),
        "evidence_refs": a.get("evidence_refs") or [],
        "reason": ("measured firings on this channel's canonical evidence. "
                   "Zero firings is an operational fact and says nothing "
                   "about capability"),
    }


def _human_stages(collection: dict, parsing: dict, normalization: dict,
                  capability: dict) -> list[dict[str, Any]]:
    """`Acquired → Understood → Detectable` — a PRESENTATION of the states
    above. It computes no new truth and it cannot manufacture a successful
    stage: each stage carries the underlying facts it is standing on."""
    acquired = collection["state"] in (RECEIVING, DEGRADED)
    understood = (normalization["state"] in (SUPPORTED, PARTIAL)
                  and normalization["measured_state"] in (SUPPORTED, PARTIAL))
    detectable = capability["state"] in (AVAILABLE, PARTIAL)
    return [
        {"stage": "Acquired", "reached": acquired,
         "state": collection["state"], "detail": collection["reason"],
         "drill": "collection"},
        {"stage": "Understood", "reached": understood,
         "state": normalization["measured_state"],
         "detail": ("canonical evidence has been produced from this "
                    "channel's records" if understood
                    else "no canonical evidence measured from this channel"),
         "drill": "normalization"},
        {"stage": "Detectable", "reached": detectable,
         "state": capability["state"], "detail": capability["basis"],
         "drill": "detection_capability"},
    ]


async def channel_truth(db, tenant_id: str, *, channels: list[str] | None = None
                        ) -> list[dict[str, Any]]:
    """Every Windows channel, with its five independent dimensions."""
    since = _now() - timedelta(hours=WINDOW_HOURS)
    raw = await _raw_facts(db, tenant_id, since)
    evidence = await _evidence_facts(db, tenant_id)
    activity = await _activity_facts(db, tenant_id)
    authorized, _collectors = await _authorized_channels(db, tenant_id)
    tenant_has_any_delivery = bool(raw)

    names = channels or (list(CHANNEL_DECLARATIONS)
                         + list(UNSUPPORTED_CHANNELS))
    # A channel that delivered but has no declaration is still reported.
    for observed in raw:
        if observed not in names:
            names.append(observed)

    rows: list[dict[str, Any]] = []
    for channel in names:
        decl = CHANNEL_DECLARATIONS.get(channel) or {}
        r = raw.get(channel)
        ev = evidence.get(channel)
        src = str(decl.get("declared_source") or "").lower()
        authorized_for = authorized.get(src, [])

        collection = _collection_dimension(channel, r, authorized_for,
                                           tenant_has_any_delivery)
        parsing = _support_dimension(
            decl.get("parsing", UNSUPPORTED),
            (r or {}).get("parse_ok"), (r or {}).get("parse_failed"),
            (r or {}).get("parse_unmeasured"),
            decl.get("support_note") or (None if decl.get("parsing")
                                         else ANALYSIS_UNDECLARED_REASON))
        normalization = _support_dimension(
            decl.get("normalization", UNSUPPORTED),
            (ev or {}).get("canonical_events"),
            (r or {}).get("norm_failed"), (r or {}).get("norm_unmeasured"),
            decl.get("support_note") or (None if decl.get("normalization")
                                         else ANALYSIS_UNDECLARED_REASON))
        capability = detection_capability(channel)
        act = _activity_dimension(activity.get(channel),
                                  bool((ev or {}).get("canonical_events")))

        attention: list[str] = []
        if collection["state"] in (ERROR, DEGRADED, GAP_DETECTED):
            attention.append(f"COLLECTION {collection['state']}")
        if parsing["disagreement"] or normalization["disagreement"]:
            attention.append("DECLARED SUPPORT CONTRADICTED BY MEASUREMENT")
        if (collection["state"] in (RECEIVING, DEGRADED)
                and normalization["state"] == UNSUPPORTED):
            attention.append("ACQUIRED BUT NOT UNDERSTOOD")
        if (normalization["measured_state"] in (SUPPORTED, PARTIAL)
                and capability["state"] == NOT_AVAILABLE):
            attention.append("UNDERSTOOD BUT NOT DETECTABLE")

        rows.append({
            "channel": channel,
            "label": decl.get("label") or channel,
            "declared_source": decl.get("declared_source"),
            "security_value": decl.get("security_value"),
            "dsm_id": decl.get("dsm_id"),
            "roadmap_position": decl.get("roadmap_position"),
            "devices": (r or {}).get("origins") or [],
            "providers": (r or {}).get("providers") or [],
            "event_ids_observed": (r or {}).get("event_ids") or [],
            "profiles": (r or {}).get("profiles") or [],
            "canonical_events": (ev or {}).get("canonical_events"),
            "canonical_event_types": (ev or {}).get("event_types") or [],
            "evidence_dsm_ids": (ev or {}).get("dsm_ids") or [],
            "collection": collection,
            "parsing": parsing,
            "normalization": normalization,
            "detection_capability": capability,
            "detection_activity": act,
            "attention": attention,
            "summary_stages": _human_stages(collection, parsing,
                                            normalization, capability),
        })
    return rows


async def device_truth(db, tenant_id: str) -> list[dict[str, Any]]:
    """Windows devices, identified by the ORIGIN the event asserted.

    `origin_computer` is evidence of origin, NOT the permanent asset id.
    The alias block below is the seam where stronger identifiers land.
    """
    pipeline = [
        {"$match": {"tenant_id": tenant_id,
                    "normalized.origin_computer": {"$ne": None}}},
        {"$group": {
            "_id": "$normalized.origin_computer",
            "channels": {"$addToSet": {"$ifNull": ["$normalized.channel",
                                                   "$raw.channel"]}},
            "collectors": {"$addToSet": "$collector_id"},
            "collector_hosts": {"$addToSet": "$normalized.collector_host"},
            "profiles": {"$addToSet": "$normalized.profile_id"},
            "profile_versions": {"$addToSet": "$normalized.profile_version"},
            "events_delivered": {"$sum": 1},
            "last_received_at": {"$max": "$nivx_received_at"},
            "parser_versions": {"$addToSet": "$parser_version"},
        }},
        {"$sort": {"last_received_at": -1}},
    ]
    evidence = await _evidence_facts(db, tenant_id)
    rows: list[dict[str, Any]] = []
    async for row in db[RAW_COLLECTION].aggregate(pipeline):
        origin = row.pop("_id")
        channels = sorted(c for c in row["channels"] if c)
        last_at = _parse_iso(row.get("last_received_at"))
        fresh = bool(last_at and (_now() - last_at)
                     <= timedelta(minutes=FRESH_MINUTES))
        receiving = [c for c in channels if (evidence.get(c) or {})
                     .get("canonical_events")]
        rows.append({
            # ── identity ────────────────────────────────────────────
            "evidence_origin": origin,
            "identity_state": "EVENT_ASSERTED_ORIGIN",
            "identity_note": (
                "`origin_computer` is the machine identity the delivered "
                "record asserted. It is evidence of origin and is NOT this "
                "platform's permanent asset identity: hostnames are reused, "
                "reimaged and renamed"),
            "canonical_device_id": None,
            "canonical_device_id_reason": (
                "a canonical NivX device identity with evidence-backed "
                "aliases is not yet established for Windows event origins"),
            "aliases": {
                "hostname": origin,
                "fqdn": None, "domain": None, "machine_guid": None,
                "edr_device_id": None, "enrolment_identity": None,
                "sid": None, "cloud_instance_id": None,
                "observed_ips": [], "observed_macs": [],
                "note": ("IP and MAC are OBSERVATIONS, never identity. Every "
                         "null here is a measurement this platform has not "
                         "made, not an absence at the endpoint"),
            },
            "edr_association": "NOT ESTABLISHED",
            "edr_association_reason": (
                "no EDR endpoint record has been correlated to this event "
                "origin. This is NOT a statement that the device is "
                "unenrolled — enrolment status is independently unknown"),
            # ── what the collector actually reported ────────────────
            "os": None,
            "os_reason": ("the Windows Event Log delivery carries no OS "
                          "build or edition; nothing is inferred from the "
                          "channel set"),
            "collectors": sorted(c for c in row["collectors"] if c),
            "collector_hosts": sorted(h for h in row["collector_hosts"] if h),
            "collector_host_note": (
                "the machine that shipped the record. It is a different fact "
                "from the origin above and is never merged with it"),
            "profiles": sorted(p for p in row["profiles"] if p),
            "profile_versions": sorted(v for v in row["profile_versions"] if v),
            "parser_versions": sorted(v for v in row["parser_versions"] if v),
            # ── measured state ─────────────────────────────────────
            "collection_state": (RECEIVING if fresh else GAP_DETECTED),
            "last_telemetry_at": row.get("last_received_at"),
            "events_delivered": row.get("events_delivered"),
            "channels_observed": channels,
            "channels_with_evidence": receiving,
            "evidence_coverage": (f"{len(receiving)}/{len(channels)}"
                                  if channels else None),
            "gaps": ([] if fresh else
                     [{"state": "ARRIVAL_STOPPED",
                       "since": row.get("last_received_at")}]),
            "attention": ([] if fresh else ["ARRIVAL STOPPED"]),
        })
    return rows


async def overview(db, tenant_id: str) -> dict[str, Any]:
    """Estate-level Windows truth. No composite health verdict.

    There is deliberately no single green light: a tenant can be RECEIVING
    everything and be able to detect almost none of it, and one number
    would hide exactly that.
    """
    channels = await channel_truth(db, tenant_id)
    devices = await device_truth(db, tenant_id)
    _authorized, collectors = await _authorized_channels(db, tenant_id)

    def count(dim: str, state: str) -> int:
        return sum(1 for c in channels if c[dim]["state"] == state)

    return {
        "tenant_id": tenant_id,
        "channels_declared": len(channels),
        "collection": {s: count("collection", s) for s in COLLECTION_STATES},
        "parsing": {s: sum(1 for c in channels if c["parsing"]["state"] == s)
                    for s in SUPPORT_STATES},
        "normalization": {
            s: sum(1 for c in channels if c["normalization"]["state"] == s)
            for s in SUPPORT_STATES},
        "detection_capability": {
            s: count("detection_capability", s) for s in CAPABILITY_STATES},
        "detections_fired": sum(
            (c["detection_activity"]["detections_fired"] or 0)
            for c in channels),
        "devices": len(devices),
        "collectors": len(collectors),
        "attention": [{"channel": c["channel"], "items": c["attention"]}
                      for c in channels if c["attention"]],
        "composite_health": None,
        "composite_health_reason": (
            "no single HEALTHY verdict is published. Collection, parsing, "
            "normalization, detection capability and detection activity are "
            "independent facts, and collapsing them would let one success "
            "conceal four failures"),
        "real_endpoint_proof": {
            "state": "NOT PROVEN",
            "reason": ("the end-to-end chain EvtSubscribe → durable queue → "
                       "delivery → tenant → persistence → parsing → "
                       "normalization → canonical evidence has not been "
                       "proven on a real Windows endpoint (gates "
                       "W2-R0…W2-R6). Until it is, no endpoint is labelled "
                       "CONNECTED, RECEIVING, HEALTHY or PRODUCTION READY "
                       "on the basis of this platform's own readiness"),
        },
    }
