"""
P1.10a · XDR Spread Watchlist — an EVIDENCE / WATCH plane.

**This is not an engine.**  It stores, dedupes and counts; it emits
correlation *evidence* and stops.  ICE remains the correlation engine,
VEEE remains the scoring engine, and the existing incident gate remains
the sole authority on promotion.  Nothing here computes a verdict,
assigns a score, or creates an incident.

    live event
        │
        ├─ evidence-gated enrollment ──> xdr_spread_watchlist
        │
        └─ same indicator on a DIFFERENT REAL endpoint
                    │
                    ▼
            threshold crossed ──> xdr_correlation_matches (ICE plane)
                                            │
                                            ▼
                                      VEEE ──> existing gate

FROZEN honesty contract for this plane
──────────────────────────────────────
*  Spread is **not** lateral movement, **not** compromise of every
   endpoint, and **not** patient zero.  Spread is evidence that the
   same tracked indicator was observed across distinct REAL endpoint
   identities.  Say "observed across N endpoints", never "spread to".
*  Watchlist enrollment is **not** a malicious verdict.  It means the
   indicator is interesting enough to watch for recurrence.
*  Only a real endpoint identity counts.  A sighting whose host is
   unknown is RETAINED, displayed and provenance-preserving, but is
   marked ``endpoint_identity_state = UNKNOWN`` and can NEVER increase
   endpoint cardinality or establish spread.  Two unknown hosts are not
   two endpoints.  A source IP is NOT an endpoint identity.
*  Evidence progression continues past the VEEE correlation cap: the
   score is bounded by the existing VEEE policy, but ``endpoint_count``
   and the threshold ledger keep the truth that an indicator went from
   3 to 10 to 50 endpoints.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from services.die.preprocessor.command_normalizer import normalize_command

WATCHLIST_COLLECTION = "xdr_spread_watchlist"
SIGHTINGS_COLLECTION = "xdr_spread_sightings"
CORRELATION_MATCHES_COLLECTION = "xdr_correlation_matches"

PLANE_ID = "nivxray::xdr::spread_watchlist"
PLANE_VERSION = "1.0.0"

SPREAD_RULE_ID = "SPREAD-WATCH-001"
SPREAD_RULE_NAME = "Tracked indicator observed across distinct endpoints"

# Primary spread identity keys — owner-locked.  Source IP, username and
# hostname are deliberately ABSENT: they are context, not identity.
INDICATOR_TYPES = (
    "file_sha256",
    "file_sha1",
    "file_md5",
    "dest_ip",
    "domain",
    "process_identity",
    "cmdline_fingerprint",
)

# Distinct REAL endpoints -> status.  Evidence is emitted once per
# threshold, never per sighting.
THRESHOLDS: tuple[tuple[int, str], ...] = (
    (2,  "SPREAD_CONFIRMED"),
    (3,  "SPREAD_ESCALATING"),
    (5,  "SPREAD_SIGNIFICANT"),
    (10, "SPREAD_WIDESPREAD"),
)

HONESTY_NOTE = (
    "Indicator observed across distinct real endpoint identities. This is "
    "evidence of indicator recurrence, NOT a claim of lateral movement, "
    "compromise of every endpoint, or patient zero. Sightings without a "
    "real endpoint identity are retained but excluded from endpoint "
    "cardinality."
)

_MIN_VERDICT_SCORE = 25          # strictly above INCONCLUSIVE (0-24)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


# ── Endpoint identity ─────────────────────────────────────────────
def endpoint_identity(canonical: dict[str, Any]) -> tuple[str | None, str]:
    """Resolve a REAL endpoint identity, or declare it UNKNOWN.

    Accepts a hostname, or a `host_id` that is not merely an IP literal.
    A source IP is never accepted: an address is not an endpoint.
    """
    host = canonical.get("host") or {}
    hostname = str(host.get("hostname") or "").strip()
    if hostname and hostname.upper() != "UNKNOWN":
        return hostname.lower(), "OBSERVED"
    host_id = str(host.get("host_id") or "").strip()
    if host_id and host_id.upper() != "UNKNOWN" and not _is_ip(host_id):
        return host_id.lower(), "OBSERVED"
    return None, "UNKNOWN"


# ── Command-line fingerprint ──────────────────────────────────────
_VOLATILE: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}\b"), "<guid>"),
    (re.compile(r"\b[0-9a-f]{16,}\b"), "<hex>"),
    (re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"), "<blob>"),
)

# Any Windows path collapses to its basename, uniformly.  Per-directory
# rules (user profile, temp, downloads) are deliberately NOT used: they
# leave the surviving directory in the fingerprint, so the same tooling
# run from two different folders would split into two indicators.
_WIN_PATH = re.compile(r"(?:[a-z]:)?(?:\\[^\\\s\"']*)+", re.I)
_TRAILING_NUM = re.compile(r"\b\d{3,}\b")

# A shell wrapper is not the activity.  `powershell.exe <script>` and
# `powershell.exe -enc <base64 of the same script>` are the same tooling
# reuse, so the interpreter and its no-op switches are stripped before
# hashing.  The interpreter is not lost: `process_identity` tracks it as
# its own indicator.
_SHELL_BINARIES = frozenset({
    "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "cmd.exe", "cmd", "wscript.exe", "cscript.exe",
})
_SHELL_NOOP_SWITCHES = frozenset({
    "-nop", "-noprofile", "-nologo", "-noni", "-noninteractive",
    "-noexit", "-sta", "-mta", "-command", "-c", "-encodedcommand",
    "-enc", "-e", "-ec", "-en", "-f", "-file", "/c", "/k", "/q",
})
_SHELL_NOOP_PAIRS = {
    "-w": {"hidden", "h", "minimized", "normal", "maximized"},
    "-windowstyle": {"hidden", "h", "minimized", "normal", "maximized"},
    "-ep": {"bypass", "unrestricted", "remotesigned"},
    "-executionpolicy": {"bypass", "unrestricted", "remotesigned"},
}


def _strip_shell_wrapper(tokens: list[str]) -> list[str]:
    if not tokens or tokens[0] not in _SHELL_BINARIES:
        return tokens
    rest = tokens[1:]
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in _SHELL_NOOP_PAIRS:
            if i + 1 < len(rest) and rest[i + 1] in _SHELL_NOOP_PAIRS[tok]:
                i += 2
                continue
            i += 1
            continue
        if tok in _SHELL_NOOP_SWITCHES:
            i += 1
            continue
        break
    return rest[i:]


def _basename(match: re.Match[str]) -> str:
    return match.group(0).rsplit("\\", 1)[-1]


def cmdline_fingerprint(command_line: str) -> tuple[str, str] | None:
    """Return ``(fingerprint, normalized_form)`` or None.

    The RAW command line is deliberately NOT the spread key — that would
    turn every user or path variation into a separate indicator.  We
    reuse the existing DIE normalizer (which also peels PowerShell
    ``-EncodedCommand``, so the same tooling encoded differently
    fingerprints identically), then strip volatile tokens.
    """
    raw = (command_line or "").strip()
    if not raw:
        return None
    text = normalize_command(raw).lower()
    text = re.sub(r"[\"']", "", text)
    for pattern, repl in _VOLATILE:
        text = pattern.sub(repl, text)
    text = _WIN_PATH.sub(_basename, text)
    text = _TRAILING_NUM.sub("<n>", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = " ".join(_strip_shell_wrapper(text.split()))
    # A single token carries no more information than process_identity,
    # which is already tracked — do not duplicate it as an indicator.
    if len(text.split()) < 3:
        return None
    return _digest("cmdline", text)[:32], text


# ── Indicator extraction ──────────────────────────────────────────
def extract_indicators(canonical: dict[str, Any]) -> list[dict[str, Any]]:
    """Project the primary spread identity keys out of a canonical event.

    `match_basis` records WHY this value is an indicator of this type, so
    every downstream spread assertion can be audited back to the field
    it came from.
    """
    out: list[dict[str, Any]] = []
    proc = canonical.get("process") or {}
    fil = canonical.get("file") or {}
    net = canonical.get("network") or {}
    hashes = {**(fil.get("hashes") or {}), **(proc.get("hashes") or {})}

    for kind in ("sha256", "sha1", "md5"):
        value = str(hashes.get(kind) or "").strip().lower()
        if value:
            out.append({"indicator_type": f"file_{kind}",
                        "indicator_value": value,
                        "indicator_display": value,
                        "match_basis": f"file/process hash ({kind})"})

    dest = str(net.get("dest_ip") or "").strip()
    if dest and _is_ip(dest):
        addr = ipaddress.ip_address(dest)
        if not (addr.is_loopback or addr.is_unspecified):
            out.append({"indicator_type": "dest_ip",
                        "indicator_value": dest,
                        "indicator_display": dest,
                        "match_basis": "network.dest_ip",
                        "scope": "private" if addr.is_private else "public"})

    domain = str(net.get("dns_query") or "").strip().lower().rstrip(".")
    if domain and not _is_ip(domain):
        out.append({"indicator_type": "domain",
                    "indicator_value": domain,
                    "indicator_display": domain,
                    "match_basis": "network.dns_query"})

    proc_name = str(proc.get("name") or "").strip()
    if not proc_name:
        proc_name = str(proc.get("executable_path") or "").strip()
    proc_name = re.split(r"[\\/]", proc_name)[-1].lower() if proc_name else ""
    if proc_name:
        out.append({"indicator_type": "process_identity",
                    "indicator_value": proc_name,
                    "indicator_display": proc_name,
                    "match_basis": "process.name (basename, lowercased)"})

    fp = cmdline_fingerprint(str(proc.get("command_line") or ""))
    if fp:
        out.append({"indicator_type": "cmdline_fingerprint",
                    "indicator_value": fp[0],
                    "indicator_display": fp[1],
                    "match_basis": "normalized command-line fingerprint "
                                   "(DIE normalizer + volatile-token strip)"})
    return out


# ── Evidence-gated enrollment ─────────────────────────────────────
def enrollment_admitted(detection: dict[str, Any] | None,
                        verdict: dict[str, Any] | None
                        ) -> tuple[bool, str]:
    """Enrollment is evidence-gated: a real detection match, or a VEEE
    verdict strictly above INCONCLUSIVE.

    Admission is NOT a malicious verdict — it only means this indicator
    is interesting enough to watch for recurrence.
    """
    if detection and detection.get("matched"):
        return True, (f"detection matched "
                      f"{detection.get('rule_id') or 'rule'}")
    score = (verdict or {}).get("score")
    label = (verdict or {}).get("label")
    if isinstance(score, int) and score >= _MIN_VERDICT_SCORE:
        return True, f"verdict {label} score={score} above INCONCLUSIVE"
    return False, (f"not admitted: no detection match and verdict "
                   f"{label or 'NONE'} score={score if score is not None else 'NONE'} "
                   f"is not above INCONCLUSIVE (min={_MIN_VERDICT_SCORE})")


def _thresholds_crossed(previous: int, current: int) -> list[tuple[int, str]]:
    return [(n, s) for n, s in THRESHOLDS if previous < n <= current]


def _status_for(count: int) -> str:
    status = "WATCHING"
    for n, s in THRESHOLDS:
        if count >= n:
            status = s
    return status


async def ensure_indexes(db: Any) -> None:
    await db[WATCHLIST_COLLECTION].create_index(
        [("tenant_id", 1), ("indicator_type", 1), ("indicator_value", 1)],
        unique=True, name="uniq_tenant_indicator")
    await db[SIGHTINGS_COLLECTION].create_index(
        "sighting_id", unique=True, name="uniq_sighting")


def _event_digest(canonical: dict[str, Any]) -> str:
    """Stable identity of the underlying raw event.

    Keyed off the verbatim line so a REPLAY of the same raw event cannot
    inflate spread, even though the canonical event id is regenerated.
    """
    line = ((canonical.get("raw_ref") or {}).get("line") or "").strip()
    if line:
        return _digest("line", line)
    return _digest("event", str(canonical.get("event_id") or uuid.uuid4()))


def _context(canonical: dict[str, Any]) -> dict[str, Any]:
    """Contextual attributes — retained as evidence, never used as
    spread identity."""
    host = canonical.get("host") or {}
    ident = canonical.get("identity") or {}
    net = canonical.get("network") or {}
    proc = canonical.get("process") or {}
    return {
        "hostname":     host.get("hostname") or None,
        "host_ip":      (host.get("ip_addresses") or [None])[0],
        "username":     ident.get("username") or None,
        "src_ip":       net.get("src_ip") or None,
        "dest_ip":      net.get("dest_ip") or None,
        "process_name": proc.get("name") or None,
        "event_time":   canonical.get("event_time"),
        "source_vendor":  canonical.get("source_vendor"),
        "source_product": canonical.get("source_product"),
    }


async def observe(db: Any, canonical: dict[str, Any], *,
                  iue: dict[str, Any] | None,
                  detection: dict[str, Any] | None,
                  verdict: dict[str, Any] | None,
                  trace_id: str,
                  tenant_id: str) -> dict[str, Any]:
    """Record sightings and emit spread correlation evidence.

    Returns a summary.  Emits ZERO scores and ZERO verdicts: the
    `correlation_matches` it returns are appended to the ICE result by
    the pipeline so the EXISTING VEEE and incident gate decide.
    """
    admitted, reason = enrollment_admitted(detection, verdict)
    indicators = extract_indicators(canonical)
    identity, identity_state = endpoint_identity(canonical)
    counts = identity is not None

    base = {
        "plane_id": PLANE_ID,
        "plane_version": PLANE_VERSION,
        "admitted": admitted,
        "admission_reason": reason,
        "endpoint_identity": identity,
        "endpoint_identity_state": identity_state,
        "counts_toward_spread": counts,
        "indicators_extracted": len(indicators),
        "sightings_recorded": 0,
        "duplicate_sightings_ignored": 0,
        "spread": [],
        "correlation_matches": [],
        "honesty_note": HONESTY_NOTE,
    }
    if not admitted:
        base["state"] = "NOT_ADMITTED"
        return base
    if not indicators:
        base["state"] = "NO_INDICATORS"
        return base

    now = _now()
    digest = _event_digest(canonical)
    detection_rule_ids = [d.get("rule_id") for d in
                          ((detection or {}).get("detections") or [])
                          if d.get("rule_id")]
    context = _context(canonical)
    recorded = duplicates = 0
    spread: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []

    for ind in indicators:
        watch_id = "wl_" + _digest(tenant_id, ind["indicator_type"],
                                   ind["indicator_value"])[:20]
        sighting_id = "sgt_" + _digest(watch_id, digest)[:24]

        existing = await db[SIGHTINGS_COLLECTION].find_one(
            {"sighting_id": sighting_id}, {"_id": 0, "sighting_id": 1})
        is_duplicate = existing is not None

        if not is_duplicate:
            await db[SIGHTINGS_COLLECTION].insert_one({
                "sighting_id":  sighting_id,
                "watch_id":     watch_id,
                "tenant_id":    tenant_id,
                "indicator_type":  ind["indicator_type"],
                "indicator_value": ind["indicator_value"],
                "indicator_display": ind["indicator_display"],
                "match_basis":  ind["match_basis"],
                "endpoint_identity": identity,
                "endpoint_identity_state": identity_state,
                "counts_toward_spread": counts,
                "canonical_event_id": canonical.get("event_id"),
                "source_event_id":    canonical.get("source_event_id"),
                "event_digest":       digest,
                "trace_id":     trace_id,
                "collector_id": ((canonical.get("provenance") or {})
                                 .get("collector_id")),
                "integration_id": ((canonical.get("provenance") or {})
                                   .get("integration_id")),
                "at":           now,
                "context":      dict(context),
                "detection_rule_ids": detection_rule_ids,
                "verdict_label": (verdict or {}).get("label"),
                "verdict_score": (verdict or {}).get("score"),
                "admission_reason": reason,
            })
            recorded += 1
        else:
            duplicates += 1

        # ── watchlist upsert ──────────────────────────────────
        doc = await db[WATCHLIST_COLLECTION].find_one(
            {"tenant_id": tenant_id,
             "indicator_type": ind["indicator_type"],
             "indicator_value": ind["indicator_value"]}, {"_id": 0})

        if doc is None:
            endpoints = ([{"endpoint_identity": identity,
                           "first_seen": now, "last_seen": now,
                           "sighting_count": 1,
                           "first_source_event": canonical.get("event_id")}]
                         if counts else [])
            doc = {
                "watch_id":       watch_id,
                "tenant_id":      tenant_id,
                "indicator_type": ind["indicator_type"],
                "indicator_value": ind["indicator_value"],
                "indicator_display": ind["indicator_display"],
                "match_basis":    ind["match_basis"],
                "status":         "WATCHING",
                "source":         "auto:evidence_gated",
                "enrolled_at":    now,
                "enrollment_basis": {
                    "reason": reason,
                    "detection_rule_ids": detection_rule_ids,
                    "verdict_label": (verdict or {}).get("label"),
                    "verdict_score": (verdict or {}).get("score"),
                    "note": "enrollment is NOT a malicious verdict",
                },
                "first_seen":     now,
                "last_seen":      now,
                "endpoints":      endpoints,
                "endpoint_count": len(endpoints),
                "unknown_endpoint_sightings": 0 if counts else 1,
                "sighting_count": 1,
                "duplicate_sightings": 0,
                "thresholds_emitted": [],
                "spread_evidence": [],
                "epistemic_state": {
                    "endpoint_cardinality":
                        "OBSERVED" if counts else "UNKNOWN",
                },
                "honesty_note":   HONESTY_NOTE,
            }
            await db[WATCHLIST_COLLECTION].insert_one(dict(doc))
            previous_count = 0
        else:
            previous_count = int(doc.get("endpoint_count") or 0)
            endpoints = list(doc.get("endpoints") or [])
            if counts:
                slot = next((e for e in endpoints
                             if e.get("endpoint_identity") == identity), None)
                if slot is None:
                    endpoints.append({
                        "endpoint_identity": identity,
                        "first_seen": now, "last_seen": now,
                        "sighting_count": 1,
                        "first_source_event": canonical.get("event_id")})
                elif not is_duplicate:
                    slot["last_seen"] = now
                    slot["sighting_count"] = int(slot.get("sighting_count") or 0) + 1
            update: dict[str, Any] = {
                "last_seen": now,
                "endpoints": endpoints,
                "endpoint_count": len(endpoints),
            }
            inc: dict[str, int] = {}
            if is_duplicate:
                inc["duplicate_sightings"] = 1
            else:
                inc["sighting_count"] = 1
                if not counts:
                    inc["unknown_endpoint_sightings"] = 1
            update["epistemic_state.endpoint_cardinality"] = (
                "OBSERVED" if endpoints else "UNKNOWN")
            await db[WATCHLIST_COLLECTION].update_one(
                {"watch_id": watch_id},
                {"$set": update, "$inc": inc})
            doc["endpoints"] = endpoints
            doc["endpoint_count"] = len(endpoints)

        current_count = int(doc.get("endpoint_count") or 0)
        already = set(doc.get("thresholds_emitted") or [])

        for n, status in _thresholds_crossed(previous_count, current_count):
            if n in already:
                continue
            match_id = "cm_" + uuid.uuid4().hex[:20]
            match_doc = {
                "match_id":        match_id,
                "rule_id":         SPREAD_RULE_ID,
                "rule_name":       SPREAD_RULE_NAME,
                "signal_id":       f"sig_{canonical.get('event_id', '')}",
                "source_event_id": canonical.get("event_id"),
                "trace_id":        trace_id,
                "tenant_id":       tenant_id,
                "emitted_at":      _now(),
                "evidence_level":  "CORRELATION_OBSERVED",
                "severity_hint":   (iue or {}).get("severity_hint"),
                "attack_techniques": [],
                "engine_id":       PLANE_ID,
                "spread": {
                    "watch_id":        watch_id,
                    "indicator_type":  ind["indicator_type"],
                    "indicator_value": ind["indicator_value"],
                    "indicator_display": ind["indicator_display"],
                    "match_basis":     ind["match_basis"],
                    "threshold":       n,
                    "status":          status,
                    "endpoint_count":  current_count,
                    "endpoints":       [e.get("endpoint_identity")
                                        for e in doc.get("endpoints") or []],
                    "unknown_endpoint_sightings":
                        int(doc.get("unknown_endpoint_sightings") or 0),
                    "first_seen":      doc.get("first_seen"),
                    "last_seen":       now,
                    "triggering_endpoint": identity,
                },
                "claim": (f"Indicator observed across {current_count} distinct "
                          f"endpoint identities."),
                "honesty_note":    HONESTY_NOTE,
            }
            await db[CORRELATION_MATCHES_COLLECTION].insert_one(dict(match_doc))
            await db[WATCHLIST_COLLECTION].update_one(
                {"watch_id": watch_id},
                {"$set": {"status": _status_for(current_count)},
                 "$push": {"thresholds_emitted": n,
                           "spread_evidence": {
                               "threshold": n, "status": status,
                               "match_id": match_id, "at": match_doc["emitted_at"],
                               "endpoint_count": current_count,
                               "trace_id": trace_id}}})
            already.add(n)
            matches.append(match_doc)
            spread.append({"watch_id": watch_id,
                           "indicator_type": ind["indicator_type"],
                           "indicator_display": ind["indicator_display"],
                           "threshold": n, "status": status,
                           "endpoint_count": current_count,
                           "match_id": match_id})

    base.update({
        "state": "SPREAD_EVIDENCE_EMITTED" if matches else "OBSERVED",
        "sightings_recorded": recorded,
        "duplicate_sightings_ignored": duplicates,
        "spread": spread,
        "correlation_matches": matches,
    })
    return base
