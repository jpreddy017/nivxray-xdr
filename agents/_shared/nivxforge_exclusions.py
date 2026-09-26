"""NivXForge Connector · endpoint-side exclusion evaluator.

CANONICAL SOURCE. A copy of this file is shipped inside every connector
release directory, and `tests/edr/test_gate7_endpoint_enforcement.py`
asserts the copies are byte-identical to this one. One evaluator, one
behaviour, on every platform.

P0-B · an exclusion now declares WHAT it suppresses:

    DETECTION  (default) the event IS collected and IS delivered. Only the
               verdict is suppressed, by the server engine that owns
               verdicts. The evidence survives the exclusion, so it stays
               in the trajectory and can be re-evaluated later.
    COLLECTION the connector does not deliver the matching event at all.
               The evidence never leaves the machine. That is real
               endpoint enforcement and a real, deliberate visibility
               loss — it is why `ENDPOINT_EXCLUSION_APPLIED` can be
               earned rather than asserted, and why it must be asked for
               explicitly.
    PREVENTION refused: this connector has no prevention engine.

An exclusion that arrives with no scope is treated as COLLECTION, because
that is exactly what every pre-P0-B exclusion already did on this
endpoint. A migration must never silently change what a live exclusion
does.

`endpoint.prevention` is deliberately NOT implemented here: the released
connector has no prevention engine, so an exclusion aimed at it is
REFUSED by the connector and the platform reports
`EXCLUSION_NOT_SUPPORTED_BY_ENGINE` from the endpoint's own statement.

What is reported back to the platform is the ENFORCEMENT FACT, never the
excluded content: the exclusion id, the attribute that matched, a count,
and SHA-256 digests of the observed values. Re-uploading the excluded
payload would defeat the exclusion the operator asked for.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import time

EVALUATOR_VERSION = "1.1.0"

#: The engine this evaluator IS.
ENGINE = "endpoint.collection"

#: Engines the released connector cannot honour locally.
UNSUPPORTED_ENGINES = ("endpoint.prevention",)

#: P0-B · what an exclusion may suppress. PREVENTION is declared by the
#: platform and refused here, never silently accepted.
SCOPE_COLLECTION = "COLLECTION"
SCOPE_DETECTION = "DETECTION"
SCOPE_PREVENTION = "PREVENTION"
SUPPORTED_SCOPES = (SCOPE_COLLECTION, SCOPE_DETECTION)
#: A scope-less exclusion keeps the behaviour it already had.
LEGACY_SCOPE = SCOPE_COLLECTION

SUPPORTED_TYPES = ("PATH", "FILE_EXTENSION", "FILE_HASH", "PROCESS",
                   "PROCESS_COMMANDLINE", "NETWORK_ADDRESS")
SUPPORTED_MATCHES = ("EXACT", "PREFIX", "SUFFIX", "CONTAINS", "GLOB")

HONOURED = "HONOURED"
REFUSED_UNSUPPORTED_TYPE = "REFUSED_UNSUPPORTED_TYPE"
REFUSED_UNSUPPORTED_ENGINE = "REFUSED_UNSUPPORTED_ENGINE"
REFUSED_MALFORMED = "REFUSED_MALFORMED"
REFUSED_UNSUPPORTED_SCOPE = "REFUSED_UNSUPPORTED_SCOPE"

ATTRIBUTE = {"PATH": "path", "FILE_EXTENSION": "path",
             "FILE_HASH": "file_hash", "PROCESS": "process",
             "PROCESS_COMMANDLINE": "command_line",
             "NETWORK_ADDRESS": "network_address"}


def scope_of(exclusion: dict) -> str:
    """The enforcement scope of one exclusion, legacy records included."""
    raw = (exclusion or {}).get("enforcement_scope")
    if raw in (SCOPE_COLLECTION, SCOPE_DETECTION, SCOPE_PREVENTION):
        return raw
    return LEGACY_SCOPE


def _sha(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def validate(exclusion: dict) -> str:
    """Can THIS connector honour this exclusion? Answered before use.

    A refusal is a reported fact, not a silent skip: an operator must
    never believe an endpoint is honouring something it cannot.
    """
    if not isinstance(exclusion, dict):
        return REFUSED_MALFORMED
    etype = exclusion.get("type")
    value = exclusion.get("value")
    match = exclusion.get("match") or "EXACT"
    if not exclusion.get("exclusion_id") or not isinstance(value, str) \
            or not value.strip():
        return REFUSED_MALFORMED
    if match not in SUPPORTED_MATCHES:
        return REFUSED_MALFORMED
    if etype == "FILE_HASH" and len(value.strip()) != 64:
        return REFUSED_MALFORMED
    if etype not in SUPPORTED_TYPES:
        return REFUSED_UNSUPPORTED_TYPE
    if scope_of(exclusion) not in SUPPORTED_SCOPES:
        return REFUSED_UNSUPPORTED_SCOPE
    engines = exclusion.get("affected_engines")
    if isinstance(engines, list) and engines and ENGINE not in engines:
        return REFUSED_UNSUPPORTED_ENGINE
    return HONOURED


def candidate(event: dict) -> dict:
    """The attributes an exclusion may be evaluated against.

    An attribute this connector did not observe stays absent, so an
    exclusion can never silently swallow activity whose relevant
    attribute was never collected.
    """
    activity = event.get("activity")
    out = {"path": None, "process": None, "command_line": None,
           "file_hash": None, "network_address": None}
    if activity == "PROCESS":
        out["path"] = event.get("image_path") or None
        # The connector reports the process name as `image` (from
        # /proc/<pid>/comm on Linux). Omitting it here meant a PROCESS
        # exclusion could never match a real collected event.
        out["process"] = (event.get("process_name") or event.get("image")
                          or event.get("name") or None)
        out["command_line"] = event.get("command_line") or None
        out["file_hash"] = event.get("sha256") or None
    elif activity == "NETWORK":
        out["network_address"] = event.get("remote_ip") or None
        out["process"] = (event.get("process_name") or event.get("image")
                          or None)
    elif activity == "FILE":
        out["path"] = event.get("path") or None
        out["file_hash"] = event.get("sha256") or None
    return out


def _match(exclusion: dict, observed: str) -> bool:
    etype = exclusion.get("type")
    value = str(exclusion.get("value") or "")
    if etype == "FILE_HASH":
        return observed.lower() == value.lower()
    o, v = observed.lower(), value.lower()
    if etype == "FILE_EXTENSION":
        return o.endswith(v if v.startswith(".") else "." + v)
    kind = exclusion.get("match") or "EXACT"
    if kind == "EXACT":
        return o == v
    if kind == "PREFIX":
        return o.startswith(v)
    if kind == "SUFFIX":
        return o.endswith(v)
    if kind == "CONTAINS":
        return v in o
    if kind == "GLOB":
        return fnmatch.fnmatch(o, v)
    return False


def evaluate(event: dict, honoured: list[dict]) -> dict | None:
    """First honoured exclusion that matches this event wins.

    Returns the enforcement fact, or None when nothing matched and the
    event must be delivered normally.
    """
    cand = candidate(event)
    for exclusion in honoured:
        attribute = ATTRIBUTE.get(exclusion.get("type"))
        observed = cand.get(attribute) if attribute else None
        if not observed:
            continue
        if _match(exclusion, str(observed)):
            return {"exclusion_id": exclusion["exclusion_id"],
                    "type": exclusion.get("type"),
                    "enforcement_scope": scope_of(exclusion),
                    "match": exclusion.get("match"),
                    "matched_attribute": attribute,
                    "observed_value_sha256": _sha(observed),
                    "activity": event.get("activity")}
    return None


class Journal:
    """Durable, cumulative record of what this connector actually enforced.

    Cumulative rather than delta: a report lost in transit must not lose
    the enforcement fact, and the platform upsert is idempotent.
    """

    def __init__(self, path):
        self.path = str(path)
        self.entries: dict = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self.entries = data.get("entries") or {}
        except (OSError, ValueError):
            self.entries = {}

    def save(self) -> None:
        tmp = self.path + ".tmp"
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"evaluator_version": EVALUATOR_VERSION,
                       "entries": self.entries,
                       "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                 time.gmtime())}, fh)
        os.replace(tmp, self.path)

    def record_acceptance(self, exclusion: dict, acceptance: str) -> None:
        e = self.entries.setdefault(exclusion["exclusion_id"], {})
        e.update({"acceptance": acceptance, "type": exclusion.get("type"),
                  "match": exclusion.get("match"),
                  "value_sha256": _sha(exclusion.get("value") or ""),
                  "engine": ENGINE})
        e.setdefault("honoured_count", 0)
        e.setdefault("observed_value_digests", [])

    def record_enforcement(self, fact: dict, policy: dict) -> None:
        e = self.entries.setdefault(fact["exclusion_id"], {})
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        e["engine"] = ENGINE
        e["acceptance"] = HONOURED
        e["type"] = fact.get("type")
        e["matched_attribute"] = fact.get("matched_attribute")
        e["honoured_count"] = int(e.get("honoured_count") or 0) + 1
        scope = fact.get("enforcement_scope") or LEGACY_SCOPE
        e["enforcement_scope"] = scope
        key = ("collection_suppressed_count" if scope == SCOPE_COLLECTION
               else "detection_suppression_requested_count")
        e[key] = int(e.get(key) or 0) + 1
        e["evidence_retained"] = scope == SCOPE_DETECTION
        e.setdefault("first_at", now)
        e["last_at"] = now
        e["policy_id"] = policy.get("policy_id")
        e["policy_version"] = policy.get("version")
        e["config_digest"] = policy.get("config_digest")
        digests = e.setdefault("observed_value_digests", [])
        if fact["observed_value_sha256"] not in digests and len(digests) < 5:
            digests.append(fact["observed_value_sha256"])

    def report(self) -> list[dict]:
        return [{"exclusion_id": k, **v} for k, v in self.entries.items()]


def partition(events: list[dict], exclusions: list[dict], journal: Journal,
              policy: dict) -> tuple[list[dict], int]:
    """Split collected events into DELIVER and ENFORCED-LOCALLY.

    P0-B · only a COLLECTION-scoped match is dropped here, on the
    endpoint: those events are never queued, never transmitted and never
    reach the backend, which is the difference between endpoint
    enforcement and server-side suppression — and a deliberate,
    irreversible loss of evidence.

    A DETECTION-scoped match is DELIVERED. The event carries the
    enforcement fact so the platform can show which exclusion applies to
    it, and the verdict is suppressed by the engine that owns verdicts.
    The telemetry and the evidence are retained.

    The returned count is the number of events SUPPRESSED FROM
    COLLECTION, because that is the only number that means "this evidence
    does not exist". The per-exclusion journal carries both counts.
    """
    honoured = []
    for exclusion in exclusions:
        acceptance = validate(exclusion)
        if not (isinstance(exclusion, dict) and exclusion.get("exclusion_id")):
            # Nothing to attribute the refusal to. It is refused and NOT
            # recorded, because a journal entry with no exclusion id would
            # be an enforcement claim the platform cannot verify.
            continue
        journal.record_acceptance(exclusion, acceptance)
        if acceptance == HONOURED:
            honoured.append(exclusion)
    if not honoured:
        return list(events), 0
    keep, enforced = [], 0
    for event in events:
        fact = evaluate(event, honoured)
        if fact is None:
            keep.append(event)
            continue
        journal.record_enforcement(fact, policy)
        if fact.get("enforcement_scope") == SCOPE_DETECTION:
            # Delivered, annotated, retained. The endpoint states what it
            # matched; it does not decide the verdict.
            marks = event.setdefault("endpoint_exclusion_matches", [])
            marks.append({"exclusion_id": fact["exclusion_id"],
                          "enforcement_scope": SCOPE_DETECTION,
                          "matched_attribute": fact.get("matched_attribute"),
                          "observed_value_sha256":
                              fact.get("observed_value_sha256"),
                          "evaluator_version": EVALUATOR_VERSION,
                          "note": ("the endpoint honoured a DETECTION-scoped "
                                   "exclusion: the evidence was retained and "
                                   "delivered, and the verdict is suppressed "
                                   "by the server engine that owns it")})
            keep.append(event)
            continue
        enforced += 1
    return keep, enforced
