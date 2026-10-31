"""D15 · Declared source routing — the authority chain for DSM selection.

    authenticated collector identity
              ↓
    collector-authorized source set   (server-side, not sent by the caller)
              ↓
    explicit per-request declaration
              ↓
    declaration / allowlist validation
              ↓
    DSM selection
              ↓
    content compatibility validation
              ↓
    canonical evidence

Four different questions, four different answers, and none of them may be
substituted for another:

  * authentication answers WHO is sending;
  * the collector's registered allowlist answers WHAT that collector is
    authorized to send;
  * the request declaration answers what THIS delivery claims to be;
  * content validation answers whether the payload is structurally
    consistent with that claim.

Content recognition may only VALIDATE a declaration. It may never select a
DSM, never override a declaration, and never rescue one. Registry ordering
is not an authority either: before D15 a payload that happened to satisfy
an earlier DSM's ``supports()`` was interpreted by that DSM, which made
resolution order a security-relevant accident. There is no fall-through
here — every disagreement is a refusal with the reason recorded.
"""
from __future__ import annotations

from typing import Any

# ── outcomes ──────────────────────────────────────────────────────
ACCEPTED = "ACCEPTED"
BLOCKED = "BLOCKED"
#: The payload was refused BEFORE routing could be evaluated (D13 shape
#: collision). Reporting it as a routing decision would be a lie.
NOT_EVALUATED = "NOT_EVALUATED"

# ── refusal codes · deliberately distinct ─────────────────────────
DECLARATION_REQUIRED = "DECLARATION_REQUIRED"
SOURCE_NOT_AUTHORIZED = "SOURCE_NOT_AUTHORIZED"
UNSUPPORTED_SOURCE = "UNSUPPORTED_SOURCE"
SOURCE_FORMAT_MISMATCH = "SOURCE_FORMAT_MISMATCH"
#: B4 · the declaration is CORRECT and the payload IS the declared format —
#: NivXRay simply has no parser/normalizer coverage for this record type yet.
#: Before this code existed such a record was reported as
#: SOURCE_FORMAT_MISMATCH, which made a healthy Windows Security channel look
#: malformed because 24 of its records carried EventIDs outside the DSM's
#: supported set. Coverage and validity are different facts.
#: Documentation note: FORMAT_INVALID ≡ SOURCE_FORMAT_MISMATCH; the API and
#: stored records keep the existing spelling.
SOURCE_RECORD_NOT_SUPPORTED = "SOURCE_RECORD_NOT_SUPPORTED"
SOURCE_DSM_UNAVAILABLE = "SOURCE_DSM_UNAVAILABLE"

#: B4 · refusals for which the raw payload MUST still be retained as
#: forensic evidence. Every code here has already passed declaration,
#: catalog and allowlist validation, so the delivery is AUTHORIZED and
#: DECLARED — the failure is downstream of authority. Discarding such a
#: record destroys the only copy of evidence an investigator could later
#: reconstruct, and it is what made the G1 Security EventIDs unrecoverable.
#:
#: Deliberately EXCLUDED: DECLARATION_REQUIRED, UNSUPPORTED_SOURCE and
#: SOURCE_NOT_AUTHORIZED. Those are authority failures and must stay
#: fail-closed — an unauthorized or undeclared source may never buy itself
#: durable storage in this tenant by being refused.
RAW_RETENTION_ELIGIBLE_CODES = frozenset({
    SOURCE_FORMAT_MISMATCH,
    SOURCE_RECORD_NOT_SUPPORTED,
    SOURCE_DSM_UNAVAILABLE,
})


def raw_retention_eligible(code: str | None) -> bool:
    """B4 · may this refusal's raw payload be retained for forensics?"""
    return code in RAW_RETENTION_ELIGIBLE_CODES

#: Who chose the DSM. Recorded on every routed event so an auditor never has
#: to infer whether selection was declared or guessed.
DECLARED_AUTHORITY = "AUTHENTICATED_COLLECTOR_DECLARATION"
#: Internal (non-HTTP) callers of the pipeline carry no authenticated
#: collector and no declaration. They are labelled for exactly what they are
#: rather than being silently presented as declared routing.
CONTENT_RESOLVED_INTERNAL = "CONTENT_RESOLVED_INTERNAL_CALLER_NOT_INGEST_PATH"

CONTENT_ROLE = ("content recognition VALIDATES the declaration; it never "
                "selects a DSM and never overrides a declaration")

#: One declared source → exactly ONE DSM authorised to interpret it.
SOURCE_CATALOG: dict[str, str] = {
    "snort-eve":              "snort-eve",
    "windows-security-evd":   "windows-security-evd",
    "microsoft-sysmon":       "microsoft-sysmon",
    "linux-auditd":           "linux-auditd",
    "aws-cloudtrail":         "aws-cloudtrail",
    "cef-leef":               "cef-leef",
    "nivxforge-linux-sensor": "nivxforge-linux-sensor",
    #: Microsoft Phase 1 · Office 365 Management Activity API records.
    "m365-unified-audit":     "m365-unified-audit",
    #: N1 · Zeek / Corelight conn + dns JSON records.
    "zeek-json":              "zeek-json",
    #: W2-1 · the PowerShell channels the native Windows adapter acquires.
    "windows-powershell-evd": "windows-powershell-evd",
    #: W2-1 · the Microsoft Defender operational channel.
    "windows-defender-evd":   "windows-defender-evd",
}

#: Spelling variants a collector may legitimately use. Every alias resolves
#: to a catalog key that names the SAME single DSM, so an alias can never
#: widen what a declaration means.
SOURCE_ALIASES: dict[str, str] = {
    "suricata-eve":      "snort-eve",
    "suricata":          "snort-eve",
    "snort":             "snort-eve",
    "windows-security":  "windows-security-evd",
    "windows":           "windows-security-evd",
    "sysmon":            "microsoft-sysmon",
    "auditd":            "linux-auditd",
    "cloudtrail":        "aws-cloudtrail",
    "aws":               "aws-cloudtrail",
    "cef":               "cef-leef",
    "leef":              "cef-leef",
    "nivxforge-sensor":  "nivxforge-linux-sensor",
    "nivxforge":         "nivxforge-linux-sensor",
    "m365":              "m365-unified-audit",
    "o365":              "m365-unified-audit",
    "office365":         "m365-unified-audit",
    "microsoft-365":     "m365-unified-audit",
    "m365-management-activity":      "m365-unified-audit",
    "office365-management-activity": "m365-unified-audit",
    #: N1 · every spelling resolves to the SAME single Zeek DSM. An alias
    #: widens nothing: authorization is still checked against the catalog
    #: key, and the payload must still be compatible with that one DSM.
    "zeek":       "zeek-json",
    "bro":        "zeek-json",
    "corelight":  "zeek-json",
    "zeek-conn":  "zeek-json",
    "zeek-dns":   "zeek-json",
    #: W2-1 · the declared_source strings the Windows Event Log adapter
    #: emits (`framework/windows_eventlog.py :: CHANNELS`). They are
    #: ALIASES, so the authorization check still resolves to the one
    #: catalog key that names the single DSM permitted to interpret them.
    "windows_security":       "windows-security-evd",
    "windows_powershell":     "windows-powershell-evd",
    "windows-powershell":     "windows-powershell-evd",
    "powershell":             "windows-powershell-evd",
    "microsoft_defender":     "windows-defender-evd",
    "microsoft-defender":     "windows-defender-evd",
    "windows_defender":       "windows-defender-evd",
    "defender":               "windows-defender-evd",
}


def canonical_source(declared: Any) -> str | None:
    """The catalog key a declaration names, or ``None`` when unknown."""
    if declared is None:
        return None
    key = str(declared).strip().lower()
    if not key:
        return None
    if key in SOURCE_CATALOG:
        return key
    return SOURCE_ALIASES.get(key)


def normalize_declarations(values: Any) -> tuple[list[str], list[str]]:
    """``(authorized_catalog_keys, unknown_values)`` for an allowlist.

    Unknown entries are returned rather than dropped: a misspelled source in
    an allowlist must fail loudly at configuration time, not quietly permit
    nothing at ingest time.
    """
    if values is None:
        return [], []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return [], [str(values)]
    ok: list[str] = []
    unknown: list[str] = []
    for v in values:
        key = canonical_source(v)
        if key is None:
            unknown.append(str(v))
        elif key not in ok:
            ok.append(key)
    return ok, unknown


def authorized_sources(collector_doc: dict[str, Any] | None) -> list[str]:
    """What this collector is authorized to send, per the SERVER's record.

    A collector with no registered allowlist is authorized for NOTHING. That
    is the fail-closed answer on purpose: an empty allowlist must not mean
    "anything", or a misconfigured collector would silently become the most
    privileged one.
    """
    keys, _unknown = normalize_declarations(
        (collector_doc or {}).get("authorized_sources"))
    return keys


def catalog() -> dict[str, Any]:
    """Operator-facing truth about what may be declared."""
    return {
        "sources": [{"declared_source": k, "dsm_id": v,
                     "aliases": sorted(a for a, t in SOURCE_ALIASES.items()
                                       if t == k)}
                    for k, v in sorted(SOURCE_CATALOG.items())],
        "routing_authority": DECLARED_AUTHORITY,
        "content_role": CONTENT_ROLE,
        "refusal_codes": [DECLARATION_REQUIRED, SOURCE_NOT_AUTHORIZED,
                          UNSUPPORTED_SOURCE, SOURCE_FORMAT_MISMATCH,
                          SOURCE_RECORD_NOT_SUPPORTED,
                          SOURCE_DSM_UNAVAILABLE],
        "refusal_code_meanings": {
            DECLARATION_REQUIRED: "the delivery declared nothing",
            UNSUPPORTED_SOURCE: "the declaration names no catalog source",
            SOURCE_NOT_AUTHORIZED: ("the collector's server-side allowlist "
                                    "does not permit the declared source"),
            SOURCE_FORMAT_MISMATCH: ("the payload is not the declared format "
                                     "(FORMAT_INVALID)"),
            SOURCE_RECORD_NOT_SUPPORTED: (
                "the payload IS the declared format; NivXRay has no coverage "
                "for this record type yet — the source is not broken"),
            SOURCE_DSM_UNAVAILABLE: ("the authorized DSM is not loaded — a "
                                     "code failure, not a payload defect"),
        },
        "raw_retention_eligible_codes": sorted(RAW_RETENTION_ELIGIBLE_CODES),
        "raw_retention_note": (
            "an AUTHORIZED + DECLARED delivery keeps its verbatim raw record "
            "as forensic evidence even when it is refused; retained raw is "
            "NOT parsed, normalized, detected, canonicalized or asserted to "
            "be benign"),
        "honesty_note": (
            "a collector with no registered authorized_sources is authorized "
            "for nothing; an empty allowlist never means 'any source'"),
    }


def _decision(*, result: str, declared: Any, resolved: str | None,
              authorized: list[str], dsm_id: str | None = None,
              compatible: bool | None = None,
              recognized: list[str] | None = None,
              format_recognized: bool | None = None,
              code: str | None = None, reason: str) -> dict[str, Any]:
    return {
        "routing_result": result,
        "routing_authority": DECLARED_AUTHORITY,
        "declared_source": (None if declared is None
                            else str(declared).strip() or None),
        "declared_source_resolved": resolved,
        "collector_authorized_sources": list(authorized),
        "selected_dsm_id": dsm_id,
        "content_compatible": compatible,
        "content_recognized_as": recognized,
        #: B4 · did the declared DSM recognise the payload's FORMAT? Only
        #: asked when compatibility already failed, so it is None whenever
        #: the question was never put.
        "declared_format_recognized": format_recognized,
        "content_role": CONTENT_ROLE,
        "mismatch_reason": code,
        #: B4 · whether this refusal's raw payload is kept as forensic
        #: evidence. Stated on the decision so the disposition and the
        #: retention promise can never disagree.
        "raw_retention_eligible": raw_retention_eligible(code),
        "reason": reason,
    }


def route(*, declared: Any, authorized: list[str], raw_event: Any,
          registry: Any) -> tuple[dict[str, Any], Any]:
    """``(decision, dsm_or_None)``. Fail closed at every step."""
    if canonical_source(declared) is None and not str(
            declared or "").strip():
        return _decision(
            result=BLOCKED, declared=declared, resolved=None,
            authorized=authorized, code=DECLARATION_REQUIRED,
            reason=("this delivery carried no declared_source; the "
                    "authenticated collector must declare what it is "
                    "sending — content is never used to guess it")), None

    resolved = canonical_source(declared)
    if resolved is None:
        return _decision(
            result=BLOCKED, declared=declared, resolved=None,
            authorized=authorized, code=UNSUPPORTED_SOURCE,
            reason=("the declared source is not in the source catalog: "
                    f"supported declarations are "
                    f"{sorted(SOURCE_CATALOG)}")), None

    if resolved not in authorized:
        return _decision(
            result=BLOCKED, declared=declared, resolved=resolved,
            authorized=authorized, code=SOURCE_NOT_AUTHORIZED,
            reason=("this collector is not authorized to send the declared "
                    "source; authentication proves who is sending, and the "
                    "server-side allowlist decides what it may send")), None

    dsm_id = SOURCE_CATALOG[resolved]
    dsm = registry.get(dsm_id)
    if dsm is None:
        return _decision(
            result=BLOCKED, declared=declared, resolved=resolved,
            authorized=authorized, dsm_id=dsm_id,
            code=SOURCE_DSM_UNAVAILABLE,
            reason=("the DSM authorised for this declared source is not "
                    "loaded, so the declaration cannot be honoured; this is "
                    "a CODE failure, not a payload defect")), None

    if not registry.compatible(dsm, raw_event):
        # B4 · two different truths, two different answers. The declaration
        # is NOT overridden either way and no other DSM is tried.
        if registry.format_recognized(dsm, raw_event):
            return _decision(
                result=BLOCKED, declared=declared, resolved=resolved,
                authorized=authorized, dsm_id=dsm_id, compatible=False,
                recognized=registry.recognize(raw_event),
                format_recognized=True,
                code=SOURCE_RECORD_NOT_SUPPORTED,
                reason=("the declared source is correct and this payload IS "
                        "that format, but the authorized DSM has no parser / "
                        "normalizer coverage for this record type yet; the "
                        "raw record is retained as forensic evidence and is "
                        "NOT parsed, normalized, detected or "
                        "canonicalized")), None
        return _decision(
            result=BLOCKED, declared=declared, resolved=resolved,
            authorized=authorized, dsm_id=dsm_id, compatible=False,
            recognized=registry.recognize(raw_event),
            format_recognized=False,
            code=SOURCE_FORMAT_MISMATCH,
            reason=("the payload is not structurally consistent with the "
                    "declared source; the declaration is NOT overridden and "
                    "no other DSM is tried — any DSM listed in "
                    "content_recognized_as is reported as evidence "
                    "only")), None

    return _decision(
        result=ACCEPTED, declared=declared, resolved=resolved,
        authorized=authorized, dsm_id=dsm_id, compatible=True,
        reason=("the authenticated collector is authorized for the declared "
                "source and the payload is consistent with it")), dsm


def not_evaluated(*, declared: Any, authorized: list[str], reason: str
                  ) -> dict[str, Any]:
    """Routing never ran, because the payload was already refused."""
    return _decision(result=NOT_EVALUATED, declared=declared,
                     resolved=canonical_source(declared),
                     authorized=authorized, reason=reason)


def internal_caller(dsm_id: str | None, *, reason: str) -> dict[str, Any]:
    """Provenance for a NON-ingest caller that resolved a DSM by content.

    The authenticated ingest boundary always declares. Internal replay and
    unit callers have no collector identity to be authorized against, so the
    record says CONTENT_RESOLVED_INTERNAL_CALLER_NOT_INGEST_PATH instead of
    claiming an authority that never existed.
    """
    return {
        "routing_result": ACCEPTED if dsm_id else BLOCKED,
        "routing_authority": CONTENT_RESOLVED_INTERNAL,
        "declared_source": None,
        "declared_source_resolved": None,
        "collector_authorized_sources": None,
        "selected_dsm_id": dsm_id,
        "content_compatible": bool(dsm_id),
        "content_recognized_as": None,
        "declared_format_recognized": None,
        "content_role": CONTENT_ROLE,
        "mismatch_reason": None if dsm_id else UNSUPPORTED_SOURCE,
        "raw_retention_eligible": False,
        "reason": reason,
    }
