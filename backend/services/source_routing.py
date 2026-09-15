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
SOURCE_DSM_UNAVAILABLE = "SOURCE_DSM_UNAVAILABLE"

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
                          SOURCE_DSM_UNAVAILABLE],
        "honesty_note": (
            "a collector with no registered authorized_sources is authorized "
            "for nothing; an empty allowlist never means 'any source'"),
    }


def _decision(*, result: str, declared: Any, resolved: str | None,
              authorized: list[str], dsm_id: str | None = None,
              compatible: bool | None = None,
              recognized: list[str] | None = None,
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
        "content_role": CONTENT_ROLE,
        "mismatch_reason": code,
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
        return _decision(
            result=BLOCKED, declared=declared, resolved=resolved,
            authorized=authorized, dsm_id=dsm_id, compatible=False,
            recognized=registry.recognize(raw_event),
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
        "content_role": CONTENT_ROLE,
        "mismatch_reason": None if dsm_id else UNSUPPORTED_SOURCE,
        "reason": reason,
    }
