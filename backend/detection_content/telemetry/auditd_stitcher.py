"""D4 · auditd record stitching.

auditd emits SEVERAL records for ONE logical operation, all sharing a single
``audit(epoch:serial)`` identity. Evaluated individually they contradict each
other: the SYSCALL record knows the pid/uid/exe but only the short ``comm``,
while the EXECVE record knows the real argv but no identity at all. A rule
keying on ``command_line`` therefore sees "not privileged", and a rule keying
on privilege sees no command line.

This module reassembles the logical event WITHOUT inventing anything:

* records are grouped ONLY by the authoritative audit identity — never by
  timestamp proximity, and never by pid, which is reused;
* every contributing raw record is preserved verbatim;
* every stitched field records WHICH record supplied it;
* a group missing an expected record stays honestly partial — absent fields
  are reported absent, never defaulted.

Pure functions, no I/O, no shared state between calls.
"""
from __future__ import annotations

import re
from typing import Any

#: Record types we know how to combine. Anything else is preserved
#: verbatim and reported as unknown rather than dropped.
KNOWN_RECORD_TYPES = ("SYSCALL", "EXECVE", "PROCTITLE", "CWD", "PATH")

#: Which record is AUTHORITATIVE for which canonical concern. Declared, so
#: the stitched event can say where each value came from.
FIELD_AUTHORITY = {
    "identity":          ("SYSCALL",),
    "process.pid":       ("SYSCALL",),
    "process.ppid":      ("SYSCALL",),
    "process.exe":       ("SYSCALL",),
    "process.comm":      ("SYSCALL",),
    "process.argv":      ("EXECVE",),
    "process.proctitle": ("PROCTITLE",),
    "working_directory": ("CWD",),
    "file.path":         ("PATH",),
}

_AUDIT_ID = re.compile(r"audit\((\d+(?:\.\d+)?):(\d+)\)")
_TYPE = re.compile(r"\btype=([A-Z_]+)")


def audit_identity(line: str) -> tuple[str, str] | None:
    """The authoritative audit event identity: ``(epoch, serial)``.

    Both halves are required. The serial alone is NOT unique — it resets, so
    two genuinely different executions can share one. Returning None means
    "cannot be stitched safely", which is a refusal, not a fallback.
    """
    m = _AUDIT_ID.search(line or "")
    return (m.group(1), m.group(2)) if m else None


def record_type(line: str) -> str:
    m = _TYPE.search(line or "")
    return m.group(1) if m else ""


def _line_of(ev: dict[str, Any]) -> str:
    return str(ev.get("message") or ev.get("raw") or ev.get("line") or "")


def is_auditd(ev: dict[str, Any]) -> bool:
    return bool(audit_identity(_line_of(ev))) and bool(
        record_type(_line_of(ev)))


def group_records(events: list[dict[str, Any]]) -> tuple[list, list]:
    """Group a batch by (tenant, collector, audit identity), order preserved.

    Grouping is deliberately partitioned by tenant AND collector as well as
    audit identity: two tenants can produce the same serial, and merging
    those would be a cross-tenant evidence leak, not a stitch.
    """
    groups: dict[tuple, dict[str, Any]] = {}
    order: list[tuple] = []
    passthrough: list[dict[str, Any]] = []

    for ev in events:
        line = _line_of(ev)
        ident = audit_identity(line)
        rtype = record_type(line)
        if not ident or not rtype:
            passthrough.append(ev)
            continue
        key = (ev.get("tenant_id"), ev.get("collector_id"), ident)
        if key not in groups:
            groups[key] = {"tenant_id": ev.get("tenant_id"),
                           "collector_id": ev.get("collector_id"),
                           "audit_epoch": ident[0], "audit_serial": ident[1],
                           "audit_id": f"{ident[0]}:{ident[1]}",
                           "records": []}
            order.append(key)
        groups[key]["records"].append({"record_type": rtype, "line": line,
                                       "event": ev})
    return [groups[k] for k in order], passthrough


def _kv(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, qv, bv in re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]+))', line):
        if k not in out:                       # first wins; never overwrite
            out[k] = qv if qv else bv
    return out


def stitch_group(group: dict[str, Any]) -> dict[str, Any]:
    """Combine one group into a single stitched record + its provenance.

    Returns a dict the auditd parser/normalizer can consume, carrying:
      ``_stitched``            the merged key/value view
      ``_field_attribution``   canonical concern -> contributing record type
      ``_contributing_records`` every raw record, verbatim
      ``_completeness``        COMPLETE / PARTIAL, with what is missing
      ``_duplicates``          duplicate record types that were NOT merged
    """
    seen_types: dict[str, int] = {}
    merged: dict[str, str] = {}
    attribution: dict[str, str] = {}
    contributing: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    unknown: list[str] = []

    # SYSCALL first so identity wins over anything a later record repeats;
    # otherwise EXECVE's argv keys could shadow authoritative identity.
    priority = {t: i for i, t in enumerate(KNOWN_RECORD_TYPES)}
    ordered = sorted(group["records"],
                     key=lambda r: priority.get(r["record_type"], 99))

    for rec in ordered:
        rtype, line = rec["record_type"], rec["line"]
        if rtype not in KNOWN_RECORD_TYPES:
            unknown.append(rtype)
        n = seen_types.get(rtype, 0)
        seen_types[rtype] = n + 1
        entry = {"record_type": rtype, "line": line,
                 "audit_id": group["audit_id"]}
        if n > 0:
            # A second record of the same type in one audit event is either a
            # duplicate delivery or a multi-PATH event. It is preserved and
            # reported, never silently merged over the first.
            entry["position"] = n
            duplicates.append(entry)
            contributing.append(entry)
            continue
        contributing.append(entry)
        for k, v in _kv(line).items():
            if k in ("type", "msg"):
                continue
            if k not in merged:
                merged[k] = v
                attribution[k] = rtype

    present = set(seen_types)
    # EXECVE is what makes an execution an execution; SYSCALL is what makes
    # it attributable. Both are "expected" only for execve syscalls.
    expected = {"SYSCALL", "EXECVE"}
    missing = sorted(expected - present)
    canonical_attr = {
        concern: next((rt for rt in rts if rt in present), None)
        for concern, rts in FIELD_AUTHORITY.items()
    }

    return {
        **{k: v for k, v in merged.items()},
        "type": "SYSCALL" if "SYSCALL" in present else (
            ordered[0]["record_type"] if ordered else ""),
        "audit_id": group["audit_serial"],
        "tenant_id": group["tenant_id"],
        "collector_id": group["collector_id"],
        "_stitched": True,
        "_audit_identity": group["audit_id"],
        "_record_types": sorted(present),
        "_field_attribution": attribution,
        "_canonical_attribution": canonical_attr,
        "_contributing_records": contributing,
        "_duplicate_records": duplicates,
        "_unknown_record_types": sorted(set(unknown)),
        "_completeness": "COMPLETE" if not missing else "PARTIAL",
        "_missing_records": missing,
    }


def plan_stitch(lines: list[str], tenants: list[Any],
                collectors: list[Any]) -> dict[str, Any]:
    """Plan a batch stitch over parallel lists, index-aligned to the caller's
    envelopes so the caller keeps its own per-envelope accounting.

    Returns ``{"roles": {idx: role}, "primary_of": {idx: primary_idx},
    "stitched": {primary_idx: stitched_record}, "report": {...}}`` where role
    is ``PRIMARY``, ``MEMBER`` or ``PASSTHROUGH``.

    The SYSCALL record is preferred as PRIMARY because it is the attributable
    one; otherwise the first arrival wins. Nothing is dropped: every index
    gets a role, so the caller can settle every idempotency claim.
    """
    groups: dict[tuple, list[int]] = {}
    order: list[tuple] = []
    roles: dict[int, str] = {}

    for i, line in enumerate(lines):
        ident = audit_identity(line)
        rtype = record_type(line)
        if not ident or not rtype:
            roles[i] = "PASSTHROUGH"
            continue
        key = (tenants[i], collectors[i], ident)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(i)

    primary_of: dict[int, int] = {}
    stitched: dict[int, dict[str, Any]] = {}
    for key in order:
        idxs = groups[key]
        primary = next((i for i in idxs
                        if record_type(lines[i]) == "SYSCALL"), idxs[0])
        roles[primary] = "PRIMARY"
        group = {"tenant_id": key[0], "collector_id": key[1],
                 "audit_epoch": key[2][0], "audit_serial": key[2][1],
                 "audit_id": f"{key[2][0]}:{key[2][1]}",
                 "records": [{"record_type": record_type(lines[i]),
                              "line": lines[i], "index": i} for i in idxs]}
        stitched[primary] = stitch_group(group)
        stitched[primary]["_primary_line"] = lines[primary]
        stitched[primary]["_member_indexes"] = [i for i in idxs
                                                if i != primary]
        for i in idxs:
            primary_of[i] = primary
            if i != primary:
                roles[i] = "MEMBER"

    return {"roles": roles, "primary_of": primary_of, "stitched": stitched,
            "report": {
                "input_events": len(lines),
                "auditd_records": sum(len(v) for v in groups.values()),
                "stitched_events": len(stitched),
                "passthrough_events": sum(1 for r in roles.values()
                                          if r == "PASSTHROUGH"),
                "complete": sum(1 for s in stitched.values()
                                if s["_completeness"] == "COMPLETE"),
                "partial": sum(1 for s in stitched.values()
                               if s["_completeness"] == "PARTIAL"),
            }}


def stitch_batch(events: list[dict[str, Any]]) -> tuple[list, dict]:
    """Stitch a whole batch. Non-auditd events pass through untouched.

    Returns ``(events_out, report)``. A single-record auditd group still goes
    through stitching so its completeness is stated rather than assumed.
    """
    groups, passthrough = group_records(events)
    stitched = [stitch_group(g) for g in groups]
    out = passthrough + stitched
    report = {
        "input_events": len(events),
        "auditd_records": sum(len(g["records"]) for g in groups),
        "stitched_events": len(stitched),
        "passthrough_events": len(passthrough),
        "complete": sum(1 for s in stitched
                        if s["_completeness"] == "COMPLETE"),
        "partial": sum(1 for s in stitched
                       if s["_completeness"] == "PARTIAL"),
        "duplicates_preserved": sum(len(s["_duplicate_records"])
                                    for s in stitched),
        "unknown_record_types": sorted({t for s in stitched
                                        for t in s["_unknown_record_types"]}),
    }
    return out, report
