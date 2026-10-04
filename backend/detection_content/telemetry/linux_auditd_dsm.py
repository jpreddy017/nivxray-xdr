"""
NivXRay XDR — Linux Auditd DSM, Parser & Normalizer.
Provides native support for Linux Auditd telemetry:
- SYSCALL, EXECVE, and PROCTITLE records
- Deterministic unhexing of hex-encoded arguments and command lines
- Resolving process lineage (exe, pid, ppid), user context (uid, auid, euid), and terminal context.
"""
from __future__ import annotations

import binascii
from datetime import datetime, timezone
import hashlib
import os
import posixpath
import re
from typing import Any, Dict, List, Optional

from services import event_time_basis
from services import tenant_authority

from .auditd_stitcher import kv_fields
from .models import (
    CanonicalTelemetryEvent,
    FileEntity,
    HostEntity,
    IdentityEntity,
    NetworkEntity,
    ProcessEntity,
    ProvenanceEnvelope,
)


class LinuxAuditdParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


# ── D16 · PATH / CWD -> canonical file & directory evidence ─────────
# auditd already delivers this: `type=CWD cwd="/home/u"` names the working
# directory, and one `type=PATH item=N name=… nametype=…` record names EACH
# object the syscall touched. None of it reached canonical evidence before
# D16, so no rule could cite a file path that auditd had actually observed.
#
# Three rules, all of them refusals rather than conveniences:
#   * a path is NEVER invented. A relative name with no observed CWD stays
#     unresolved and says so.
#   * PATH records are NEVER collapsed. Each `item` is kept as its own
#     entry, in item order, with the record that produced it.
#   * auditd does not say whether a NORMAL path is a file or a directory,
#     so the object kind stays NOT_OBSERVED. Only `nametype=PARENT` is
#     recorded as a directory, because that is what auditd means by it.

#: The PATH attributes worth carrying into canonical evidence, verbatim.
_PATH_ATTRS = ("inode", "dev", "mode", "ouid", "ogid", "rdev", "objtype",
               "cap_fp", "cap_fi", "cap_fe", "cap_fver")

#: auditd `nametype` values whose action is unambiguous. NORMAL and UNKNOWN
#: are deliberately absent: they do not name an action.
_NAMETYPE_ACTION = {"CREATE": "create", "DELETE": "delete"}

_UNUSABLE_NAMES = {"", "(null)", "(none)", "-", "?"}


def _path_records(fields: Dict[str, Any], record_type: str
                  ) -> List[Dict[str, Any]]:
    """Every PATH record of this audit event, unmerged, in arrival order.

    A stitched group merges only the FIRST record of each type, so later
    PATH records are re-read from their preserved verbatim lines. That is
    what keeps a multi-PATH event from collapsing into a single path.
    """
    out: List[Dict[str, Any]] = []
    contributing = fields.get("_contributing_records") or []
    for rec in contributing:
        if str(rec.get("record_type") or "").upper() != "PATH":
            continue
        kv = kv_fields(str(rec.get("line") or ""))
        out.append({"kv": kv,
                    "record_ref": {"record_type": "PATH",
                                   "audit_id": rec.get("audit_id"),
                                   "position": rec.get("position", 0),
                                   "line": rec.get("line")}})
    if out or contributing:
        return out
    # Unstitched delivery: a lone PATH record, already flattened by the
    # parser. Its own fields ARE the record.
    if record_type == "PATH":
        out.append({"kv": {k: v for k, v in fields.items()
                           if isinstance(v, str)},
                    "record_ref": {"record_type": "PATH",
                                   "audit_id": fields.get("audit_id"),
                                   "position": 0,
                                   "line": str(fields.get("message")
                                               or fields.get("line") or "")}})
    return out


def _entry(kv: Dict[str, Any], record_ref: Dict[str, Any],
           cwd: Optional[str]) -> Dict[str, Any]:
    """One PATH record, mapped without inventing anything."""
    name = _unhex_if_needed(str(kv.get("name") or ""))
    nametype = str(kv.get("nametype") or "").upper()
    item: Optional[int]
    try:
        item = int(kv.get("item"))
    except (TypeError, ValueError):
        item = None

    entry: Dict[str, Any] = {
        "item": item,
        "path": name or None,
        "name": posixpath.basename(name) if name else None,
        "nametype": nametype or None,
        "kind": ("DIRECTORY" if nametype == "PARENT" else "PATH_OBJECT"),
        "kind_state": ("OBSERVED" if nametype == "PARENT"
                       else "OBJECT_KIND_NOT_OBSERVED"),
        "kind_reason": (None if nametype == "PARENT" else
                        "auditd names the path but not whether the object "
                        "is a file or a directory; only nametype=PARENT "
                        "states a directory"),
        "action": _NAMETYPE_ACTION.get(nametype) or None,
        "action_basis": (f"auditd:PATH nametype={nametype}"
                         if nametype in _NAMETYPE_ACTION else None),
        "action_state": ("OBSERVED" if nametype in _NAMETYPE_ACTION
                         else "NOT_OBSERVED"),
        "record_ref": record_ref,
    }
    for attr in _PATH_ATTRS:
        if kv.get(attr) is not None:
            entry[attr] = kv[attr]

    if not name or name in _UNUSABLE_NAMES:
        entry.update({
            "path": None,
            "name": None,
            "path_state": "NOT_OBSERVED",
            "path_not_observed_reason": (
                f"this PATH record carried no usable name "
                f"({name!r} means absent to auditd); a path is never "
                "substituted from another record"),
            "absolute_path": None,
            "absolute_path_state": "NOT_RESOLVABLE",
        })
        return entry

    entry["path_state"] = "OBSERVED"
    if name.startswith("/"):
        entry.update({"absolute_path": posixpath.normpath(name),
                      "absolute_path_basis": "VERBATIM_ABSOLUTE",
                      "absolute_path_state": "OBSERVED"})
    elif cwd:
        # Derived, and labelled as derived: auditd emitted a relative name
        # and a working directory, and joining them is the only thing that
        # makes the two records mean anything together. The filesystem is
        # never consulted — no realpath, no symlink resolution, no stat.
        entry.update({
            "absolute_path": posixpath.normpath(posixpath.join(cwd, name)),
            "absolute_path_basis": "DERIVED_FROM_OBSERVED_CWD",
            "absolute_path_state": "DERIVED",
            "absolute_path_resolved_from": {"cwd": cwd, "relative_name": name},
        })
    else:
        entry.update({
            "absolute_path": None,
            "absolute_path_basis": None,
            "absolute_path_state": "NOT_RESOLVABLE",
            "absolute_path_not_resolvable_reason": (
                "the PATH name is relative and no CWD record was delivered "
                "for this audit event; an absolute path is NOT guessed"),
        })
    return entry


def _project_paths(fields: Dict[str, Any], record_type: str
                   ) -> Dict[str, Any]:
    """``{file_entity, mapping}`` — canonical file/directory evidence.

    `mapping` is the per-field provenance: where the working directory came
    from, every PATH item with its own record reference, and why a primary
    file was or was not chosen.
    """
    attribution = fields.get("_canonical_attribution") or {}
    raw_cwd = _unhex_if_needed(str(fields.get("cwd") or ""))
    cwd_ok = bool(raw_cwd) and raw_cwd not in _UNUSABLE_NAMES
    cwd_block: Dict[str, Any]
    if cwd_ok:
        cwd_block = {
            "path": raw_cwd,
            "state": "OBSERVED",
            "source": "auditd:CWD cwd=",
            "source_record": attribution.get("working_directory")
            or ("CWD" if record_type == "CWD" else None),
        }
    else:
        cwd_block = {
            "path": None,
            "state": "NOT_OBSERVED",
            "reason": ("no CWD record was delivered for this audit event; "
                       "the working directory is unknown, not '/'"),
        }

    records = _path_records(fields, record_type)
    items = [_entry(r["kv"], r["record_ref"], raw_cwd if cwd_ok else None)
             for r in records]
    items.sort(key=lambda e: (e["item"] is None, e["item"] or 0,
                              e["record_ref"].get("position") or 0))

    directories = [e for e in items if e["kind"] == "DIRECTORY"
                   and e["path_state"] == "OBSERVED"]
    objects = [e for e in items if e["kind"] != "DIRECTORY"
               and e["path_state"] == "OBSERVED"]
    unusable = [e for e in items if e["path_state"] != "OBSERVED"]

    primary = objects[0] if objects else None
    if primary is not None:
        basis = ("LOWEST_PATH_ITEM_EXCLUDING_PARENT"
                 if len(objects) > 1 else "SINGLE_PATH_OBJECT")
    else:
        basis = None

    mapping: Dict[str, Any] = {
        "working_directory": cwd_block,
        "path_records_observed": len(records),
        "path_items": items,
        "directory_paths": [e["absolute_path"] or e["path"]
                            for e in directories],
        "primary_file_basis": basis,
        "unusable_path_records": len(unusable),
        "collapse_note": (
            "every PATH record is kept as its own item, in item order, with "
            "the record that produced it; several paths are never merged "
            "into one, and the canonical `file` entity names ONLY the "
            "primary item"),
    }
    if primary is None:
        mapping["primary_file_reason"] = (
            "no PATH record delivered a usable non-parent path, so the "
            "canonical file entity stays empty rather than naming a "
            "directory or an invented path"
            if records else
            "this audit event delivered no PATH record")

    file_entity = FileEntity()
    if primary is not None:
        file_entity = FileEntity(
            path=primary["absolute_path"] or primary["path"] or "",
            name=primary["name"] or "",
            action=primary["action"] or "",
        )
        mapping["file_path_state"] = (
            "OBSERVED" if primary["absolute_path_state"] == "OBSERVED"
            else primary["absolute_path_state"])
        mapping["file_path_item"] = primary["item"]
        mapping["file_path_record_ref"] = primary["record_ref"]
    return {"file": file_entity, "mapping": mapping}


def _unhex_if_needed(s: str) -> str:
    """Unhex hex-encoded string if valid hex without whitespace."""
    s = s.strip().strip('"')
    if len(s) > 2 and len(s) % 2 == 0 and re.match(r"^[0-9a-fA-F]+$", s):
        try:
            decoded = binascii.unhexlify(s).decode("utf-8", errors="replace")
            # If it decoded into printable characters or null-separated args
            if any(c.isalnum() for c in decoded):
                return decoded.replace("\x00", " ").strip()
        except Exception:
            pass
    return s


class LinuxAuditdParser:
    id = "linux-auditd-parser"

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ev, dict):
            raise LinuxAuditdParserError("INVALID_EVENT", "Event is not a JSON/dict object")

        # May receive pre-parsed dict or raw auditd line in "message" / "raw"
        raw_msg = ev.get("message") or ev.get("raw") or ""
        parsed_fields: Dict[str, Any] = dict(ev)

        if isinstance(raw_msg, str) and "type=" in raw_msg:
            # Parse auditd key=value pairs: type=SYSCALL msg=audit(1693829482.123:456): arch=c000003e syscall=59 ...
            kv_pairs = re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]+))', raw_msg)
            for k, v_quoted, v_bare in kv_pairs:
                val = v_quoted if v_quoted else v_bare
                parsed_fields[k] = val

            # Parse timestamp from msg=audit(TIMESTAMP:ID)
            m = re.search(r"audit\((\d+(?:\.\d+)?):(\d+)\)", raw_msg)
            if m:
                epoch = float(m.group(1))
                parsed_fields["timestamp"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
                parsed_fields["audit_id"] = m.group(2)
                # D11 · the audit header IS the kernel's record of when the
                # activity happened. Marked as such so the normalizer can
                # tell it apart from any other `timestamp` key that merely
                # rode in on the envelope.
                parsed_fields["_audit_epoch"] = m.group(1)
                parsed_fields["_audit_timestamp_state"] = "OBSERVED"
            elif "audit(" in raw_msg:
                # The header is there and we could not read it. That is a
                # broken source, not an absent one, and it must not quietly
                # look the same as a record that never carried a time.
                parsed_fields["_audit_timestamp_state"] = "MALFORMED"
            else:
                parsed_fields["_audit_timestamp_state"] = "ABSENT"

        record_type = str(parsed_fields.get("type") or parsed_fields.get("record_type") or "").upper()
        if not record_type and "syscall" not in parsed_fields and "exe" not in parsed_fields:
            raise LinuxAuditdParserError("UNRECOGNIZED_AUDITD", "Event lacks auditd type, syscall, or exe markers")

        return {
            "parser_id": self.id,
            "raw": ev,
            "record_type": record_type or "SYSCALL",
            "fields": parsed_fields,
        }


class LinuxAuditdNormalizer:
    id = "linux-auditd-normalizer"

    def normalize(
        self,
        parsed: Dict[str, Any],
        dsm_id: str,
        collector_id: str,
        integration_id: str,
        trace_id: str,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        raw = parsed["raw"]
        # D14 · the authenticated delivery is the only authority. A tenant
        # named in the payload is recorded as an untrusted claim and used
        # for nothing — including the deterministic event_id below.
        resolved_tenant, _tenant_claim = tenant_authority.resolve(
            tenant_id, *tenant_authority.payload_claims(raw))

        fields = parsed["fields"]
        now_iso = datetime.now(timezone.utc).isoformat()

        # ── D2 · host identity, from authoritative telemetry only ───
        # Declared precedence, strongest source first. Every value records
        # WHERE it came from, and nothing is invented: no localhost, no
        # default placeholder, no tenant name, and never the collector's own
        # identity standing in for the endpoint.
        raw_dict = raw if isinstance(raw, dict) else {}
        node = str(fields.get("node") or "").strip()
        envelope_source = str(raw_dict.get("source")
                              or fields.get("source") or "").strip()
        explicit_host = str(fields.get("host")
                            or fields.get("hostname") or "").strip()

        _REJECT = {"localhost", "localhost.localdomain", "127.0.0.1",
                   "::1", "unknown", "default", "-", "none", "null"}

        def _usable(v: str) -> bool:
            return bool(v) and v.lower() not in _REJECT

        if _usable(explicit_host):
            hostname, host_source = explicit_host, "auditd:host"
        elif _usable(node):
            # auditd's own host naming (`name_format=hostname`) — the
            # endpoint naming itself, not an inference.
            hostname, host_source = node, "auditd:node"
        elif _usable(envelope_source):
            # The collector's label for the ORIGIN of this record. For a
            # syslog collector the source IS the sending host, which is the
            # explicit semantic justification for using it. It is recorded
            # as `collector:envelope.source` so an analyst can see it is the
            # transport's view of the origin, not the endpoint's own claim.
            hostname, host_source = envelope_source, "collector:envelope.source"
        else:
            hostname, host_source = "", None

        host = HostEntity(
            hostname=hostname,
            host_id=hostname,
            os_family="linux",
        )

        # Process extraction
        exe = _unhex_if_needed(str(fields.get("exe") or ""))
        comm = _unhex_if_needed(str(fields.get("comm") or ""))
        proctitle = _unhex_if_needed(str(fields.get("proctitle") or ""))

        # Assemble argv arguments if present (a0, a1, a2, ...)
        argv: List[str] = []
        i = 0
        while f"a{i}" in fields:
            arg_val = _unhex_if_needed(str(fields[f"a{i}"]))
            argv.append(arg_val)
            i += 1

        # D4 · declared field precedence. EXECVE argv is the authoritative
        # execution vector; PROCTITLE is a truncated display string (the
        # real `curl ... | bash` argv arrives as argv, while proctitle
        # decodes to just "/bin/bash -c"). For a stitched group argv
        # therefore wins, with proctitle as fallback only. The unstitched
        # path keeps its previous order — correcting that belongs to the
        # D3/D2 auditd gate, not here.
        if fields.get("_stitched"):
            cmd_line = " ".join(argv) or proctitle or comm or exe
            cmd_source = ("EXECVE" if argv else
                          "PROCTITLE" if proctitle else
                          "SYSCALL" if (comm or exe) else None)
        else:
            cmd_line = proctitle or " ".join(argv) or comm or exe
            cmd_source = None
        proc_name = os.path.basename(exe) if exe else comm

        pid: Optional[int] = None
        if "pid" in fields:
            try:
                pid = int(fields["pid"])
            except Exception:
                pass

        ppid: Optional[int] = None
        if "ppid" in fields:
            try:
                ppid = int(fields["ppid"])
            except Exception:
                pass

        process = ProcessEntity(
            name=proc_name or "unknown",
            executable_path=exe,
            command_line=cmd_line,
            pid=pid,
            ppid=ppid,
        )

        # ── D2 · user identity, on BOTH paths ───────────────────────
        # The old code produced `username="uid:"` with
        # `is_privileged=False` whenever no uid was present — asserting an
        # unprivileged actor on no evidence. Identity is now either observed
        # or explicitly NOT_OBSERVED, and the unstitched path behaves exactly
        # like the stitched one so it cannot become a second, weaker truth.
        uid = str(fields.get("uid") or "")
        auid = str(fields.get("auid") or "")
        euid = str(fields.get("euid") or "")
        user_name = str(fields.get("user") or fields.get("username") or "")
        identity_observed = bool(user_name or uid or auid or euid)
        if not user_name and identity_observed:
            user_name = "root" if (uid == "0" or auid == "0") \
                else f"uid:{uid or auid or euid}"

        if identity_observed:
            identity = IdentityEntity(
                principal_id=user_name,
                username=user_name,
                is_privileged=(uid == "0" or euid == "0" or auid == "0"),
            )
        else:
            identity = IdentityEntity(
                principal_id="", username="", is_privileged=False)

        # ── D4 · stitch provenance and honest partials ──────────────
        stitched = bool(fields.get("_stitched"))
        contributing = fields.get("_contributing_records") or []
        completeness = fields.get("_completeness")
        missing_records = fields.get("_missing_records") or []
        identity_source = (fields.get("_canonical_attribution")
                           or {}).get("identity")
        if stitched and not identity_observed:
            # No record in the group supplied identity — almost always a
            # SYSCALL that never arrived. Reporting `uid:` and
            # `is_privileged=False` here would be a fabricated claim that an
            # unprivileged user did this. Say we did not observe it.
            identity = IdentityEntity(
                principal_id="",
                username="",
                is_privileged=False,
            )

        # ── D11/D12 · activity time, from the audit header or not at all ──
        # `msg=audit(epoch:serial)` is the kernel's own record of when the
        # syscall happened. Only that value may become activity time. Any
        # other `timestamp` key rode in on an envelope and its origin cannot
        # be verified, so it is never promoted to activity time. The shared
        # resolver enforces that consequence; this DSM only declares what
        # its own wire format proves.
        audit_ts_state = str(fields.get("_audit_timestamp_state")
                             or "NOT_DETERMINED")
        _audit_ts = fields.get("timestamp") \
            if audit_ts_state == "OBSERVED" else None
        _other_ts = None if _audit_ts else (fields.get("timestamp")
                                            or raw.get("timestamp"))
        etb = event_time_basis.resolve(
            activity=([(_audit_ts, "auditd:msg=audit(epoch:serial)")]
                      if _audit_ts else ()),
            supplied=([(_other_ts,
                        "raw:timestamp — supplied by the delivery, not "
                        "readable from the audit header, so its origin "
                        "cannot be verified as activity time")]
                      if _other_ts else ()),
            clock=now_iso,
            clock_source=f"pipeline:normalizer clock at {self.id}",
            activity_absent_reason=(
                "no readable audit activity time: "
                f"audit_timestamp_state={audit_ts_state}; "
                "the substituted event_time is NOT activity time"),
            observation_absent_reason=(
                "auditd emits no separate daemon observation time; only the "
                "kernel activity time is recorded in the record itself"))
        event_time = etb.event_time

        provenance = ProvenanceEnvelope(
            trace_id=trace_id,
            collector_id=collector_id,
            integration_id=integration_id,
            dsm_id=dsm_id,
            parser_id=LinuxAuditdParser.id,
            normalizer_id=self.id,
            ingest_time=now_iso,
        )

        record_types = fields.get("_record_types") or [parsed["record_type"]]
        # D16 · PATH / CWD -> canonical file & directory evidence.
        _paths = _project_paths(fields, parsed["record_type"])
        # D3 · an EXECVE record IS an execution, whether it arrived as part
        # of a stitched group or on its own. The old branch required
        # `syscall` or `exe`, neither of which an EXECVE record carries, so
        # a lone EXECVE was mislabelled `auditd_syscall`.
        if "EXECVE" in record_types:
            event_type = "process_execution"
        elif "execve" in str(fields.get("syscall", "")).lower() or exe:
            event_type = "process_execution"
        elif parsed["record_type"] in ("PATH", "CWD") \
                and len(record_types) == 1:
            # D16 · a PATH or CWD record delivered on its own is real auditd
            # evidence, and it is labelled as the fragment it is instead of
            # being refused as "not auditd" or dressed up as a syscall.
            event_type = ("auditd_path_record"
                          if parsed["record_type"] == "PATH"
                          else "auditd_cwd_record")
        else:
            event_type = "auditd_syscall"

        # D10 · deterministic identity on BOTH paths, so replaying the same
        # logical evidence can never create a second security object.
        #   stitched   -> (tenant, collector, audit identity)
        #   unstitched -> (tenant, collector, audit identity, record type)
        #                 record type is included so a lone SYSCALL and a
        #                 lone EXECVE of the SAME audit event stay distinct
        #                 rather than collapsing into one.
        #   no audit id -> hash of the verbatim line, still deterministic.
        # Tenant and collector are always part of the material, so two
        # tenants can never collide into one canonical event.
        audit_identity = (fields.get("_audit_identity")
                          or fields.get("audit_id") or "")
        if stitched and audit_identity:
            id_material = f"{resolved_tenant}|{collector_id}|{audit_identity}"
            id_basis = "tenant+collector+audit_identity"
        elif audit_identity:
            id_material = (f"{resolved_tenant}|{collector_id}|"
                           f"{audit_identity}|{parsed['record_type']}")
            id_basis = "tenant+collector+audit_identity+record_type"
        else:
            verbatim = str(raw_dict.get("message") or raw_dict.get("line")
                           or raw_dict.get("raw") or "")
            id_material = (f"{resolved_tenant}|{collector_id}|"
                           f"verbatim|{verbatim}")
            id_basis = "tenant+collector+verbatim_line"
        event_id = "cev_auditd_" + hashlib.sha256(
            id_material.encode()).hexdigest()[:24]

        extra: Dict[str, Any] = {
            "syscall": fields.get("syscall"),
            "record_type": parsed["record_type"],
            # D2 provenance — where the host name came from, or that it was
            # never observed.
            "host_identity_source": host_source,
            "host_identity_state": ("OBSERVED" if hostname
                                    else "NOT_OBSERVED"),
            # D2 provenance — identity, on both paths.
            "identity_observed": identity_observed,
            "identity_state": ("OBSERVED" if identity_observed
                               else "NOT_OBSERVED"),
            # D10 provenance — what the canonical identity was derived from.
            "event_id_basis": id_basis,
            # D11 provenance — what `event_time` actually means here is
            # published by the shared basis resolver; this is the auditd
            # -specific reason behind it.
            "audit_timestamp_state": audit_ts_state,
            # D16 provenance — the working directory, every PATH item and
            # the record each one came from.
            "path_mapping": _paths["mapping"],
            "working_directory": _paths["mapping"]["working_directory"],
        }
        if event_type in ("auditd_path_record", "auditd_cwd_record"):
            extra["fragment_state"] = "STANDALONE_RECORD_NO_PROCESS_CONTEXT"
            extra["fragment_reason"] = (
                "this record arrived without the SYSCALL/EXECVE records of "
                "its audit event, so process and identity context were "
                "never delivered — they are absent, not unprivileged")
        if not hostname:
            extra["host_not_observed_reason"] = (
                "no authoritative host name was available: the audit record "
                "carried no node/host field and the collector supplied no "
                "origin label; a placeholder would be a fabricated claim")
        if not identity_observed:
            extra["identity_not_observed_reason"] = (
                "no contributing audit record supplied uid/auid/euid; "
                "privilege is unknown, not unprivileged")
        if stitched:
            extra.update({
                "stitched": True,
                "stitch_audit_identity": audit_identity,
                "stitch_record_types": record_types,
                "stitch_completeness": completeness,
                "stitch_missing_records": missing_records,
                "stitch_contributing_records": contributing,
                "stitch_field_attribution": fields.get("_field_attribution"),
                "stitch_canonical_attribution":
                    fields.get("_canonical_attribution"),
                "stitch_duplicate_records":
                    fields.get("_duplicate_records") or [],
                "stitch_unknown_record_types":
                    fields.get("_unknown_record_types") or [],
                "identity_source_record": identity_source,
                "command_line_source_record": cmd_source,
            })

        canonical = CanonicalTelemetryEvent(
            event_id=event_id,
            tenant_id=resolved_tenant,
            source_vendor="Linux",
            source_product="Auditd",
            source_event_id=str(audit_identity
                                or fields.get("audit_id")
                                or fields.get("syscall") or "auditd"),
            event_type=event_type,
            event_time=str(event_time),
            ingest_time=now_iso,
            host=host,
            identity=identity,
            process=process,
            file=_paths["file"],
            raw_ref=raw,
            provenance=provenance,
            additional_fields=extra,
        )
        out = canonical.to_dict()
        tenant_authority.record(out, _tenant_claim)
        # ── D11/D12 · seed the eight boundaries, so a gap is visible ──
        # Only the two this normalizer can honestly speak for are filled,
        # and the resolver guarantees `activity_occurred_at` is measured
        # only when the basis is ACTIVITY_TIME. The transport boundaries are
        # the ingest handler's to measure and the pipeline stamps its own.
        event_time_basis.apply(out, etb)
        if stitched:
            # Every contributing raw record is referenced from the canonical
            # event, so an analyst can walk citation -> canonical field ->
            # stitched event -> the original audit record.
            out["evidence_refs"] = [
                {"record_type": r.get("record_type"),
                 "audit_id": r.get("audit_id"),
                 "line": r.get("line"),
                 "position": r.get("position")}
                for r in contributing]
        return out


class LinuxAuditdDSM:
    id = "linux-auditd"
    vendor = "Linux"
    product = "Linux Auditd"
    version = "1"
    source_type = "ENDPOINT_AUDIT"

    def supports(self, ev: Dict[str, Any]) -> bool:
        if not isinstance(ev, dict):
            return False
        # Direct key checks
        if ev.get("type") in ("SYSCALL", "EXECVE", "PROCTITLE", "AVC",
                              "CWD", "PATH"):
            return True
        if "syscall" in ev and ("exe" in ev or "comm" in ev):
            return True
        # Check raw string
        msg = str(ev.get("message") or ev.get("raw") or "")
        # D16 · CWD and PATH are auditd records too. Refusing them as "not
        # auditd" discarded the only file evidence the source ever sent.
        return any(f"type={t}" in msg for t in
                   ("SYSCALL", "EXECVE", "PROCTITLE", "CWD", "PATH"))

    def select_parser(self) -> LinuxAuditdParser:
        return LinuxAuditdParser()

    def select_normalizer(self) -> LinuxAuditdNormalizer:
        return LinuxAuditdNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "source_type": self.source_type,
        }
