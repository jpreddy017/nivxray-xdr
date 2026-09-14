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
import re
from typing import Any, Dict, List, Optional

from services import event_time_basis
from services import tenant_authority

from .models import (
    CanonicalTelemetryEvent,
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
        # D3 · an EXECVE record IS an execution, whether it arrived as part
        # of a stitched group or on its own. The old branch required
        # `syscall` or `exe`, neither of which an EXECVE record carries, so
        # a lone EXECVE was mislabelled `auditd_syscall`.
        if "EXECVE" in record_types:
            event_type = "process_execution"
        elif "execve" in str(fields.get("syscall", "")).lower() or exe:
            event_type = "process_execution"
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
        }
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
        if ev.get("type") in ("SYSCALL", "EXECVE", "PROCTITLE", "AVC"):
            return True
        if "syscall" in ev and ("exe" in ev or "comm" in ev):
            return True
        # Check raw string
        msg = str(ev.get("message") or ev.get("raw") or "")
        return "type=SYSCALL" in msg or "type=EXECVE" in msg or "type=PROCTITLE" in msg

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
