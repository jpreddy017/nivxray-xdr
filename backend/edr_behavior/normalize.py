"""Adapters: current runtime canonical shape (M1 canonical_bridge / windows_eventlog) -> EvidenceRecord.

Tenant and endpoint always come from the authenticated context, never the payload.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .contracts import (KIND_AUTH, KIND_DETECTION, KIND_DNS, KIND_FILE,
                        KIND_NETWORK, KIND_PROCESS, KIND_PROCESS_TERMINATION,
                        KIND_REGISTRY, STORE_UNSPECIFIED, STORES, EvidenceRecord,
                        EvidenceRef, MLSignal, ProcessRef)

NORMALIZER_ID = "edr_behavior.normalize.canonical_v1"
MAX_STR = 8192
MAX_LIST = 64
MAX_FUTURE_SKEW = timedelta(seconds=300)
_KINDS = {"PROCESS": KIND_PROCESS, "PROCESS_TERMINATION": KIND_PROCESS_TERMINATION,
          "FILE": KIND_FILE, "NETWORK": KIND_NETWORK, "REGISTRY": KIND_REGISTRY,
          "DNS": KIND_DNS, "AUTHENTICATION": KIND_AUTH, "AUTH": KIND_AUTH}


class NormalizationError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def parse_time(v: Any) -> Optional[datetime]:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if not isinstance(v, str) or not v or len(v) > 64:
        return None
    s = v.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class _Bounded:
    def __init__(self) -> None:
        self.truncated: List[str] = []

    def s(self, v: Any, path: str) -> Optional[str]:
        if v is None or isinstance(v, (dict, list, bool)):
            return None
        out = str(v)
        if not out:
            return None
        if len(out) > MAX_STR:
            self.truncated.append(path)
            out = out[:MAX_STR]
        return out

    def lst(self, v: Any, path: str) -> Optional[List[str]]:
        if not isinstance(v, list):
            return None
        if len(v) > MAX_LIST:
            self.truncated.append(path)
        vals = [self.s(x, path) for x in v[:MAX_LIST]]
        return [x for x in vals if x] or None


def _base(p: Optional[str]) -> Optional[str]:
    return p.replace("\\", "/").rsplit("/", 1)[-1] if p else None


def _clean(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


def _kind(c: Dict[str, Any]) -> str:
    act = c.get("activity") or (c.get("additional_fields") or {}).get("activity_type")
    k = _KINDS.get(str(act or "").upper())
    if not k:
        raise NormalizationError("UNSUPPORTED_KIND", str(act)[:64])
    return k


def from_canonical(canonical: Dict[str, Any], *, tenant_id: str, endpoint_id: str,
                   raw_id: str, canonical_event_id: Optional[str] = None,
                   generation: Optional[int] = None, store: str = STORE_UNSPECIFIED,
                   record_id: Optional[str] = None, sub_key: Optional[str] = None,
                   now: Optional[datetime] = None) -> EvidenceRecord:
    if not isinstance(canonical, dict):
        raise NormalizationError("MALFORMED", "canonical is not an object")
    for name, v in (("tenant_id", tenant_id), ("endpoint_id", endpoint_id), ("raw_id", raw_id)):
        if not isinstance(v, str) or not v or len(v) > 256:
            raise NormalizationError("MISSING_CONTEXT", name)
    claimed = canonical.get("tenant_id")
    if claimed not in (None, "", tenant_id):
        raise NormalizationError("TENANT_MISMATCH", "payload tenant differs from authenticated tenant")
    if store not in STORES:
        raise NormalizationError("MALFORMED", "unknown store tag")
    kind = _kind(canonical)
    ts = parse_time(canonical.get("event_time")) or parse_time(canonical.get("activity_time"))
    if ts is None:
        raise NormalizationError("MISSING_EVENT_TIME")
    now = now or datetime.now(timezone.utc)
    if ts > now + MAX_FUTURE_SKEW:
        raise NormalizationError("TIMESTAMP_UNTRUSTED", "event_time beyond allowed future skew")
    b = _Bounded()
    proc = canonical.get("process") or {}
    ident = canonical.get("identity") or {}
    file_ = canonical.get("file") or {}
    net = canonical.get("network") or {}
    reg = canonical.get("registry") or {}
    dns = canonical.get("dns") or {}
    auth = canonical.get("authentication") or {}
    exe = b.s(proc.get("executable_path"), "process.executable_path")
    pexe = b.s(proc.get("parent_executable_path"), "parent.executable_path")
    fpath = b.s(file_.get("path"), "file.path")
    fields = {
        "process": _clean({
            "name": _base(exe) or b.s(proc.get("name"), "process.name"),
            "executable_path": exe,
            "command_line": b.s(proc.get("command_line"), "process.command_line"),
            "sha256": b.s((proc.get("hashes") or {}).get("sha256"), "process.sha256"),
            "signer": b.s(proc.get("signer"), "process.signer"),
            "integrity_level": b.s(proc.get("integrity_level"), "process.integrity_level"),
            "original_file_name": b.s(proc.get("original_file_name"), "process.original_file_name"),
            "current_directory": b.s(proc.get("current_directory"), "process.current_directory"),
        }),
        "parent": _clean({
            "name": _base(pexe) or b.s(proc.get("parent_name"), "parent.name"),
            "executable_path": pexe,
            "command_line": b.s(proc.get("parent_command_line"), "parent.command_line"),
        }),
        "file": _clean({"path": fpath, "name": _base(fpath) or b.s(file_.get("name"), "file.name"),
                        "operation": b.s(file_.get("operation"), "file.operation"),
                        "sha256": b.s((file_.get("hashes") or {}).get("sha256"), "file.sha256"),
                        "signer": b.s(file_.get("signer"), "file.signer")}),
        "registry": _clean({"key": b.s(reg.get("key"), "registry.key"),
                            "value_data": b.s(reg.get("value_data"), "registry.value_data"),
                            "operation": b.s(reg.get("operation"), "registry.operation")}),
        "dns": _clean({"query_name": b.s(dns.get("query_name"), "dns.query_name"),
                       "answers": b.lst(dns.get("answers"), "dns.answers")}),
        "network": _clean({"dest_ip": b.s(net.get("dest_ip"), "network.dest_ip"),
                           "dest_port": b.s(net.get("dest_port"), "network.dest_port"),
                           "src_ip": b.s(net.get("src_ip"), "network.src_ip"),
                           "protocol": b.s(net.get("protocol"), "network.protocol"),
                           "direction": b.s(net.get("direction"), "network.direction"),
                           "dest_hostname": b.s(net.get("dest_hostname"), "network.dest_hostname")}),
        "auth": _clean({"logon_type": b.s(auth.get("logon_type"), "auth.logon_type"),
                        "outcome": b.s(auth.get("outcome"), "auth.outcome"),
                        "target_user": b.s(auth.get("target_user"), "auth.target_user"),
                        "source_ip": b.s(auth.get("source_ip"), "auth.source_ip"),
                        "logon_id": b.s(auth.get("target_logon_id"), "auth.logon_id")}),
        "user": _clean({"name": b.s(ident.get("username"), "user.name")}),
    }
    pref = None
    if proc:
        pref = ProcessRef(process_iid=b.s(proc.get("process_iid"), "process.process_iid"),
                          pid=b.s(proc.get("pid"), "process.pid"),
                          process_guid=b.s(proc.get("process_guid"), "process.process_guid"),
                          parent_pid=b.s(proc.get("parent_pid") or proc.get("ppid"), "process.parent_pid"),
                          parent_process_guid=b.s(proc.get("parent_process_guid"), "process.parent_process_guid"),
                          start_time=b.s(proc.get("start_time"), "process.start_time"),
                          attribution_state=b.s(proc.get("attribution_state"), "process.attribution_state"))
    epi = (canonical.get("additional_fields") or {}).get("epistemic_state") or {}
    not_obs = tuple(str(x)[:128] for x in (canonical.get("not_observed") or epi.get("not_observed") or [])[:MAX_LIST])
    not_sup = tuple(str(x)[:128] for x in (epi.get("not_supported") or [])[:MAX_LIST])
    ref = EvidenceRef(tenant_id=tenant_id, raw_id=raw_id, canonical_event_id=canonical_event_id,
                      generation=generation, store=store, record_id=record_id, sub_key=sub_key)
    return EvidenceRecord(tenant_id=tenant_id, endpoint_id=endpoint_id, kind=kind, event_time=ts,
                          ref=ref, fields={k: v for k, v in fields.items() if v}, process=pref,
                          source=str(canonical.get("source_product") or "")[:64],
                          not_observed=not_obs, not_supported=not_sup,
                          truncated_fields=tuple(b.truncated),
                          provenance={"normalizer": NORMALIZER_ID,
                                      "process_identity_authority": "edr_plane.canonical_bridge.bind_process_identity"})


def from_detection_observation(obs: Dict[str, Any], *, tenant_id: str, endpoint_id: str,
                               raw_id: str, canonical_event_id: Optional[str] = None,
                               process: Optional[ProcessRef] = None) -> EvidenceRecord:
    """A prior detection (e.g. an existing rule match or ML signal) as DETECTION evidence."""
    ts = parse_time(obs.get("event_time"))
    if ts is None:
        raise NormalizationError("MISSING_EVENT_TIME")
    b = _Bounded()
    mitre = b.lst([str(m) for m in (obs.get("mitre") or []) if isinstance(m, (str, int))], "detection.mitre")
    fields = {"detection": _clean({"rule_id": b.s(obs.get("rule_id"), "detection.rule_id"),
                                   "name": b.s(obs.get("name"), "detection.name"),
                                   "source": b.s(obs.get("source"), "detection.source"),
                                   "severity": b.s(obs.get("severity"), "detection.severity"),
                                   "mitre": mitre})}
    return EvidenceRecord(tenant_id=tenant_id, endpoint_id=endpoint_id, kind=KIND_DETECTION,
                          event_time=ts, ref=EvidenceRef(tenant_id, raw_id, canonical_event_id,
                                                         sub_key=str(obs.get("rule_id") or "")[:64]),
                          fields=fields, process=process, source="detection",
                          truncated_fields=tuple(b.truncated),
                          provenance={"normalizer": NORMALIZER_ID + ".detection"})


def from_ml_signal(sig: MLSignal, *, endpoint_id: str) -> EvidenceRecord:
    """ML boundary: a signal becomes DETECTION evidence; it never becomes a verdict itself."""
    first = sig.evidence_refs[0]
    return EvidenceRecord(
        tenant_id=first.tenant_id, endpoint_id=endpoint_id, kind=KIND_DETECTION,
        event_time=sig.inference_time, ref=EvidenceRef(first.tenant_id, first.raw_id,
                                                       first.canonical_event_id,
                                                       sub_key=f"ml:{sig.model_id}:{sig.model_version}"),
        fields={"detection": {"rule_id": f"ml:{sig.model_id}", "source": "ML",
                              "name": f"{sig.model_id}@{sig.model_version}",
                              "score": round(float(sig.score), 4)}},
        source="ml", provenance={"model_id": sig.model_id, "model_version": sig.model_version,
                                 "feature_schema_version": sig.feature_schema_version,
                                 "evidence": [r.stable_key() for r in sig.evidence_refs]})


def scope_key(rec: EvidenceRecord, scope: str) -> Tuple[str, bool]:
    """(key, authoritative). Falls back to the evidence key, never to a guess."""
    if scope == "device":
        return f"device:{rec.endpoint_id}", True
    if scope == "process" and rec.process and rec.process.process_iid:
        return f"process:{rec.process.process_iid}", True
    if scope == "user":
        u = (rec.fields.get("user") or {}).get("name")
        if u:
            return f"user:{u.lower()}", True
    if scope == "file":
        f = rec.fields.get("file") or {}
        if f.get("sha256"):
            return f"file:{f['sha256'].lower()}", True
        if f.get("path"):
            return f"path:{f['path'].lower()}", True
    return f"evidence:{rec.stable_key}", False
