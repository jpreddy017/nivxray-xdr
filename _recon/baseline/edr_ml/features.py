"""Bounded, windowed feature extraction over the existing edr_behavior EvidenceProvider."""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Sequence

from edr_behavior.contracts import (KIND_DNS, KIND_NETWORK, KIND_PROCESS, KIND_REGISTRY,
                                    EvidenceRecord, EvidenceRef)
from edr_behavior.predicates import get_field
from edr_behavior.provider import EvidenceProvider, dedupe

from .baseline import Baseline, BaselineConfig, BaselineStore, inbound
from .safe import MAX_ENTROPY_CHARS, MAX_KEY_TEXT, clamp01, entropy, r6, text, time_ok, token
from .schema import COLD, KNOWN, UNKNOWN, FeatureSchema, FeatureSpec, FeatureValue, FeatureVector, SchemaError

PERSISTENCE_KEYS = ("/currentversion/run", "/currentversion/runonce", "/currentversion/winlogon",
                    "/currentcontrolset/services/", "/image file execution options/",
                    "/currentversion/explorer/shell folders", "/policies/explorer/run",
                    "/currentversion/windows/appinit_dlls")
POWERSHELL = ("powershell.exe", "pwsh.exe", "powershell", "pwsh")
B64 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
B64_RUN = 100


class MLInputError(ValueError):
    pass


@dataclass
class _Ctx:
    rec: EvidenceRecord
    events: List[EvidenceRecord]
    ent: List[EvidenceRecord]
    proc: Optional[EvidenceRecord]
    ep_base: Optional[Baseline]
    tn_base: Optional[Baseline]
    cfg: BaselineConfig
    truncated: bool
    max_refs: int

    def base(self, spec: FeatureSpec) -> Optional[Baseline]:
        return {"endpoint": self.ep_base, "tenant": self.tn_base}.get(spec.baseline)


def _fv(ctx: _Ctx, spec: FeatureSpec, state: str, value: Optional[float] = None,
        refs: Sequence[EvidenceRef] = (), baseline: Optional[dict] = None, reason: str = "") -> FeatureValue:
    anchor = ctx.rec.ref
    extra = sorted({r.stable_key(): r for r in refs if r.stable_key() != anchor.stable_key()}.items())
    return FeatureValue(spec.name, state, r6(value) if state == KNOWN else None,
                        (anchor,) + tuple(r for _, r in extra[:ctx.max_refs - 1]), baseline or {}, reason)


def _cold(ctx, spec, base, fam):
    return _fv(ctx, spec, COLD, baseline={"total": base.total(fam) if base else 0,
                                          "min_observations": ctx.cfg.min_observations},
               reason="baseline below min_observations")


def _rarity(n: int, total: int) -> float:
    if n == 0:
        return 1.0
    return clamp01(math.log(total / n) / math.log(total)) if total > 1 else 0.0


def _cmd(ctx: _Ctx):
    if ctx.proc is None:
        return None, "entity PROCESS evidence absent in window"
    c = text(get_field(ctx.proc, "process.command_line"))
    return (c, "") if c else (None, "process.command_line absent")


def f_cmd_len(ctx, spec):
    c, why = _cmd(ctx)
    if c is None:
        return _fv(ctx, spec, UNKNOWN, reason=why)
    trunc = "process.command_line" in ctx.proc.truncated_fields
    return _fv(ctx, spec, KNOWN, len(c), [ctx.proc.ref], {"truncated_lower_bound": trunc})


def f_cmd_entropy(ctx, spec):
    c, why = _cmd(ctx)
    if c is None:
        return _fv(ctx, spec, UNKNOWN, reason=why)
    return _fv(ctx, spec, KNOWN, entropy(c), [ctx.proc.ref],
               {"chars_considered": min(len(c), MAX_ENTROPY_CHARS)})


def _longest_b64(s: str) -> int:
    best = cur = 0
    for ch in s:
        cur = cur + 1 if ch in B64 else 0
        best = max(best, cur)
    return best


def f_cmd_encoded(ctx, spec):
    c, why = _cmd(ctx)
    if c is None:
        return _fv(ctx, spec, UNKNOWN, reason=why)
    low = c.lower()
    hits = []
    if token(get_field(ctx.proc, "process.name")) in POWERSHELL:
        for tok in low.split():
            body = tok.strip("\"'")
            if body[:1] in ("-", "/") and len(body) > 1 and "encodedcommand".startswith(body[1:]):
                hits.append("powershell_encoded_flag")
                break
    if "frombase64string" in low:
        hits.append("frombase64string")
    if _longest_b64(c) >= B64_RUN:
        hits.append("base64_run")
    return _fv(ctx, spec, KNOWN, 1.0 if hits else 0.0, [ctx.proc.ref], {"indicators": hits})


def _proc_tok(ctx, field):
    return token(get_field(ctx.proc, field)) if ctx.proc is not None else None


def _rarity_feature(ctx, spec, fam, tok, why):
    if tok is None:
        return _fv(ctx, spec, UNKNOWN, reason=why)
    base = ctx.base(spec)
    if base is None or not base.warm(fam, ctx.cfg):
        return _cold(ctx, spec, base, fam)
    n, total = base.count(fam, tok), base.total(fam)
    return _fv(ctx, spec, KNOWN, _rarity(n, total), [ctx.proc.ref], {"count": n, "total": total})


def f_pc_rarity(ctx, spec):
    name, parent = _proc_tok(ctx, "process.name"), _proc_tok(ctx, "parent.name")
    tok = f"{parent}>{name}" if name and parent else None
    return _rarity_feature(ctx, spec, "pc", tok, "parent or process image name absent")


def f_proc_rarity(ctx, spec):
    return _rarity_feature(ctx, spec, "proc", _proc_tok(ctx, "process.name"), "process image name absent")


def f_first_seen_binary(ctx, spec):
    exe = _proc_tok(ctx, "process.executable_path")
    if exe is None:
        return _fv(ctx, spec, UNKNOWN, reason="process.executable_path absent")
    base = ctx.base(spec)
    if base is None or not base.warm("bin", ctx.cfg):
        return _cold(ctx, spec, base, "bin")
    n = base.count("bin", exe)
    return _fv(ctx, spec, KNOWN, 1.0 if n == 0 else 0.0, [ctx.proc.ref], {"count": n, "total": base.total("bin")})


def _first_seen_obs(ctx, spec, kind, field, fam):
    recs = [e for e in ctx.ent if e.kind == kind and not (kind == KIND_NETWORK and inbound(e))]
    if not recs:
        return _fv(ctx, spec, UNKNOWN, reason=f"no {kind} evidence for entity in window (absence not provable)")
    base = ctx.base(spec)
    if base is None or not base.warm(fam, ctx.cfg):
        return _cold(ctx, spec, base, fam)
    pairs = [(t.rstrip(".") if fam == "dom" else t, e) for e in recs for t in [token(get_field(e, field))] if t]
    if not pairs:
        return _fv(ctx, spec, UNKNOWN, reason=f"{field} absent")
    unseen = [(t, e) for t, e in pairs if base.count(fam, t) == 0]
    return _fv(ctx, spec, KNOWN, 1.0 if unseen else 0.0, [e.ref for _, e in (unseen or pairs)],
               {"observed": len({t for t, _ in pairs}), "unseen": len({t for t, _ in unseen})})


def f_first_seen_domain(ctx, spec):
    return _first_seen_obs(ctx, spec, KIND_DNS, "dns.query_name", "dom")


def f_first_seen_ip(ctx, spec):
    return _first_seen_obs(ctx, spec, KIND_NETWORK, "network.dest_ip", "ip")


def f_fanout(ctx, spec):
    if ctx.truncated:
        return _fv(ctx, spec, UNKNOWN, reason="window truncated; count not provable")
    recs = [e for e in ctx.ent if e.kind == KIND_NETWORK and not inbound(e)]
    ips = {token(get_field(e, "network.dest_ip")) for e in recs} - {None}
    if not ips:
        return _fv(ctx, spec, UNKNOWN, reason="no outbound NETWORK evidence for entity (absence not provable)")
    return _fv(ctx, spec, KNOWN, len(ips), [e.ref for e in recs], {"distinct_dest_ips": len(ips)})


def f_reg_persist(ctx, spec):
    if ctx.truncated:
        return _fv(ctx, spec, UNKNOWN, reason="window truncated; count not provable")
    recs = [e for e in ctx.ent if e.kind == KIND_REGISTRY]
    if not recs:
        return _fv(ctx, spec, UNKNOWN, reason="no REGISTRY evidence for entity (absence not provable)")
    hits = [e for e in recs
            if any(k in (token(get_field(e, "registry.key"), MAX_KEY_TEXT) or "") for k in PERSISTENCE_KEYS)]
    return _fv(ctx, spec, KNOWN, len(hits), [e.ref for e in (hits or recs)], {"registry_events": len(recs)})


def f_child_burst(ctx, spec):
    if ctx.truncated:
        return _fv(ctx, spec, UNKNOWN, reason="window truncated; count not provable")
    p = ctx.proc
    if p is None or p.process is None or not p.process.process_guid:
        return _fv(ctx, spec, UNKNOWN, reason="process GUID absent; child linkage not provable")
    g = p.process.process_guid.lower()
    kids = [e for e in ctx.events if e.kind == KIND_PROCESS and e.process and e.stable_key != p.stable_key
            and (e.process.parent_process_guid or "").lower() == g]
    return _fv(ctx, spec, KNOWN, len(kids), [e.ref for e in kids], {"linkage": "SOURCE_PROCESS_GUID"})


def f_off_hours(ctx, spec):
    base = ctx.base(spec)
    if base is None or not base.warm("hour", ctx.cfg):
        return _cold(ctx, spec, base, "hour")
    h = f"{ctx.rec.event_time.astimezone(timezone.utc).hour:02d}"
    n, total = base.count("hour", h), base.total("hour")
    return _fv(ctx, spec, KNOWN, clamp01(1.0 - n / (total / 24.0)), [ctx.rec.ref],
               {"hour_utc": h, "count": n, "total": total})


FEATURES: Dict[str, Callable[[_Ctx, FeatureSpec], FeatureValue]] = {
    "parent_child_rarity": f_pc_rarity, "cmdline_length": f_cmd_len, "cmdline_entropy": f_cmd_entropy,
    "cmdline_encoded_indicator": f_cmd_encoded, "process_rarity_endpoint": f_proc_rarity,
    "process_rarity_tenant": f_proc_rarity, "first_seen_binary": f_first_seen_binary,
    "first_seen_domain": f_first_seen_domain, "first_seen_ip": f_first_seen_ip,
    "outbound_fanout": f_fanout, "registry_persistence_touches": f_reg_persist,
    "child_spawn_burst": f_child_burst, "off_hours": f_off_hours,
}


class FeatureExtractor:
    def __init__(self, schema: FeatureSchema, provider: EvidenceProvider, baselines: BaselineStore, *,
                 window_seconds: int = 300, max_events: int = 2000, max_refs: int = 16,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        missing = [n for n in schema.names() if n not in FEATURES]
        if missing:
            raise SchemaError(f"no extractor for features {missing}")
        self.schema, self.provider, self.baselines = schema, provider, baselines
        self.window, self.max_events, self.max_refs, self.clock = window_seconds, max_events, max_refs, clock

    async def extract(self, rec: EvidenceRecord) -> FeatureVector:
        if not rec.tenant_id or not rec.endpoint_id or rec.ref.tenant_id != rec.tenant_id:
            raise MLInputError("record tenant/endpoint missing or inconsistent")
        now = self.clock()
        skew = timedelta(seconds=self.baselines.cfg.max_future_skew_seconds)
        if not time_ok(rec.event_time, now, skew):
            raise MLInputError("record timestamp is in the future or not timezone-aware")
        w = timedelta(seconds=self.window)
        got = await self.provider.window(tenant_id=rec.tenant_id, endpoint_id=rec.endpoint_id,
                                         start=rec.event_time - w, end=rec.event_time + w,
                                         kinds=self.schema.kinds(), limit=self.max_events + 1)
        clean = [e for e in got if e.tenant_id == rec.tenant_id and e.endpoint_id == rec.endpoint_id
                 and e.ref.tenant_id == rec.tenant_id and time_ok(e.event_time, now, skew)]
        events = dedupe(clean + [rec])
        truncated = len(events) > self.max_events
        if truncated:
            events = dedupe(events[:self.max_events - 1] + [rec])
        entity = rec.process.process_iid if rec.process and rec.process.process_iid else None
        ent = [e for e in events if entity is None or (e.process and e.process.process_iid == entity)]
        proc = rec if rec.kind == KIND_PROCESS else next(
            (e for e in ent if e.kind == KIND_PROCESS and entity), None)
        scopes = self.baselines.scopes(rec.endpoint_id)
        ctx = _Ctx(rec=rec, events=events, ent=ent, proc=proc,
                   ep_base=self.baselines.peek(rec.tenant_id, scopes[0]),
                   tn_base=self.baselines.peek(rec.tenant_id, scopes[1]),
                   cfg=self.baselines.cfg, truncated=truncated, max_refs=self.max_refs)
        values = tuple(FEATURES[s.name](ctx, s) for s in self.schema.features)
        return FeatureVector(schema_version=self.schema.version, schema_hash=self.schema.content_hash,
                             tenant_id=rec.tenant_id, endpoint_id=rec.endpoint_id, entity=entity,
                             anchor=rec.ref, anchor_time=rec.event_time, values=values)
