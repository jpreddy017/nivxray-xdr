"""Per-tenant / per-endpoint baselines: incremental, bounded, deterministic, JSON-serializable."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from edr_behavior.contracts import KIND_DNS, KIND_NETWORK, KIND_PROCESS, EvidenceRecord
from edr_behavior.predicates import get_field

from .safe import time_ok, token

BASELINE_FORMAT = "e3ml.baseline.v1"
FAMILIES = ("proc", "bin", "pc", "dom", "ip", "hour")
UPDATED, DUPLICATE, FROZEN, RATE_LIMITED, TIME_REJECTED = (
    "UPDATED", "DUPLICATE", "FROZEN", "RATE_LIMITED", "TIME_REJECTED")
TENANT_SCOPE = "tenant"


@dataclass(frozen=True)
class BaselineConfig:
    min_observations: int = 50
    max_keys_per_family: int = 2048
    max_seen_keys: int = 4096
    half_life_days: int = 30
    ttl_days: int = 120
    max_updates_per_hour: int = 500
    max_future_skew_seconds: int = 300
    frozen: bool = False  # learning-period freeze for every baseline


def inbound(rec: EvidenceRecord) -> bool:
    return str(get_field(rec, "network.direction") or "").lower() in ("inbound", "in", "ingress")


def tokens_of(rec: EvidenceRecord) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if rec.kind == KIND_PROCESS:
        name, parent = token(get_field(rec, "process.name")), token(get_field(rec, "parent.name"))
        exe = token(get_field(rec, "process.executable_path"))
        if name:
            out["proc"] = name
        if exe:
            out["bin"] = exe
        if name and parent:
            out["pc"] = f"{parent}>{name}"
        out["hour"] = f"{rec.event_time.astimezone(timezone.utc).hour:02d}"
    elif rec.kind == KIND_DNS:
        d = token(get_field(rec, "dns.query_name"))
        if d:
            out["dom"] = d.rstrip(".")
    elif rec.kind == KIND_NETWORK and not inbound(rec):
        ip = token(get_field(rec, "network.dest_ip"))
        if ip:
            out["ip"] = ip
    return out


class Baseline:
    def __init__(self, tenant_id: str, scope: str) -> None:
        if not tenant_id or not scope:
            raise ValueError("baseline requires an explicit tenant_id and scope")
        self.tenant_id, self.scope = tenant_id, scope
        self.counters: Dict[str, Dict[str, int]] = {f: {} for f in FAMILIES}
        self.observations = 0
        self.epoch_day: Optional[int] = None
        self.rate_bucket: Optional[int] = None
        self.rate_count = 0
        self.frozen = False
        self._seen: List[str] = []
        self._seen_set: set = set()

    def count(self, fam: str, tok: str) -> int:
        return self.counters[fam].get(tok, 0)

    def total(self, fam: str) -> int:
        return sum(self.counters[fam].values())

    def warm(self, fam: str, cfg: BaselineConfig) -> bool:
        return self.total(fam) >= cfg.min_observations

    def size(self) -> int:
        return sum(len(c) for c in self.counters.values()) + len(self._seen)

    def observe(self, rec: EvidenceRecord, cfg: BaselineConfig, now: datetime) -> str:
        if self.frozen or cfg.frozen:
            return FROZEN
        t = rec.event_time
        if not time_ok(t, now, timedelta(seconds=cfg.max_future_skew_seconds)) \
                or t < now - timedelta(days=cfg.ttl_days):
            return TIME_REJECTED
        if rec.stable_key in self._seen_set:
            return DUPLICATE
        bucket = int(t.timestamp()) // 3600
        if self.rate_bucket is None or bucket > self.rate_bucket:
            self.rate_bucket, self.rate_count = bucket, 0
        if self.rate_count >= cfg.max_updates_per_hour:
            return RATE_LIMITED
        self._decay(t, cfg)
        for fam, tok in sorted(tokens_of(rec).items()):
            c = self.counters[fam]
            c[tok] = c.get(tok, 0) + 1
            self._cap(fam, tok, cfg)
        self.observations += 1
        self.rate_count += 1
        self._seen.append(rec.stable_key)
        self._seen_set.add(rec.stable_key)
        while len(self._seen) > cfg.max_seen_keys:
            self._seen_set.discard(self._seen.pop(0))
        return UPDATED

    def _decay(self, t: datetime, cfg: BaselineConfig) -> None:
        day = int(t.timestamp()) // 86400
        if self.epoch_day is None:
            self.epoch_day = day
            return
        steps = (day - self.epoch_day) // cfg.half_life_days
        if steps <= 0:
            return
        shift = min(steps, 62)
        for fam in FAMILIES:
            self.counters[fam] = {k: v >> shift for k, v in self.counters[fam].items() if v >> shift}
        self.observations >>= shift
        self.epoch_day += steps * cfg.half_life_days

    def _cap(self, fam: str, keep: str, cfg: BaselineConfig) -> None:
        c = self.counters[fam]
        while len(c) > cfg.max_keys_per_family:
            victim = min((v, k) for k, v in c.items() if k != keep)[1]
            del c[victim]

    def to_dict(self) -> Dict[str, Any]:
        return {"format": BASELINE_FORMAT, "tenant_id": self.tenant_id, "scope": self.scope,
                "counters": {f: dict(sorted(self.counters[f].items())) for f in FAMILIES},
                "observations": self.observations, "epoch_day": self.epoch_day,
                "rate_bucket": self.rate_bucket, "rate_count": self.rate_count,
                "frozen": self.frozen, "seen": list(self._seen)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any], cfg: BaselineConfig) -> "Baseline":
        if not isinstance(d, dict) or d.get("format") != BASELINE_FORMAT:
            raise ValueError("unsupported baseline format")
        b = cls(d.get("tenant_id"), d.get("scope"))
        counters = d.get("counters")
        if not isinstance(counters, dict) or set(counters) != set(FAMILIES):
            raise ValueError("baseline counters malformed")
        for fam in FAMILIES:
            c = counters[fam]
            if not isinstance(c, dict) or len(c) > cfg.max_keys_per_family:
                raise ValueError(f"baseline family {fam} malformed or over cap")
            for k, v in c.items():
                if not isinstance(k, str) or len(k) > 512 or isinstance(v, bool) \
                        or not isinstance(v, int) or v < 0:
                    raise ValueError("baseline counts must be non-negative integers")
            b.counters[fam] = dict(c)
        for k in ("observations", "rate_count"):
            v = d.get(k)
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError(f"baseline {k} malformed")
        for k in ("epoch_day", "rate_bucket"):
            v = d.get(k)
            if v is not None and (isinstance(v, bool) or not isinstance(v, int)):
                raise ValueError(f"baseline {k} malformed")
        seen = d.get("seen", [])
        if not isinstance(seen, list) or len(seen) > cfg.max_seen_keys \
                or not all(isinstance(s, str) and len(s) <= 64 for s in seen):
            raise ValueError("baseline seen keys malformed or over cap")
        b.observations, b.rate_count = d["observations"], d["rate_count"]
        b.epoch_day, b.rate_bucket = d.get("epoch_day"), d.get("rate_bucket")
        b.frozen = bool(d.get("frozen", False))
        b._seen, b._seen_set = list(seen), set(seen)
        return b


class BaselineStore:
    """In-process store keyed strictly by (tenant_id, scope). No default tenant, no shared state."""

    def __init__(self, cfg: BaselineConfig = BaselineConfig()) -> None:
        self.cfg = cfg
        self._b: Dict[Tuple[str, str], Baseline] = {}

    @staticmethod
    def scopes(endpoint_id: str) -> Tuple[str, str]:
        if not endpoint_id:
            raise ValueError("endpoint_id is mandatory")
        return (f"endpoint:{endpoint_id}", TENANT_SCOPE)

    def peek(self, tenant_id: str, scope: str) -> Optional[Baseline]:
        if not tenant_id:
            raise ValueError("tenant_id is mandatory")
        return self._b.get((tenant_id, scope))

    def get(self, tenant_id: str, scope: str) -> Baseline:
        if not tenant_id:
            raise ValueError("tenant_id is mandatory")
        return self._b.setdefault((tenant_id, scope), Baseline(tenant_id, scope))

    def observe(self, rec: EvidenceRecord, now: datetime) -> Dict[str, str]:
        if not rec.tenant_id or rec.ref.tenant_id != rec.tenant_id:
            raise ValueError("record tenant is missing or inconsistent")
        return {s: self.get(rec.tenant_id, s).observe(rec, self.cfg, now)
                for s in self.scopes(rec.endpoint_id)}

    def freeze(self, tenant_id: str, scope: str, frozen: bool = True) -> None:
        self.get(tenant_id, scope).frozen = frozen

    def state_size(self) -> int:
        return sum(b.size() for b in self._b.values())

    def export(self, tenant_id: str) -> str:
        if not tenant_id:
            raise ValueError("tenant_id is mandatory")
        items = [b.to_dict() for (t, _), b in sorted(self._b.items()) if t == tenant_id]
        return json.dumps({"format": BASELINE_FORMAT, "tenant_id": tenant_id, "baselines": items},
                          sort_keys=True, separators=(",", ":"))

    def load(self, tenant_id: str, payload: str) -> int:
        if not tenant_id:
            raise ValueError("tenant_id is mandatory")
        doc = json.loads(payload, parse_constant=_reject_constant)
        if not isinstance(doc, dict) or doc.get("format") != BASELINE_FORMAT \
                or doc.get("tenant_id") != tenant_id:
            raise ValueError("baseline export format or tenant mismatch")
        loaded = [Baseline.from_dict(d, self.cfg) for d in doc.get("baselines", [])]
        if any(b.tenant_id != tenant_id for b in loaded):
            raise ValueError("baseline export contains a foreign tenant")
        for b in loaded:
            self._b[(tenant_id, b.scope)] = b
        return len(loaded)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite constant {name} not allowed")


def fit_baselines(store: BaselineStore, records, *, now: datetime, data_label: str) -> Dict[str, int]:
    """Bulk fit for this phase: SYNTHETIC data only. Same code path as online updates."""
    if data_label != "SYNTHETIC":
        raise ValueError("baseline fitting is restricted to SYNTHETIC data in this phase")
    out: Dict[str, int] = {}
    for rec in sorted(records, key=lambda r: r.sort_key()):
        for outcome in store.observe(rec, now).values():
            out[outcome] = out.get(outcome, 0) + 1
    return out
