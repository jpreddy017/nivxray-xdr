"""Synthetic-only builders for edr_ml tests (fixed seeds, no network, no Mongo, no real data)."""
from __future__ import annotations

import asyncio
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from edr_behavior import normalize, provider
from edr_ml.baseline import BaselineConfig, BaselineStore
from edr_ml.models import ModelRegistry, load_models
from edr_ml.pipeline import MLPipeline
from edr_ml.schema import SchemaRegistry, load_schema
from edr_ml.signals import InMemorySignalStore

T0 = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
NOW = T0 + timedelta(days=10)
SEED = 1337
BENIGN = [("explorer.exe", "chrome.exe", '"C:\\Program Files\\Google\\Chrome\\chrome.exe" --profile-directory=Default'),
          ("explorer.exe", "outlook.exe", '"C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE"'),
          ("services.exe", "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"),
          ("explorer.exe", "teams.exe", '"C:\\Users\\u\\AppData\\Local\\Teams\\teams.exe" --process-start-args'),
          ("explorer.exe", "notepad.exe", '"C:\\Windows\\system32\\notepad.exe" C:\\Users\\u\\notes.txt')]
ENC = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMA" * 3


def run(coro):
    return asyncio.run(coro)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def _path(name: str) -> str:
    return "C:\\Program Files\\App\\" + name


def proc(name: str, guid: str, raw: str, *, t: float, parent: Optional[str] = "explorer.exe",
         parent_guid: Optional[str] = None, cmd: Optional[str] = None, tenant: str = "t1",
         endpoint: str = "ep1", generation: int = 0, path: Optional[str] = None):
    p = {"executable_path": path or _path(name), "process_guid": guid, "process_iid": "proc_" + guid,
         "parent_executable_path": _path(parent) if parent else None, "command_line": cmd,
         "parent_process_guid": parent_guid}
    c = {"activity": "PROCESS", "activity_time": at(t).isoformat(),
         "process": {k: v for k, v in p.items() if v is not None}}
    return normalize.from_canonical(c, tenant_id=tenant, endpoint_id=endpoint, raw_id=raw,
                                    canonical_event_id=f"cev_{raw}_g{generation}", generation=generation, now=NOW)


def act(kind: str, guid: str, raw: str, *, t: float, tenant: str = "t1", endpoint: str = "ep1", **block):
    key = {"NETWORK": "network", "DNS": "dns", "REGISTRY": "registry"}[kind]
    c = {"activity": kind, "activity_time": at(t).isoformat(),
         "process": {"process_guid": guid, "process_iid": "proc_" + guid}, key: block}
    return normalize.from_canonical(c, tenant_id=tenant, endpoint_id=endpoint, raw_id=raw,
                                    canonical_event_id=f"cev_{raw}", generation=0, now=NOW)


def benign_history(*, n: int = 160, seed: int = SEED, tenant: str = "t1", endpoint: str = "ep1",
                   days: int = 5) -> List[Any]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        parent, name, cmd = BENIGN[rng.randrange(len(BENIGN))]
        t = rng.randrange(days) * 86400 + rng.randrange(9, 17) * 3600 + rng.randrange(3600)
        out.append(proc(name, f"{tenant}-{endpoint}-H{i}", f"{tenant}-{endpoint}-h{i}", t=t, parent=parent,
                        cmd=cmd, tenant=tenant, endpoint=endpoint))
        if i % 4 == 0:
            g = f"{tenant}-{endpoint}-H{i}"
            out.append(act("DNS", g, f"{tenant}-{endpoint}-d{i}", t=t + 1, tenant=tenant, endpoint=endpoint,
                           query_name=f"svc{i % 3}.example.com"))
            out.append(act("NETWORK", g, f"{tenant}-{endpoint}-n{i}", t=t + 2, tenant=tenant, endpoint=endpoint,
                           dest_ip=f"10.0.0.{i % 5}", dest_port="443", direction="outbound"))
    return out


class MLH:
    def __init__(self, cfg: BaselineConfig = BaselineConfig(min_observations=20), **kw) -> None:
        self.schemas = SchemaRegistry()
        self.schema = self.schemas.register(load_schema())
        self.models = ModelRegistry(self.schemas)
        load_models(self.models)
        self.provider = provider.InMemoryEvidenceProvider()
        self.baselines = BaselineStore(cfg)
        self.store = InMemorySignalStore()
        self.pipeline = MLPipeline(self.schema, self.models, self.provider, self.baselines, self.store,
                                   clock=lambda: NOW, **kw)

    def feed(self, *recs) -> List[Dict[str, Any]]:
        out = []
        for r in recs:
            self.provider.add(r)
            out.extend(run(self.pipeline.process(r)))
        return out

    def warm(self, recs) -> None:
        for r in recs:
            self.provider.add(r)
        for r in sorted(recs, key=lambda r: r.sort_key()):
            run(self.pipeline.process(r))

    def vector(self, rec):
        self.provider.add(rec)
        return run(self.pipeline.extractor.extract(rec))

    def by_model(self, decisions, model_id):
        return next(d for d in decisions if d["model_id"] == model_id)


def attack_chain(*, t: float = 4 * 86400 + 3 * 3600, tenant: str = "t1", endpoint: str = "ep1"):
    """winword -> powershell -enc ... with fan-out, a first-seen domain and a Run-key write."""
    w = proc("winword.exe", "AW", "a-w", t=t, parent="explorer.exe", cmd="WINWORD.EXE /n invoice.docm",
             tenant=tenant, endpoint=endpoint)
    ps = proc("powershell.exe", "AP", "a-p", t=t + 2, parent="winword.exe", parent_guid="AW",
              cmd=f"powershell.exe -nop -w hidden -enc {ENC}", tenant=tenant, endpoint=endpoint)
    extra = [act("NETWORK", "AP", f"a-n{i}", t=t + 3 + i, tenant=tenant, endpoint=endpoint,
                 dest_ip=f"203.0.113.{i}", dest_port="443", direction="outbound") for i in range(12)]
    extra.append(act("DNS", "AP", "a-d", t=t + 3, tenant=tenant, endpoint=endpoint, query_name="xk2.evil.test"))
    extra.append(act("REGISTRY", "AP", "a-r", t=t + 5, tenant=tenant, endpoint=endpoint,
                     key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd", operation="SET"))
    kids = [proc("cmd.exe", f"AK{i}", f"a-k{i}", t=t + 4 + i, parent="powershell.exe", parent_guid="AP",
                 cmd="cmd.exe /c whoami", tenant=tenant, endpoint=endpoint) for i in range(6)]
    return w, ps, extra + kids
