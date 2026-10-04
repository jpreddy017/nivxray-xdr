"""B5-GAP-1 · deterministic Windows source-log harness.

Replaces `wevtutil` with a SOURCE OF TRUTH the tests own, so paging,
continuity, fairness, rollover and backlog behaviour can be asserted on a
Linux CI host without a Windows endpoint and without touching production.

EVIDENCE LABELLING — TEST/SYNTHETIC. No live telemetry, no production
query, no endpoint contact.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

AGENT_DIR = Path("/app/agents/nivxforge-windows")
SENSOR = AGENT_DIR / "nivxforge_sensor.py"

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SECURITY_CHANNEL = "Security"
SYSTEM_CHANNEL = "System"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
HOST = "NIVX-WIN-TEST"


def load_sensor(state_dir: Path):
    """A fresh sensor module bound to an explicit state root."""
    sys.path.insert(0, str(AGENT_DIR))
    for name in ("nivxforge_sensor", "nivxforge_journal",
                 "nivxforge_exclusions", "nivxforge_delivery_counters",
                 "nivxforge_content_acquisition"):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("nivxforge_sensor", SENSOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules["nivxforge_sensor"] = module
    spec.loader.exec_module(module)
    module.use_state_dir(state_dir)
    return module


SYSMON_PROVIDER_GUID = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
OTHER_PROVIDER_GUID = "{73A33AB2-1966-4999-8ADD-868C41415269}"


def event_xml(provider: str, channel: str, event_id: int, record_id: int,
              data: dict | None = None,
              time_created: str = "2026-09-29T14:45:09.3050000Z") -> str:
    rows = "".join(f'<Data Name="{k}">{v}</Data>'
                   for k, v in (data or {}).items())
    # The provider GUID must FOLLOW the provider name, otherwise a
    # non-Sysmon fixture would carry Sysmon provenance and the
    # provider-qualified B5 counting tests would prove nothing.
    guid = (SYSMON_PROVIDER_GUID if provider == SYSMON_PROVIDER
            else OTHER_PROVIDER_GUID)
    return (f'<Event xmlns="{NS}"><System>'
            f'<Provider Name="{provider}" Guid="{guid}"/>'
            f'<EventID>{event_id}</EventID><Level>4</Level>'
            f'<TimeCreated SystemTime="{time_created}"/>'
            f'<EventRecordID>{record_id}</EventRecordID>'
            f'<Channel>{channel}</Channel><Computer>{HOST}</Computer>'
            f'</System><EventData>{rows}</EventData></Event>')


def sensor_event(channel: str, record_id: int, event_id: int = 1,
                 provider: str = SYSMON_PROVIDER,
                 data: dict | None = None,
                 observed_at: str = "2026-09-29T14:45:10+00:00") -> dict:
    """Exactly the shape `_query_channel` produces."""
    return {
        "observed_at": observed_at,
        "kind": "WINDOWS_EVENT_LOG",
        "winlog": {
            "channel": channel,
            "record_id": record_id,
            "event_id": str(event_id),
            "time_created": "2026-09-29T14:45:09.3050000Z",
            "computer": HOST,
            "provider": provider,
            "xml": event_xml(provider, channel, event_id, record_id, data),
        },
    }


class FakeChannel:
    """A circular Windows channel: records can be produced and purged."""

    def __init__(self, name: str, provider: str = SYSMON_PROVIDER):
        self.name = name
        self.provider = provider
        self.records: list[dict] = []
        self.failure: str | None = None
        self.elapsed_ms = 1

    def produce(self, count: int, start: int, event_id: int = 1,
                data: dict | None = None) -> list[int]:
        ids = list(range(start, start + count))
        for record_id in ids:
            self.records.append(sensor_event(
                self.name, record_id, event_id, self.provider, data))
        return ids

    def add(self, event: dict) -> None:
        self.records.append(event)

    def roll_to(self, oldest_kept: int) -> int:
        """Circular rollover: discard everything older, exactly as a full
        64 MiB EVTX does. Nothing is 'skipped' — the records are GONE."""
        before = len(self.records)
        self.records = [r for r in self.records
                        if (r["winlog"]["record_id"] or 0) >= oldest_kept]
        return before - len(self.records)

    def oldest(self) -> int | None:
        ids = [r["winlog"]["record_id"] for r in self.records
               if r["winlog"]["record_id"]]
        return min(ids) if ids else None

    def newest(self) -> int | None:
        ids = [r["winlog"]["record_id"] for r in self.records
               if r["winlog"]["record_id"]]
        return max(ids) if ids else None


class FakeSource:
    """Stands in for `sensor._query_channel`, oldest-first, strictly `>`."""

    def __init__(self, *channels: FakeChannel):
        self.channels = {c.name: c for c in channels}
        self.calls: list[tuple[str, int, int]] = []
        self.on_page = None

    def channel(self, name: str) -> FakeChannel:
        return self.channels[name]

    def query(self, channel: str, after_record: int,
              limit: int | None = None) -> tuple[list[dict], str | None, int]:
        limit = 500 if limit is None else limit
        self.calls.append((channel, after_record, limit))
        source = self.channels.get(channel)
        if source is None:
            return [], f"channel {channel} not present on this host", 0
        if source.failure:
            return [], source.failure, source.elapsed_ms
        page = [r for r in sorted(
            source.records, key=lambda r: r["winlog"]["record_id"] or 0)
            if (r["winlog"]["record_id"] or 0) > after_record][:limit]
        if self.on_page:
            self.on_page(channel, after_record, page)
        return [json.loads(json.dumps(r)) for r in page], None, \
            source.elapsed_ms

    def tails(self) -> dict:
        return {name: {"oldest": c.oldest(), "newest": c.newest()}
                for name, c in self.channels.items()}


def wire(module, source: FakeSource, *, accept=None, monkeypatch):
    """Point the sensor at the fake source and neutralise every network
    call except the one a test wants to observe."""
    calls = {"posted": [], "accepted": 0, "heartbeats": 0}

    def _post(api, path, body, bearer=None):
        calls["posted"].append((path, body))
        if path == "/api/edr/agent/telemetry":
            if accept is not None:
                accept(body)
            calls["accepted"] += 1
            return {"accepted": True}
        if path == "/api/edr/agent/telemetry/batch":
            # The real per-event contract, so a test can assert either
            # shape and batching cannot be silently un-exercised.
            results = []
            for index, event in enumerate(body["events"]):
                calls["posted"].append(("/api/edr/agent/telemetry", event))
                if accept is not None:
                    accept(event)
                calls["accepted"] += 1
                results.append({"index": index, "accepted": True,
                                "stored": True, "duplicate": False})
            return {"batch_id": body.get("batch_id"),
                    "count": len(results),
                    "accepted": len(results), "results": results}
        if path == "/api/edr/agent/heartbeat":
            calls["heartbeats"] += 1
        return {}

    monkeypatch.setattr(module, "_query_channel", source.query)
    monkeypatch.setattr(module, "_post", _post)
    monkeypatch.setattr(module, "_open_session", lambda api, i: "tok")
    monkeypatch.setattr(module, "_sync_policy",
                        lambda api, i, s: {"exclusions": [], "stale": False})
    monkeypatch.setattr(module, "_report_enforcement",
                        lambda *a, **k: "NOTHING_TO_REPORT")
    monkeypatch.setattr(module, "_probe_source_tail",
                        lambda channel: source.tails().get(channel, {}))
    monkeypatch.setattr(module, "CHANNELS", tuple(source.channels))
    return calls


def batch_aware(single):
    """Wrap a single-event `_post` fake so it also serves the batch route
    with the real per-event contract. Keeps a test's intent (slow, flaky,
    down) while exercising the shipped delivery path."""
    def _post(api, path, body, bearer=None):
        if path != "/api/edr/agent/telemetry/batch":
            return single(api, path, body, bearer)
        results = []
        for index, event in enumerate(body["events"]):
            try:
                single(api, "/api/edr/agent/telemetry",
                       {"payload": event["payload"]}, bearer)
                results.append({"index": index, "accepted": True,
                                "stored": True})
            except Exception as ex:
                if str(ex).startswith(("401", "403", "404", "405", "413")):
                    raise
                results.append({"index": index, "accepted": False,
                                "error": type(ex).__name__,
                                "detail": str(ex)[:200]})
        return {"batch_id": body.get("batch_id"), "count": len(results),
                "accepted": sum(1 for r in results if r["accepted"]),
                "results": results}
    return _post


IDENTITY = {"tenant_id": "ten_test", "endpoint_id": "ep_test",
            "agent_credential": "nvxcred_REDACTED_TEST",
            "credential_id": "cred_test"}


def write_identity(module) -> dict:
    module.IDENTITY_FILE.parent.mkdir(parents=True, exist_ok=True)
    module.IDENTITY_FILE.write_text(json.dumps(IDENTITY))
    return dict(IDENTITY)
