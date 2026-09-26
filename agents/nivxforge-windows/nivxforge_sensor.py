#!/usr/bin/env python3
"""NivXForge EDR · Windows sensor (V1 onboarding).

Same permanent contract as the Linux sensor
(`agents/nivxforge-linux/nivxforge_sensor.py`), deliberately:

    enrol (one-time token) -> durable per-device credential -> session
      -> DURABLE LOCAL JOURNAL -> authenticated telemetry -> heartbeat

No second telemetry architecture is created for onboarding: this sensor
speaks the existing authenticated agent surface (`/api/edr/agent/*`), and
every observation is written to the local journal and fsynced BEFORE any
network call, so a backend outage can never lose acquired evidence. The
journal offset advances only after the platform confirms the accept, so a
connectivity loss REPLAYS instead of losing evidence.

The sensor never proposes its own endpoint_id: the platform mints it from
durable machine attributes (MachineGuid > processor id > hostname).

What it collects in V1: Windows Event Log records (Security, System, and
Sysmon when present) via `wevtutil`, which is present on every supported
Windows build and needs no third-party Python package. Anything it cannot
observe is declared NOT SUPPORTED at enrolment so the console resolves it
as unsupported rather than as "nothing happened".
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SENSOR_VERSION = "0.2.0-windows"
PLATFORM = "WINDOWS"

STATE_DIR = Path(os.environ.get(
    "NIVXFORGE_SENSOR_STATE",
    os.path.join(os.environ.get("ProgramData", "/var/lib"),
                 "NivXForge", "sensor")))
IDENTITY_FILE = STATE_DIR / "identity.json"     # admin/SYSTEM only ACL
QUEUE_FILE = STATE_DIR / "outbox.jsonl"
OFFSET_FILE = STATE_DIR / "outbox.offset"
BOOKMARK_FILE = STATE_DIR / "channels.json"

#: Channels asked for in order. A missing channel is reported, never faked.
CHANNELS = ("Security", "System",
            "Microsoft-Windows-Sysmon/Operational")

CAPABILITIES = {
    "collects": ["WINDOWS_EVENT_LOG"],
    "fields_supported": [
        "winlog.channel", "winlog.event_id", "winlog.record_id",
        "winlog.provider", "winlog.computer", "winlog.time_created",
        "winlog.level", "winlog.xml",
    ],
    "fields_not_supported": [
        "process.sha256", "process.exit_time", "file.actor_process",
        "network.process_iid", "registry.*", "usb_device.*", "memory.*",
    ],
    "response_actions": [],
    "response_actions_conditional": {
        "ISOLATE_ENDPOINT": "not implemented by the Windows sensor in V1",
    },
    "collection_method": "WINDOWS_EVENTLOG_QUERY",
    "limits": [
        "records are read from the Windows Event Log, so anything the OS "
        "does not audit is not observed by this sensor",
        "no kernel driver and no ETW session, so no syscall-level fidelity",
        "a channel that is disabled or unreadable is reported as "
        "unavailable, never as an absence of activity",
    ],
}


# GATE 7 · the CANONICAL endpoint exclusion evaluator, shipped beside
# this file in the connector release. Imported, never reimplemented, so
# the Windows and Linux connectors cannot drift apart.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nivxforge_exclusions as nvx_excl        # noqa: E402

POLICY_FILE = STATE_DIR / "policy.json"
EXCLUSION_JOURNAL = STATE_DIR / "exclusion_enforcement.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _post(api: str, path: str, body: dict, bearer: str | None = None) -> dict:
    req = urllib.request.Request(
        f"{api}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 # Explicit UA: some edges reject the default urllib agent
                 # outright, which looks exactly like an auth failure.
                 "User-Agent": f"NivXForge-EDR-Sensor/{SENSOR_VERSION}",
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{e.code} {e.read().decode()[:400]}") from None


# ── durable identity ──────────────────────────────────────────────
def _read_identity() -> dict:
    if not IDENTITY_FILE.exists():
        sys.exit("not enrolled: run `nivxforge_sensor.py enrol` first")
    return json.loads(IDENTITY_FILE.read_text())


def _reg_machine_guid() -> str | None:
    try:
        import winreg                                       # noqa: PLC0415
    except ImportError:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value).strip() or None
    except OSError:
        return None


def _wmic(query: str, field: str) -> str | None:
    try:
        out = subprocess.run(["wmic", query, "get", field, "/value"],
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    for line in (out.stdout or "").splitlines():
        if "=" in line:
            value = line.split("=", 1)[1].strip()
            if value:
                return value
    return None


def _machine_facts() -> dict:
    """Durable machine attributes ONLY. The platform mints endpoint_id."""
    processor = _wmic("cpu", "ProcessorId")
    return {
        "processor_id": (hashlib.sha256(processor.encode()).hexdigest()[:24]
                         if processor else None),
        "machine_guid": _reg_machine_guid() or _wmic("csproduct", "UUID"),
        "hostname": socket.gethostname(),
        "platform": PLATFORM,
        "os_version": f"{platform.system()} {platform.release()} "
                      f"{platform.version()}".strip(),
    }


def enrol(api: str, tenant: str, token: str) -> dict:
    facts = _machine_facts()
    if not facts["processor_id"] and not facts["machine_guid"]:
        sys.exit("refusing to enrol: no durable machine attribute found. An "
                 "unattributed observation is not an endpoint.")
    res = _post(api, "/api/edr/agent/enroll", {
        "tenant_id": tenant, "enrollment_token": token,
        "sensor_version": SENSOR_VERSION,
        "processor_id": facts["processor_id"],
        "machine_guid": facts["machine_guid"],
        "hostname": facts["hostname"], "platform": facts["platform"]})
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    IDENTITY_FILE.write_text(json.dumps({
        "tenant_id": tenant, "endpoint_id": res["endpoint_id"],
        "credential_id": res["credential_id"],
        "agent_credential": res["agent_credential"],
        "os_version": facts["os_version"],
        "enrolled_at": _now(), "capabilities": CAPABILITIES}, indent=2))
    try:
        os.chmod(IDENTITY_FILE, 0o600)
    except OSError:
        pass                     # on Windows the installer applies the ACL
    print(f"enrolled endpoint_id={res['endpoint_id']}")
    print(f"credential stored at {IDENTITY_FILE} (administrators/SYSTEM only)")
    print(f"sensor_state={res.get('sensor_state')}  (nothing collected yet)")
    return res


def _open_session(api: str, ident: dict) -> str:
    return _post(api, "/api/edr/agent/session",
                 {"tenant_id": ident["tenant_id"],
                  "agent_credential": ident["agent_credential"]}
                 )["session_token"]


# ── real collection · Windows Event Log ───────────────────────────
def _bookmarks() -> dict:
    try:
        return json.loads(BOOKMARK_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save_bookmarks(marks: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    BOOKMARK_FILE.write_text(json.dumps(marks, indent=2))


def _query_channel(channel: str, after_record: int,
                   limit: int = 100) -> tuple[list[dict], str | None]:
    """Records newer than the bookmark, or an honest unavailability reason."""
    query = f"*[System[EventRecordID>{int(after_record)}]]"
    try:
        out = subprocess.run(
            ["wevtutil", "qe", channel, f"/q:{query}", f"/c:{limit}",
             "/e:Events", "/f:RenderedXml", "/rd:false"],
            capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        return [], "wevtutil is not available on this host"
    except (OSError, subprocess.SubprocessError) as ex:
        return [], f"{type(ex).__name__}: {ex}"
    if out.returncode != 0:
        return [], (out.stderr or "").strip()[:200] or "channel unreadable"
    events: list[dict] = []
    for chunk in (out.stdout or "").split("</Event>"):
        if "<Event" not in chunk:
            continue
        xml = chunk[chunk.index("<Event"):] + "</Event>"
        record_id = _between(xml, "<EventRecordID>", "</EventRecordID>")
        events.append({
            "observed_at": _now(),
            "kind": "WINDOWS_EVENT_LOG",
            "winlog": {
                "channel": channel,
                "record_id": int(record_id) if record_id else None,
                "event_id": _between(xml, "<EventID", "</EventID>"),
                "time_created": _attr(xml, "TimeCreated", "SystemTime"),
                "computer": _between(xml, "<Computer>", "</Computer>"),
                "provider": _attr(xml, "Provider", "Name"),
                "xml": xml,
            },
        })
    return events, None


def _between(text: str, start: str, end: str) -> str | None:
    try:
        head = text.index(start) + len(start)
        body = text[head:text.index(end, head)]
    except ValueError:
        return None
    return body.split(">")[-1].strip() or None


def _attr(text: str, element: str, attribute: str) -> str | None:
    try:
        head = text.index(f"<{element}")
        fragment = text[head:text.index(">", head)]
        marker = f'{attribute}="'
        start = fragment.index(marker) + len(marker)
        return fragment[start:fragment.index('"', start)]
    except ValueError:
        return None


def collect() -> tuple[list[dict], dict]:
    marks, events, unavailable = _bookmarks(), [], {}
    for channel in CHANNELS:
        after = int(marks.get(channel) or 0)
        found, reason = _query_channel(channel, after)
        if reason:
            unavailable[channel] = reason
            continue
        for event in found:
            record = event["winlog"].get("record_id")
            if record and record > int(marks.get(channel) or 0):
                marks[channel] = record
        events.extend(found)
    return events, {"channels_unavailable": unavailable, "bookmarks": marks}


def _get(api: str, path: str, bearer: str) -> dict:
    req = urllib.request.Request(
        f"{api}{path}",
        headers={"User-Agent": f"NivXForge-EDR-Sensor/{SENSOR_VERSION}",
                 "Authorization": f"Bearer {bearer}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{e.code} {e.read().decode()[:300]}") from None


def _sync_policy(api: str, ident: dict, session: dict) -> dict:
    """Fetch the assigned policy, apply it locally, acknowledge it.

    Fetching is what the platform records as DELIVERED. Only this
    connector's acknowledgement of the EXACT config digest can make the
    platform report APPLIED. A fetch failure keeps the last applied
    policy enforcing and marks the report `policy_stale`.
    """
    try:
        persisted = json.loads(POLICY_FILE.read_text())
    except (OSError, ValueError):
        persisted = {}
    try:
        if not session.get("token"):
            session["token"] = _open_session(api, ident)
        out = _get(api, "/api/edr/agent/policy", session["token"])
    except (RuntimeError, urllib.error.URLError, OSError) as e:
        if str(e).startswith(("401", "403")):
            session["token"] = None
        base = persisted or {"exclusions": []}
        return {**base, "stale": True, "stale_reason": str(e)[:120]}

    policy = out.get("policy")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not policy:
        POLICY_FILE.write_text(json.dumps({"exclusions": [],
                                           "state": out.get("state"),
                                           "synced_at": _now()}))
        return {"exclusions": [], "state": out.get("state"), "stale": False}

    applied = {"policy_id": policy.get("policy_id"),
               "version": policy.get("version"),
               "config_digest": policy.get("config_digest"),
               "config": policy.get("config") or {},
               "exclusions": out.get("exclusions") or [],
               "synced_at": _now(), "stale": False}
    POLICY_FILE.write_text(json.dumps(applied))
    honoured = sum(1 for x in applied["exclusions"]
                   if nvx_excl.validate(x) == nvx_excl.HONOURED)
    try:
        _post(api, "/api/edr/agent/policy-ack",
              {"policy_id": applied["policy_id"],
               "version": applied["version"],
               "config_digest": applied["config_digest"],
               "applied": True,
               "running_config_digest": applied["config_digest"],
               "connector_version": SENSOR_VERSION,
               "exclusions_applied": honoured},
              bearer=session["token"])
        applied["acknowledged"] = True
    except (RuntimeError, urllib.error.URLError, OSError) as e:
        if str(e).startswith(("401", "403")):
            session["token"] = None
        applied["acknowledged"] = False
        applied["ack_error"] = str(e)[:120]
    return applied


def _report_enforcement(api: str, ident: dict, session: dict,
                        journal, policy: dict) -> str:
    """Report what the LOCAL engine enforced: counts and value digests
    only. The excluded events were dropped on this machine and are never
    transmitted."""
    entries = journal.report()
    if not entries:
        return "NOTHING_TO_REPORT"
    try:
        if not session.get("token"):
            session["token"] = _open_session(api, ident)
        _post(api, "/api/edr/agent/exclusion-enforcement",
              {"evaluator_version": nvx_excl.EVALUATOR_VERSION,
               "engine": nvx_excl.ENGINE,
               "policy_id": policy.get("policy_id"),
               "version": policy.get("version"),
               "config_digest": policy.get("config_digest"),
               "policy_stale": bool(policy.get("stale")),
               "exclusions": entries},
              bearer=session["token"])
        return f"SENT:{len(entries)}"
    except (RuntimeError, urllib.error.URLError, OSError) as e:
        if str(e).startswith(("401", "403")):
            session["token"] = None
        return f"FAILED:{str(e)[:80]}"


# ── durable journal ───────────────────────────────────────────────
def _enqueue(events: list[dict]) -> None:
    """Journal FIRST, fsync, and only then let delivery try. Acquisition is
    never coupled to network success."""
    if not events:
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(QUEUE_FILE, "a") as fh:
        for event in events:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _queue_depth() -> int:
    if not QUEUE_FILE.exists():
        return 0
    offset = int(OFFSET_FILE.read_text()) if OFFSET_FILE.exists() else 0
    depth = 0
    with open(QUEUE_FILE, "rb") as fh:
        fh.seek(offset)
        while fh.readline():
            depth += 1
    return depth


def _drain(api: str, ident: dict, session: dict, interval: int | None = None,
           max_per_cycle: int = 200) -> tuple[int, int]:
    """Send what the journal holds; advance the offset ONLY after an accept."""
    if not QUEUE_FILE.exists():
        return 0, 0
    offset = int(OFFSET_FILE.read_text()) if OFFSET_FILE.exists() else 0
    sent = failed = 0
    with open(QUEUE_FILE, "rb") as fh:
        fh.seek(offset)
        while raw_line := fh.readline():
            consumed = len(raw_line)
            line = raw_line.decode(errors="replace").strip()
            if not line:
                offset += consumed
                OFFSET_FILE.write_text(str(offset))
                continue
            try:
                if not session.get("token"):
                    session["token"] = _open_session(api, ident)
                _post(api, "/api/edr/agent/telemetry",
                      {"payload": line, "source_kind": "sensor",
                       "sensor_version": SENSOR_VERSION,
                       **({"report_interval_seconds": float(interval)}
                          if interval else {})},
                      bearer=session["token"])
                sent += 1
                offset += consumed
                OFFSET_FILE.write_text(str(offset))
                if sent >= max_per_cycle:
                    break
            except (RuntimeError, urllib.error.URLError, OSError) as ex:
                message = str(ex)
                if message.startswith(("401", "403")) and session.get("token"):
                    session["token"] = None
                    fh.seek(offset)
                    continue
                failed += 1
                print(f"[journal] held at offset {offset}: {message[:140]}")
                break
    return sent, failed


def _heartbeat(api: str, ident: dict, session: dict,
               interval: int) -> None:
    """Liveness. NOT telemetry: it never makes a silent sensor look busy."""
    try:
        if not session.get("token"):
            session["token"] = _open_session(api, ident)
        _post(api, "/api/edr/agent/heartbeat",
              {"report_interval_seconds": float(interval),
               "sensor_version": SENSOR_VERSION,
               "queue_depth": _queue_depth()},
              bearer=session["token"])
    except (RuntimeError, urllib.error.URLError, OSError) as ex:
        print(f"[heartbeat] {str(ex)[:140]}")
        session["token"] = None


def run(api: str, interval: int = 30, once: bool = False) -> dict:
    ident = _read_identity()
    session: dict = {"token": None}
    while True:
        policy = _sync_policy(api, ident, session)
        events, state = collect()
        # GATE 7 · endpoint exclusion enforcement. Matching events are
        # dropped HERE — before the durable outbox — so an exclusion
        # cannot be defeated by a replay, and the excluded evidence never
        # leaves this machine.
        journal = nvx_excl.Journal(EXCLUSION_JOURNAL)
        events, excluded = nvx_excl.partition(
            events, policy.get("exclusions") or [], journal, policy)
        journal.save()
        _enqueue(events)
        _save_bookmarks(state["bookmarks"])
        sent, failed = _drain(api, ident, session, interval)
        _heartbeat(api, ident, session, interval)
        reported = _report_enforcement(api, ident, session, journal, policy)
        report = {"at": _now(), "collected": len(events), "sent": sent,
                  "failed": failed, "queue_depth": _queue_depth(),
                  "collection_suppressed_at_endpoint": excluded,
                  "policy_id": policy.get("policy_id"),
                  "policy_version": policy.get("version"),
                  "policy_stale": bool(policy.get("stale")),
                  "exclusions_delivered":
                      len(policy.get("exclusions") or []),
                  "enforcement_report": reported,
                  "channels_unavailable": state["channels_unavailable"]}
        print(json.dumps(report))
        if once:
            return report
        time.sleep(max(5, interval))


def status() -> dict:
    enrolled = IDENTITY_FILE.exists()
    ident = json.loads(IDENTITY_FILE.read_text()) if enrolled else {}
    return {"sensor_version": SENSOR_VERSION, "enrolled": enrolled,
            "endpoint_id": ident.get("endpoint_id"),
            "tenant_id": ident.get("tenant_id"),
            "state_dir": str(STATE_DIR), "queue_depth": _queue_depth(),
            "credential_present": bool(ident.get("agent_credential")),
            "note": "the credential value itself is never printed"}


def main() -> None:
    ap = argparse.ArgumentParser(description="NivXForge EDR Windows sensor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enrol")
    e.add_argument("--api", required=True)
    e.add_argument("--tenant", required=True)
    e.add_argument("--token", required=True)
    r = sub.add_parser("run")
    r.add_argument("--api", required=True)
    r.add_argument("--interval", type=int, default=30)
    r.add_argument("--once", action="store_true")
    sub.add_parser("status")
    sub.add_parser("capabilities")
    args = ap.parse_args()
    if args.cmd == "enrol":
        enrol(args.api, args.tenant, args.token)
    elif args.cmd == "run":
        run(args.api, args.interval, args.once)
    elif args.cmd == "status":
        print(json.dumps(status(), indent=2))
    else:
        print(json.dumps({"sensor_version": SENSOR_VERSION,
                          **_machine_facts(), **CAPABILITIES}, indent=2))


if __name__ == "__main__":
    main()
