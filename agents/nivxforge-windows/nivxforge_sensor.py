#!/usr/bin/env python3
"""NivXForge EDR · Windows sensor (V1 onboarding).

Same permanent contract as the Linux sensor
(`agents/nivxforge-linux/nivxforge_sensor.py`), deliberately:

    enrol (one-time secret, STDIN only) -> durable per-device credential
      -> session
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
import http.client
import itertools
import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SENSOR_VERSION = "0.3.0-windows"
PLATFORM = "WINDOWS"

def _default_state_root() -> str:
    """Where ProgramData lives, WITHOUT trusting a single variable.

    A LocalSystem service inherits its environment from services.exe and
    does not reliably carry the variables an interactive session has, so
    `ProgramData` alone is not a safe way to find the state root: a miss
    would silently move the enrolment identity, the journal and the
    bookmarks somewhere the installer never wrote them. For an INSTALLED
    service the authoritative answer is the `--state-dir` the installer
    passes (see `use_state_dir`); this chain is defence in depth.
    """
    for key in ("ProgramData", "ALLUSERSPROFILE"):
        value = os.environ.get(key)
        if value:
            return value
    drive = os.environ.get("SystemDrive")
    if drive:
        return os.path.join(drive + os.sep, "ProgramData")
    return "/var/lib"


STATE_DIR = Path(os.environ.get(
    "NIVXFORGE_SENSOR_STATE",
    os.path.join(_default_state_root(), "NivXForge", "sensor")))
IDENTITY_FILE = STATE_DIR / "identity.json"     # admin/SYSTEM only ACL
QUEUE_FILE = STATE_DIR / "outbox.jsonl"
OFFSET_FILE = STATE_DIR / "outbox.offset"
#: LEGACY, and no longer the cursor AUTHORITY. The authority is the
#: `cursors` table of the Local Evidence Journal, which is committed in the
#: same transaction as the evidence itself. This file is still written, as a
#: read-only mirror, so a downgrade and an operator's eye both still work.
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
        "acquired evidence is held in a BOUNDED local evidence journal; "
        "when local durable capacity is exhausted acquisition HALTS and "
        "says so, and no unacknowledged evidence is ever overwritten",
        "a source RecordID discontinuity is declared as an acquisition gap "
        "with cause NOT_PROVEN; the sensor never reconstructs the records "
        "it did not observe",
    ],
}


# GATE 7 · the CANONICAL endpoint exclusion evaluator, shipped beside
# this file in the connector release. Imported, never reimplemented, so
# the Windows and Linux connectors cannot drift apart.
sys.path.insert(0, str(Path(__file__).resolve().parent))
# DELIVERY FIDELITY + B3 CONTENT IDENTITY · both are CAPABILITIES and both
# are OFF unless their environment flag is set. Same implementation the
# Linux connector uses, so the two cannot drift apart.
import nivxforge_content_acquisition as nvx_hash
import nivxforge_delivery_counters as nvx_counters
import nivxforge_exclusions as nvx_excl

# B5-GAP-1 · the LOCAL EVIDENCE JOURNAL. Acquisition durability is no
# longer coupled to network delivery, and the source cursor is a
# consequence of durable ownership rather than of a read.
import nivxforge_journal as nvx_journal

COUNTERS = nvx_counters.DeliveryCounters(STATE_DIR)
ACQUIRER = nvx_hash.Acquirer()

POLICY_FILE = STATE_DIR / "policy.json"
EXCLUSION_JOURNAL = STATE_DIR / "exclusion_enforcement.json"


# ── B5-GAP-1 acquisition budget ───────────────────────────────────
# WHY THESE SHAPES. The defect was not "100 is too small": it was that a
# single bounded read per cycle had no way to catch up, and that delivery
# could occupy the only thread for minutes. So the page size is a PAGE (we
# keep asking), and every stage gets a WALL-CLOCK budget instead of a fixed
# message count — a count cannot bound time when each POST costs ~2.7s.
def _f_env(name: str, default: float) -> float:
    try:
        value = float(str(os.environ.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _i_env(name: str, default: int) -> int:
    try:
        value = int(str(os.environ.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def page_size() -> int:
    return _i_env("NIVX_SENSOR_ACQUIRE_PAGE_SIZE", 500)


def max_records_per_channel_per_cycle() -> int:
    """Headroom, not a target. Production Sysmon was measured at ~20
    records/sec, i.e. ~600 records per 30s cycle; this ceiling lets a
    backlog be drained ~30x faster than it is produced while still
    guaranteeing the loop terminates and the other channels get served."""
    return _i_env("NIVX_SENSOR_ACQUIRE_MAX_PER_CHANNEL", 20000)


def acquire_budget_seconds(interval: int) -> float:
    return _f_env("NIVX_SENSOR_ACQUIRE_BUDGET_SECONDS",
                  max(5.0, interval * 0.5))


def deliver_budget_seconds(interval: int) -> float:
    return _f_env("NIVX_SENSOR_DELIVER_BUDGET_SECONDS",
                  max(5.0, float(interval)))


def legacy_drain_budget_seconds(interval: int) -> float:
    """The pre-journal `outbox.jsonl` must stay deliverable, but it must not
    be able to starve either acquisition or the journal's own delivery."""
    return _f_env("NIVX_SENSOR_LEGACY_DRAIN_BUDGET_SECONDS",
                  max(2.0, interval * 0.25))


def source_tail_probe_enabled() -> bool:
    return os.environ.get("NIVX_SENSOR_SOURCE_TAIL_PROBE",
                          "1").strip() in ("1", "true", "TRUE", "yes")


def use_state_dir(path: str | os.PathLike) -> Path:
    """Re-point EVERY state path at one explicit root.

    Called by the service host with the directory the installer chose, so
    the running service reads the same identity, journal, offset,
    bookmarks, policy and enforcement journal the installer wrote — never
    a second location it inferred from its own environment. Repointing
    only the log would be worse than useless: the service would look
    healthy while reading an identity that is not there.
    """
    global STATE_DIR, IDENTITY_FILE, QUEUE_FILE, OFFSET_FILE
    global BOOKMARK_FILE, POLICY_FILE, EXCLUSION_JOURNAL
    global JOURNAL_FILE
    STATE_DIR = Path(path)
    JOURNAL_FILE = STATE_DIR / nvx_journal.JOURNAL_FILENAME
    IDENTITY_FILE = STATE_DIR / "identity.json"
    QUEUE_FILE = STATE_DIR / "outbox.jsonl"
    OFFSET_FILE = STATE_DIR / "outbox.offset"
    BOOKMARK_FILE = STATE_DIR / "channels.json"
    POLICY_FILE = STATE_DIR / "policy.json"
    EXCLUSION_JOURNAL = STATE_DIR / "exclusion_enforcement.json"
    # The counters follow the state root the installer chose, so a
    # service-hosted sensor does not write them to a second location.
    COUNTERS.state_dir = STATE_DIR
    return STATE_DIR


JOURNAL_FILE = STATE_DIR / nvx_journal.JOURNAL_FILENAME


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def http_keepalive_enabled() -> bool:
    return os.environ.get("NIVX_SENSOR_HTTP_KEEPALIVE",
                          "1").strip() in ("1", "true", "TRUE", "yes")


def delivery_batch_size() -> int:
    """Events per delivery request. CHOSEN FROM MEASUREMENT, not taste.

    GATE B, measured through the real ingress:
        fresh connection per POST (the pre-fix sensor)   5.7 ev/s
        one persistent connection, one event per POST    9.7 ev/s
        batch of 10                                     43.1 ev/s
        batch of 50                                     48.3 ev/s   <- default
        batch of 100                                    33.5 ev/s
    Past ~50 the amortisation is spent and SERVER-SIDE PER-EVENT work
    dominates (loopback single-event cost was 38.6 ms), so a bigger batch
    only lengthens one request — 3.0 s at 100 — for less throughput and
    more ingress-timeout exposure. 48.3 ev/s is 2.4x the ~20 ev/s the
    endpoint produces.
    """
    return max(1, _i_env("NIVX_SENSOR_DELIVERY_BATCH", 50))


class _Transport:
    """ONE persistent HTTP connection, reconnected on failure.

    The pre-fix sensor used `urllib.request.urlopen` per call, so every
    single event paid DNS + TCP + TLS. stdlib `http.client` keeps the
    connection, which needs no dependency and no proxy.
    """

    def __init__(self) -> None:
        self._conn = None
        self._origin: tuple | None = None

    def _connect(self, api: str):
        parsed = urllib.parse.urlparse(api)
        origin = (parsed.scheme, parsed.netloc)
        if self._conn is not None and self._origin == origin:
            return self._conn
        self.close()
        cls = (http.client.HTTPSConnection if parsed.scheme == "https"
               else http.client.HTTPConnection)
        self._conn = cls(parsed.netloc, timeout=30)
        self._origin = origin
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except (http.client.HTTPException, OSError):
                pass
        self._conn, self._origin = None, None

    def request(self, api: str, path: str, method: str,
                body: bytes | None, headers: dict) -> tuple[int, bytes]:
        parsed = urllib.parse.urlparse(api)
        target = (parsed.path.rstrip("/") + path) or path
        for attempt in (1, 2):
            conn = self._connect(api)
            try:
                conn.request(method, target, body=body, headers=headers)
                response = conn.getresponse()
                payload = response.read()
                if not http_keepalive_enabled():
                    self.close()
                return response.status, payload
            except (http.client.HTTPException, OSError) as ex:
                # A reused connection the peer has since closed fails on
                # the FIRST write. That is normal, and it must not look
                # like a backend outage: reconnect once, then report.
                self.close()
                if attempt == 2:
                    raise OSError(f"transport: {type(ex).__name__}: {ex}"
                                  ) from None
        raise OSError("transport: unreachable")


TRANSPORT = _Transport()


def _request(api: str, path: str, method: str, body: dict | None,
             bearer: str | None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": f"NivXForge-EDR-Sensor/{SENSOR_VERSION}",
               "Accept": "application/json",
               **({"Content-Type": "application/json"} if data else {}),
               **({"Content-Length": str(len(data))} if data else {}),
               **({"Authorization": f"Bearer {bearer}"} if bearer else {})}
    status, payload = TRANSPORT.request(api, path, method, data, headers)
    if status >= 400:
        raise RuntimeError(f"{status} {payload.decode(errors='replace')[:400]}")
    try:
        return json.loads(payload) if payload else {}
    except ValueError:
        return {}


def _post(api: str, path: str, body: dict, bearer: str | None = None) -> dict:
    return _request(api, path, "POST", body, bearer)


# ── durable identity ──────────────────────────────────────────────
def _read_identity() -> dict:
    if not IDENTITY_FILE.exists():
        sys.exit("not enrolled: run `nivxforge_sensor.py enrol` first")
    return json.loads(IDENTITY_FILE.read_text())


def _reg_machine_guid() -> str | None:
    try:
        import winreg
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


# ── enrolment secret input · never on a command line ──────────────
#: Written wherever a secret could otherwise reach a log, a report or an
#: exception message.
SECRET_REDACTED = "[REDACTED]"
#: Flags that USED to accept the one-time enrolment secret as an argv
#: value. They are refused outright: Windows records process command
#: lines (Sysmon EID 1, the service binPath, PowerShell history), so a
#: secret passed this way becomes endpoint telemetry and can be delivered
#: to the very backend it authenticates against.
LEGACY_TOKEN_FLAGS = ("--token", "-token", "--enrollment-token",
                      "--enrolment-token")
#: Prefix of a minted enrolment secret. Used ONLY to refuse one that is
#: found on a command line; never to generate or validate a secret.
ENROLMENT_SECRET_PREFIX = "nvxenr_"
STDIN_ONLY_NOTICE = (
    "the one-time enrolment secret is read from STDIN via --token-stdin "
    "and is never accepted as a command-line value, because Windows "
    "records process command lines (Sysmon EID 1, service binPath, "
    "PowerShell history) and a recorded secret becomes endpoint "
    "telemetry. Supply it like this:\n"
    "  <secret-producing command> | NivXForgeEDRSetup.exe install "
    "--tenant <tenant-id> --token-stdin")


def redact(text: str, secret: str | None) -> str:
    """Replace every occurrence of `secret` in `text`."""
    if not secret:
        return text
    return text.replace(secret, SECRET_REDACTED)


def refuse_secret_on_command_line(argv: list[str]) -> None:
    """Refuse a command line that carries, or could carry, the secret.

    This runs BEFORE argparse on purpose: argparse echoes unrecognised
    arguments in its own error text, which would itself publish the
    secret to stderr and to any log that captures it.
    """
    for arg in argv:
        name, _, value = arg.partition("=")
        if name in LEGACY_TOKEN_FLAGS:
            raise SystemExit(f"refusing to run: {name} is REMOVED — "
                             + STDIN_ONLY_NOTICE)
        if arg.startswith(ENROLMENT_SECRET_PREFIX) or \
                value.startswith(ENROLMENT_SECRET_PREFIX):
            raise SystemExit(
                "refusing to run: what looks like an enrolment secret was "
                "found on this command line (no value is echoed) — "
                + STDIN_ONLY_NOTICE)


def read_enrolment_secret(stream=None) -> str:
    """Read the one-time enrolment secret from stdin, and nowhere else."""
    stream = sys.stdin if stream is None else stream
    if stream is None:
        raise SystemExit("no stdin is attached to this process, so "
                         + STDIN_ONLY_NOTICE)
    secret = (stream.readline() or "").strip()
    if not secret:
        raise SystemExit("stdin carried no enrolment secret — "
                         + STDIN_ONLY_NOTICE)
    if any(char.isspace() for char in secret):
        raise SystemExit("the value read from stdin contains whitespace and "
                         "was not accepted as an enrolment secret (no value "
                         "is echoed)")
    return secret


def enrol(api: str, tenant: str, token: str) -> dict:
    # Defence in depth: prove at RUNTIME that the secret this process is
    # about to use is not also sitting on its own command line.
    refuse_secret_on_command_line(list(sys.argv))
    if token in sys.argv:
        raise SystemExit("refusing to enrol: the enrolment secret is "
                         "present in this process's argv")
    facts = _machine_facts()
    if not facts["processor_id"] and not facts["machine_guid"]:
        sys.exit("refusing to enrol: no durable machine attribute found. An "
                 "unattributed observation is not an endpoint.")
    failure: str | None = None
    res: dict = {}
    try:
        res = _post(api, "/api/edr/agent/enroll", {
            "tenant_id": tenant, "enrollment_token": token,
            "sensor_version": SENSOR_VERSION,
            "processor_id": facts["processor_id"],
            "machine_guid": facts["machine_guid"],
            "hostname": facts["hostname"], "platform": facts["platform"]})
    except Exception as ex:                                  # noqa: BLE001
        # A rejected enrolment must not publish the secret: a backend
        # validation error can echo the request body straight back.
        failure = redact(f"enrolment failed: {type(ex).__name__}: "
                         f"{str(ex)[:400]}", token)
    if failure is not None:
        # Raised OUTSIDE the except block on purpose. `raise ... from None`
        # only suppresses the DISPLAY of the chain: the original exception
        # would still be reachable as `__context__`, carrying the
        # unredacted value with it.
        raise SystemExit(failure)
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


def _wevtutil_argv(channel: str, after_record: int, limit: int) -> list[str]:
    """The exact command line, built in one place so a test can assert the
    page size and the read direction rather than trusting a comment.

    `/rd:false` is OLDEST-FIRST and is load-bearing: it makes each page a
    forward page from the cursor. With `/rd:true` the sensor would read the
    newest N and the cursor would jump to the channel tail, which is the
    failure everybody assumed B5-GAP-1 was. It is not, and it must not
    become one.
    """
    return ["wevtutil", "qe", channel,
            f"/q:*[System[EventRecordID>{int(after_record)}]]",
            f"/c:{int(limit)}", "/e:Events", "/f:RenderedXml", "/rd:false"]


def _query_channel(channel: str, after_record: int,
                   limit: int | None = None
                   ) -> tuple[list[dict], str | None, int]:
    """ONE forward page after the cursor, or an honest unavailability reason.

    Returns `(events, reason, elapsed_ms)`. The elapsed time is recorded by
    the caller because `EventRecordID > N` is an unindexed scan whose cost
    grows with how far behind the cursor is; measuring it is how a future
    decision about the Windows API can rest on evidence instead of taste.
    """
    limit = page_size() if limit is None else limit
    started = time.monotonic()
    try:
        out = subprocess.run(_wevtutil_argv(channel, after_record, limit),
                             capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        return [], "wevtutil is not available on this host", 0
    except (OSError, subprocess.SubprocessError) as ex:
        return [], f"{type(ex).__name__}: {ex}", \
            int((time.monotonic() - started) * 1000)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if out.returncode != 0:
        return [], (out.stderr or "").strip()[:200] or "channel unreadable", \
            elapsed_ms
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
    return events, None, elapsed_ms


def _probe_source_tail(channel: str) -> dict:
    """The oldest and newest RecordID the source still holds.

    This is the ONLY honest way to say "we are behind" or "records we never
    acquired are provably gone". Both are single-record reads at the head
    and the tail, so the probe is cheap and it never mutates the channel.
    """
    out: dict = {}
    for key, direction in (("oldest", "false"), ("newest", "true")):
        try:
            result = subprocess.run(
                ["wevtutil", "qe", channel, "/c:1", f"/rd:{direction}",
                 "/e:Events", "/f:RenderedXml"],
                capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue
        value = _between(result.stdout or "", "<EventRecordID>",
                         "</EventRecordID>")
        if value:
            try:
                out[key] = int(value)
            except ValueError:
                pass
    return out


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


def _data_field(text: str, name: str) -> str | None:
    """One `<Data Name="...">value</Data>` field. String extraction only —
    it reads what the record states and infers nothing."""
    marker = f'Name="{name}">'
    try:
        head = text.index(marker) + len(marker)
        return text[head:text.index("</Data>", head)].strip() or None
    except ValueError:
        return None


def _record_ids(events: list[dict]) -> list[int]:
    ids = [e.get("winlog", {}).get("record_id") for e in events]
    return [int(i) for i in ids if i is not None]


def detect_gaps(channel: str, cursor: int, continuity: bool,
                events: list[dict]) -> list[dict]:
    """Source continuity, stated as a fact and nothing more.

    Two shapes are detected. LEADING: the first record of the page is not
    `cursor + 1`, so source records between them were never acquired.
    INTERIOR: two returned records are not adjacent, so records between two
    survivors are gone. Both are reported with `cause = NOT_PROVEN`.

    A RecordID discontinuity does NOT prove that every missing RecordID
    carried a security event, and it does NOT prove rollover. It proves a
    discontinuity, which is precisely what the platform previously could
    not tell apart from "nothing happened".

    `continuity` guards the very first acquisition on a channel: without a
    cursor this sensor itself committed, the pre-install history is not a
    gap and must not be reported as one.
    """
    ids = _record_ids(events)
    if not ids:
        return []
    gaps: list[dict] = []
    if continuity and cursor and ids[0] > cursor + 1:
        gaps.append(nvx_journal.build_gap(channel, cursor + 1, ids[0],
                                          "LEADING"))
    for previous, current in itertools.pairwise(ids):
        if current > previous + 1:
            gaps.append(nvx_journal.build_gap(channel, previous + 1, current,
                                              "INTERIOR"))
    return gaps


def _acquire_file_content(events: list[dict]) -> None:
    """B3 · optional content identity for Sysmon 11/15. Capability-gated and
    OFF by default; when it is on it sleeps per file, which the acquisition
    budget will notice and report as ACQUISITION_LAGGING rather than hide."""
    if not nvx_hash.enabled():
        return
    for event in events:
        if str(event["winlog"].get("event_id") or "") not in ("11", "15"):
            continue
        target = _data_field(event["winlog"].get("xml") or "",
                             "TargetFilename")
        if target:
            event["file_content_acquisition"] = ACQUIRER.acquire(
                target, operation="CREATE",
                event_observed_at=(event["winlog"].get("time_created")
                                   or event["observed_at"]),
                settle_seconds=nvx_hash.SETTLE_SECONDS)


def acquire(journal, policy: dict, excl_journal, budget_seconds: float,
            ident: dict | None = None) -> dict:
    """PAGED, BOUNDED, FAIR acquisition into durable local ownership.

    The loop that B5-GAP-1 lacked. One page per channel per pass, passes
    repeated until every channel is caught up or a bound is reached, so a
    channel producing more than one page between scheduling opportunities
    is followed instead of abandoned.

    Order within a page is the contract:

        read page -> adjudicate exclusions -> save exclusion journal
                  -> ONE transaction { evidence + gaps + cursor }

    The cursor is inside that transaction, so it cannot advance over
    evidence NivXForge does not own.
    """
    deadline = time.monotonic() + budget_seconds
    honoured = policy.get("exclusions") or []
    channels = list(CHANNELS)
    taken = {channel: 0 for channel in channels}
    journaled = {channel: 0 for channel in channels}
    duplicates = 0
    suppressed = 0
    unavailable: dict = {}
    caught_up = {channel: False for channel in channels}
    gaps_found: list[dict] = []
    pages = 0
    halted: str | None = None
    active = list(channels)
    while active and time.monotonic() < deadline and not halted:
        for channel in list(active):
            if time.monotonic() >= deadline:
                break
            admitted, reason = journal.admits_acquisition()
            if not admitted:
                halted = reason
                break
            cursor = journal.cursor(channel)
            continuity = journal.continuity_established(channel)
            found, failure, elapsed_ms = _query_channel(channel, cursor,
                                                        page_size())
            journal.observe_query(channel, elapsed_ms, ok=not failure)
            if failure:
                # The cursor is NOT advanced. A channel we could not read is
                # reported unavailable, never as an absence of activity.
                unavailable[channel] = failure
                active.remove(channel)
                continue
            pages += 1
            if not found:
                caught_up[channel] = True
                active.remove(channel)
                continue
            ids = _record_ids(found)
            gaps = detect_gaps(channel, cursor, continuity, found)
            # `partition` returns (kept, SUPPRESSED COUNT) — an int, not a
            # list. The pre-journal run loop called len() on it, which
            # raised TypeError the moment a COLLECTION-scoped exclusion
            # actually matched. Counted correctly here.
            kept, excluded = nvx_excl.partition(found, honoured,
                                                excl_journal, policy)
            excluded = int(excluded or 0)
            _acquire_file_content(kept)
            # GATE 7 is preserved: an excluded record never enters the
            # durable evidence store. Its adjudication is made durable
            # FIRST, so the cursor only ever advances over records that are
            # either owned as evidence or owned as a recorded suppression.
            excl_journal.save()
            result = journal.commit_page(
                channel, kept, max(cursor, max(ids) if ids else cursor), gaps,
                endpoint_id=(ident or {}).get("endpoint_id"),
                tenant_id=(ident or {}).get("tenant_id"))
            taken[channel] += len(found)
            journaled[channel] += result["journaled"]
            duplicates += result["duplicates_ignored"]
            suppressed += excluded
            gaps_found.extend(gaps)
            COUNTERS.bump("endpoint_observed", len(found))
            COUNTERS.bump("endpoint_read", len(found))
            COUNTERS.bump("sensor_suppressed_by_policy", excluded)
            journal.bump("records_read", len(found))
            journal.bump("records_journaled", result["journaled"])
            journal.set_gauge(f"last_record_id_journaled:{channel}",
                              result["cursor_committed"])
            if len(found) < page_size():
                caught_up[channel] = True
                active.remove(channel)
            elif taken[channel] >= max_records_per_channel_per_cycle():
                active.remove(channel)
    if gaps_found:
        journal.bump("acquisition_gaps_detected", len(gaps_found))
    return {"records_read": sum(taken.values()),
            "records_journaled": sum(journaled.values()),
            "duplicates_ignored": duplicates,
            "per_channel_read": taken, "pages": pages,
            "caught_up": caught_up, "channels_unavailable": unavailable,
            "acquisition_gaps": gaps_found,
            "collection_suppressed_at_endpoint": suppressed,
            "acquisition_halted": halted,
            "budget_exhausted": bool(active) and not halted}


def _get(api: str, path: str, bearer: str) -> dict:
    return _request(api, path, "GET", None, bearer)


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
    """LEGACY writer for `outbox.jsonl`, no longer used by the run loop.

    Acquisition durability now belongs to the Local Evidence Journal, whose
    COMMIT also carries the source cursor. This is retained only because
    the legacy file it wrote must stay readable and deliverable on an
    upgraded endpoint; nothing should start writing to it again.
    """
    if not events:
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(QUEUE_FILE, "a") as fh:
        fh.writelines(json.dumps(event, separators=(",", ":")) + "\n" for event in events)
        fh.flush()
        os.fsync(fh.fileno())


def _queue_depth(journal=None) -> int:
    """Unsent evidence the endpoint still holds: the legacy `outbox.jsonl`
    remainder PLUS the journal's undelivered rows. A backlog is a backlog
    whichever store it is sitting in."""
    depth = 0
    if QUEUE_FILE.exists():
        offset = int(OFFSET_FILE.read_text()) if OFFSET_FILE.exists() else 0
        with open(QUEUE_FILE, "rb") as fh:
            fh.seek(offset)
            while fh.readline():
                depth += 1
    if journal is not None:
        depth += journal.depth()
    return depth


def _legacy_remaining() -> int:
    return _queue_depth(None)


def _drain(api: str, ident: dict, session: dict, interval: int | None = None,
           budget_seconds: float | None = None) -> tuple[int, int]:
    """Drain the LEGACY pre-journal outbox. Kept so an upgraded endpoint
    still delivers everything the old build had acquired; the file is never
    deleted or rewritten by the upgrade.

    Bounded by WALL CLOCK, not by a message count: a count cannot bound
    time when each POST costs seconds, and that is exactly how delivery
    came to occupy the whole cycle.
    """
    if not QUEUE_FILE.exists():
        return 0, 0
    deadline = time.monotonic() + (budget_seconds
                                   if budget_seconds is not None else 30.0)
    offset = int(OFFSET_FILE.read_text()) if OFFSET_FILE.exists() else 0
    sent = failed = 0
    with open(QUEUE_FILE, "rb") as fh:
        fh.seek(offset)
        while raw_line := fh.readline():
            if time.monotonic() >= deadline:
                break
            consumed = len(raw_line)
            line = raw_line.decode(errors="replace").strip()
            if not line:
                offset += consumed
                OFFSET_FILE.write_text(str(offset))
                continue
            try:
                if not session.get("token"):
                    session["token"] = _open_session(api, ident)
                COUNTERS.bump("sensor_attempted")
                _post(api, "/api/edr/agent/telemetry",
                      {"payload": line, "source_kind": "sensor",
                       "sensor_version": SENSOR_VERSION,
                       **({"report_interval_seconds": float(interval)}
                          if interval else {})},
                      bearer=session["token"])
                sent += 1
                COUNTERS.bump("sensor_sent")
                offset += consumed
                OFFSET_FILE.write_text(str(offset))
            except (RuntimeError, urllib.error.URLError, OSError) as ex:
                message = str(ex)
                if message.startswith(("401", "403")) and session.get("token"):
                    session["token"] = None
                    fh.seek(offset)
                    continue
                failed += 1
                COUNTERS.bump("sensor_failed")
                print(f"[journal] held at offset {offset}: {message[:140]}")
                break
    return sent, failed


#: Set once if the backend does not offer the batch route, so an upgraded
#: sensor talking to an older backend degrades to the single-event path
#: instead of failing. There is no third path.
BATCH_SUPPORT = {"available": True, "reason": None}


def _deliver_batch(api: str, ident: dict, session: dict, journal,
                   rows: list, interval: int | None) -> dict:
    """ONE request, PER-EVENT acceptance.

    Only the indices the platform said `accepted` are released. A refused
    event stays owned by the endpoint — `SENT != ACCEPTED` survives
    batching, which is the only reason batching is allowed here at all.
    """
    body = {"events": [{"payload": row["payload"]} for row in rows],
            "source_kind": "sensor", "sensor_version": SENSOR_VERSION,
            "batch_id": f"{int(time.time() * 1000)}-"
                        f"{int(rows[0]['journal_sequence'])}",
            **({"report_interval_seconds": float(interval)}
               if interval else {})}
    COUNTERS.bump("sensor_attempted", len(rows))
    out = _post(api, "/api/edr/agent/telemetry/batch", body,
                bearer=session["token"])
    accepted, refused = [], []
    for result in out.get("results") or []:
        index = result.get("index")
        if not isinstance(index, int) or not 0 <= index < len(rows):
            continue
        sequence = int(rows[index]["journal_sequence"])
        if result.get("accepted"):
            accepted.append(sequence)
        else:
            refused.append((sequence, str(result.get("detail")
                                          or result.get("error"))[:200]))
    if accepted:
        journal.mark_accepted(accepted)
        journal.bump("backend_accepted", len(accepted))
        COUNTERS.bump("sensor_sent", len(accepted))
    for sequence, detail in refused:
        journal.mark_attempt_failed(sequence, detail)
        journal.bump("delivery_failures")
        COUNTERS.bump("sensor_failed")
    return {"sent": len(accepted), "failed": len(refused)}


def _drain_journal(api: str, ident: dict, session: dict, journal,
                   interval: int | None = None,
                   budget_seconds: float | None = None,
                   batch: int | None = None) -> dict:
    """Deliver journaled evidence in journal order, within a time budget.

    SENT != ACCEPTED. A row becomes BACKEND_ACCEPTED only when the platform
    returns an accept for that specific row; a transport attempt that
    merely left the host records a failed attempt and the evidence stays
    owned locally.
    """
    deadline = time.monotonic() + (budget_seconds
                                   if budget_seconds is not None else 30.0)
    size = batch if batch is not None else delivery_batch_size()
    sent = failed = 0
    unreachable = False
    while time.monotonic() < deadline and not unreachable:
        rows = journal.next_undelivered(limit=max(1, size))
        if not rows:
            break
        if not session.get("token"):
            try:
                session["token"] = _open_session(api, ident)
            except (RuntimeError, urllib.error.URLError, OSError) as ex:
                print(f"[journal] session unavailable: {str(ex)[:140]}")
                return {"sent": sent, "failed": failed,
                        "backend_unreachable": True,
                        "batch_size": size,
                        "budget_exhausted": False}
        if size > 1 and BATCH_SUPPORT["available"]:
            try:
                out = _deliver_batch(api, ident, session, journal, rows,
                                     interval)
                sent += out["sent"]
                failed += out["failed"]
                if out["sent"] == 0:
                    # Nothing was accepted. Stop rather than spin: the
                    # evidence is still owned and will be retried.
                    unreachable = True
                continue
            except (RuntimeError, urllib.error.URLError, OSError) as ex:
                message = str(ex)
                if message.startswith(("401", "403")):
                    session["token"] = None
                    continue
                if message.startswith(("404", "405")):
                    BATCH_SUPPORT.update(
                        available=False,
                        reason="backend does not offer "
                               "/api/edr/agent/telemetry/batch")
                    print("[journal] batch route unavailable; falling back "
                          "to single-event delivery")
                    continue
                if message.startswith("413") and size > 1:
                    size = max(1, size // 2)
                    print(f"[journal] batch refused as too large; "
                          f"reducing to {size}")
                    continue
                journal.mark_attempt_failed(
                    int(rows[0]["journal_sequence"]), message)
                journal.bump("delivery_failures")
                COUNTERS.bump("sensor_failed")
                failed += 1
                unreachable = True
                print(f"[journal] evidence retained at sequence "
                      f"{rows[0]['journal_sequence']}: {message[:140]}")
                continue
        for row in rows:
            if time.monotonic() >= deadline:
                break
            sequence = int(row["journal_sequence"])
            try:
                if not session.get("token"):
                    session["token"] = _open_session(api, ident)
                COUNTERS.bump("sensor_attempted")
                _post(api, "/api/edr/agent/telemetry",
                      {"payload": row["payload"], "source_kind": "sensor",
                       "sensor_version": SENSOR_VERSION,
                       **({"report_interval_seconds": float(interval)}
                          if interval else {})},
                      bearer=session["token"])
                journal.mark_accepted([sequence])
                journal.bump("backend_accepted")
                COUNTERS.bump("sensor_sent")
                sent += 1
            except (RuntimeError, urllib.error.URLError, OSError) as ex:
                message = str(ex)
                if message.startswith(("401", "403")) and session.get("token"):
                    session["token"] = None
                    continue
                journal.mark_attempt_failed(sequence, message)
                journal.bump("delivery_failures")
                COUNTERS.bump("sensor_failed")
                failed += 1
                unreachable = True
                print(f"[journal] evidence retained at sequence {sequence}: "
                      f"{message[:140]}")
                break
    return {"sent": sent, "failed": failed,
            "backend_unreachable": unreachable, "batch_size": size,
            "budget_exhausted": time.monotonic() >= deadline}


def _report_integrity(api: str, ident: dict, session: dict, journal,
                      health: dict, acquired: dict) -> str:
    """Send acquisition integrity on its OWN versioned contract.

    Not folded into the heartbeat: `HeartbeatBody` is `extra="forbid"`, so
    extra fields there would 422 every production sensor. A gap is only
    marked reported once the platform has it, so a delivery failure keeps
    it pending instead of losing the declaration.
    """
    gaps = journal.unreported_gaps(limit=200)
    channels = {}
    for channel in CHANNELS:
        tail = (health.get("source_tails") or {}).get(channel) or {}
        channels[channel] = {
            "last_cursor_committed": journal.cursor(channel),
            "last_record_id_journaled": (health.get("counters") or {}).get(
                f"last_record_id_journaled:{channel}"),
            "records_read": acquired["per_channel_read"].get(channel),
            "acquisition_lag_records": (
                health.get("acquisition_lag_records") or {}).get(channel),
            "source_oldest_record_id": tail.get("oldest"),
            "source_newest_record_id": tail.get("newest"),
            "query_ms_last": (health.get("counters") or {}).get(
                f"query_ms_last:{channel}"),
            "caught_up": acquired["caught_up"].get(channel),
            "unavailable_reason":
                acquired["channels_unavailable"].get(channel),
        }
    body = {"at": health.get("at"), "contract_version": 1,
            "sensor_version": SENSOR_VERSION, "channels": channels,
            "acquisition_gaps": [
                {"channel": g["channel"], "position": g["position"],
                 "expected_next_record_id": g["expected_next_record_id"],
                 "first_observed_record_id": g["first_observed_record_id"],
                 "detected_at": g["detected_at"]} for g in gaps],
            "acquisition_gap_count": health.get("acquisition_gap_count"),
            "journal_depth": health.get("delivery_queue_depth"),
            "journal_bytes": health.get("journal_bytes"),
            "journal_live_bytes": health.get("journal_live_bytes"),
            "delivery_backlog": health.get("delivery_queue_depth"),
            "health_states": health.get("states") or []}
    try:
        if not session.get("token"):
            session["token"] = _open_session(api, ident)
        _post(api, "/api/edr/agent/acquisition-integrity", body,
              bearer=session["token"])
    except (RuntimeError, urllib.error.URLError, OSError) as ex:
        message = str(ex)
        if message.startswith(("401", "403")):
            session["token"] = None
        if message.startswith(("404", "405")):
            return "UNSUPPORTED_BY_BACKEND"
        return f"FAILED:{message[:80]}"
    if gaps:
        journal.mark_gaps_reported([int(g["gap_id"]) for g in gaps])
    return f"SENT:{len(gaps)}"


def _heartbeat(api: str, ident: dict, session: dict,
               interval: int, journal=None) -> None:
    """Liveness. NOT telemetry: it never makes a silent sensor look busy.

    The body is unchanged on purpose. `HeartbeatBody` is `extra="forbid"`,
    so adding acquisition-integrity fields here would 422 every production
    heartbeat. Integrity therefore lives in the local machine-readable
    snapshot and in the cycle report until a backend contract for it is
    approved separately.
    """
    try:
        if not session.get("token"):
            session["token"] = _open_session(api, ident)
        _post(api, "/api/edr/agent/heartbeat",
              {"report_interval_seconds": float(interval),
               "sensor_version": SENSOR_VERSION,
               "queue_depth": _queue_depth(journal),
               # Additive and only when the CAPABILITY is enabled.
               **COUNTERS.heartbeat_fields()},
              bearer=session["token"])
    except (RuntimeError, urllib.error.URLError, OSError) as ex:
        print(f"[heartbeat] {str(ex)[:140]}")
        session["token"] = None


def _mirror_bookmarks(journal) -> None:
    """Write the legacy `channels.json` as a NON-AUTHORITATIVE mirror of the
    journal cursors, so a downgrade and an operator both still work."""
    try:
        _save_bookmarks(journal.cursors())
    except OSError:
        pass


def _cycle(api: str, ident: dict, session: dict, journal,
           interval: int) -> dict:
    """ONE bounded scheduling opportunity: ACQUIRE -> PROCESS -> DELIVER.

    Every stage gets its own wall-clock budget, so a slow backend produces
    a DELIVERY_BACKLOG and never an ACQUISITION_LOSS. This is the whole
    point of B5-GAP-1: the failure domains are now separate.
    """
    policy = _sync_policy(api, ident, session)
    excl_journal = nvx_excl.Journal(EXCLUSION_JOURNAL)
    acquired = acquire(journal, policy, excl_journal,
                       acquire_budget_seconds(interval), ident)
    excl_journal.save()
    _mirror_bookmarks(journal)

    legacy_sent, legacy_failed = _drain(
        api, ident, session, interval, legacy_drain_budget_seconds(interval))
    delivered = _drain_journal(api, ident, session, journal, interval,
                               deliver_budget_seconds(interval))
    reclaimed = journal.reclaim()

    _heartbeat(api, ident, session, interval, journal)
    reported = _report_enforcement(api, ident, session, excl_journal, policy)

    tails = {}
    if source_tail_probe_enabled():
        tails = {channel: _probe_source_tail(channel) for channel in CHANNELS}
    health = journal.health(
        channels_unavailable=acquired["channels_unavailable"],
        backend_unreachable=delivered["backend_unreachable"],
        caught_up=acquired["caught_up"], source_tails=tails)
    journal.write_integrity_snapshot(health)
    integrity = _report_integrity(api, ident, session, journal, health,
                                  acquired)

    depth = _queue_depth(journal)
    COUNTERS.observe_gauge("sensor_queue_depth", depth)
    COUNTERS.persist()
    return {"at": _now(), "sensor_version": SENSOR_VERSION,
            "records_read": acquired["records_read"],
            "records_journaled": acquired["records_journaled"],
            "duplicates_ignored": acquired["duplicates_ignored"],
            "pages": acquired["pages"],
            "per_channel_read": acquired["per_channel_read"],
            "caught_up": acquired["caught_up"],
            "acquisition_gaps": acquired["acquisition_gaps"],
            "acquisition_halted": acquired["acquisition_halted"],
            "acquisition_budget_exhausted": acquired["budget_exhausted"],
            "sent": delivered["sent"] + legacy_sent,
            "failed": delivered["failed"] + legacy_failed,
            "legacy_outbox_sent": legacy_sent,
            "legacy_outbox_remaining": _legacy_remaining(),
            "journal_reclaimed": reclaimed["reclaimed"],
            "delivery_batch_size": delivered["batch_size"],
            "integrity_report": integrity,
            "queue_depth": depth,
            "health": health["states"],
            "collection_suppressed_at_endpoint":
                acquired["collection_suppressed_at_endpoint"],
            "policy_id": policy.get("policy_id"),
            "policy_version": policy.get("version"),
            "policy_stale": bool(policy.get("stale")),
            "exclusions_delivered": len(policy.get("exclusions") or []),
            "enforcement_report": reported,
            "channels_unavailable": acquired["channels_unavailable"]}


def run(api: str, interval: int = 30, once: bool = False) -> dict:
    ident = _read_identity()
    session: dict = {"token": None}
    journal = nvx_journal.open_journal(STATE_DIR, BOOKMARK_FILE)
    try:
        while True:
            report = _cycle(api, ident, session, journal, interval)
            print(json.dumps(report))
            if once:
                return report
            time.sleep(max(5, interval))
    finally:
        journal.close()
        TRANSPORT.close()


def status() -> dict:
    enrolled = IDENTITY_FILE.exists()
    ident = json.loads(IDENTITY_FILE.read_text()) if enrolled else {}
    out = {"sensor_version": SENSOR_VERSION, "enrolled": enrolled,
           "endpoint_id": ident.get("endpoint_id"),
           "tenant_id": ident.get("tenant_id"),
           "state_dir": str(STATE_DIR),
           "legacy_outbox_remaining": _legacy_remaining(),
           "credential_present": bool(ident.get("agent_credential")),
           "note": "the credential value itself is never printed"}
    try:
        journal = nvx_journal.open_journal(STATE_DIR)
    except nvx_journal.JournalUnavailable as ex:
        out["journal"] = {"states": [nvx_journal.JOURNAL_CORRUPT],
                          "error": str(ex)[:200]}
        out["queue_depth"] = out["legacy_outbox_remaining"]
        return out
    try:
        out["queue_depth"] = _queue_depth(journal)
        out["journal"] = journal.health()
    finally:
        journal.close()
    return out


def main() -> None:
    refuse_secret_on_command_line(list(sys.argv[1:]))
    ap = argparse.ArgumentParser(description="NivXForge EDR Windows sensor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enrol")
    e.add_argument("--api", required=True)
    e.add_argument("--tenant", required=True)
    e.add_argument("--token-stdin", action="store_true", required=True,
                   help="read the one-time enrolment secret from stdin")
    r = sub.add_parser("run")
    r.add_argument("--api", required=True)
    r.add_argument("--interval", type=int, default=30)
    r.add_argument("--once", action="store_true")
    sub.add_parser("status")
    sub.add_parser("capabilities")
    args = ap.parse_args()
    if args.cmd == "enrol":
        enrol(args.api, args.tenant, read_enrolment_secret())
    elif args.cmd == "run":
        run(args.api, args.interval, args.once)
    elif args.cmd == "status":
        print(json.dumps(status(), indent=2))
    else:
        print(json.dumps({"sensor_version": SENSOR_VERSION,
                          **_machine_facts(), **CAPABILITIES}, indent=2))


if __name__ == "__main__":
    main()
