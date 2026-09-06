#!/usr/bin/env python3
"""NivXForge EDR · Linux sensor (P0-B).

A REAL endpoint sensor. Every field it emits is read from the running
kernel via /proc. Nothing is simulated, and where the kernel will not tell
us something the sensor says so explicitly rather than guessing.

    enrol (one-time token) → durable credential → session
      → collect real process / file / network activity
      → local durable queue  → authenticated ingest

Honest limits, declared in the sensor's own capability block and therefore
visible to the platform rather than discovered later:

  * **Process EXIT is not observed.** Polling /proc cannot distinguish a
    process that exited from one we simply missed between scans, so we
    report first-observation only and never claim an exit time.
  * **The file WRITER is not observed.** inotify (and mtime polling) tell
    us a path changed; they do not tell us which process changed it. So
    `actor` is NOT_OBSERVED rather than attributed to a guess.
  * **Short-lived processes can be missed entirely.** A poll interval is a
    sampling window; anything that starts and exits inside it is invisible.
    That is a VISIBILITY GAP, not an absence of activity.
  * No eBPF, so there is no syscall-level fidelity.

Run:
    python3 nivxforge_sensor.py enrol --api URL --tenant T --token enr_...
    python3 nivxforge_sensor.py run   --api URL [--once] [--watch DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import socket
import sys
import time
import shutil
import signal
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SENSOR_VERSION = "0.1.0"
STATE_DIR = Path(os.environ.get("NIVXFORGE_SENSOR_STATE",
                                "/var/lib/nivxforge-sensor"))
IDENTITY_FILE = STATE_DIR / "identity.json"      # mode 0600
QUEUE_FILE = STATE_DIR / "outbox.jsonl"
OFFSET_FILE = STATE_DIR / "outbox.offset"
#: What this sensor has ALREADY reported. Durable, because an in-memory
#: set means a sensor restart re-reports the entire process table and the
#: same real process then appears many times in the trajectory as if it
#: had started many times.
OBSERVED_FILE = STATE_DIR / "observed.json"

#: What this sensor can actually produce. Sent at enrolment so the platform
#: resolves an unsupported field as NOT_SUPPORTED, never NOT_OBSERVED.
CAPABILITIES = {
    "collects": ["PROCESS", "FILE", "NETWORK"],
    "fields_supported": [
        "process.pid", "process.ppid", "process.image", "process.image_path",
        "process.sha256", "process.command_line", "process.user",
        "process.start_time", "process.parent_image",
        "process.parent_image_path",
        "file.path", "file.filename", "file.size", "file.sha256",
        "file.operation",
        "network.protocol", "network.local_ip", "network.local_port",
        "network.remote_ip", "network.remote_port", "network.direction",
        "network.process_iid",
    ],
    "fields_not_supported": [
        "process.exit_time", "process.signer", "process.integrity",
        "file.actor_process", "registry.*", "usb_device.*", "memory.*",
    ],
    "response_actions": ["KILL_PROCESS"],
    #: Declared but privilege-gated. The sensor reports the exact missing
    #: capability at command time rather than claiming containment it
    #: cannot enforce.
    "response_actions_conditional": {
        "ISOLATE_ENDPOINT": "requires CAP_NET_ADMIN and nft or iptables on "
                            "this endpoint",
        "RELEASE_ISOLATION": "requires CAP_NET_ADMIN and nft or iptables on "
                             "this endpoint",
    },
    "collection_method": "PROC_POLL",
    "limits": [
        "process exit is not observed; polling cannot distinguish exit from "
        "a missed scan",
        "the file writer is not observed; a path change does not identify "
        "the process that made it",
        "processes that start and exit within one poll interval are missed "
        "entirely — a visibility gap, not an absence of activity",
        "no eBPF, so no syscall-level fidelity",
    ],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _post(api: str, path: str, body: dict, bearer: str | None = None) -> dict:
    req = urllib.request.Request(
        f"{api}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 # An explicit UA: some edge proxies reject the default
                 # urllib agent outright, which would look like an auth
                 # failure and send an operator hunting the wrong thing.
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


def _machine_facts() -> dict:
    """Durable machine attributes. The platform mints endpoint_id from
    these — the sensor never proposes one."""
    processor_id = None
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith(("serial", "model name")):
                processor_id = hashlib.sha256(
                    line.split(":", 1)[1].strip().encode()).hexdigest()[:24]
                break
    except OSError:
        pass
    guid = None
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            guid = Path(p).read_text().strip() or None
            if guid:
                break
        except OSError:
            continue
    # Container fallback: the cgroup/boot identity is still durable for the
    # lifetime of this container and is honestly labelled as such.
    if not processor_id and not guid:
        try:
            guid = hashlib.sha256(
                Path("/proc/sys/kernel/random/boot_id").read_bytes()
            ).hexdigest()[:32]
        except OSError:
            pass
    return {"processor_id": processor_id, "machine_guid": guid,
            "hostname": socket.gethostname(), "platform": "LINUX"}


def enrol(api: str, tenant: str, token: str) -> None:
    facts = _machine_facts()
    if not facts["processor_id"] and not facts["machine_guid"]:
        sys.exit("refusing to enrol: no durable machine attribute found. An "
                 "unattributed observation is not an endpoint.")
    res = _post(api, "/api/edr/agent/enroll", {
        "tenant_id": tenant, "enrollment_token": token,
        "sensor_version": SENSOR_VERSION, **facts})
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    IDENTITY_FILE.write_text(json.dumps({
        "tenant_id": tenant, "endpoint_id": res["endpoint_id"],
        "credential_id": res["credential_id"],
        "agent_credential": res["agent_credential"],
        "enrolled_at": _now(), "capabilities": CAPABILITIES}, indent=2))
    IDENTITY_FILE.chmod(0o600)
    print(f"enrolled endpoint_id={res['endpoint_id']}")
    print(f"credential stored 0600 at {IDENTITY_FILE}")
    print(f"sensor_state={res['sensor_state']}  (nothing collected yet)")


def _open_session(api: str, ident: dict) -> str:
    return _post(api, "/api/edr/agent/session",
                 {"tenant_id": ident["tenant_id"],
                  "agent_credential": ident["agent_credential"]}
                 )["session_token"]


# ── real collection ───────────────────────────────────────────────

def _sha256_file(path: str, limit: int = 64 * 1024 * 1024) -> str | None:
    try:
        h, size = hashlib.sha256(), 0
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                size += len(chunk)
                if size > limit:
                    return None
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def collect_processes(seen: set[str], hash_exe: bool = True) -> list[dict]:
    """Real processes from /proc. Emits an event the first time a (pid,
    start_ticks) pair is observed, so a restart does not re-report the
    whole process table."""
    out = []
    try:
        boot = 0.0
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime"):
                boot = float(line.split()[1])
                break
        hz = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError):
        boot, hz = 0.0, 100
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            rparen = stat.rindex(")")
            fields = stat[rparen + 2:].split()
            ppid = int(fields[1])
            start_ticks = int(fields[19])
            key = f"{pid}:{start_ticks}"
            if key in seen:
                continue
            seen.add(key)
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes() \
                .replace(b"\x00", b" ").decode(errors="replace").strip()
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                exe = None
            uid = os.stat(f"/proc/{pid}").st_uid
            try:
                user = pwd.getpwuid(uid).pw_name
            except KeyError:
                user = f"uid:{uid}"
            parent = _proc_parent(ppid, start_ticks)
            out.append({
                "activity": "PROCESS",
                "operation": "PROCESS_OBSERVED",
                "observed_at": _now(),
                "start_time": (datetime.fromtimestamp(
                    boot + start_ticks / hz, timezone.utc).isoformat()
                    if boot else None),
                # The kernel's own start-time counter (field 22 of
                # /proc/<pid>/stat). This — NOT the wall-clock string — is
                # the process start IDENTITY: it is exact, it is what can
                # be re-read later, and it is the only thing that
                # distinguishes this process from a future process that
                # reuses the same pid. Response targeting depends on it.
                "start_ticks": start_ticks,
                "pid": pid, "ppid": ppid,
                "image": (exe.rsplit("/", 1)[-1] if exe
                          else stat[stat.index("(") + 1:rparen]),
                "image_path": exe,
                "command_line": cmdline or None,
                "user": user,
                "sha256": _sha256_file(exe) if (exe and hash_exe) else None,
                "parent_image": parent["parent_image"],
                "parent_image_path": parent["parent_image_path"],
                "parent_lookup_state": parent["parent_lookup_state"],
                # Declared, not inferred. See the module docstring.
                "not_observed": (["exit_time", "signer", "integrity"]
                                 + ([] if parent["parent_lookup_state"]
                                    == "OBSERVED" else ["parent_image"])),
            })
        except (OSError, ValueError, IndexError):
            continue
    return out


def _proc_parent(ppid: int, child_start_ticks: int) -> dict:
    """Real parent evidence read from /proc — never inferred.

    A bare ppid is NOT ancestry. Linux reuses PIDs, so the process sitting
    at that pid now may not be the process that forked this one. The parent
    is therefore attributed only when /proc still holds it AND its start
    time precedes the child's. Otherwise the state names exactly what we
    could not establish, and no parent image is claimed.
    """
    none = {"parent_image": None, "parent_image_path": None,
            "parent_start_ticks": None}
    if ppid == 0:
        # PID 0 is the kernel boundary. It is not a missing parent and it
        # is not an invented root.
        return {**none, "parent_lookup_state": "KERNEL_BOUNDARY"}
    try:
        stat = Path(f"/proc/{ppid}/stat").read_text()
        rparen = stat.rindex(")")
        comm = stat[stat.index("(") + 1:rparen]
        pstart = int(stat[rparen + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return {**none, "parent_lookup_state": "PARENT_NOT_PRESENT"}
    if pstart > child_start_ticks:
        return {**none,
                "parent_lookup_state": "PID_REUSED_PARENT_NOT_ATTRIBUTABLE"}
    try:
        pexe = os.readlink(f"/proc/{ppid}/exe")
    except OSError:
        pexe = None
    return {"parent_image": (pexe.rsplit("/", 1)[-1] if pexe else comm),
            "parent_image_path": pexe, "parent_start_ticks": pstart,
            "parent_lookup_state": "OBSERVED"}


def _inode_pid_map() -> dict[str, int]:
    m: dict[str, int] = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            for fd in os.scandir(f"/proc/{entry.name}/fd"):
                try:
                    target = os.readlink(fd.path)
                except OSError:
                    continue
                if target.startswith("socket:["):
                    m[target[8:-1]] = int(entry.name)
        except OSError:
            continue
    return m


def _hexip(raw: str) -> str:
    if len(raw) == 8:
        b = bytes.fromhex(raw)
        return ".".join(str(x) for x in reversed(b))
    try:
        groups = [raw[i:i + 8] for i in range(0, 32, 8)]
        packed = b"".join(bytes.fromhex(g)[::-1] for g in groups)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except (ValueError, OSError):
        return raw


def collect_network(seen: set[str]) -> list[dict]:
    """Real TCP connections from /proc/net, with the owning PID resolved
    through the socket inode. A remote IP is a network peer — never an
    endpoint and never a process."""
    inode_pid = _inode_pid_map()
    out = []
    for proto, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")):
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 10:
                continue
            try:
                lip, lport = f[1].split(":")
                rip, rport = f[2].split(":")
                state, inode = f[3], f[9]
            except (ValueError, IndexError):
                continue
            lport_i, rport_i = int(lport, 16), int(rport, 16)
            local, remote = _hexip(lip), _hexip(rip)
            key = f"{proto}|{local}:{lport_i}|{remote}:{rport_i}|{state}"
            if key in seen:
                continue
            seen.add(key)
            listening = state == "0A"
            out.append({
                "activity": "NETWORK",
                "operation": "CONNECTION_OBSERVED",
                "observed_at": _now(),
                "protocol": proto.upper(),
                "local_ip": local, "local_port": lport_i,
                "remote_ip": None if listening else remote,
                "remote_port": None if listening else rport_i,
                "direction": "LISTEN" if listening else "OUTBOUND",
                "tcp_state": state,
                "pid": inode_pid.get(inode),
                "not_observed": (["remote_ip", "remote_port"] if listening
                                 else []) + ([] if inode in inode_pid
                                             else ["owning_process"]),
            })
    return out


def collect_files(watch: str, known: dict[str, tuple]) -> list[dict]:
    """Real file activity under a watched directory.

    Operation is derived from what the filesystem actually shows: a path
    that was not there is CREATE, a changed size/mtime is MODIFY, a path
    that vanished is DELETE. The WRITER is never attributed — see the
    module docstring.
    """
    out, current = [], {}
    root = Path(watch)
    if not root.is_dir():
        return out
    for dirpath, _dirs, files in os.walk(watch):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                st = os.stat(p)
            except OSError:
                continue
            current[p] = (st.st_mtime_ns, st.st_size)
    for p, sig in current.items():
        if p not in known:
            op = "CREATE"
        elif known[p] != sig:
            op = "MODIFY"
        else:
            continue
        out.append({
            "activity": "FILE", "operation": op, "observed_at": _now(),
            "path": p, "filename": p.rsplit("/", 1)[-1], "size": sig[1],
            "sha256": _sha256_file(p),
            "not_observed": ["actor_process"],
        })
    for p in set(known) - set(current):
        out.append({
            "activity": "FILE", "operation": "DELETE", "observed_at": _now(),
            "path": p, "filename": p.rsplit("/", 1)[-1], "size": None,
            "sha256": None, "not_observed": ["actor_process", "size",
                                             "sha256"],
        })
    known.clear()
    known.update(current)
    return out


# ── local durable queue · no silent evidence loss ─────────────────

def _enqueue(events: list[dict]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(QUEUE_FILE, "a") as f:
        for e in events:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())


def _drain(api: str, ident: dict, session: dict) -> tuple[int, int]:
    """Send everything the queue holds, advancing the offset only after a
    confirmed accept. A connectivity loss therefore REPLAYS instead of
    losing evidence."""
    if not QUEUE_FILE.exists():
        return 0, 0
    offset = int(OFFSET_FILE.read_text()) if OFFSET_FILE.exists() else 0
    sent = failed = 0
    # Binary mode with an explicitly accumulated offset. Text-mode
    # readline()+tell() advances past the whole read buffer, which would
    # re-send everything after the first line on the next run.
    with open(QUEUE_FILE, "rb") as f:
        f.seek(offset)
        while raw_line := f.readline():
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
                       "sensor_version": SENSOR_VERSION},
                      bearer=session["token"])
                sent += 1
                offset += consumed
                OFFSET_FILE.write_text(str(offset))
            except (RuntimeError, urllib.error.URLError, OSError) as e:
                msg = str(e)
                if msg.startswith(("401", "403")) and session.get("token"):
                    # Session expired or was revoked. Re-open once; if the
                    # credential itself is dead the next attempt fails and
                    # the event STAYS queued — never dropped.
                    session["token"] = None
                    f.seek(offset)
                    continue
                failed += 1
                print(f"[queue] held back at offset {offset}: {msg[:140]}")
                break
    return sent, failed


def _load_observed() -> tuple[set[str], set[str], dict[str, tuple], set[str]]:
    """What this sensor has already reported, across restarts."""
    try:
        d = json.loads(OBSERVED_FILE.read_text())
    except (OSError, ValueError):
        return set(), set(), {}, set()
    return (set(d.get("processes") or ()), set(d.get("connections") or ()),
            {k: tuple(v) for k, v in (d.get("files") or {}).items()},
            set(d.get("baselined_dirs") or ()))


def _save_observed(procs: set[str], conns: set[str],
                   files: dict[str, tuple], baselined: set[str]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OBSERVED_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"processes": sorted(procs),
                               "connections": sorted(conns),
                               "files": {k: list(v)
                                         for k, v in files.items()},
                               "baselined_dirs": sorted(baselined),
                               "saved_at": _now()}))
    tmp.replace(OBSERVED_FILE)


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


def _isolation_capability() -> dict:
    """Preflight. Names the EXACT missing privilege, because "isolation
    failed" sends an operator hunting the wrong thing."""
    cap = False
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                cap = bool((int(line.split()[1], 16) >> 12) & 1)  # NET_ADMIN
                break
    except (OSError, ValueError):
        pass
    backend = ("nft" if shutil.which("nft")
               else "iptables" if shutil.which("iptables") else None)
    missing = ([] if cap else ["CAP_NET_ADMIN"]) + \
              ([] if backend else ["nft or iptables"])
    return {"available": bool(cap and backend), "backend": backend,
            "cap_net_admin": cap, "missing": missing,
            "detail": (f"network containment enforceable with {backend}"
                       if cap and backend else
                       "cannot enforce network containment: missing "
                       + ", ".join(missing))}


def _is_literal_addr(s: str) -> bool:
    host = s.split("/", 1)[0]
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def _resolve_allow(entries: list[str]) -> tuple[list[str], list[str]]:
    """Hostnames → addresses. A name we cannot resolve is REPORTED, never
    dropped silently: a missing allow-list entry becomes an outage."""
    out: list[str] = []
    failed: list[str] = []
    for raw in entries:
        e = str(raw).strip()
        if not e:
            continue
        if _is_literal_addr(e):
            out.append(e)
            continue
        try:
            for info in socket.getaddrinfo(e, None, socket.AF_INET):
                out.append(info[4][0])
        except OSError:
            failed.append(e)
    return sorted(set(out)), failed


def _control_channel(api: str) -> tuple[str, int]:
    from urllib.parse import urlsplit
    u = urlsplit(api)
    return (u.hostname or "", u.port or (443 if u.scheme == "https" else 80))


def _nameservers() -> list[str]:
    try:
        return [ln.split()[1] for ln in
                Path("/etc/resolv.conf").read_text().splitlines()
                if ln.startswith("nameserver") and len(ln.split()) > 1]
    except OSError:
        return []


NFT_TABLE = "nivxforge_isolation"


def _nft_ruleset(allowed: list[str], dns: list[str]) -> str:
    els = ", ".join(allowed) or "127.0.0.1"
    dns_out = "\n".join(
        f"    ip daddr {{ {', '.join(dns)} }} {p} dport 53 accept"
        for p in ("udp", "tcp")) if dns else ""
    dns_in = "\n".join(
        f"    ip saddr {{ {', '.join(dns)} }} {p} sport 53 accept"
        for p in ("udp", "tcp")) if dns else ""
    return f"""table inet {NFT_TABLE} {{
  set nivx_allow {{ type ipv4_addr; elements = {{ {els} }} }}
  chain nivx_out {{
    type filter hook output priority -150; policy drop;
    oifname "lo" accept
    ip daddr @nivx_allow accept
{dns_out}
  }}
  chain nivx_in {{
    type filter hook input priority -150; policy drop;
    iifname "lo" accept
    ip saddr @nivx_allow accept
{dns_in}
  }}
  chain nivx_fwd {{
    type filter hook forward priority -150; policy drop;
  }}
}}
"""


def _run(cmd: list[str], stdin: str | None = None):
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True)


def _apply_isolation(backend: str, allowed: list[str],
                     dns: list[str]) -> tuple[bool, str]:
    if backend == "nft":
        _run(["nft", "delete", "table", "inet", NFT_TABLE])
        r = _run(["nft", "-f", "-"], stdin=_nft_ruleset(allowed, dns))
        return r.returncode == 0, (r.stderr or r.stdout).strip()[:400]
    errs = []
    for chain, direction in (("NIVX_ISO_OUT", "OUTPUT"),
                             ("NIVX_ISO_IN", "INPUT")):
        _run(["iptables", "-N", chain])
        _run(["iptables", "-F", chain])
        rules = [["-A", chain, "-o" if direction == "OUTPUT" else "-i",
                  "lo", "-j", "ACCEPT"]]
        for ip in allowed:
            rules.append(["-A", chain,
                          "-d" if direction == "OUTPUT" else "-s", ip,
                          "-j", "ACCEPT"])
        for ip in dns:
            for proto in ("udp", "tcp"):
                rules.append(["-A", chain, "-p", proto,
                              "-d" if direction == "OUTPUT" else "-s", ip,
                              "--dport" if direction == "OUTPUT"
                              else "--sport", "53", "-j", "ACCEPT"])
        rules.append(["-A", chain, "-j", "DROP"])
        for rule in rules:
            r = _run(["iptables", *rule])
            if r.returncode != 0:
                errs.append(r.stderr.strip()[:160])
        _run(["iptables", "-D", direction, "-j", chain])
        r = _run(["iptables", "-I", direction, "1", "-j", chain])
        if r.returncode != 0:
            errs.append(r.stderr.strip()[:160])
    return (not errs), "; ".join(errs)[:400]


def _remove_isolation(backend: str) -> tuple[bool, str]:
    if backend == "nft":
        r = _run(["nft", "delete", "table", "inet", NFT_TABLE])
        gone = _run(["nft", "list", "table", "inet",
                     NFT_TABLE]).returncode != 0
        return gone, (r.stderr or "").strip()[:400]
    errs = []
    for chain, direction in (("NIVX_ISO_OUT", "OUTPUT"),
                             ("NIVX_ISO_IN", "INPUT")):
        _run(["iptables", "-D", direction, "-j", chain])
        _run(["iptables", "-F", chain])
        r = _run(["iptables", "-X", chain])
        if r.returncode != 0 and "No chain" not in r.stderr:
            errs.append(r.stderr.strip()[:160])
    return (not errs), "; ".join(errs)[:400]


def _control_plane_proof(backend: str, allowed: list[str]) -> dict:
    """Proof 1 — read the policy back OUT of the kernel. Never trust the
    fact that the apply command exited 0."""
    if backend == "nft":
        r = _run(["nft", "list", "table", "inet", NFT_TABLE])
        text = r.stdout
        present = r.returncode == 0 and bool(text.strip())
        deny = [c for c in ("nivx_out", "nivx_in", "nivx_fwd")
                if f"chain {c}" in text
                and "policy drop" in text.split(f"chain {c}", 1)[1][:400]]
    else:
        out = _run(["iptables", "-S", "NIVX_ISO_OUT"])
        inp = _run(["iptables", "-S", "NIVX_ISO_IN"])
        text = out.stdout + inp.stdout
        present = out.returncode == 0 and inp.returncode == 0
        deny = [c for c, s in (("NIVX_ISO_OUT", out.stdout),
                               ("NIVX_ISO_IN", inp.stdout))
                if f"-A {c} -j DROP" in s]
    missing = [ip for ip in allowed if ip.split("/")[0] not in text]
    return {"rules_installed": bool(present and deny and not missing),
            "rules_absent": not present,
            "backend": backend, "deny_chains": deny,
            "allowed_expected": allowed, "allowed_missing_in_kernel": missing,
            "ruleset_digest": hashlib.sha256(text.encode()).hexdigest()[:32],
            "detail": (f"{backend}: {len(deny)} default-deny chains, "
                       f"{len(allowed) - len(missing)}/{len(allowed)} "
                       f"allow-list entries present in the kernel"
                       if present else
                       f"{backend} holds no {NFT_TABLE} policy")}


def _tcp_probe(host: str, port: int, timeout: float = 4.0) -> dict:
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"target": f"{host}:{port}", "reachable": True,
                    "ms": int((time.time() - t0) * 1000), "error": None}
    except Exception as e:  # noqa: BLE001
        return {"target": f"{host}:{port}", "reachable": False,
                "ms": int((time.time() - t0) * 1000),
                "error": f"{type(e).__name__}: {e}"[:160]}


def _behavioural_proof(api: str, policy: dict, *, isolated: bool) -> dict:
    """Proof 2 — what the endpoint can actually REACH, right now."""
    vt = policy.get("verification_target") or {}
    ext = _tcp_probe(str(vt.get("host")), int(vt.get("port") or 443))
    ch, cp = _control_channel(api)
    ctrl = _tcp_probe(ch, cp)
    out = {"external_target": ext["target"], "external_probe": ext,
           "control_channel": ctrl["target"], "control_probe": ctrl,
           "control_channel_reachable": ctrl["reachable"]}
    if isolated:
        out["external_blocked"] = not ext["reachable"]
    else:
        out["external_restored"] = ext["reachable"]
    return out


def _execute_isolation(cmd: dict, api: str) -> tuple[str, str, dict]:
    action = cmd.get("action")
    policy = (cmd.get("target") or {}).get("policy") or {}
    cap = _isolation_capability()
    if not cap["available"]:
        return ("CAPABILITY_UNAVAILABLE",
                f"MISSING_PRIVILEGE: {', '.join(cap['missing'])} — "
                f"{cap['detail']}. Network containment is reported as "
                f"unavailable rather than faked.", cap)

    if action == "RELEASE_ISOLATION":
        ok, err = _remove_isolation(cap["backend"])
        if not ok:
            return "FAILED", f"could not remove containment: {err}", cap
        return ("EXECUTED", f"containment policy removed with "
                f"{cap['backend']}", {**cap, "removed": True})

    # The self-lockout guard. The sensor's OWN control channel is allowed
    # by invariant, and if it cannot be resolved the sensor refuses to
    # isolate at all — a contained host we cannot reach is not contained,
    # it is lost.
    ch_host, ch_port = _control_channel(api)
    ctrl_ips, ctrl_failed = _resolve_allow([ch_host]
                                           + list(policy.get(
                                               "extra_control_hosts") or []))
    if not ctrl_ips:
        return ("FAILED",
                f"CONTROL_CHANNEL_UNRESOLVED: {ch_host} could not be "
                f"resolved ({', '.join(ctrl_failed)}), so isolating would "
                f"strand this endpoint. Nothing was applied.",
                {"control_channel": f"{ch_host}:{ch_port}"})
    allow_ips, allow_failed = _resolve_allow(policy.get("allow_list") or [])
    allowed = sorted(set(ctrl_ips + allow_ips))
    dns = _nameservers() if policy.get("allow_dns") else []
    ok, err = _apply_isolation(cap["backend"], allowed, dns)
    if not ok:
        return "FAILED", f"could not apply containment: {err}", cap
    return ("EXECUTED",
            f"default-deny containment applied with {cap['backend']}; "
            f"{len(allowed)} allowed addresses, DNS "
            f"{'allowed' if dns else 'denied'}",
            {**cap, "allowed": allowed, "dns_servers": dns,
             "control_channel": f"{ch_host}:{ch_port}",
             "unresolved_allow_list_entries": allow_failed,
             "policy_version": policy.get("policy_version")})


def _verify_isolation(cmd: dict, api: str) -> dict:
    """Both proofs, gathered AFTER the action and independent of it."""
    action = cmd.get("action")
    policy = (cmd.get("target") or {}).get("policy") or {}
    cap = _isolation_capability()
    allowed = ((cmd.get("_applied") or {}).get("allowed")
               or [_control_channel(api)[0]])
    isolated = action == "ISOLATE_ENDPOINT"
    return {"method": "post_action_dual_proof",
            "control_plane": _control_plane_proof(cap["backend"] or "nft",
                                                  allowed if isolated else []),
            "behavioural": _behavioural_proof(api, policy, isolated=isolated),
            "detail": ("kernel policy state + independent connectivity "
                       "behaviour; a rule alone is not containment")}


def _proc_identity(pid: int) -> dict:
    """What is at this pid RIGHT NOW, read from /proc. Never inferred.

    Returns the CURRENT start-time ticks so a caller can compare process
    IDENTITY, not just pid occupancy. A bare pid is not a process: Linux
    reuses pids within minutes, so acting on a pid alone is how a response
    plane terminates the wrong process.

    A zombie (state Z) has ALREADY terminated — /proc holds the entry only
    until its parent reaps it. Counting that as "still running" would
    report a successful kill as a failure.
    """
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return {"present": False, "state": None, "start_ticks": None,
                "reason": "NO_PROC_ENTRY"}
    try:
        tail = stat[stat.rindex(")") + 2:].split()
        state, ticks = tail[0], int(tail[19])
    except (ValueError, IndexError):
        return {"present": False, "state": None, "start_ticks": None,
                "reason": "PROC_STAT_UNPARSEABLE"}
    if state == "Z":
        return {"present": False, "state": "Z", "start_ticks": ticks,
                "reason": "ZOMBIE_ALREADY_TERMINATED"}
    return {"present": True, "state": state, "start_ticks": ticks,
            "reason": "RUNNING"}


def _execute_command(cmd: dict, api: str = "") -> tuple[str, str, dict]:
    """Perform the action for real. Never report success it did not have."""
    action, target = cmd.get("action"), cmd.get("target") or {}
    if action == "KILL_PROCESS":
        pid = target.get("pid")
        want = target.get("observed_start_ticks")
        if not isinstance(pid, int) or pid <= 1:
            return "FAILED", "no valid pid in the command target", {}
        if not isinstance(want, int):
            # The one refusal that matters most. Killing on a pid the
            # platform never bound to a start time is unsafe by design,
            # and this sensor will not do it silently or at all.
            return ("FAILED",
                    "TARGET_IDENTITY_UNVERIFIED: this command carries no "
                    "observed process start identity. A bare pid is not a "
                    "process — Linux reuses pids — so nothing was killed.",
                    {"pre_state": "IDENTITY_ABSENT"})
        cur = _proc_identity(pid)
        if not cur["present"]:
            return ("FAILED",
                    f"pid {pid} is not present on this endpoint now "
                    f"({cur['reason']}) — nothing was killed",
                    {"pre_state": cur["reason"], "proc_state": cur["state"]})
        if cur["start_ticks"] != want:
            return ("FAILED",
                    f"TARGET_IDENTITY_MISMATCH_PID_REUSE: pid {pid} now holds "
                    f"a process started at {cur['start_ticks']} ticks, not "
                    f"the observed {want}. That is a DIFFERENT process; this "
                    f"sensor refuses to kill something the platform never "
                    f"observed.",
                    {"pre_state": "PID_REUSED",
                     "observed_start_ticks": want,
                     "current_start_ticks": cur["start_ticks"],
                     "proc_state": cur["state"]})
        try:
            os.kill(pid, signal.SIGKILL)
        except PermissionError:
            return ("CAPABILITY_UNAVAILABLE",
                    f"this sensor lacks permission to signal pid {pid}", {})
        except OSError as e:
            return "FAILED", f"kill failed: {e}", {}
        time.sleep(0.4)
        return ("EXECUTED",
                f"SIGKILL delivered to pid {pid} "
                f"(start identity {want} ticks confirmed before signalling)",
                {"signal": "SIGKILL", "pid": pid,
                 "observed_start_ticks": want,
                 "identity_confirmed_before_signal": True})
    if action in ("ISOLATE_ENDPOINT", "RELEASE_ISOLATION"):
        return _execute_isolation(cmd, api)
    return "FAILED", f"unknown action {action}", {}


def _verify_command(cmd: dict, result: tuple) -> dict:
    """Evidence gathered AFTER the action, independent of the action.

    Identity-aware on purpose: "the pid is free" is NOT proof that the
    observed process is gone, and a pid re-occupied by a new process is
    not proof that the kill failed. Both facts are reported.
    """
    target = cmd.get("target") or {}
    if cmd.get("action") == "KILL_PROCESS":
        pid = target.get("pid")
        want = target.get("observed_start_ticks")
        cur = (_proc_identity(pid) if isinstance(pid, int)
               else {"present": False, "state": None, "start_ticks": None,
                     "reason": "NO_VALID_PID"})
        same_identity = cur["start_ticks"] == want
        reoccupied = bool(cur["present"] and not same_identity)
        present = bool(cur["present"] and same_identity)
        if present:
            detail = (f"/proc/{pid} still holds the OBSERVED process "
                      f"(start {cur['start_ticks']} ticks, state "
                      f"{cur['state']})")
        elif reoccupied:
            detail = (f"the observed process (start {want} ticks) is gone; "
                      f"pid {pid} is now held by a DIFFERENT process "
                      f"started at {cur['start_ticks']} ticks")
        else:
            detail = (f"/proc/{pid} {cur['reason']}"
                      + (f" (state {cur['state']})" if cur["state"] else ""))
        return {"method": "post_action_proc_read",
                "identity_basis": "start_ticks",
                "observed_start_ticks": want,
                "current_start_ticks": cur["start_ticks"],
                "pid_reoccupied": reoccupied,
                "process_present": present,
                "pid": pid, "proc_state": cur["state"],
                "proc_reason": cur["reason"],
                "detail": detail}
    return {"method": "post_action_probe", "effect_confirmed": False,
            "detail": "no verification method exists for this action yet"}


def _serve_commands(api: str, ident: dict, session: dict) -> int:
    """Claim, execute and then PROVE. A command is never marked verified
    from the fact that it ran."""
    if not session.get("token"):
        session["token"] = _open_session(api, ident)
    try:
        cmds = _get(api, "/api/edr/agent/commands",
                    session["token"]).get("commands") or []
    except RuntimeError as e:
        if "401" in str(e):
            session["token"] = None
        return 0
    for cmd in cmds:
        outcome, detail, evidence = _execute_command(cmd, api)
        print(f"[{_now()}] command {cmd['command_id']} {cmd['action']} "
              f"→ {outcome}: {detail}")
        _post(api, "/api/edr/agent/command-result",
              {"command_id": cmd["command_id"], "outcome": outcome,
               "detail": detail, "evidence": evidence},
              bearer=session["token"])
        if outcome == "EXECUTED":
            if cmd.get("action") in ("ISOLATE_ENDPOINT",
                                     "RELEASE_ISOLATION"):
                probe = _verify_isolation({**cmd, "_applied": evidence}, api)
            else:
                probe = _verify_command(cmd, (outcome, detail, evidence))
            v = _post(api, "/api/edr/agent/command-verification",
                      {"command_id": cmd["command_id"], "probe": probe},
                      bearer=session["token"])
            print(f"[{_now()}]   verification → {v.get('state')}: "
                  f"{v.get('finding')}")
    return len(cmds)


def run(api: str, interval: int, watch: str | None, once: bool) -> None:
    ident = _read_identity()
    session: dict = {"token": None}
    seen_pids, seen_conns, known_files, baselined = _load_observed()
    # The baseline must be recorded EXPLICITLY. Inferring it from an empty
    # file map means an empty watched directory is baselined on every run,
    # and the first real file created in it is then swallowed as if it had
    # always been there.
    if watch and watch not in baselined:
        collect_files(watch, known_files)   # baseline, not reported
        baselined.add(watch)
        _save_observed(seen_pids, seen_conns, known_files, baselined)
    while True:
        batch = collect_processes(seen_pids) + collect_network(seen_conns)
        if watch:
            batch += collect_files(watch, known_files)
        for e in batch:
            e.update({"sensor_version": SENSOR_VERSION,
                      "collection_method": "PROC_POLL"})
        if batch:
            _enqueue(batch)
        _save_observed(seen_pids, seen_conns, known_files, baselined)
        sent, failed = _drain(api, ident, session)
        served = _serve_commands(api, ident, session)
        print(f"[{_now()}] commands={served} collected={len(batch)} sent={sent} "
              f"held={failed} endpoint={ident['endpoint_id']}")
        if once:
            return
        time.sleep(interval)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enrol")
    e.add_argument("--api", required=True)
    e.add_argument("--tenant", required=True)
    e.add_argument("--token", required=True)
    r = sub.add_parser("run")
    r.add_argument("--api", required=True)
    r.add_argument("--interval", type=int, default=15)
    r.add_argument("--watch", default=None)
    r.add_argument("--once", action="store_true")
    sub.add_parser("capabilities")
    a = ap.parse_args()
    if a.cmd == "enrol":
        enrol(a.api, a.tenant, a.token)
    elif a.cmd == "run":
        run(a.api, a.interval, a.watch, a.once)
    else:
        print(json.dumps({"sensor_version": SENSOR_VERSION,
                          **_machine_facts(), **CAPABILITIES}, indent=2))


if __name__ == "__main__":
    main()
