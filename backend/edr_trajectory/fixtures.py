"""Deterministic proof datasets. SYNTHETIC scenarios + one SHAPE-FAITHFUL (NOT PRODUCTION DATA)
KUSHU-shaped snapshot. Emitted in BOTH candidate store shapes so the adapters, dedup and the
store-authority question are exercised, not assumed. No real host, tenant or evidence."""
from __future__ import annotations

import random
from typing import Any

from .contracts import SHAPE_FAITHFUL, SYNTHETIC, iso

REF = 1790915400000            # 2026-10-02T04:30:00Z
M, H, D = 60_000, 3_600_000, 86_400_000
TA, TB = "ten_syn_a", "ten_syn_b"


def _zless(ms: int) -> str:     # Sysmon-style zone-less UTC string
    return iso(ms)[:-1].replace("T", " ")


class _B:
    def __init__(self, tenant: str, device: str, label: str = SYNTHETIC, zless: bool = False) -> None:
        self.t, self.d, self.label, self.zless, self.n = tenant, device, label, zless, 0
        self.shadow: list[dict[str, Any]] = []
        self.canonical: list[dict[str, Any]] = []

    def ts(self, ms: int | None) -> str | None:
        return None if ms is None else (_zless(ms) if self.zless else iso(ms))

    def add(self, t: int, act: str, op: str, proc: dict[str, Any] | None = None, parent: dict | None = None,
            *, store: str = "both", ing: int | None = None, file: dict | None = None, net: dict | None = None,
            sev: str = "INFO", detection: dict | None = None, creator: dict | None = None, aid: str | None = None):
        self.n += 1
        aid = aid or f"act_{self.t}_{self.d}_{self.n:05d}"
        p, q, ing = dict(proc or {}), dict(parent or {}), (t + 2000 if ing is None else ing)
        st = lambda x: self.ts(x) if isinstance(x, int) else x
        if store in ("both", "canonical"):
            self.canonical.append({
                "event_id": f"cev_{aid}_1", "tenant_id": self.t, "event_type": f"{act.lower()}_{op}",
                "event_time": self.ts(t), "ingest_time": self.ts(ing),
                "host": {"host_id": self.d, "hostname": self.d}, "provenance": {"collector_id": self.d},
                "process": {"pid": p.get("pid"), "process_guid": p.get("guid"), "start_time": st(p.get("start")),
                            "executable_path": p.get("image"), "command_line": p.get("cmd"),
                            "hashes": {"sha256": p["sha256"]} if p.get("sha256") else {},
                            "parent_pid": q.get("pid"), "parent_process_guid": q.get("guid"),
                            "parent_start_time": st(q.get("start")), "parent_executable_path": q.get("image")}
                if p else {},
                "identity": {"username": p.get("user")}, "file": ({"path": file.get("path"), "previous_path":
                                                                   file.get("prev"), "hashes": {"sha256": file["sha256"]}
                                                                   if file.get("sha256") else {}} if file else {}),
                "network": {k: v for k, v in (net or {}).items() if k != "query"},
                "dns": {"query": (net or {}).get("query")} if (net or {}).get("query") else {},
                "additional_fields": {"activity_type": act, "operation": op, "activity_identity": aid, "severity": sev,
                                      "detection": detection, "creator": creator, "data_label": self.label}})
        if store in ("both", "shadow"):
            self.shadow.append({
                "tenant_id": self.t, "observation_id": f"obs_{aid}", "activity_identity": aid,
                "canonical_event_id": f"cev_{aid}_1", "collector_id": self.d, "captured_at": self.ts(t),
                "ingest_time": self.ts(ing), "kind": f"{act.lower()}_{op}", "process_guid": p.get("guid"),
                "event": {"ts": self.ts(t), "activity": act, "op": op, "device_iid": self.d, "computer": self.d,
                          "process": {"pid": p.get("pid"), "guid": p.get("guid"), "start_time": st(p.get("start")),
                                      "image": p.get("image"), "cmdline": p.get("cmd"), "user": p.get("user"),
                                      "sha256": p.get("sha256"), "ppid": q.get("pid"), "parent_guid": q.get("guid"),
                                      "parent_start_time": st(q.get("start")), "parent_image": q.get("image")}
                          if p else {},
                          "file": {"path": file.get("path"), "prev_path": file.get("prev"),
                                   "sha256": file.get("sha256")} if file else {},
                          "network": {"dest_ip": (net or {}).get("dest_ip"), "dest_port": (net or {}).get("dest_port"),
                                      "proto": (net or {}).get("protocol"), "query": (net or {}).get("query")}
                          if net else {},
                          "severity": sev, "detection": detection, "creator": creator, "data_label": self.label}})
        return aid

    def start(self, t, proc, parent=None, **kw):
        return self.add(t, "PROCESS", "start", proc, parent, **kw)


def _p(pid, start, image, cmd=None, guid=None, user="SYN\\alice", sha256=None):
    return {"pid": pid, "start": start, "image": image, "cmd": cmd or image, "guid": guid, "user": user, "sha256": sha256}


H_UPD = "a1" * 32
H_PS = "b2" * 32


def office_chain() -> dict[str, Any]:
    b = _B(TA, "SYN-WS-01")
    exp = _p(3120, REF - 6 * H, "C:\\Windows\\explorer.exe", guid="{AAAA0001}")
    b.start(REF - 6 * H, exp, {"pid": 2900, "image": "C:\\Windows\\System32\\userinit.exe"})
    word = _p(5520, REF - 50 * M, "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
              "WINWORD.EXE /n C:\\Users\\alice\\Downloads\\invoice_0931.docm", "{AAAA0002}")
    b.start(word["start"], word, exp)
    b.add(REF - 49 * M, "FILE", "create", word, file={"path": "C:\\Users\\alice\\AppData\\Local\\Temp\\~WRD0001.tmp"},
          store="shadow")
    ws = _p(6612, REF - 47 * M, "C:\\Windows\\System32\\wscript.exe", "wscript.exe //B C:\\Users\\Public\\inv.js", "{AAAA0003}")
    b.start(ws["start"], ws, word)
    ps = _p(7040, REF - 46 * M, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -nop -w hidden -enc SQBFAFgA", "{AAAA0004}", sha256=H_PS)
    b.start(ps["start"], ps, ws, sev="HIGH", detection={"detection_id": "det_syn_0001", "rule": "E3-SEQ-OFFICE-SCRIPT-PS",
                                                         "engine": "nivxforge-own", "at": iso(REF - 46 * M)})
    b.add(REF - 45 * M, "NETWORK", "connect", ps, net={"dest_ip": "198.51.100.23", "dest_port": 443, "protocol": "tcp",
                                                       "initiated": True}, store="canonical")
    b.add(REF - 44 * M, "FILE", "create", ps, file={"path": "C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe",
                                                    "sha256": H_UPD}, store="shadow", sev="MEDIUM")
    upd = _p(7420, REF - 43 * M, "C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe", "upd.exe -s", "{AAAA0005}", sha256=H_UPD)
    b.start(upd["start"], upd, ps, sev="MEDIUM")
    for i in range(6):
        b.add(REF - (42 - i) * M, "NETWORK", "connect", upd, net={"dest_ip": "203.0.113.50", "dest_port": 8443,
                                                                  "protocol": "tcp", "initiated": True},
              store="canonical", sev="HIGH")
    return _pack("office_chain", b, "Office document → script host → PowerShell (encoded) → download → "
                 "execute dropped binary → periodic network callback",
                 status_events=[{"subject": H_UPD, "kind": "RETRO_DETECTION", "state": "DETECTED",
                                 "recorded_at": iso(REF - 5 * M), "references": None,
                                 "provenance": {"source": "nivxforge-own:retro-rescan", "rule": "E3-RETRO-DROPPED-PE"}}],
                 detections={H_PS: [{"detection_id": "det_syn_0001", "rule": "E3-SEQ-OFFICE-SCRIPT-PS",
                                     "at": iso(REF - 46 * M)}]})


def benign_tree() -> dict[str, Any]:
    b = _B(TA, "SYN-WS-02")
    svc = _p(700, REF - 3 * D, "C:\\Windows\\System32\\services.exe", guid="{BBBB0001}", user="NT AUTHORITY\\SYSTEM")
    b.start(svc["start"], svc, {"pid": 560, "image": "C:\\Windows\\System32\\wininit.exe", "guid": "{BBBB0000}"})
    sv = _p(1300, REF - 3 * D + M, "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", "{BBBB0002}",
            user="NT AUTHORITY\\SYSTEM")
    b.start(sv["start"], sv, svc)
    ti = _p(4400, REF - 3 * H, "C:\\Windows\\WinSxS\\TiWorker.exe", "TiWorker.exe -Embedding", "{BBBB0003}",
            user="NT AUTHORITY\\SYSTEM")
    b.start(ti["start"], ti, sv)
    for i in range(5):
        b.add(REF - 3 * H + (i + 1) * 10 * M, "FILE", "write", ti,
              file={"path": f"C:\\Windows\\WinSxS\\Temp\\pkg_{i}.cab"})
    b.add(REF - 2 * H, "PROCESS", "end", ti)
    exp = _p(3300, REF - 8 * H, "C:\\Windows\\explorer.exe", guid="{BBBB0010}", user="SYN\\bob")
    b.start(exp["start"], exp, None)
    ch = _p(9000, REF - 2 * H, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", guid="{BBBB0011}",
            user="SYN\\bob")
    b.start(ch["start"], ch, exp)
    for j, pid in enumerate((9100, 9104)):
        r = _p(pid, REF - 2 * H + (j + 1) * M, ch["image"], "chrome.exe --type=renderer", f"{{BBBB002{j}}}", user="SYN\\bob")
        b.start(r["start"], r, ch)
        b.add(r["start"] + 30_000, "NETWORK", "connect", r, net={"dest_ip": "192.0.2.80", "dest_port": 443,
                                                                  "protocol": "tcp", "initiated": True})
    return _pack("benign_tree", b, "Benign service and browser process trees (no detections)")


def lateral_dump() -> dict[str, Any]:
    b = _B(TA, "SYN-SRV-03")
    wmi = _p(2800, REF - 9 * D, "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", user="NT AUTHORITY\\NETWORK SERVICE")
    b.add(REF - 30 * M, "NETWORK", "connect", wmi, net={"dest_ip": "10.0.4.20", "dest_port": 135, "protocol": "tcp"},
          store="canonical")
    cmd = _p(5100, REF - 25 * M, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /Q /c rundll32 ...", "{CCCC0001}",
             user="SYN\\svc_backup")
    b.start(cmd["start"], cmd, {"pid": 2800})                     # parent pid ONLY → at best CORRELATED
    rd = _p(5300, REF - 24 * M, "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Windows\\Temp\\d.bin full", "{CCCC0002}",
            user="SYN\\svc_backup")
    b.start(rd["start"], rd, cmd, sev="HIGH")
    b.add(REF - 23 * M, "FILE", "create", rd, file={"path": "C:\\Windows\\Temp\\d.bin"}, sev="HIGH")
    b.add(REF - 20 * M, "FILE", "move", cmd, file={"path": "C:\\Users\\Public\\logs.zip", "prev": "C:\\Windows\\Temp\\d.bin"})
    spoof = _p(6000, REF - 19 * M, "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k fake", "{CCCC0003}")
    b.start(spoof["start"], spoof, {"pid": 700, "guid": "{CCCC0700}", "image": "C:\\Windows\\System32\\services.exe"},
            creator={"pid": 5300, "guid": "{CCCC0002}", "image": rd["image"]}, sev="HIGH")
    for i in range(3):                                            # WFP-style: no process attribution
        b.add(REF - (18 - i) * M, "NETWORK", "connect", None, net={"dest_ip": "10.0.4.20", "dest_port": 445,
                                                                   "protocol": "tcp"}, store="canonical")
    return _pack("lateral_dump", b, "WMI-spawned shell (parent pid only) → credential dump → staging → SMB; "
                 "PPID-spoofed child; unattributed network")


def edge_cases() -> dict[str, Any]:
    b = _B(TA, "SYN-EDGE-04")
    orphan = _p(4100, REF - 3 * H, "C:\\Tools\\orphan.exe", guid="{EEEE0001}")
    b.start(orphan["start"], orphan, {"guid": "{EEEE9999}", "pid": 4000, "image": "C:\\Tools\\launcher.exe"})
    nop = _p(4150, REF - 3 * H + M, "C:\\Tools\\noparent.exe", guid="{EEEE0002}")
    b.start(nop["start"], nop, None)
    late = _p(4200, REF - 4 * H, "C:\\Tools\\late.exe", guid="{EEEE0003}")
    b.start(late["start"], late, None, ing=REF - 1 * H)                        # 3 h late
    n1 = _p(4242, REF - 5 * H, "C:\\Windows\\System32\\notepad.exe")          # PID reuse: same pid, two lifetimes
    n2 = _p(4242, REF - 2 * H, "C:\\Windows\\System32\\notepad.exe")
    b.start(n1["start"], n1, None)
    b.add(REF - 4 * H, "PROCESS", "end", n1)
    b.start(n2["start"], n2, None)
    b.add(REF - 90 * M, "FILE", "write", n2, file={"path": "C:\\Users\\alice\\notes.txt"})
    sql = _p(1800, REF - 40 * D, "C:\\Program Files\\SQL\\sqlservr.exe", guid="{EEEE0004}", user="NT SERVICE\\MSSQL")
    for i in range(4):                                                         # long-lived, no start record
        b.add(REF - (6 - i) * H, "NETWORK", "connect", sql, net={"dest_ip": "10.0.9.9", "dest_port": 1433}, store="shadow")
    b.add(REF - 70 * M, "NETWORK", "connect", None, net={"dest_ip": "192.0.2.99", "dest_port": 53, "protocol": "udp",
                                                        "query": "syn-example.invalid"}, store="shadow")
    dup = _p(4300, REF - 60 * M, "C:\\Tools\\dup.exe", guid="{EEEE0005}")
    b.start(dup["start"], dup, None, store="both")                             # same activity in BOTH stores
    rnd = random.Random(7)
    replay = [REF - 20 * H + i * 3 * M for i in range(20)]
    rnd.shuffle(replay)
    bk = _p(4400, REF - 21 * H, "C:\\Tools\\backlog.exe", guid="{EEEE0006}")
    b.start(bk["start"], bk, None, ing=REF - 50 * M)
    for t in replay:                                                           # delivered ~19 h late, shuffled
        b.add(t, "FILE", "write", bk, file={"path": "C:\\Data\\journal.log"}, ing=REF - 60 * M + rnd.randint(0, 600_000))
    for t in (1774745999000, 1774746001000, 1762063140000, 1762063260000):    # EU DST 2026-03-29 01:00Z, US DST 2025-11-02 06:00Z
        b.add(t, "FILE", "write", n2, file={"path": "C:\\Users\\alice\\dst.txt"}, store="canonical")
    x = _B(TB, "SYN-EDGE-04")                                                  # OTHER tenant, same device id + pid
    x.start(REF - 2 * H, _p(4242, REF - 2 * H, "C:\\Windows\\System32\\notepad.exe", user="OTHER\\eve"), None)
    x.add(REF - 100 * M, "FILE", "write", _p(4242, REF - 2 * H, "C:\\Windows\\System32\\notepad.exe"),
          file={"path": "C:\\Users\\eve\\secret.txt"})
    pk = _pack("edge_cases", b, "Missing/unresolved parents, late arrival, PID reuse, long-lived process, unattributed "
               "network, cross-store duplicate, telemetry gap, backlog replay, DST boundaries, cross-tenant twin",
               declared_gaps=[{"from_ms": REF - 12 * H, "to_ms": REF - 10 * H, "kind": "DECLARED",
                               "basis": "SYNTHETIC sensor acquisition_gaps record"}])
    pk["shadow"] += x.shadow
    pk["canonical"] += x.canonical
    return pk


def bulk_process(n: int = 12_000) -> dict[str, Any]:
    b = _B(TA, "SYN-BULK-05")
    bp = _p(5600, REF - 3 * H, "C:\\Program Files\\Backup\\backup_agent.exe", guid="{FFFF0001}", user="NT AUTHORITY\\SYSTEM")
    b.start(bp["start"], bp, None, store="canonical")
    for i in range(n):
        b.add(REF - 2 * H + i * 600, "FILE", "write", bp, file={"path": f"D:\\Backup\\chunk_{i % 97:03d}.bin"},
              store="canonical")
    return _pack("bulk_process", b, f">10k-event process ({n} file writes in 2 h)")


def kushu_shape() -> dict[str, Any]:
    """SHAPE-FAITHFUL / NOT PRODUCTION DATA. Mirrors the field shapes of the Sysmon/Security channels the
    sensor collects (zone-less UTC strings, braced GUIDs, shadow store only). No real KUSHU evidence was
    available to E3; values are invented."""
    b = _B("ten_SHAPE_kushu", "KUSHU-SHAPE", label=SHAPE_FAITHFUL, zless=True)
    exp = _p(6216, REF - 18 * H, "C:\\Windows\\explorer.exe", guid="{5E1F0A11-0000-0000-0000-000000000001}",
             user="KUSHU-SHAPE\\user", sha256="c3" * 32)
    b.start(exp["start"], exp, {"pid": 6100, "guid": "{5E1F0A11-0000-0000-0000-000000000000}",
                                "image": "C:\\Windows\\System32\\userinit.exe"}, store="shadow", ing=REF - 30 * M)
    ed = _p(8812, REF - 17 * H, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            guid="{5E1F0A11-0000-0000-0000-000000000002}", user="KUSHU-SHAPE\\user", sha256="d4" * 32)
    b.start(ed["start"], ed, exp, store="shadow", ing=REF - 29 * M)
    for i in range(8):
        b.add(REF - 17 * H + (i + 1) * 5 * M, "NETWORK", "connect", ed, store="shadow", ing=REF - 28 * M,
              net={"dest_ip": f"192.0.2.{10 + i}", "dest_port": 443, "protocol": "tcp", "initiated": True})
        b.add(REF - 17 * H + (i + 1) * 5 * M - 500, "DNS", "query", ed, store="shadow", ing=REF - 28 * M,
              net={"query": f"cdn{i}.example.invalid"})
    b.add(REF - 16 * H, "FILE", "create", ed, file={"path": "C:\\Users\\user\\Downloads\\setup.msi"}, store="shadow",
          ing=REF - 27 * M)                                                         # Sysmon 11: no hash
    sec = {"pid": 9120, "start": None, "image": "C:\\Windows\\System32\\msiexec.exe", "cmd": None, "guid": None,
           "user": "KUSHU-SHAPE\\user", "sha256": None}
    b.start(REF - 16 * H + M, sec, {"pid": 8812}, store="shadow", ing=REF - 27 * M)   # Security 4688-shaped
    return _pack("kushu_shape", b, "KUSHU-shaped Sysmon/Security telemetry (SHAPE-FAITHFUL / NOT PRODUCTION DATA): "
                 "process create with hashes, network with ProcessGuid, DNS, FileCreate without hash, "
                 "4688-style process without GUID or start time; delivered ~17 h late (backlog)")


def _pack(sid: str, b: _B, desc: str, **extra: Any) -> dict[str, Any]:
    return {"scenario_id": sid, "tenant_id": b.t, "device_id": b.d, "label": b.label, "description": desc,
            "reference_ms": REF, "reference_at": iso(REF), "shadow": b.shadow, "canonical": b.canonical,
            "heartbeats_ms": extra.get("heartbeats_ms", []), "declared_gaps": extra.get("declared_gaps", []),
            "status_events": extra.get("status_events", []), "detections": extra.get("detections", {})}


BUILDERS = {"office_chain": office_chain, "benign_tree": benign_tree, "lateral_dump": lateral_dump,
            "edge_cases": edge_cases, "bulk_process": bulk_process, "kushu_shape": kushu_shape}
