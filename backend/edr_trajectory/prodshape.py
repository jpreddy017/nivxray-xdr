"""SYNTHETIC / SHAPE-FAITHFUL production-shaped Windows endpoint dataset for the E3 preview.

Every observation is produced by E1's OWN Windows pipeline: connector journal line →
canonical_bridge.parse → bind_process_identity → telemetry_bridge.observation_doc, so field
shapes are the shapes v2_shadow_observations holds. Not production data; no real host or tenant.
`load_export(path)` accepts a read-only JSON export (list of v2_shadow_observations docs) instead.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from typing import Any

LABEL = "SYNTHETIC / SHAPE-FAITHFUL · NOT PRODUCTION DATA"
TENANT = "ten_syn_preview"
ENDPOINT = "ep_syn_lt0427"
HOST = "SYN-LT-0427"
M, H, D = 60_000, 3_600_000, 86_400_000
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SYSMON = ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational")
SECURITY = ("Microsoft-Windows-Security-Auditing", "Security")
USER = "SYN\\priya"


def _utc(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _xml_escape(v: Any) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _line(src: tuple[str, str], eid: int, rec: int, t: int, ing: int, data: dict[str, Any]) -> str:
    """The connector journal line, same envelope as tests/edr/fixtures_windows_eventlog.py."""
    rows = "".join(f'<Data Name="{k}">{_xml_escape(v)}</Data>' for k, v in data.items())
    xml = (f'<Event xmlns="{NS}"><System><Provider Name="{src[0]}" Guid="{{00000000-0000-0000-0000-000000000000}}"/>'
           f"<EventID>{eid}</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>"
           f'<TimeCreated SystemTime="{_iso(t)[:-1]}0000Z"/><EventRecordID>{rec}</EventRecordID>'
           f'<Execution ProcessID="2048" ThreadID="3072"/><Channel>{src[1]}</Channel><Computer>{HOST}</Computer>'
           f'<Security UserID="S-1-5-18"/></System><EventData>{rows}</EventData></Event>')
    return json.dumps({"observed_at": _iso(ing).replace("Z", "+00:00"), "kind": "WINDOWS_EVENT_LOG",
                       "winlog": {"channel": src[1], "record_id": rec, "event_id": str(eid), "time_created": _iso(t),
                                  "computer": HOST, "provider": src[0], "xml": xml}}, separators=(",", ":"))


class Proc:
    def __init__(self, g: "Gen", t: int, image: str, cmd: str, parent: "Proc | None", user: str = USER,
                 sha256: str | None = None, guid: bool = True):
        g.pidn += 4
        self.pid, self.image, self.cmd, self.parent, self.user, self.t = g.pidn % 30000 + 400, image, cmd, parent, user, t
        self.guid = f"{{5c1e0000-{g.recs % 65536:04x}-{(g.recs // 65536) % 65536:04x}-0000-{g.pidn:012x}}}" if guid else None
        self.sha256 = sha256


class Gen:
    def __init__(self, ref_ms: int, seed: int = 4270):
        self.ref, self.r, self.recs, self.pidn = ref_ms, random.Random(seed), 100000, 1000
        self.lines: list[tuple[str, dict[str, Any]]] = []

    def emit(self, src, eid, t, data, ing=None, tag=None):
        self.recs += 1
        ing = t + self.r.randint(800, 4000) if ing is None else ing
        self.lines.append((_line(src, eid, self.recs, t, ing, {"RuleName": "-", "UtcTime": _utc(t), **data}),
                           {"tag": tag, "late": ing - t > 5 * M}))

    def base(self, p: Proc) -> dict[str, Any]:
        d = {"ProcessId": str(p.pid), "Image": p.image, "User": p.user}
        if p.guid:
            d["ProcessGuid"] = p.guid
        return d

    def start(self, t, p: Proc, ing=None, tag=None):
        d = {**self.base(p), "CommandLine": p.cmd, "CurrentDirectory": "C:\\Windows\\system32\\", "LogonId": "0x3e7f1",
             "TerminalSessionId": "1", "IntegrityLevel": "Medium"}
        if p.sha256:
            d["Hashes"] = f"SHA256={p.sha256.upper()}"
        if p.parent:
            d.update({"ParentProcessId": str(p.parent.pid), "ParentImage": p.parent.image, "ParentCommandLine": p.parent.cmd})
            if p.parent.guid:
                d["ParentProcessGuid"] = p.parent.guid
        self.emit(SYSMON, 1, t, d, ing, tag)
        return p

    def sec4688(self, t, image, cmd, creator: Proc, ing=None, tag=None):
        self.pidn += 4
        self.emit(SECURITY, 4688, t, {"SubjectUserName": "priya", "SubjectDomainName": "SYN", "NewProcessId": hex(self.pidn % 30000 + 400),
                                      "NewProcessName": image, "CommandLine": cmd, "ProcessCommandLine": cmd,
                                      "ProcessId": hex(creator.pid), "CreatorProcessId": hex(creator.pid),
                                      "CreatorProcessName": creator.image}, ing, tag)

    def net(self, t, p, ip, port, host="", ing=None, tag=None):
        self.emit(SYSMON, 3, t, {**self.base(p), "Protocol": "tcp", "Initiated": "true", "SourceIp": "192.168.1.37",
                                 "SourceHostname": HOST, "SourcePort": str(49152 + self.r.randint(0, 16000)),
                                 "DestinationIp": ip, "DestinationHostname": host, "DestinationPort": str(port)}, ing, tag)

    def dns(self, t, p, q, ip, ing=None, tag=None):
        self.emit(SYSMON, 22, t, {**self.base(p), "QueryName": q, "QueryStatus": "0", "QueryResults": f"::ffff:{ip};"}, ing, tag)

    def file(self, t, p, path, ing=None, tag=None):
        self.emit(SYSMON, 11, t, {**self.base(p), "TargetFilename": path, "CreationUtcTime": _utc(t)}, ing, tag)

    def reg(self, t, p, key, val, ing=None, tag=None):
        self.emit(SYSMON, 13, t, {**self.base(p), "EventType": "SetValue", "TargetObject": key, "Details": val}, ing, tag)


SITES = [("www.bing.com", "204.79.197.200"), ("outlook.office365.com", "52.96.165.18"), ("github.com", "140.82.112.4"),
         ("teams.microsoft.com", "52.113.194.132"), ("docs.python.org", "151.101.0.223"), ("www.lenovo.com", "23.45.120.66")]
MS_SVC = [("settings-win.data.microsoft.com", "20.42.65.90"), ("v10.events.data.microsoft.com", "13.69.239.72"),
          ("ctldl.windowsupdate.com", "93.184.221.240"), ("login.live.com", "20.190.151.68")]
VANTAGE = "C:\\ProgramData\\Lenovo\\Vantage\\Addins"
ADDINS = ["GenericMessagingAddin\\1.0.0.94\\LenovoVantage-(GenericMessagingAddin).exe",
          "DeviceSettingsSystemAddin\\1.0.4.21\\LenovoVantage-(DeviceSettingsSystemAddin).exe",
          "LenovoBatteryGaugeAddin\\1.0.1.2\\LenovoVantage-(LenovoBatteryGaugeAddin).exe"]
MEI = ["python311.dll", "_ssl.pyd", "_socket.pyd", "select.pyd", "unicodedata.pyd", "libcrypto-3.dll", "libssl-3.dll",
       "_hashlib.pyd", "_ctypes.pyd", "base_library.zip"]
H_UPD = "7f3a9c" + "e1" * 29


def _session(g: Gen, t0: int, t1: int, rate: float, installer: bool):
    r = g.r
    svc = Proc(g, t0, "C:\\Windows\\System32\\services.exe", "C:\\Windows\\system32\\services.exe", None, "NT AUTHORITY\\SYSTEM")
    hosts = [g.start(t0 + 1500 + i * 700, Proc(g, t0, "C:\\Windows\\System32\\svchost.exe", f"C:\\Windows\\system32\\svchost.exe -k {k} -p",
                                                 svc, "NT AUTHORITY\\SYSTEM"))
             for i, k in enumerate(("netsvcs", "LocalService", "NetworkService", "DcomLaunch"))]
    vsvc = g.start(t0 + 6000, Proc(g, t0, "C:\\Program Files (x86)\\Lenovo\\VantageService\\4.1.12.0\\LenovoVantageService.exe",
                                   "LenovoVantageService.exe", svc, "NT AUTHORITY\\SYSTEM"))
    exp = g.start(t0 + 9000, Proc(g, t0, "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE",
                                  Proc(g, t0, "C:\\Windows\\System32\\userinit.exe", "userinit.exe", None)))
    chrome = g.start(t0 + 40000, Proc(g, t0, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                      '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"', exp))
    renderers = []
    t = t0 + 60000
    while t < t1:
        t += int(r.expovariate(rate / H))
        if t >= t1:
            break
        x = r.random()
        if x < 0.22:
            q, ip = r.choice(MS_SVC)
            h = r.choice(hosts)
            g.dns(t, h, q, ip)
            g.net(t + 120, h, ip, 443, q)
        elif x < 0.50:
            q, ip = r.choice(SITES)
            p = r.choice(renderers) if renderers and r.random() < 0.6 else chrome
            g.dns(t, chrome, q, ip)
            g.net(t + 90, p, ip, 443, q)
        elif x < 0.58:
            renderers.append(g.start(t, Proc(g, t, chrome.image, f'"{chrome.image}" --type=renderer --renderer-client-id={r.randint(5, 400)} '
                                             f"--launch-time-ticks={r.randint(10**9, 10**10)}", chrome)))
            renderers[:] = renderers[-6:]
        elif x < 0.68:
            a = g.start(t, Proc(g, t, f"{VANTAGE}\\{r.choice(ADDINS)}", "LenovoVantage-Addin.exe --ipc", vsvc, "NT AUTHORITY\\SYSTEM"))
            g.net(t + 2000, a, "23.211.140.91", 443, "vantage.csw.lenovo.com")
            g.reg(t + 2500, a, "HKLM\\SOFTWARE\\Lenovo\\Vantage\\AddinData\\LastRun", _utc(t))
        elif x < 0.80:
            g.reg(t, r.choice(hosts), f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-1\\{r.randint(1, 99)}", "Binary Data")
        elif x < 0.92:
            g.file(t, r.choice(hosts), f"C:\\Windows\\Prefetch\\{r.choice(['CHROME.EXE', 'SVCHOST.EXE', 'TEAMS.EXE', 'SEARCHAPP.EXE'])}-{r.randint(10**7, 10**8):08X}.pf")
        else:
            g.sec4688(t, "C:\\Windows\\System32\\conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1", exp)
    if installer:
        ti = t0 + (t1 - t0) // 2
        inst = g.start(ti, Proc(g, ti, "C:\\Users\\priya\\Downloads\\netmon_setup_2.3.1.exe", "netmon_setup_2.3.1.exe", exp,
                                sha256="4d" * 32))
        child = g.start(ti + 1800, Proc(g, ti, inst.image, "netmon_setup_2.3.1.exe --onefile-child", inst, sha256="4d" * 32))
        mei = f"C:\\Users\\priya\\AppData\\Local\\Temp\\_MEI{r.randint(10000, 99999)}"
        for i, f in enumerate(MEI):
            g.file(ti + 900 + i * 40, inst, f"{mei}\\{f}")
        g.reg(ti + 5000, child, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NetMon", "netmon 2.3.1")
    return exp


def _office_chain(g: Gen, exp: Proc, t: int):
    tag = "office_chain"
    w = g.start(t, Proc(g, t, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                        "WINWORD.EXE /n C:\\Users\\priya\\Downloads\\invoice_0931.docm", exp), tag=tag)
    ws = g.start(t + 3 * M, Proc(g, t, "C:\\Windows\\System32\\wscript.exe", "wscript.exe //B C:\\Users\\Public\\inv.js", w), tag=tag)
    ps = g.start(t + 4 * M, Proc(g, t, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                 "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", ws), tag=tag)
    g.dns(t + 4 * M + 4000, ps, "cdn-update-check.example", "198.51.100.23", tag=tag)
    g.net(t + 5 * M, ps, "198.51.100.23", 443, "cdn-update-check.example", tag=tag)
    g.file(t + 6 * M, ps, "C:\\Users\\priya\\AppData\\Local\\Temp\\upd.exe", tag=tag)
    u = g.start(t + 7 * M, Proc(g, t, "C:\\Users\\priya\\AppData\\Local\\Temp\\upd.exe", "upd.exe -s", ps, sha256=H_UPD), tag=tag)
    g.reg(t + 7 * M + 3000, u, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
          "C:\\Users\\priya\\AppData\\Local\\Temp\\upd.exe -s", tag=tag)
    for i in range(6):
        g.net(t + (8 + i) * M, u, "203.0.113.50", 8443, "", tag=tag)


def _lateral_dump(g: Gen, t: int):
    tag = "lateral_dump"
    svc = Proc(g, t, "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k DcomLaunch -p", None, "NT AUTHORITY\\SYSTEM")
    wmi = g.start(t, Proc(g, t, "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "C:\\Windows\\system32\\wbem\\wmiprvse.exe -Embedding",
                          svc, "NT AUTHORITY\\NETWORK SERVICE"), tag=tag)
    g.sec4688(t + 20_000, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /Q /c cd \\ 1> \\\\127.0.0.1\\ADMIN$\\__1790 2>&1", wmi, tag=tag)
    ghost = Proc(g, t, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /Q /c", None, guid=True)
    rd = g.start(t + 50_000, Proc(g, t, "C:\\Windows\\System32\\rundll32.exe",
                                  "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 692 C:\\Windows\\Temp\\logs.bin full",
                                  ghost, "NT AUTHORITY\\SYSTEM"), tag=tag)
    g.file(t + 70_000, rd, "C:\\Windows\\Temp\\logs.bin", tag=tag)
    g.net(t + 3 * M, rd, "10.10.4.20", 445, "FS-01", tag=tag)


def generate(ref_ms: int, seed: int = 4270) -> tuple[list[str], list[dict[str, Any]]]:
    """Journal lines + per-line meta for 30 days ending at ref_ms. Nights, a weekend and a delivery outage are gaps."""
    g = Gen(ref_ms, seed)
    for k in range(29, -1, -1):
        day_end = ref_ms - k * D
        weekend = k % 7 in (2, 3)
        if k == 0:
            t0, t1 = ref_ms - 14 * H, ref_ms - 20_000
        elif weekend:
            t0, t1 = day_end - 13 * H, day_end - 10 * H
        else:
            t0, t1 = day_end - 13 * H, day_end - 2 * H
        n0 = len(g.lines)
        exp = _session(g, t0, t1, 130.0 if k == 0 else (45.0 if not weekend else 25.0), installer=(k % 5 == 1))
        if k == 0:
            # Delivery outage REF-13h..REF-9h: evidence observed then arrives as one late backlog at REF-25m.
            out0, out1 = ref_ms - 13 * H, ref_ms - 9 * H
            for i in range(n0, len(g.lines)):
                line, meta = g.lines[i]
                rec = json.loads(line)
                tc = datetime.fromisoformat(rec["winlog"]["time_created"].replace("Z", "+00:00")).timestamp() * 1000
                if out0 <= tc < out1:
                    rec["observed_at"] = _iso(ref_ms - 25 * M + i % 600).replace("Z", "+00:00")
                    g.lines[i] = (json.dumps(rec, separators=(",", ":")), {**meta, "late": True, "tag": meta["tag"] or "backlog"})
            _office_chain(g, exp, ref_ms - 50 * M)
        if k == 5:
            _lateral_dump(g, t0 + 3 * H)
    return [x[0] for x in g.lines], [x[1] for x in g.lines]


def to_docs(lines: list[str]) -> list[dict[str, Any]]:
    """E1's own pipeline: parse → bind_process_identity → observation_doc (as the ingest bridge stores them)."""
    from edr_plane.canonical_bridge import bind_process_identity, parse
    from v2.ingestion.telemetry_bridge import observation_doc

    env = {"source": "nivxforge-windows-sensor", "connector_id": ENDPOINT, "collector_id": ENDPOINT,
           "collection_method": "WINDOWS_EVENT_LOG", "parser_version": "1.0.0"}
    out = []
    for i, line in enumerate(lines):
        c = parse(line)
        c["event_id"] = f"cev_{ENDPOINT}_{i:06d}"
        c["raw_ref"] = {"raw_id": f"raw_{ENDPOINT}_{i:06d}", "collection": "edr_raw_events"}
        c["host"] = {"host_id": ENDPOINT, "hostname": HOST}
        c = bind_process_identity(c, ENDPOINT)
        obs = json.loads(line)["observed_at"]
        d = observation_doc(c, envelope={**env, "source_event_id": c["event_id"], "collection_timestamp": obs}, tenant_id=TENANT)
        d["ingest_time"] = obs
        d["data_label"] = LABEL
        out.append(d)
    return out


def load_export(path: str) -> list[dict[str, Any]]:
    """A read-only JSON export of v2_shadow_observations (list of docs, or {"docs": [...]})."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["docs"] if isinstance(data, dict) else data
