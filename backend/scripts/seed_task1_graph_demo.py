"""Local-only deterministic seed for Task 1 process-graph UI validation.

Writes one tenant-linked endpoint (`E3-GRAPH-LAB`) plus a realistic process
lineage into the LOCAL dev database so the implemented graph can be opened in
a browser. Never run against production: it only touches DB_NAME from
backend/.env and uses a dedicated collector id.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deps import db  # noqa: F401  (loads dotenv)
from pymongo import MongoClient

TENANT = "default"
COLLECTOR = "col_e3graph01"
DEVICE_IID = "dev_e3graph01"
HOSTNAME = "E3-GRAPH-LAB"
ENDPOINT_ID = "ep_e3graph0000000000001"
BASE = datetime.now(timezone.utc) - timedelta(minutes=40)


def obs(iid, name, pid, parent_iid=None, ppid=None, minute=0, rules=None,
        user="CORP\\j.rivera", cmd=None, state="PARENT_OBSERVED", sha=None):
    ts = (BASE + timedelta(minutes=minute)).isoformat()
    return {
        "tenant_id": TENANT,
        "collector_id": COLLECTOR,
        "kind": "process",
        "origin": "collector-live",
        "captured_at": ts,
        "process_iid": iid,
        "event": {
            "iid": f"ev_{iid}",
            "device_iid": DEVICE_IID,
            "computer": HOSTNAME,
            "process": {"iid": iid, "name": name, "parent_iid": parent_iid},
            "rule_ids": rules or [],
            "raw": {
                "pid": pid,
                "ppid": ppid,
                "computer": HOSTNAME,
                "hostname": HOSTNAME,
                "command_line": cmd or name,
                "user": user,
                "image_path": f"C:\\Windows\\System32\\{name}",
                "sha256": sha,
                "parent_lookup_state": state,
                "utc_time": ts,
            },
        },
    }


DOCS = [
    obs("p_explorer", "explorer.exe", 4312, minute=0,
        cmd="C:\\Windows\\explorer.exe"),
    obs("p_winword", "winword.exe", 7788, "p_explorer", 4312, minute=3,
        cmd='"C:\\Program Files\\Microsoft Office\\WINWORD.EXE" /n "Q3-Invoice.docm"'),
    obs("p_cmd", "cmd.exe", 9120, "p_winword", 7788, minute=4,
        cmd='cmd.exe /c powershell -nop -w hidden -enc SQBFAFgA',
        rules=["OFFICE_SPAWNS_SHELL"]),
    obs("p_powershell", "powershell.exe", 9412, "p_cmd", 9120, minute=4,
        cmd='powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA',
        rules=["ENCODED_POWERSHELL", "SUSPICIOUS_PARENT_CHAIN"],
        sha="4f1d0a7b9c2e3f5a6b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c"),
    obs("p_rundll", "rundll32.exe", 9533, "p_powershell", 9412, minute=5,
        cmd="rundll32.exe C:\\Users\\Public\\upd.dll,Start",
        rules=["LOLBIN_EXECUTION"]),
    obs("p_netsh", "netsh.exe", 9601, "p_powershell", 9412, minute=6,
        cmd="netsh advfirewall firewall add rule name=svc dir=in action=allow"),
    # recycled pid: same pid as the earlier cmd.exe, unrelated identity
    obs("p_notepad", "notepad.exe", 9120, "p_explorer", 4312, minute=22,
        cmd="notepad.exe C:\\Users\\j.rivera\\notes.txt"),
    # start event for the parent was never collected
    obs("p_orphan_svc", "svchost.exe", 2204, "p_parent_never_seen", 1988,
        minute=12, state="PARENT_NOT_OBSERVED",
        cmd="svchost.exe -k netsvcs -p"),
    # thin telemetry: name only
    {"tenant_id": TENANT, "collector_id": COLLECTOR, "kind": "process",
     "origin": "collector-live",
     "captured_at": (BASE + timedelta(minutes=15)).isoformat(),
     "process_iid": "p_thin",
     "event": {"iid": "ev_p_thin", "device_iid": DEVICE_IID,
               "computer": HOSTNAME,
               "process": {"iid": "p_thin", "name": "conhost.exe"},
               "raw": {"computer": HOSTNAME}}},
]


def main():
    client = MongoClient(os.environ["MONGO_URL"])
    d = client[os.environ["DB_NAME"]]
    d["v2_shadow_observations"].delete_many({"collector_id": COLLECTOR})
    d["v2_shadow_observations"].insert_many(DOCS)
    d["edr_endpoints"].update_one(
        {"endpoint_id": ENDPOINT_ID},
        {"$set": {"endpoint_id": ENDPOINT_ID, "tenant_id": TENANT,
                  "collector_id": COLLECTOR, "device_iid": DEVICE_IID,
                  "hostname": HOSTNAME, "platform": "windows",
                  "enrollment_state": "ENROLLED", "sensor_state": "ACTIVE",
                  "credential_state": "ACTIVE",
                  "last_seen": DOCS[-1]["captured_at"],
                  "last_telemetry_at": DOCS[-1]["captured_at"],
                  "event_count": len(DOCS)}},
        upsert=True)
    print("seeded", len(DOCS), "process observations for", HOSTNAME,
          ENDPOINT_ID, DEVICE_IID)
    client.close()


if __name__ == "__main__":
    main()
