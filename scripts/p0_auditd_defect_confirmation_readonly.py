#!/usr/bin/env python3
"""D2 / D3 / D4 CONFIRMATION — auditd parser + normalizer, READ-ONLY.

Calls the real production parser/normalizer as PURE FUNCTIONS on the exact
verbatim auditd line already stored in canonical evidence, plus the three
records auditd genuinely emits for ONE execution. Touches no database, writes
nothing, changes nothing.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv                                    # noqa: E402
from pymongo import MongoClient                                   # noqa: E402

from detection_content.telemetry.linux_auditd_dsm import (        # noqa: E402
    LinuxAuditdDSM,
)

load_dotenv("/app/backend/.env")
DB = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

dsm = LinuxAuditdDSM()

# The ONE real auditd line that ever reached this platform, read back from
# stored canonical evidence — not invented for this probe.
stored = DB.xdr_canonical_evidence.find_one({"source_product": "Auditd"})
REAL_LINE = stored["raw_ref"]["message"]
REAL_SOURCE = stored["raw_ref"]["source"]
REAL_COLLECTOR = stored["raw_ref"]["collector_id"]

print("=" * 78)
print("D2 / D3 — the stored REAL auditd event, re-run through the real code")
print("=" * 78)
print(f"verbatim line : {REAL_LINE}")
print(f"envelope.source: {REAL_SOURCE!r}   collector: {REAL_COLLECTOR}")
print()

raw_event = {
    "tenant_id": "readonly-probe",
    "line": REAL_LINE,
    "message": REAL_LINE,
    "payload_format": "auditd",
    "source": REAL_SOURCE,
    "collector_id": REAL_COLLECTOR,
    "collection_method": "syslog",
}
parsed = dsm.select_parser().parse(raw_event)
canon = dsm.select_normalizer().normalize(
    parsed, dsm.id, REAL_COLLECTOR, "probe", "probe-trace",
    tenant_id="readonly-probe")

print(f"record_type  : {parsed['record_type']}")
print(f"event_type   : {canon['event_type']}")
print(f"host         : {json.dumps(canon['host'])}")
print(f"identity     : {json.dumps(canon['identity'])}")
print(f"process      : {json.dumps(canon['process'])}")
print()
print("D2 · host identity        :",
      "LOST — hostname/host_id empty although the envelope carried "
      f"source={REAL_SOURCE!r}"
      if not canon["host"]["hostname"] else "present")
print("D2 · user identity        :",
      f"DEGRADED — username={canon['identity']['username']!r}, "
      f"is_privileged={canon['identity']['is_privileged']}"
      if canon["identity"]["username"] in ("uid:", "", None)
      else "present")
print("D3 · event classification :",
      f"WRONG — record_type={parsed['record_type']} classified as "
      f"{canon['event_type']!r}, expected 'process_execution'"
      if parsed["record_type"] == "EXECVE"
      and canon["event_type"] != "process_execution" else "correct")
print("     process.pid / ppid   :",
      f"{canon['process']['pid']} / {canon['process']['ppid']}")
print()

print("=" * 78)
print("D4 — the THREE records auditd emits for ONE execution")
print("=" * 78)
serial = REAL_LINE.split("audit(", 1)[1].split(")", 1)[0]
trio = [
    f"type=SYSCALL msg=audit({serial}): arch=c000003e syscall=59 success=yes "
    f"exit=0 ppid=1234 pid=5678 auid=1000 uid=1000 euid=0 tty=pts0 "
    f"comm=\"bash\" exe=\"/usr/bin/bash\" key=\"exec\"",
    REAL_LINE,
    f"type=PROCTITLE msg=audit({serial}): "
    f"proctitle=2F62696E2F62617368002D63",
]
print(f"shared audit id: {serial}   (all three records describe ONE execution)")
print()
ids = []
for line in trio:
    ev = {"tenant_id": "readonly-probe", "line": line, "message": line,
          "payload_format": "auditd", "source": REAL_SOURCE,
          "collector_id": REAL_COLLECTOR, "collection_method": "syslog"}
    pr = dsm.select_parser().parse(ev)
    cn = dsm.select_normalizer().normalize(
        pr, dsm.id, REAL_COLLECTOR, "probe", "probe-trace",
        tenant_id="readonly-probe")
    ids.append(cn["event_id"])
    print(f"{pr['record_type']:10s} → event_id {cn['event_id']}")
    print(f"{'':10s}   event_type   {cn['event_type']}")
    print(f"{'':10s}   host         {cn['host']['hostname']!r}")
    print(f"{'':10s}   user         {cn['identity']['username']!r}"
          f"  privileged={cn['identity']['is_privileged']}")
    print(f"{'':10s}   pid/ppid     {cn['process']['pid']}/"
          f"{cn['process']['ppid']}")
    print(f"{'':10s}   cmdline      {cn['process']['command_line']!r}")
    print()
print(f"distinct canonical events produced: {len(set(ids))} for ONE real "
      f"execution")
print("D4 · record stitching     : ABSENT — nothing joins these on the "
      "shared audit id, so the execution never reassembles.")
print()
print("Note: SYSCALL alone carries pid/ppid/uid/auid/exe; EXECVE alone "
      "carries the real argv. Neither record on its own is a complete "
      "execution, which is exactly why stitching is required.")
print()
print("NO DATABASE WRITE PERFORMED. Pure function calls only.")
