#!/usr/bin/env python3
"""N-3 · data-driven reproduction for the three reported 500s.

The three endpoints return Mongo documents to FastAPI's default encoder with
no BSON normalisation. This probe inserts one document per endpoint into a
DISPOSABLE database, each carrying a BSON value that is legal in Mongo but not
JSON-encodable, and records the resulting status plus the server-side
exception. Nothing is written to any pre-existing database.

    python3 repro_data.py <repo-root>
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from bson import Binary, Decimal128, ObjectId
from pymongo import MongoClient

ROOT = pathlib.Path(sys.argv[1]).resolve()
BACKEND = ROOT / "backend"
OUT = pathlib.Path(__file__).resolve().parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def secret() -> str:
    return secrets.token_urlsafe(48)


mongo_port = free_port()
dbpath = pathlib.Path(tempfile.mkdtemp(prefix="nivx-n3-mongo-"))
mongo = subprocess.Popen(
    ["mongod", "--dbpath", str(dbpath), "--port", str(mongo_port),
     "--bind_ip", "127.0.0.1", "--quiet"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
deadline = time.time() + 60
while time.time() < deadline:
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", mongo_port)) == 0:
            break
    time.sleep(0.4)

db_name = f"nivx_n3_{secrets.token_hex(4)}"
mongo_url = f"mongodb://127.0.0.1:{mongo_port}"

env = dict(os.environ)
env.update({
    "MONGO_URL": mongo_url, "DB_NAME": db_name,
    "NIVXRAY_REPO_ROOT": str(ROOT), "JWT_SECRET": secret(),
    "XDR_ROOT_KEY": secret(), "XDR_AUDIT_MASTER_SECRET": secret(),
    "XDR_SECRETS_MASTER_SECRET": secret(), "EDR_AUTH_PEPPER": secret(),
    "ADMIN_EMAIL": "admin@nivxray.com", "ADMIN_PASSWORD": secret(),
    "EMERGENT_LLM_KEY": "probe-no-llm-call", "NIVX_EDR_WORKERS_DISABLED": "1",
})
env.pop("PYTEST_ADDOPTS", None)

port = free_port()
log = OUT / "repro-backend.log"
handle = log.open("wb")
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1",
     "--port", str(port), "--workers", "1"],
    cwd=str(BACKEND), env=env, stdout=handle, stderr=handle)
origin = f"http://127.0.0.1:{port}"
healthy = False
deadline = time.time() + 300
while time.time() < deadline:
    if proc.poll() is not None:
        break
    try:
        with urllib.request.urlopen(f"{origin}/api/health", timeout=5) as r:
            healthy = r.status == 200
            if healthy:
                break
    except (urllib.error.URLError, OSError):
        time.sleep(1)

now = dt.datetime.now(dt.timezone.utc)
CASES = [
    # (label, collection, document, path)
    ("telemetry·nested-objectid", "frontend_telemetry",
     {"session_id": "ses_probe", "recorded_at": now,
      "case_ref": {"oid": ObjectId()}},
     "/api/telemetry/frontend/recent"),
    ("telemetry·binary", "frontend_telemetry",
     {"session_id": "ses_probe2", "recorded_at": now,
      "blob": Binary(b"\x00\x01\x02")},
     "/api/telemetry/frontend/recent"),
    ("telemetry·decimal128", "frontend_telemetry",
     {"session_id": "ses_probe3", "recorded_at": now,
      "total_ms": Decimal128("418.5")},
     "/api/telemetry/frontend/recent"),
    ("cortex-actions·nested-objectid", "xdr_response_actions",
     {"action_id": "probe-a1", "xdr_incident_id": "inc-probe",
      "completed_at": now.isoformat(), "result": {"ref": ObjectId()}},
     "/api/xdr/vendor/cortex/actions"),
    ("cortex-actions·datetime-in-result", "xdr_response_actions",
     {"action_id": "probe-a2", "completed_at": now.isoformat(),
      "result": {"vendor_seen_at": now}},
     "/api/xdr/vendor/cortex/actions"),
    ("vendor-connections·nested-objectid", "xdr_integrations",
     {"integration_id": "probe-c1", "vendor_key": "cortex",
      "vendor": "palo_alto_cortex_xdr", "probe": {"ref": ObjectId()}},
     "/api/xdr/vendor/cortex/connections"),
    ("vendor-connections·binary-credential", "xdr_integrations",
     {"integration_id": "probe-c2", "vendor_key": "cortex",
      "vendor": "palo_alto_cortex_xdr",
      "credentials_blob": Binary(b"\xde\xad\xbe\xef")},
     "/api/xdr/vendor/cortex/connections"),
]


def probe(path: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(
                urllib.request.Request(origin + path, method="GET"),
                timeout=60) as r:
            return r.status, r.read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(300).decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, f"{type(e).__name__}: {e}"


results = []
if healthy:
    client = MongoClient(mongo_url)
    db = client[db_name]
    for label, coll, doc, path in CASES:
        before = probe(path)
        ins = db[coll].insert_one(dict(doc))
        after = probe(path)
        db[coll].delete_one({"_id": ins.inserted_id})
        clean = probe(path)
        results.append({"case": label, "collection": coll, "path": path,
                        "status_before": before[0], "status_with_doc": after[0],
                        "status_after_removal": clean[0],
                        "body_with_doc": after[1]})
        print(f"{label}\n  {path}\n  before={before[0]} with_doc={after[0]} "
              f"after_removal={clean[0]}\n  {after[1][:200]}")
    client.close()

(OUT / "repro_data.json").write_text(json.dumps(
    {"root": str(ROOT), "healthy": healthy, "cases": results}, indent=2))

proc.send_signal(signal.SIGTERM)
try:
    proc.wait(timeout=30)
except subprocess.TimeoutExpired:
    proc.kill()
mongo.send_signal(signal.SIGTERM)
try:
    mongo.wait(timeout=30)
except subprocess.TimeoutExpired:
    mongo.kill()
shutil.rmtree(dbpath, ignore_errors=True)
handle.close()
print(f"healthy={healthy} log={log}")
