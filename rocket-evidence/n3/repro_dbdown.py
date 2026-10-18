#!/usr/bin/env python3
"""N-3 · dependency-availability variant.

The three endpoints are among the few UNAUTHENTICATED GETs that query Mongo
with no fail-closed guard, so a database that is merely unreachable surfaces
as a 500 on exactly these paths while authenticated paths still refuse with
403. This probe proves or disproves that mechanism: it brings the disposable
mongod down under a running backend and re-probes.

    python3 repro_dbdown.py <repo-root>
"""
from __future__ import annotations

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

ROOT = pathlib.Path(sys.argv[1]).resolve()
BACKEND = ROOT / "backend"
OUT = pathlib.Path(__file__).resolve().parent

TARGETS = ["/api/telemetry/frontend/recent",
           "/api/xdr/vendor/cortex/actions",
           "/api/xdr/vendor/cortex/connections"]
CONTROLS = ["/api/health", "/api/incidents", "/api/behaviors/registry"]


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

env = dict(os.environ)
env.update({
    "MONGO_URL": f"mongodb://127.0.0.1:{mongo_port}",
    "DB_NAME": f"nivx_n3_{secrets.token_hex(4)}",
    "NIVXRAY_REPO_ROOT": str(ROOT), "JWT_SECRET": secret(),
    "XDR_ROOT_KEY": secret(), "XDR_AUDIT_MASTER_SECRET": secret(),
    "XDR_SECRETS_MASTER_SECRET": secret(), "EDR_AUTH_PEPPER": secret(),
    "ADMIN_EMAIL": "admin@nivxray.com", "ADMIN_PASSWORD": secret(),
    "EMERGENT_LLM_KEY": "probe-no-llm-call", "NIVX_EDR_WORKERS_DISABLED": "1",
})
env.pop("PYTEST_ADDOPTS", None)

port = free_port()
log = OUT / "dbdown-backend.log"
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


def probe(path: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(
                urllib.request.Request(origin + path, method="GET"),
                timeout=120) as r:
            return r.status, r.read(250).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(250).decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, f"{type(e).__name__}: {e}"


phases: dict[str, list] = {}
if healthy:
    phases["database_up"] = [{"path": p, "status": probe(p)[0]}
                             for p in CONTROLS + TARGETS]
    print("database_up:", phases["database_up"])

    mongo.send_signal(signal.SIGTERM)
    try:
        mongo.wait(timeout=30)
    except subprocess.TimeoutExpired:
        mongo.kill()
    print("[phase] mongod stopped")

    rows = []
    for p in CONTROLS + TARGETS:
        t0 = time.time()
        status, body = probe(p)
        rows.append({"path": p, "status": status,
                     "seconds": round(time.time() - t0, 1), "body": body})
        print(f"  {status}  {p}  ({rows[-1]['seconds']}s)\n        {body[:200]}")
    phases["database_down"] = rows

(OUT / "repro_dbdown.json").write_text(json.dumps(
    {"root": str(ROOT), "healthy": healthy, "phases": phases}, indent=2))

proc.send_signal(signal.SIGTERM)
try:
    proc.wait(timeout=30)
except subprocess.TimeoutExpired:
    proc.kill()
if mongo.poll() is None:
    mongo.kill()
shutil.rmtree(dbpath, ignore_errors=True)
handle.close()
print(f"healthy={healthy} log={log}")
