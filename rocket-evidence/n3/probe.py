#!/usr/bin/env python3
"""N-3 reproduction probe. READ-ONLY against the candidate worktree.

Starts an ephemeral mongod and the candidate backend on free ports (same
preconditions as tools/security-harness/run.py), then issues UNAUTHENTICATED
GETs against the three endpoints reported as 500 in the F1 acceptance package.
Nothing is written to any existing database and no application file is touched.
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

TARGETS = [
    "/api/telemetry/frontend/recent",
    "/api/xdr/vendor/cortex/actions",
    "/api/xdr/vendor/cortex/connections",
]
# Controls: a known-good open GET and a known fail-closed GET, so a blanket
# breakage of the probe cannot be mistaken for an endpoint defect.
CONTROLS = ["/api/health", "/api/incidents"]


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
    "NIVXRAY_REPO_ROOT": str(ROOT),
    "JWT_SECRET": secret(),
    "XDR_ROOT_KEY": secret(),
    "XDR_AUDIT_MASTER_SECRET": secret(),
    "XDR_SECRETS_MASTER_SECRET": secret(),
    "EDR_AUTH_PEPPER": secret(),
    "ADMIN_EMAIL": "admin@nivxray.com",
    "ADMIN_PASSWORD": secret(),
    "EMERGENT_LLM_KEY": "probe-no-llm-call",
    "NIVX_EDR_WORKERS_DISABLED": "1",
})
env.pop("PYTEST_ADDOPTS", None)

port = free_port()
log = OUT / "backend.log"
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
            if r.status == 200:
                healthy = True
                break
    except (urllib.error.URLError, OSError):
        time.sleep(1)

results = []
if healthy:
    for path in CONTROLS + TARGETS:
        req = urllib.request.Request(origin + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                status, body = r.status, r.read(600).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read(600).decode("utf-8", "replace")
        except Exception as e:                       # noqa: BLE001
            status, body = -1, f"{type(e).__name__}: {e}"
        results.append({"path": path, "status": status, "body": body})
        print(f"{status}  {path}")
        print(f"      {body[:300]}")

(OUT / "probe.json").write_text(json.dumps(
    {"root": str(ROOT), "healthy": healthy, "results": results}, indent=2))

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
