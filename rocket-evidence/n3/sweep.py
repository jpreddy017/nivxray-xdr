#!/usr/bin/env python3
"""N-3 · unauthenticated GET sweep against the candidate backend.

Replicates the F1 acceptance-package methodology: enumerate every
parameterless GET from the candidate's own OpenAPI document and probe each one
with NO credential, then classify the responses. Read-only; the only database
touched is a disposable mongod created for the run.

    python3 sweep.py <repo-root> <out-prefix> [seed-dir]

`seed-dir` is an optional mongorestore dump directory used to populate the
disposable database before probing, so the same surface can be measured empty
and populated.
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
PREFIX = sys.argv[2]
SEED = pathlib.Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else None
BACKEND = ROOT / "backend"
OUT = pathlib.Path(__file__).resolve().parent

# Expensive by design — excluded by name, exactly as the F1 probe did, so a
# sweep cannot be mistaken for a load test.
SKIP = {"/api/benchmark/refresh", "/api/benchmark/run", "/api/metrics/scrape"}


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
if SEED:
    r = subprocess.run(["mongorestore", "--port", str(mongo_port),
                        "--nsFrom", "src.*", "--nsTo", f"{db_name}.*",
                        "--quiet", str(SEED)], capture_output=True, text=True)
    print(f"[seed] mongorestore rc={r.returncode} {r.stderr[-400:]}")

env = dict(os.environ)
env.update({
    "MONGO_URL": f"mongodb://127.0.0.1:{mongo_port}",
    "DB_NAME": db_name,
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
log = OUT / f"{PREFIX}-backend.log"
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

results: list[dict] = []
paths: list[str] = []
if healthy:
    with urllib.request.urlopen(f"{origin}/api/openapi.json", timeout=120) as r:
        spec = json.loads(r.read().decode())
    paths = sorted(p for p, ops in spec.get("paths", {}).items()
                   if "get" in ops and "{" not in p and p not in SKIP)
    print(f"[sweep] parameterless GETs: {len(paths)}")
    for path in paths:
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(origin + path, method="GET"),
                    timeout=120) as r:
                status, body = r.status, r.read(400).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read(400).decode("utf-8", "replace")
        except Exception as e:                               # noqa: BLE001
            status, body = -1, f"{type(e).__name__}: {e}"
        results.append({"path": path, "status": status, "body": body})
        if status not in (200, 401, 403):
            print(f"  {status}  {path}\n        {body[:200]}")

buckets: dict[str, int] = {}
for r in results:
    buckets[str(r["status"])] = buckets.get(str(r["status"]), 0) + 1
summary = {"root": str(ROOT), "seeded": bool(SEED), "healthy": healthy,
           "probed": len(results), "buckets": buckets,
           "non_2xx_401_403": [r for r in results
                               if r["status"] not in (200, 401, 403)]}
(OUT / f"{PREFIX}-sweep.json").write_text(
    json.dumps({"summary": summary, "results": results}, indent=2))
print(json.dumps(summary["buckets"], indent=2))
print(f"non-401/403/200: {len(summary['non_2xx_401_403'])}")

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
