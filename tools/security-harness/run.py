#!/usr/bin/env python3
"""Security-suite test harness · TEST-ONLY, no production role.

Several security suites were unrunnable outside a fully provisioned pod, not
because the controls were absent but because the suites need preconditions
nothing supplied: a database, a signed-audit key, an admin credential and —
for the live-HTTP suites — a reachable backend. The result was that the
controls those suites exist to prove were never exercised by any gate.

This harness supplies exactly those preconditions and nothing else:

  * an ephemeral mongod on a free port with a throwaway dbpath,
  * independently generated, process-local secrets,
  * optionally a backend on a free port for the suites that speak HTTP,
  * a `NIVXRAY_EXPORT_REQUIRED_CREDENTIAL_*` contract filled with the same
    generated values the tests expect to find in the environment.

It deliberately does NOT: weaken a control, pre-authorize a principal,
disable tenant isolation, or set any value this repository knows. Every
secret is random per run, so a suite that passes because a key was guessable
would fail here.

    python3 tools/security-harness/run.py --tier 1
    python3 tools/security-harness/run.py --tier 2
    python3 tools/security-harness/run.py --suite tests/test_xdr_webhooks.py
"""
from __future__ import annotations

import argparse
import os
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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"

#: In-process suites: TestClient plus a database.
TIER1 = [
    "tests/test_xdr_webhooks.py",
    "tests/test_collector_api_key_auth.py",
    "tests/test_d11_ingest_provenance.py",
    "tests/test_p0prod1_secret_policy.py",
    "tests/test_v2_isolation.py",
    "tests/test_phase2_1_tenant_isolation.py",
]

#: Live-HTTP suites: these drive a running server over REACT_APP_BACKEND_URL.
TIER2 = [
    "tests/test_collector_plane_auth.py",
    "tests/test_edr_route_tenant_authority.py",
]

#: Credential slots the suites read from the environment. Names only — the
#: values are generated per run and never leave this process tree.
CREDENTIAL_SLOTS = ("001", "003", "004", "005", "006", "009", "010", "011")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _secret() -> str:
    return secrets.token_urlsafe(48)


def build_env(mongo_url: str, db_name: str) -> dict:
    env = dict(os.environ)
    admin_password = _secret()
    env.update({
        "MONGO_URL": mongo_url,
        "DB_NAME": db_name,
        # `routers/benchmark.py` inserts `$NIVXRAY_REPO_ROOT/backend` and
        # `.../backend/tests` into sys.path at application import time and
        # defaults that root to "/app". Without this, a suite run from a
        # checkout imports its helpers from the DEPLOYED tree and silently
        # audits the wrong source. Reported as an application-side blocker.
        "NIVXRAY_REPO_ROOT": str(ROOT),
        "JWT_SECRET": _secret(),
        "XDR_ROOT_KEY": _secret(),
        "XDR_AUDIT_MASTER_SECRET": _secret(),
        "XDR_SECRETS_MASTER_SECRET": _secret(),
        "EDR_AUTH_PEPPER": _secret(),
        "ADMIN_EMAIL": "admin@nivxray.com",
        "ADMIN_PASSWORD": admin_password,
        # Non-empty so config validation passes; the harness performs no LLM
        # call and the integration tier may be absent entirely.
        "EMERGENT_LLM_KEY": "harness-no-llm-call",
        "NIVX_EDR_WORKERS_DISABLED": "1",
        "HARNESS_TENANT": f"harness-ten-{secrets.token_hex(4)}",
        "HARNESS_ANALYST_EMAIL": "analyst@default.com",
    })
    for slot in CREDENTIAL_SLOTS:
        env[f"NIVXRAY_EXPORT_REQUIRED_CREDENTIAL_{slot}"] = admin_password
    # Slot 011 is the unprivileged analyst, not the administrator. Keeping it
    # distinct means a suite cannot pass by confusing the two identities.
    env["NIVXRAY_EXPORT_REQUIRED_CREDENTIAL_011"] = _secret()
    env.pop("PYTEST_ADDOPTS", None)
    return env


class Mongo:
    """A disposable mongod. Nothing it stores survives the run."""

    def __init__(self) -> None:
        self.port = _free_port()
        self.dbpath = Path(tempfile.mkdtemp(prefix="nivx-harness-mongo-"))
        self.proc: subprocess.Popen | None = None

    @property
    def url(self) -> str:
        return f"mongodb://127.0.0.1:{self.port}"

    def start(self) -> None:
        if not shutil.which("mongod"):
            raise SystemExit("mongod is not installed; the harness cannot "
                             "fabricate a database")
        self.proc = subprocess.Popen(
            ["mongod", "--dbpath", str(self.dbpath), "--port", str(self.port),
             "--bind_ip", "127.0.0.1", "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 60
        while time.time() < deadline:
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", self.port)) == 0:
                    return
            if self.proc.poll() is not None:
                raise SystemExit("mongod exited during startup")
            time.sleep(0.4)
        raise SystemExit("mongod did not become reachable")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.dbpath, ignore_errors=True)


class Backend:
    """A backend on a free port, for the suites that speak HTTP."""

    def __init__(self, env: dict) -> None:
        self.port = _free_port()
        self.env = dict(env)
        self.log = Path(tempfile.mkstemp(prefix="nivx-harness-backend-",
                                         suffix=".log")[1])
        self.proc: subprocess.Popen | None = None

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        handle = self.log.open("wb")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "server:app",
             "--host", "127.0.0.1", "--port", str(self.port), "--workers", "1"],
            cwd=str(BACKEND), env=self.env, stdout=handle, stderr=handle)
        deadline = time.time() + 180
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise SystemExit(f"backend exited during startup; see {self.log}")
            try:
                with urllib.request.urlopen(f"{self.origin}/api/health",
                                            timeout=5) as r:
                    if r.status == 200:
                        return
            except (urllib.error.URLError, OSError):
                time.sleep(1)
        raise SystemExit(f"backend did not become healthy; see {self.log}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()


PROVISION = r'''
import os, sys, uuid
sys.path.insert(0, os.getcwd())
from services import tenant_registry as tr
import deps
from tests._verified_session import authorize_tenants, provision_rbac_principal

TENANT = os.environ["HARNESS_TENANT"]
ADMIN = os.environ["ADMIN_EMAIL"]
ANALYST = os.environ["HARNESS_ANALYST_EMAIL"]
ANALYST_PW = os.environ["NIVXRAY_EXPORT_REQUIRED_CREDENTIAL_011"]

org = tr.create_organization(slug=f"harness-{uuid.uuid4().hex[:6]}",
                             display_name="harness suite", kind="CUSTOMER",
                             created_by="harness")
tr.adopt_legacy(tenant_id=TENANT, organization_id=org["id"], slug=TENANT,
                display_name=TENANT, created_by="harness")

# The administrator: authorized for the tenant and provisioned in it.
#
# Deliberately an EXPLICIT GRANT, not `authority_scope == "PLATFORM"`. Both
# were tried. PLATFORM breadth makes `GET /api/xdr/tenants` fail with
# TENANT_REQUIRED ("a platform-scoped principal must name the customer"),
# which breaks the suite's own registry discovery and produced 67 failures.
# A single explicit grant resolves through SINGLE_AUTHORIZED_TENANT and
# leaves only one assertion family failing — an expected rejection whose
# CODE differs from the suite's expectation. See the A1 report; that is an
# application-contract question for the owner, not something to tune here.
authorize_tenants(ADMIN, TENANT)
provision_rbac_principal(TENANT, ADMIN, "platform_admin")

# An authenticated principal that is deliberately NOT authorized for the
# collector plane. `read_only` holds no `collectors.*` permission, so the
# refusal the suite asserts is a real authorization decision rather than a
# missing account.
users = deps.sync_collection("users")
users.delete_many({"email": ANALYST})
users.insert_one({"email": ANALYST, "password": deps.hash_password(ANALYST_PW),
                  "role": "analyst", "tenant_ids": [TENANT], "enabled": True})
provision_rbac_principal(TENANT, ANALYST, "read_only")
print(f"[harness] provisioned tenant={TENANT} admin={ADMIN} analyst={ANALYST}")
'''


def provision(env: dict) -> None:
    """Create the principals the live-HTTP suites expect to already exist.

    These suites were written against a long-lived preview database and log
    in as specific principals. On a blank database every login fails with
    401, which looks like 62 security failures and is really an absent
    environment. This creates the same server-side state an operator's
    provisioning step creates — and nothing else: no permission is widened,
    and the unprivileged principal is given a role that genuinely lacks
    collector authority so its refusal is a real decision.
    """
    proc = subprocess.run([sys.executable, "-c", PROVISION],
                          cwd=str(BACKEND), env=env,
                          capture_output=True, text=True)
    sys.stdout.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit("provisioning failed; refusing to report suite "
                         "results from an unprovisioned environment")


def run(suites: list[str], env: dict, junit: Path | None) -> int:
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:randomly", *suites]
    if junit:
        junit.parent.mkdir(parents=True, exist_ok=True)
        cmd.append(f"--junitxml={junit}")
    print(f"[harness] {' '.join(cmd)}", flush=True)
    return subprocess.call(cmd, cwd=str(BACKEND), env=env)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tier", choices=["1", "2"],
                    help="1 = in-process suites, 2 = live-HTTP suites")
    ap.add_argument("--suite", action="append", default=[],
                    help="explicit suite path, relative to backend/")
    ap.add_argument("--junitxml", type=Path)
    args = ap.parse_args()

    if args.suite:
        suites, need_backend = args.suite, args.tier == "2"
    elif args.tier == "1":
        suites, need_backend = TIER1, False
    elif args.tier == "2":
        suites, need_backend = TIER2, True
    else:
        ap.error("supply --tier or --suite")

    mongo = Mongo()
    backend: Backend | None = None
    try:
        mongo.start()
        env = build_env(mongo.url, f"nivx_harness_{secrets.token_hex(6)}")
        print(f"[harness] mongod on {mongo.url}", flush=True)
        if need_backend:
            backend = Backend(env)
            backend.start()
            env["REACT_APP_BACKEND_URL"] = backend.origin
            print(f"[harness] backend on {backend.origin}", flush=True)
            provision(env)
        return run(suites, env, args.junitxml)
    finally:
        if backend:
            backend.stop()
        mongo.stop()
        print("[harness] torn down", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
