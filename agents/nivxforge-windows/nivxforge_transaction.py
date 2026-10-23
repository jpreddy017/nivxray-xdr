"""Installer transaction ownership, durable intent and verified reconciliation.

No collector/backend logic. Windows APIs run in a bounded child worker; local
tests substitute the observation/mutation boundary, never a production bypass.
"""
from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid


class TransactionError(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def directory_sync(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_bytes(path, data):
    path = Path(path)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".new")
    try:
        with open(temp, "xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        durable_replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def durable_replace(source, dest):
    if os.name == "nt":
        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        move.restype = ctypes.c_int
        if not move(str(source), str(dest), 1 | 8):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.replace(source, dest)
        directory_sync(Path(dest).parent)


def durable_copy(source, dest):
    # Flush writable handles while staging; FlushFileBuffers is not a valid
    # durability proof on a read-only Windows handle.
    with open(source, "rb") as src, open(dest, "xb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())
    shutil.copystat(source, dest)
    return dest


def inventory(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise TransactionError("payload root is not a regular directory")
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or (os.name == "nt" and p.lstat().st_file_attributes & 1024):
            raise TransactionError("reparse point in payload")
        if p.is_file():
            sha = hashlib.sha256()
            with p.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    sha.update(chunk)
            files[p.relative_to(root).as_posix()] = {
                "size": p.stat().st_size, "sha256": sha.hexdigest()}
    if "NivXForgeSensor.exe" not in files:
        raise TransactionError("manifest lacks service executable")
    return files


def validate(root, manifest):
    if not isinstance(manifest, dict) or inventory(root) != manifest:
        raise TransactionError("payload differs from pinned manifest")


def manifest_id(manifest):
    """Stable identity of a pinned payload: the digest of its hash set."""
    return digest(canonical(manifest))[:16]


#: An operation record is settled once it reaches one of these. Nothing
#: ever leaves this set, and no record is ever deleted: an uncertain
#: outcome is RESOLVED with its evidence, never erased.
SETTLED_OPERATIONS = ("FINISHED", "RESOLVED_BY_OBSERVATION",
                      "RESOLVED_BY_OPERATOR")
#: Seconds added to the service's own cycle interval to bound a stop. The
#: sensor sleeps up to one interval between cycles and may hold a delivery
#: round trip, so a fixed 25s ceiling timed out a stop that was merely
#: SLOW. The budget is derived from the service's declared cadence, and
#: the SCM's CheckPoint/WaitHint progress contract is honoured inside it.
STOP_GRACE_SECONDS = 45
STOP_BUDGET_FLOOR = 60
STOP_BUDGET_CEILING = 600


def stop_budget(config):
    """Seconds to allow a stop, from the service's OWN declared cadence.

    Raising a constant is not a fix: the correct ceiling is a function of
    how long this service is entitled to take. Honour its interval, then
    clamp so a hostile or absent argument cannot produce an unbounded or
    uselessly short wait.
    """
    interval = 0
    argv = (config or {}).get("argv") or []
    for key, value in zip(argv[2::2], argv[3::2]):
        if key == "--interval":
            try:
                interval = int(value)
            except (TypeError, ValueError):
                interval = 0
    return max(STOP_BUDGET_FLOOR,
               min(STOP_BUDGET_CEILING, interval + STOP_GRACE_SECONDS))


def process_alive(pid):
    """Deprecated two-state check; retained only as a thin shim."""
    return worker_state({"worker_pid": pid, "worker_token": None}) == "ALIVE"


#: Seconds between the two observations a settlement must agree on. A
#: worker that delivered a control and then died leaves that control
#: landing inside the service, so ONE observation can catch a service a
#: moment before it transitions. Two agreeing FINAL observations are the
#: minimum proof that nothing is still arriving.
OBSERVATION_SETTLE_SECONDS = .75


def query_process(pid):
    """(identity_token, 'OK' | 'GONE' | 'UNKNOWN') for a process.

    A query that FAILS is not a dead process. The previous helper returned
    False — "dead" — when OpenProcess or GetExitCodeProcess failed for any
    reason, including ERROR_ACCESS_DENIED, so a denied query read as
    confirmed termination and settlement proceeded underneath a worker
    that might still be running. In a design that refuses everywhere else
    without proof, that single path failed OPEN.

    The token is the process CREATION time, so a reused PID is a different
    process rather than the same worker.
    """
    if os.name == "nt":
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.restype = ctypes.c_void_p
        handle = k.OpenProcess(0x1000, False, int(pid))
        if not handle:
            # 87 ERROR_INVALID_PARAMETER is how Windows answers "no such
            # process id". Anything else is a query we could not perform.
            return (None, "GONE" if ctypes.get_last_error() == 87
                    else "UNKNOWN")
        try:
            created = wintypes.FILETIME()
            times = (wintypes.FILETIME * 3)()
            k.GetProcessTimes.argtypes = [ctypes.c_void_p] + \
                [ctypes.POINTER(wintypes.FILETIME)] * 4
            if not k.GetProcessTimes(handle, ctypes.byref(created),
                                     ctypes.byref(times[0]),
                                     ctypes.byref(times[1]),
                                     ctypes.byref(times[2])):
                return None, "UNKNOWN"
            code = wintypes.DWORD()
            k.GetExitCodeProcess.argtypes = [ctypes.c_void_p,
                                             ctypes.POINTER(wintypes.DWORD)]
            if not k.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None, "UNKNOWN"
            if code.value != 259:                          # not STILL_ACTIVE
                return None, "GONE"
            return ("%d:%d" % (created.dwHighDateTime,
                               created.dwLowDateTime), "OK")
        finally:
            ctypes.WinDLL("kernel32").CloseHandle(ctypes.c_void_p(handle))
    try:
        fields = Path("/proc/%d/stat" % int(pid)).read_text().rsplit(") ", 1)
    except FileNotFoundError:
        return None, "GONE"
    except (OSError, ValueError):
        return None, "UNKNOWN"
    try:
        return fields[1].split()[19], "OK"                 # starttime
    except IndexError:
        return None, "UNKNOWN"


def worker_state(record):
    """'ALIVE' | 'GONE' | 'UNKNOWN' for the worker that made a request.

    UNKNOWN is a first-class answer and refuses, because a worker whose
    liveness cannot be established is a worker that might still be writing
    to the SCM.
    """
    pid = record.get("worker_pid")
    if not pid:
        # No pid was ever recorded, so the request was never released to
        # the worker's stdin and no mutation can have been attempted.
        return "GONE"
    if not record.get("worker_token"):
        # A pid with no identity proof cannot be distinguished from a
        # reused pid in either direction.
        return "UNKNOWN"
    token, status = query_process(pid)
    if status == "GONE":
        return "GONE"
    if status != "OK":
        return "UNKNOWN"
    # Same pid, different creation time: the worker is gone and an
    # unrelated process now holds its number.
    return "ALIVE" if token == record["worker_token"] else "GONE"


def final_observation(obs):
    """Is this observation a FINAL, verifiable service state?

    PENDING is not an outcome. `operation_outcome` was previously handed
    the RAW observation rather than `require_observation`'s verified form,
    so a service in START/STOP_PENDING produced applied=False and was
    written RESOLVED_BY_OBSERVATION — settling an operation against a
    state that had not finished happening.
    """
    if obs.get("presence") == "ABSENT":
        return obs.get("error") == 1060
    if obs.get("presence") != "PRESENT":
        return False
    return obs.get("state") in FINAL_SERVICE_STATES


FINAL_SERVICE_STATES = ("RUNNING", "STOPPED")


def observation_identity(obs):
    """The facts two observations must agree on to count as stable."""
    return canonical({"presence": obs.get("presence"),
                      "state": obs.get("state"), "pid": obs.get("pid"),
                      "image": obs.get("image"),
                      "binpath": (obs.get("config") or {}).get("binpath")})


def operation_outcome(record, obs):
    """What a FINAL, stable SCM observation proves about a mutation.

    Only reached once the requesting worker is proved GONE and the SCM has
    held the same final state across two observations. A non-final state
    returns None and keeps the record UNCERTAIN.
    """
    if not final_observation(obs):
        return None
    action = record.get("action")
    present = obs["presence"] == "PRESENT"
    if action == "stop":
        applied = not present or (obs.get("state") == "STOPPED"
                                  and obs.get("pid") == 0)
    elif action == "start":
        applied = present and obs.get("state") == "RUNNING" \
            and bool(obs.get("pid"))
    elif action == "set_path":
        applied = present and (obs.get("config") or {}).get("binpath") \
            == record.get("binpath")
    elif action == "create":
        applied = present
    elif action == "delete":
        applied = not present
    else:
        return None
    return {"applied": bool(applied), "final": True,
            "presence": obs["presence"],
            "state": obs.get("state"), "pid": obs.get("pid"),
            "binpath": (obs.get("config") or {}).get("binpath"),
            "image": obs.get("image")}


class Owner:
    """OS-owned lock, released on death. Never delete a lock-file pathname."""
    def __init__(self, root):
        self.root = Path(root)

    def __enter__(self):
        if os.name == "nt":
            self.k = ctypes.WinDLL("kernel32", use_last_error=True)
            self.k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
            self.k.CreateMutexW.restype = ctypes.c_void_p
            self.k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            self.k.ReleaseMutex.argtypes = [ctypes.c_void_p]
            self.k.CloseHandle.argtypes = [ctypes.c_void_p]
            name = "Global\\NivXForgeInstaller-" + digest(str(self.root.resolve()).casefold().encode())
            self.handle = self.k.CreateMutexW(None, False, name)
            if not self.handle:
                raise TransactionError("cannot obtain installer ownership")
            if self.k.WaitForSingleObject(self.handle, 0) not in (0, 128):
                self.k.CloseHandle(self.handle)
                raise TransactionError("another installer owns this installation")
        else:
            import fcntl
            self.stream = open(self.root / "installer.lock", "a+b")
            try:
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as ex:
                self.stream.close()
                raise TransactionError("another installer owns this installation") from ex
        return self

    def __exit__(self, *_):
        if os.name == "nt":
            self.k.ReleaseMutex(self.handle)
            self.k.CloseHandle(self.handle)
        else:
            self.stream.close()


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.record = self.root / "transaction.json"
        self.active = self.root / "active.json"

    def read(self):
        try:
            raw = self.record.read_bytes()
        except FileNotFoundError:
            return None
        try:
            envelope = json.loads(raw)
            value = envelope["record"]
            if envelope["sha256"] != digest(canonical(value)) or value["schema"] != 1:
                raise ValueError("integrity")
            return value
        except (ValueError, KeyError, TypeError) as ex:
            raise TransactionError("MANUAL_RECOVERY: transaction record unreadable/corrupt") from ex

    def write(self, record):
        atomic_bytes(self.record, canonical({"record": record, "sha256": digest(canonical(record))}))

    def amend(self, state, **evidence):
        """Move an operation record forward, APPEND-ONLY.

        The prior state is pushed onto `history` and kept. Nothing is ever
        deleted: an uncertain SCM outcome is evidence, and evidence is not
        something an installer is permitted to tidy away.
        """
        record = self.read()
        entry = {"from": record.get("state"), "to": state, **evidence}
        record = {**record, "state": state,
                  "history": [*record.get("history", []), entry]}
        self.write(record)
        return record

    def active_bytes(self):
        try:
            return self.active.read_bytes()
        except FileNotFoundError:
            return None

    def restore_active(self, encoded):
        expected = None if encoded is None else base64.b64decode(encoded, validate=True)
        if self.active_bytes() == expected:
            return
        if encoded is None:
            try:
                self.active.unlink()
                directory_sync(self.root)
            except FileNotFoundError:
                pass
        else:
            atomic_bytes(self.active, expected)


def require_observation(value):
    if value.get("presence") == "ABSENT":
        if value.get("error") != 1060:
            raise TransactionError("absence not proved by ERROR_SERVICE_DOES_NOT_EXIST")
        return value
    if value.get("presence") != "PRESENT":
        raise TransactionError("SCM UNREADABLE: " + str(value.get("reason", "unknown")))
    if value.get("state") not in ("RUNNING", "STOPPED"):
        raise TransactionError("SCM state not stable or verifiable")
    if not isinstance(value.get("config"), dict) or not value["config"].get("binpath"):
        raise TransactionError("SCM configuration incomplete")
    return value


def same_config(a, b):
    return canonical(a) == canonical(b)


class Engine:
    def __init__(self, root, backend, hook=None):
        self.root = Path(root).resolve()
        self.backend = backend
        self.store = Store(self.root)
        self.hook = hook or (lambda _: None)

    def observation(self):
        return require_observation(self.backend.observe())

    def check(self, target, manifest=None):
        obs = self.observation()
        if target["presence"] == "ABSENT":
            if obs["presence"] != "ABSENT":
                raise TransactionError("original absence not restored")
            return
        if obs["presence"] != "PRESENT" or not same_config(obs["config"], target["config"]):
            raise TransactionError("exact supported SCM configuration not restored")
        if obs["state"] != target["state"]:
            raise TransactionError("service state mismatch")
        if target["state"] == "RUNNING":
            if not obs.get("image") or Path(obs["image"]).resolve() != Path(target["image"]).resolve():
                raise TransactionError("live executable UNVERIFIED or MISMATCH")
            if not obs.get("pid"):
                raise TransactionError("live PID unverified")
        elif obs.get("pid") != 0:
            raise TransactionError("stopped service process absence unverified")
        if manifest:
            validate(Path(target["image"]).parent, manifest)

    def stop(self):
        obs = self.observation()
        if obs["presence"] == "PRESENT" and obs["state"] != "STOPPED":
            self.backend.stop(stop_budget(obs.get("config")))
        # The backend's mutation may have timed out; never infer its outcome.
        obs = self.observation()
        if obs["presence"] == "PRESENT" and (obs["state"] != "STOPPED" or obs.get("pid") != 0):
            raise TransactionError("service did not stop; manual recovery required")

    def predecessor(self, original):
        """The pinned manifest of the build actually installed here.

        Refusal is safe and must stay safe, but it must also be
        ACTIONABLE: the diagnostic names the payload directory, the
        identity of what is installed, and every predecessor this
        artifact is authenticated to replace.
        """
        payload_dir = Path(original["image"]).parent
        try:
            installed = inventory(payload_dir)
        except TransactionError as ex:
            raise TransactionError(
                "cannot identify the installed payload at " + str(payload_dir)
                + " (" + str(ex) + "); no service was mutated") from None
        installed_id = manifest_id(installed)
        for entry in self.backend.predecessors():
            if entry["manifest"] == installed:
                print("  predecessor : " + entry["id"] + " ("
                      + str(entry["build"]) + ") — authenticated")
                return entry["manifest"]
        supported = self.backend.predecessors()
        raise TransactionError(
            "UNSUPPORTED_PREDECESSOR: the build installed at " + str(payload_dir)
            + " has payload identity " + installed_id + ", which this "
            "installer is not authenticated to replace. Supported "
            "predecessors: "
            + (", ".join(f"{e['id']} ({e['build']})" for e in supported)
               if supported else "none are pinned in this artifact")
            + ". Nothing was stopped, staged, reconfigured or activated, and "
            "identity, tenant, credentials, journal, cursors and queued "
            "evidence are untouched. Obtain an installer whose predecessor "
            "policy pins " + installed_id + ", or follow the reviewed "
            "migration procedure for this build.")

    def phase(self, record, phase):
        record["phase"] = phase
        self.store.write(record)
        self.hook(phase)

    def reconcile(self):
        self.backend.recovery_safe()
        r = self.store.read()
        if not r:
            return None
        self.backend.protect(Path(r["state_root"]))
        if r["phase"] in ("ROLLED_BACK", "COMPLETE"):
            # Completed records are still checked before a later update.
            target = r["original"] if r["phase"] == "ROLLED_BACK" else r["target"]
            manifest = r.get("original_manifest") if r["phase"] == "ROLLED_BACK" else r["manifest"]
            obs = self.observation()
            # A completed transaction does not prohibit a later deliberate
            # operator start/stop. Configuration, payload and metadata may not drift.
            target = {**target, "state": obs.get("state", target.get("state"))}
            self.check(target, manifest)
            encoded = r["original_active"] if r["phase"] == "ROLLED_BACK" else r["candidate_active"]
            expected = None if encoded is None else base64.b64decode(encoded)
            if self.store.active_bytes() != expected:
                raise TransactionError("MANUAL_RECOVERY: completed metadata drift")
            return r["phase"]
        if r["phase"] == "COMMITTED":
            # Commit is authoritative. Finish candidate, never revert only SCM.
            validate(Path(r["target"]["image"]).parent, r["manifest"])
            obs = self.observation()
            if obs["presence"] == "ABSENT" and r["original"]["presence"] == "ABSENT":
                self.backend.create(r["target"]["config"])
            elif obs["presence"] == "PRESENT" and same_config(obs["config"], r["original"].get("config")):
                self.stop()
                self.backend.set_path(r["target"]["config"]["binpath"])
            obs = self.observation()
            if obs["presence"] != "PRESENT" or not same_config(obs["config"], r["target"]["config"]):
                raise TransactionError("MANUAL_RECOVERY: committed configuration drift")
            if r["target"]["state"] == "RUNNING" and obs["state"] == "STOPPED":
                self.backend.start()
            elif r["target"]["state"] == "STOPPED":
                self.stop()
            self.store.restore_active(r["candidate_active"])
            self.check(r["target"])
            self.phase(r, "COMPLETE")
            return "COMPLETE"
        if r["phase"] not in ("PREPARING", "STAGED", "PREPARED", "STOPPED", "CONFIGURED", "ACTIVATED", "ROLLING_BACK"):
            raise TransactionError("MANUAL_RECOVERY: unknown transaction phase")
        previous_phase = r["phase"]
        self.phase(r, "ROLLING_BACK")
        original = r["original"]
        if r.get("original_manifest"):
            validate(Path(original["image"]).parent, r["original_manifest"])
        if previous_phase in ("PREPARING", "STAGED", "PREPARED"):
            try:
                self.check(original, r.get("original_manifest"))
                expected = None if r["original_active"] is None else base64.b64decode(r["original_active"])
                if self.store.active_bytes() != expected:
                    raise TransactionError("unmutated transaction metadata drift")
            except TransactionError:
                # A crash may occur after a mutation and before the next
                # checkpoint. Reconcile the observed state, not the phase alone.
                pass
            else:
                self.phase(r, "ROLLED_BACK")
                return "ROLLED_BACK"
        observed = self.observation()
        if observed["presence"] == "PRESENT" and not any(
            same_config(observed["config"], known.get("config"))
            for known in (original, r["target"]) if known["presence"] == "PRESENT"
        ):
            raise TransactionError("MANUAL_RECOVERY: unexpected service configuration; refusing to stop it")
        self.stop()
        obs = self.observation()
        if original["presence"] == "ABSENT":
            if obs["presence"] == "PRESENT":
                # Do not delete an unrelated/replaced service object.
                if not same_config(obs["config"], r.get("target", {}).get("config")):
                    raise TransactionError("MANUAL_RECOVERY: unexpected service, refusing deletion")
                self.backend.delete()
        else:
            if obs["presence"] != "PRESENT":
                raise TransactionError("MANUAL_RECOVERY: original service object disappeared")
            self.backend.set_path(original["config"]["binpath"])
            if original["state"] == "RUNNING":
                self.backend.start()
        self.check(original, r.get("original_manifest"))
        self.store.restore_active(r["original_active"])
        self.check(original)
        expected = None if r["original_active"] is None else base64.b64decode(r["original_active"])
        if self.store.active_bytes() != expected:
            raise TransactionError("original metadata not restored")
        self.phase(r, "ROLLED_BACK")
        return "ROLLED_BACK"

    def run(self, payload, manifest, prepare=None):
        self.root.mkdir(parents=True, exist_ok=True)
        with Owner(self.root):
            self.backend.protect(self.root)
            self.reconcile()
            original = self.observation()
            self.backend.supported(original)
            if original["presence"] == "PRESENT":
                # Capture the actual complete installed payload without renaming it.
                original["image"] = self.backend.executable(original["config"])
                previous = self.store.read()
                old_manifest = None
                if previous:
                    if previous["phase"] == "COMPLETE" and previous["target"]["image"] == original["image"]:
                        old_manifest = previous["manifest"]
                    elif previous["phase"] == "ROLLED_BACK" and previous["original"].get("image") == original["image"]:
                        old_manifest = previous["original_manifest"]
                if old_manifest is None:
                    old_manifest = self.predecessor(original)
                self.check(original, old_manifest)
            else:
                old_manifest = None
            validate(payload, manifest)
            self.hook("PREFLIGHT")
            ident = uuid.uuid4().hex
            candidate = self.root / "versions" / digest(canonical(manifest))
            target = self.backend.target(original, candidate / "NivXForgeSensor.exe")
            old_active = self.store.active_bytes()
            if old_active is not None:
                try:
                    meta = json.loads(old_active)
                    if not set(meta) <= {"service_exe", "version_dir", "previous_version_dir", "activated_at", "build", "transaction"}:
                        raise ValueError("unsupported active metadata schema")
                    if "build" in meta and not set(meta["build"]) <= {"setup_version", "sensor_version", "build_commit", "build_time", "build_run_id"}:
                        raise ValueError("unsupported build metadata schema")
                    old_pointer = Path(meta["service_exe"]).resolve()
                    if original["presence"] != "PRESENT" or old_pointer != Path(original["image"]).resolve():
                        raise ValueError("pointer drift")
                except (ValueError, KeyError, TypeError) as ex:
                    raise TransactionError("MANUAL_RECOVERY: original active metadata and SCM disagree") from ex
            new_active = canonical({"service_exe": str(candidate / "NivXForgeSensor.exe"),
                                    "version_dir": str(candidate), "transaction": ident})
            r = {"schema": 1, "id": ident, "phase": "PREPARING", "original": original,
                 "state_root": str(self.backend.setup.sensor.STATE_DIR),
                 "original_manifest": old_manifest, "original_active": None if old_active is None else base64.b64encode(old_active).decode(),
                 "target": target, "manifest": manifest, "candidate": str(candidate),
                 "candidate_active": base64.b64encode(new_active).decode()}
            self.phase(r, "PREPARING")
            try:
                candidate.parent.mkdir(exist_ok=True)
                self.backend.protect(candidate.parent)
                if not candidate.exists():
                    staging = candidate.parent / (".staging-" + ident)
                    shutil.copytree(payload, staging, copy_function=durable_copy)
                    validate(staging, manifest)
                    for p in sorted((p for p in staging.rglob("*") if p.is_dir()), reverse=True):
                        directory_sync(p)
                    directory_sync(staging)
                    durable_replace(staging, candidate)
                else:
                    validate(candidate, manifest)
                self.backend.protect(candidate)
                self.phase(r, "STAGED")
                if prepare:
                    prepare()
                self.phase(r, "PREPARED")
                self.stop()
                self.phase(r, "STOPPED")
                if original["presence"] == "ABSENT":
                    self.backend.create(target["config"])
                else:
                    self.backend.set_path(target["config"]["binpath"])
                self.phase(r, "CONFIGURED")
                self.backend.start()
                self.check({**target, "state": "RUNNING"}, manifest)
                self.phase(r, "ACTIVATED")
                if target["state"] == "STOPPED":
                    self.stop()
                self.check(target)
                atomic_bytes(self.store.active, new_active)
                self.hook("AFTER_METADATA_REPLACE")
                self.phase(r, "COMMITTED")
                self.check(target)
                self.phase(r, "COMPLETE")
                return "COMPLETE"
            except BaseException:
                try:
                    outcome = self.reconcile()
                    print("RECOVERY STATUS: " + str(outcome))
                except BaseException as ex:
                    raise TransactionError("MANUAL_RECOVERY: preserve transaction and payloads; " + str(ex)) from ex
                if outcome == "COMPLETE":
                    return "COMPLETE"
                raise


class WindowsBackend:
    def __init__(self, setup, api, interval):
        self.setup, self.api, self.interval = setup, api, interval

    def call(self, action, **data):
        prefix = [sys.executable]
        if not getattr(sys, "frozen", False):
            prefix.append(str(Path(self.setup.__file__).resolve()))
        if os.name != "nt":
            raise TransactionError("Windows adapter requires Windows")
        operation = None
        request = {"action": action, "service": self.setup.SERVICE_NAME, **data}
        budget = int(data.pop("budget", 0) or 0) if action in ("stop", "start") else 0
        if budget:
            request["budget"] = budget
        if action in ("stop", "start", "create", "set_path", "delete"):
            directory = self.setup.INSTALL_DIR / "operations"
            directory.mkdir(exist_ok=True)
            operation = Store(directory)
            operation.record = directory / (uuid.uuid4().hex + ".json")
            operation.write({"schema": 1, "state": "REQUESTED", "action": action,
                             "service": self.setup.SERVICE_NAME,
                             "binpath": data.get("binpath"), "history": []})
            request["operation_file"] = str(operation.record)
        import win32api
        import win32job
        # Do not release a mutation request until the worker belongs to a
        # kill-on-parent-close job. Parent death cannot leave a worker writing
        # SCM after the next installer acquires the abandoned mutex.
        job = win32job.CreateJobObject(None, None)
        info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
        process = None
        try:
            process = subprocess.Popen(prefix + ["--transaction-scm-worker"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            handle = win32api.OpenProcess(0x101, False, process.pid)
            try:
                win32job.AssignProcessToJobObject(job, handle)
            finally:
                handle.Close()
            if operation is not None:
                # Recorded BEFORE the request is released, so a later
                # reconciliation can tell "worker still in flight" from
                # "worker gone and the SCM is now the ground truth". The
                # token is the process creation time, so a reused pid is a
                # different process rather than this worker.
                token, status = query_process(process.pid)
                operation.amend("REQUESTED", worker_pid=process.pid,
                                worker_token=token,
                                worker_identity=status)
            stdout, _ = process.communicate(json.dumps(request),
                                            timeout=(budget or 25) + 10)
            if process.returncode:
                raise TransactionError("bounded Windows worker failed; inspect local diagnostics")
        finally:
            job.Close()
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
        value = json.loads(stdout)
        if value.get("error") and action != "observe":
            raise TransactionError("Windows operation failed: " + str(value["error"]))
        return value

    def operations(self):
        directory = self.setup.INSTALL_DIR / "operations"
        if not directory.exists():
            return []
        found = []
        for path in sorted(directory.glob("*.json")):
            store = Store(directory)
            store.record = path
            found.append((path, store, store.read()))
        return found

    def stable_observation(self, path, record, store):
        """Two agreeing FINAL observations, or no settlement at all."""
        first = self.observe()
        if not final_observation(first):
            store.amend("UNCERTAIN", observation=first.get("presence"),
                        scm_state=first.get("state"),
                        reason=str(first.get("reason", "not final")))
            raise TransactionError(
                "MANUAL_RECOVERY: SCM operation " + path.name + " ("
                + str(record.get("action")) + ") cannot be settled because "
                "the service is " + str(first.get("state")
                                        or first.get("presence"))
                + ", which is not a final state. The record and every "
                "payload are preserved. Re-run `recover-transaction` once "
                "the service has settled, or record a verified operator "
                "acknowledgement with `resolve-operation --id " + path.stem
                + " --expect-state <RUNNING|STOPPED|ABSENT>`.")
        time.sleep(OBSERVATION_SETTLE_SECONDS)
        second = self.observe()
        if not final_observation(second) \
                or observation_identity(first) != observation_identity(second):
            store.amend("UNCERTAIN", observation=second.get("presence"),
                        scm_state=second.get("state"), reason="unstable")
            raise TransactionError(
                "MANUAL_RECOVERY: the service did not hold still while SCM "
                "operation " + path.name + " was being settled (" 
                + str(first.get("state")) + " then "
                + str(second.get("state")) + "); a control delivered before "
                "the worker died may still be landing. Nothing was changed "
                "and no evidence was removed. Re-run `recover-transaction` "
                "once the service has settled.")
        return second

    def recovery_safe(self):
        """Settle unresolved SCM operations against the SCM itself.

        A record is settled only by PROOF: the requesting worker must be
        provably GONE (not merely unqueryable), and the SCM must hold the
        same FINAL state across two observations. Anything else — a live
        worker, an unknown worker, a pending state, an unreadable SCM, a
        service still moving — refuses and keeps the evidence.
        """
        for path, store, record in self.operations():
            if record is None:
                raise TransactionError(
                    "MANUAL_RECOVERY: unreadable SCM operation record "
                    + path.name + "; preserve evidence")
            if record.get("state") in SETTLED_OPERATIONS:
                continue
            liveness = worker_state(record)
            if liveness == "ALIVE":
                raise TransactionError(
                    "MANUAL_RECOVERY: SCM operation " + path.name + " ("
                    + str(record.get("action")) + ") is still in flight in "
                    "worker pid " + str(record.get("worker_pid"))
                    + "; refusing to reconcile underneath it")
            if liveness == "UNKNOWN":
                store.amend("UNCERTAIN", reason="worker liveness unknown",
                            worker_pid=record.get("worker_pid"))
                raise TransactionError(
                    "MANUAL_RECOVERY: whether the worker for SCM operation "
                    + path.name + " is still running could not be determined"
                    + (" (no identity was recorded for pid "
                       + str(record.get("worker_pid")) + ")"
                       if not record.get("worker_token")
                       else " (the process query failed)")
                    + ". A query that fails is not a terminated process, so "
                    "nothing was settled, nothing was changed and no "
                    "evidence was removed. Re-run `recover-transaction` from "
                    "an elevated prompt.")
            obs = self.stable_observation(path, record, store)
            outcome = operation_outcome(record, obs)
            if outcome is None:
                store.amend("UNCERTAIN", observation=obs.get("presence"),
                            reason="outcome not derivable")
                raise TransactionError(
                    "MANUAL_RECOVERY: SCM operation " + path.name + " ("
                    + str(record.get("action")) + ") cannot be settled from "
                    "the observed state. Evidence preserved.")
            store.amend("RESOLVED_BY_OBSERVATION", evidence=outcome)

    def resolve_operation(self, identity, expect_state):
        """Authenticated operator settlement of one uncertain operation.

        Authenticated by elevation, by the SYSTEM/Administrators-only DACL
        over the operations directory, and by the operator's claim being
        CHECKED against the live SCM rather than believed. A non-final
        state, an unreadable SCM or a disagreeing claim is refused:
        accepting an unproven state is the defect, not the remedy. The
        record is amended, never removed.
        """
        for path, store, record in self.operations():
            if path.stem != identity:
                continue
            if record is None:
                raise TransactionError("operation record " + identity
                                       + " is unreadable; preserve evidence")
            if record.get("state") in SETTLED_OPERATIONS:
                return record.get("state")
            liveness = worker_state(record)
            if liveness != "GONE":
                raise TransactionError(
                    "operation " + identity + ": the worker (pid "
                    + str(record.get("worker_pid")) + ") is " + liveness
                    + "; refusing to settle while it may still be writing "
                    "to the SCM. Nothing was changed.")
            obs = self.observe()
            presence = obs.get("presence")
            if presence not in ("PRESENT", "ABSENT"):
                raise TransactionError(
                    "refusing to settle " + identity + ": the SCM is "
                    + str(presence) + ", so no claim about it can be "
                    "verified. Nothing was changed.")
            if not final_observation(obs):
                raise TransactionError(
                    "refusing to settle " + identity + ": the service is "
                    + str(obs.get("state")) + ", which is not in a final "
                    "state, so no claim about it can be verified. Nothing "
                    "was changed.")
            observed = "ABSENT" if presence == "ABSENT" else obs.get("state")
            if observed != expect_state:
                raise TransactionError(
                    "refusing to settle " + identity + ": operator expected "
                    + str(expect_state) + " but the SCM reports "
                    + str(observed) + ". Nothing was changed.")
            store.amend("RESOLVED_BY_OPERATOR", expected=expect_state,
                        evidence=operation_outcome(record, obs)
                        or {"presence": presence, "state": observed,
                            "final": True})
            return "RESOLVED_BY_OPERATOR"
        raise TransactionError("no SCM operation record " + identity)

    def observe(self):
        try:
            return self.call("observe")
        except (OSError, subprocess.TimeoutExpired, ValueError, TransactionError) as ex:
            return {"presence": "UNREADABLE", "reason": type(ex).__name__}

    def supported(self, obs):
        if obs["presence"] == "ABSENT":
            return
        c = obs["config"]
        fields = {"type", "start", "error_control", "binpath", "argv", "group", "tag",
                  "dependencies", "account", "display", "description", "failure", "delayed",
                  "failure_flag", "sid_type", "privileges", "preshutdown", "security",
                  "trigger_count", "launch_protected", "security_safe"}
        if set(c) != fields or not c["security"] or not c["argv"]:
            raise TransactionError("incomplete or unsupported service configuration schema")
        if c["type"] != 16 or c["account"].casefold() != "localsystem" or c["start"] not in (2, 3):
            raise TransactionError("unsupported service type/account/startup; no service mutation")
        if c["security_safe"] is not True:
            raise TransactionError("unsafe or unverifiable service permissions")
        if c["error_control"] not in (0, 1, 2, 3) or c["sid_type"] not in (0, 1, 3):
            raise TransactionError("unknown service enum; no mutation")
        if c["group"] or c["tag"] or c["trigger_count"] or c["launch_protected"]:
            raise TransactionError("unsupported group/tag/trigger/protected service")
        f = c["failure"]
        if f.get("Command") or f.get("RebootMsg") or any(a[0] not in (0, 1) for a in f["Actions"]):
            raise TransactionError("unsupported command/reboot recovery actions")
        exe = Path(self.executable(c)).resolve()
        base = self.setup.INSTALL_DIR.resolve()
        legacy = exe.parent == base / "service"
        versioned = exe.parent.parent == base / "versions" and len(exe.parent.name) in (16, 64) and all(ch in "0123456789abcdef" for ch in exe.parent.name)
        if exe.name != "NivXForgeSensor.exe" or not exe.is_relative_to(base) or not (legacy or versioned):
            raise TransactionError("unsupported original image location")
        argv = c["argv"]
        expected = {"--backend": self.setup._assert_backend, "--interval": int, "--state-dir": Path}
        values = {}
        if len(argv) < 2 or argv[1] != "--service-run":
            raise TransactionError("unsupported original service arguments")
        tail = argv[2:]
        if len(tail) % 2:
            raise TransactionError("malformed service arguments")
        for k, v in zip(tail[::2], tail[1::2]):
            if k not in expected or k in values:
                raise TransactionError("unsupported/duplicate service argument")
            values[k] = expected[k](v)
        if set(values) != set(expected) or values["--state-dir"].resolve() != self.setup.sensor.STATE_DIR.resolve() or values["--interval"] <= 0:
            raise TransactionError("service arguments do not match protected state root")

    def executable(self, config):
        return config["argv"][0]

    def previous_manifest(self):
        bundle = getattr(sys, "_MEIPASS", None)
        if not bundle:
            return None
        path = Path(bundle) / "previous-payload-manifest.json"
        return json.loads(path.read_text()) if path.is_file() else None

    def predecessors(self):
        """The predecessor builds this installer is AUTHENTICATED to replace.

        A single pinned predecessor manifest made the installer able to
        upgrade exactly one build, byte-for-byte, and refuse the whole
        existing estate. The policy is a LIST, carried inside the signed
        one-file artifact alongside the payload manifest, so its
        provenance is the artifact's own provenance; each entry still
        pins a complete path/size/SHA-256 set, so nothing unknown or
        modified is ever accepted. Breadth of policy, not weakness of
        verification.
        """
        bundle = getattr(sys, "_MEIPASS", None)
        entries = []
        policy = Path(bundle) / "predecessor-policy.json" if bundle else None
        if policy is not None and policy.is_file():
            document = json.loads(policy.read_text())
            if document.get("schema") != 1:
                raise TransactionError("unsupported predecessor policy schema")
            for entry in document["predecessors"]:
                manifest = entry["manifest"]
                if entry.get("id") != manifest_id(manifest):
                    raise TransactionError(
                        "predecessor policy entry id does not match its "
                        "pinned manifest; refusing an unauthenticated policy")
                entries.append({"id": entry["id"], "manifest": manifest,
                                "build": entry.get("build", "unidentified")})
        legacy = self.previous_manifest()
        if legacy and all(e["manifest"] != legacy for e in entries):
            entries.append({"id": manifest_id(legacy), "manifest": legacy,
                            "build": "paired-previous-build"})
        return entries

    def target(self, original, exe):
        if original["presence"] == "PRESENT":
            c = json.loads(json.dumps(original["config"]))
            argv = [str(exe), *c["argv"][1:]]
            c["argv"], c["binpath"] = argv, subprocess.list2cmdline(argv)
            state = original["state"]
        else:
            argv = [str(exe), "--service-run", "--backend", self.api, "--interval", str(self.interval), "--state-dir", str(self.setup.sensor.STATE_DIR)]
            c = self.call("defaults", argv=argv)["config"]
            state = "RUNNING"
        return {"presence": "PRESENT", "config": c, "state": state, "image": str(exe)}

    def protect(self, path):
        self.call("protect", path=str(path))

    def stop(self, budget=None): self.call("stop", budget=budget or STOP_BUDGET_FLOOR)
    def start(self, budget=None): self.call("start", budget=budget or STOP_BUDGET_FLOOR)
    def delete(self): self.call("delete")
    def set_path(self, path): self.call("set_path", binpath=path)
    def create(self, config): self.call("create", config=config)