"""Bounded-process Windows API adapter. Never import/run on non-Windows."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import time


#: Absolute ceiling on any single service transition, whatever the caller
#: asks for. The budget bounds a HEALTHY wait; this bounds a hostile one.
TRANSITION_CEILING = 600
#: The only two states the SCM reports that are FINAL. Everything else —
#: START_PENDING(2), STOP_PENDING(3), CONTINUE_PENDING(5), PAUSE_PENDING(6)
#: — is a transition in progress and proves nothing about an operation.
FINAL_STATES = {1: "STOPPED", 4: "RUNNING"}


class TransitionTimeout(OSError):
    """A service transition that did not complete inside its budget.

    Carries WHY, because "stalled with no progress at all" and "still
    making progress when the deadline arrived" are different operational
    facts and the operator needs to be told which one happened.
    """

    def __init__(self, message, classification, checkpoints, waited, state):
        super().__init__(message)
        self.classification = classification
        self.checkpoints = checkpoints
        self.waited = waited
        self.state = state


def wait_for_state(query, target, budget, now=time.monotonic,
                   sleep=time.sleep):
    """Wait for a service to actually REACH `target`.

    `ControlService` returns when a control is DELIVERED, not when the
    transition has completed, so completion is only ever what the SCM
    reports. The total deadline is therefore the single authority here.

    CheckPoint and WaitHint are recorded for diagnosis and are NOT allowed
    to end the wait early. The NivXForge sensor's `SvcStop()` reports
    STOP_PENDING with waitHint=20000 exactly ONCE, sets its stop event and
    returns; it never advances CheckPoint again, and then finishes the
    current collection and delivery cycle before `SvcRun`'s finally
    reports SERVICE_STOPPED. With `--interval 30` that is routinely longer
    than the single declared hint. Treating a stagnant CheckPoint as a
    hang therefore aborted a perfectly healthy stop at 20s against a
    budget that was nowhere near exhausted — and Windows permits a service
    to never advance CheckPoint at all, so stagnation is not evidence of
    anything.
    """
    deadline = now() + min(int(budget), TRANSITION_CEILING)
    status = query()
    seen = {status.get("CheckPoint")}
    started = now()
    while status["CurrentState"] != target:
        if status["CurrentState"] in FINAL_STATES:
            # Settled on the WRONG final state: waiting longer cannot help.
            raise TransitionTimeout(
                "service reached %s, not the requested state"
                % FINAL_STATES[status["CurrentState"]],
                "FINAL_NOT_TARGET", len(seen), now() - started,
                FINAL_STATES[status["CurrentState"]])
        if now() >= deadline:
            classification = ("STALLED_NO_PROGRESS" if len(seen) <= 1
                              else "PENDING_AT_DEADLINE")
            raise TransitionTimeout(
                "service transition did not complete within %ds (%s, "
                "%d checkpoint value(s) observed, last WaitHint %dms); the "
                "operation outcome is UNKNOWN and must be reconciled, not "
                "assumed" % (int(now() - started), classification, len(seen),
                             int(status.get("WaitHint") or 0)),
                classification, len(seen), now() - started, "PENDING")
        sleep(.2)
        status = query()
        seen.add(status.get("CheckPoint"))
    return status


def argv_windows(command):
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    count = ctypes.c_int()
    values = shell.CommandLineToArgvW(command, ctypes.byref(count))
    if not values:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return [values[i] for i in range(count.value)]
    finally:
        kernel.LocalFree(values)


def live_image(pid):
    if not pid:
        return None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        return buf.value if kernel.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)) else None
    finally:
        kernel.CloseHandle(handle)


def extra_native(handle, level):
    """Query DWORD config levels not exposed by pywin32 (triggers/protection)."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    fn = adv.QueryServiceConfig2W
    fn.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    fn.restype = wintypes.BOOL
    size = wintypes.DWORD()
    fn(int(handle), level, None, 0, ctypes.byref(size))
    if not size.value or size.value > 1024 * 1024:
        raise OSError("unsupported/unreadable extended service configuration")
    buf = ctypes.create_string_buffer(size.value)
    if not fn(int(handle), level, buf, size.value, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value


def protect(path):
    import win32security as sec
    import ntsecuritycon as con
    path = Path(path)
    # Validate existing ancestry before creating anything through a junction.
    for p in (path, *path.parents):
        if p.exists() and p.lstat().st_file_attributes & 1024:
            raise OSError("reparse point in protected path")
    path.mkdir(parents=True, exist_ok=True)
    volume = ctypes.create_unicode_buffer(32768)
    fs = ctypes.create_unicode_buffer(256)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    k.GetVolumeInformationW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    k.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    if not k.GetVolumePathNameW(str(path), volume, len(volume)) or not k.GetVolumeInformationW(volume.value, None, 0, None, None, None, fs, len(fs)) or fs.value != "NTFS" or k.GetDriveTypeW(volume.value) != 3:
        raise OSError("protected transaction storage must be local NTFS")
    admins = sec.CreateWellKnownSid(sec.WinBuiltinAdministratorsSid, None)
    system = sec.CreateWellKnownSid(sec.WinLocalSystemSid, None)
    import win32api
    token = sec.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        issuer = sec.GetTokenInformation(token, sec.TokenUser)[0]
    finally:
        token.Close()
    trusted_owners = {str(admins), str(system), str(issuer)}
    nodes = (path, *path.rglob("*"))
    # Never take ownership of an untrusted user's tree or follow hard links.
    # Validate the whole tree before changing any descriptor.
    unsafe_write = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000
    anchors = [Path(os.environ[k]) for k in ("ProgramFiles", "ProgramData") if os.environ.get(k)]
    anchor = next((a for a in anchors if path.is_relative_to(a) and path != a), None)
    if anchor is None:
        raise OSError("protected path must be below a Windows installation/state anchor")
    parents = []
    for parent in path.parents:
        if parent == anchor:
            break
        parents.append(parent)
    for p in (*parents, *nodes):
        st = p.lstat()
        if st.st_file_attributes & 1024 or (p.is_file() and st.st_nlink != 1):
            raise OSError("reparse point/hard link in protected tree")
        sd = sec.GetNamedSecurityInfo(str(p), sec.SE_FILE_OBJECT, 7)
        dacl = sd.GetSecurityDescriptorDacl()
        if str(sd.GetSecurityDescriptorOwner()) not in trusted_owners or dacl is None:
            raise OSError("untrusted preexisting owner/NULL DACL; refuse before taking ownership")
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            if ace[0][0] == 0 and not (ace[0][1] & 8) and str(ace[-1]) not in trusted_owners and ace[1] & unsafe_write:
                raise OSError("untrusted principal can mutate preexisting state; manual remediation required")
    acl = sec.ACL()
    for sid in (system, admins):
        acl.AddAccessAllowedAceEx(sec.ACL_REVISION_DS, 3, con.FILE_ALL_ACCESS, sid)
    allowed = {str(admins), str(system)}
    for p in nodes:
        if p.lstat().st_file_attributes & 1024:
            raise OSError("reparse point in protected tree")
        sec.SetNamedSecurityInfo(str(p), sec.SE_FILE_OBJECT,
                                sec.OWNER_SECURITY_INFORMATION | sec.GROUP_SECURITY_INFORMATION |
                                sec.DACL_SECURITY_INFORMATION | sec.PROTECTED_DACL_SECURITY_INFORMATION,
                                admins, admins, acl, None)
        sd = sec.GetNamedSecurityInfo(str(p), sec.SE_FILE_OBJECT, 7)
        dacl = sd.GetSecurityDescriptorDacl()
        if str(sd.GetSecurityDescriptorOwner()) not in allowed or dacl is None:
            raise OSError("untrusted owner or NULL DACL")
        rights = set()
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            if ace[0][0] != 0 or str(ace[-1]) not in allowed:
                raise OSError("unexpected ACL principal/type; manual remediation required")
            if ace[1] & con.FILE_ALL_ACCESS == con.FILE_ALL_ACCESS:
                rights.add(str(ace[-1]))
        if rights != allowed:
            raise OSError("SYSTEM/Administrators full access not proved")
    return {"protected": True}


def main(request):
    if os.name != "nt":
        raise OSError("Windows SCM adapter requires Windows")
    import win32service as svc
    import win32security as sec
    action, name = request["action"], request["service"]
    # Only this installer's service; no generic remote service-management API.
    if name != "NivXForgeSensor":
        raise OSError("unsupported service namespace")
    if action == "protect":
        return protect(request["path"])
    security = "O:BAG:BAD:P(A;;0xf01ff;;;SY)(A;;0xf01ff;;;BA)"
    sd = sec.ConvertStringSecurityDescriptorToSecurityDescriptor(security, 1)
    security = sec.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, 7)
    levels = {"description": 1, "failure": 2, "delayed": 3, "failure_flag": 4,
              "sid_type": 5, "privileges": 6, "preshutdown": 7}
    if action == "defaults":
        argv = request["argv"]
        return {"config": {"type": 16, "start": 2, "error_control": 1,
                "binpath": subprocess.list2cmdline(argv), "argv": argv,
                "group": "", "tag": 0, "dependencies": [], "account": "LocalSystem",
                "display": "NivXForge EDR Sensor", "description": "NivXForge endpoint sensor",
                "failure": {"ResetPeriod": 86400, "RebootMsg": "", "Command": "", "Actions": [[1,60000]] * 3},
                "delayed": False, "failure_flag": False, "sid_type": 0,
                "privileges": [], "preshutdown": 180000, "security": security, "security_safe": True,
                "trigger_count": 0, "launch_protected": 0}}
    manager = svc.OpenSCManager(None, None, svc.SC_MANAGER_CONNECT | (svc.SC_MANAGER_CREATE_SERVICE if action == "create" else 0))
    handle = None
    try:
        if action == "create":
            c = request["config"]
            handle = svc.CreateService(manager, name, c["display"], svc.SERVICE_ALL_ACCESS,
                c["type"], c["start"], c["error_control"], c["binpath"], None, 0,
                c["dependencies"], c["account"], None)
            for key, level in levels.items():
                value = c[key]
                if key == "failure":
                    value = {**value, "Actions": tuple(tuple(a) for a in value["Actions"])}
                svc.ChangeServiceConfig2(handle, level, value)
            svc.SetServiceObjectSecurity(handle, 7 | sec.PROTECTED_DACL_SECURITY_INFORMATION,
                                        sec.ConvertStringSecurityDescriptorToSecurityDescriptor(c["security"], 1))
            return {"ok": True}
        try:
            access = svc.SERVICE_QUERY_CONFIG | svc.SERVICE_QUERY_STATUS | 0x20000
            access |= {"stop": svc.SERVICE_STOP, "start": svc.SERVICE_START,
                       "set_path": svc.SERVICE_CHANGE_CONFIG, "delete": 0x10000}.get(action, 0)
            handle = svc.OpenService(manager, name, access)
        except svc.error as ex:
            if action == "observe" and ex.winerror == 1060:
                return {"presence": "ABSENT", "error": 1060}
            raise
        if action == "observe":
            status = svc.QueryServiceStatusEx(handle)
            deadline = time.monotonic() + 20
            while status["CurrentState"] in (2, 3, 5, 6) and time.monotonic() < deadline:
                time.sleep(.2)
                status = svc.QueryServiceStatusEx(handle)
            base = svc.QueryServiceConfig(handle)
            keys = ("type", "start", "error_control", "binpath", "group", "tag", "dependencies", "account", "display")
            c = dict(zip(keys, base))
            c["group"] = c["group"] or ""
            c["dependencies"] = list(c["dependencies"] or [])
            c["argv"] = argv_windows(c["binpath"])
            for key, level in levels.items():
                c[key] = svc.QueryServiceConfig2(handle, level)
            c["description"] = c["description"] or ""
            c["privileges"] = list(c["privileges"] or [])
            c["failure"]["Command"] = c["failure"].get("Command") or ""
            c["failure"]["RebootMsg"] = c["failure"].get("RebootMsg") or ""
            c["trigger_count"] = extra_native(handle, 8)
            c["launch_protected"] = extra_native(handle, 12)
            descriptor = svc.QueryServiceObjectSecurity(handle, 7)
            c["security"] = sec.ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1, 7)
            import win32api
            token = sec.OpenProcessToken(win32api.GetCurrentProcess(), 8)
            try:
                issuer = sec.GetTokenInformation(token, sec.TokenUser)[0]
            finally:
                token.Close()
            trusted = {str(sec.CreateWellKnownSid(sec.WinLocalSystemSid, None)),
                       str(sec.CreateWellKnownSid(sec.WinBuiltinAdministratorsSid, None)), str(issuer)}
            acl = descriptor.GetSecurityDescriptorDacl()
            safe = acl is not None and str(descriptor.GetSecurityDescriptorOwner()) in trusted
            if acl is not None:
                for i in range(acl.GetAceCount()):
                    ace = acl.GetAce(i)
                    if ace[0][0] not in (0, 1) or (ace[0][0] == 0 and str(ace[-1]) not in trusted and ace[1] & 0x500d0172):
                        safe = False
            c["security_safe"] = safe
            state = {1: "STOPPED", 4: "RUNNING"}.get(status["CurrentState"], "PENDING")
            pid = status["ProcessId"]
            return {"presence": "PRESENT", "state": state, "pid": pid,
                    "image": live_image(pid), "config": c}
        if action == "set_path":
            svc.ChangeServiceConfig(handle, svc.SERVICE_NO_CHANGE, svc.SERVICE_NO_CHANGE,
                                    svc.SERVICE_NO_CHANGE, request["binpath"], None, 0, None, None, None, None)
        elif action in ("start", "stop"):
            target = 4 if action == "start" else 1
            if svc.QueryServiceStatusEx(handle)["CurrentState"] != target:
                if action == "start": svc.StartService(handle, None)
                else: svc.ControlService(handle, svc.SERVICE_CONTROL_STOP)
            # The control is now DELIVERED. Completion is whatever the SCM
            # reports, inside the caller's budget; see wait_for_state.
            wait_for_state(lambda: svc.QueryServiceStatusEx(handle), target,
                           request.get("budget") or 60)
        elif action == "delete":
            svc.DeleteService(handle)
        else:
            raise OSError("unknown installer SCM operation")
        return {"ok": True}
    finally:
        if handle is not None: svc.CloseServiceHandle(handle)
        svc.CloseServiceHandle(manager)


def entry():
    import sys
    request = None
    try:
        request = json.load(sys.stdin)
        value = main(request)
    except Exception as ex:
        value = {"presence": "UNREADABLE", "error": getattr(ex, "winerror", None) or type(ex).__name__, "reason": str(ex)[:300]}
    if request and request.get("operation_file"):
        try:
            from nivxforge_transaction import Store
            path = Path(request["operation_file"])
            expected = Path(os.environ["ProgramFiles"]) / "NivXForge/sensor/operations"
            if path.parent.resolve() != expected.resolve() or len(path.stem) != 32 or not all(c in "0123456789abcdef" for c in path.stem):
                raise ValueError("unexpected operation acknowledgement path")
            store = Store(path.parent)
            store.record = path
            record = store.read()
            if record["action"] != request["action"] or record["state"] != "REQUESTED":
                raise ValueError("operation identity mismatch")
            store.write({**record, "state": "FINISHED" if value.get("ok") is True else "UNCERTAIN"})
        except Exception:
            value = {"presence": "UNREADABLE", "error": "ACK_FAILED", "reason": "preserve operation intent; do not infer RPC cancellation"}
    print(json.dumps(value))
