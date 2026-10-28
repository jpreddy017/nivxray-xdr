"""G4-A1 regression: default Windows ACLs vs protected M1 bootstrap root.

Portable tests exercise production ACL verdicts with a small effective-access
double; the native Windows test reads real ACLs and never mutates them.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] /
                       "agents" / "nivxforge-windows"))

from nivxforge_m1 import (  # noqa: E402
    ACCESS_ALLOWED_ACE_TYPE, DANGEROUS_ANCESTOR_RIGHTS,
    DANGEROUS_OWNED_RIGHTS, FILE_APPEND_DATA, FILE_DELETE_CHILD,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    FILE_GENERIC_MAPPING, FILE_ALL_ACCESS, GENERIC_ALL, INHERIT_ONLY_ACE, M1Error,
    PATH_DIRECTORY, PATH_FILE, REQUIRED_CONTEXT_SIDS, ROLE_ANCESTOR,
    ROLE_OWNED, SID_LOCAL_SYSTEM, SID_TRUSTED_INSTALLER, WindowsHost,
    WRITE_DAC, WRITE_OWNER, DELETE, filesystem_ace_inspection,
    filesystem_token_verdict, load_config, map_generic, path_security_verdict,
    normalise_descriptor, descriptor_to_sddl, SE_DACL_PRESENT, SE_DACL_PROTECTED,
)

USERS = "S-1-5-32-545"
AUTH = "S-1-5-11"


def allow(mask, sid=USERS, flags=0):
    return {"type": ACCESS_ALLOWED_ACE_TYPE, "sid": sid,
            "mask": mask, "flags": flags}


def descriptor(*aces, owner=SID_LOCAL_SYSTEM, protected=True):
    return {"owner": owner, "group": SID_LOCAL_SYSTEM, "dacl": list(aces),
            "dacl_present": True, "protected": protected}


class FakeEffectiveAccess:
    def __init__(self, unknown=False):
        self.unknown = unknown

    def access_context(self):
        return {"sids": REQUIRED_CONTEXT_SIDS, "token": "simulated"}

    def access_check(self, desc, context, right, mapping):
        if self.unknown:
            return None
        for ace in desc.get("dacl") or []:
            if ace.get("type") != ACCESS_ALLOWED_ACE_TYPE:
                continue
            if ace.get("flags", 0) & INHERIT_ONLY_ACE:
                continue
            if ace.get("sid") in context["sids"]:
                if map_generic(ace["mask"], mapping) & right:
                    return True
        return False


def verdict(desc, role=ROLE_ANCESTOR, *, unknown=False):
    return path_security_verdict(desc, role, FakeEffectiveAccess(unknown))


def test_rights_separation_is_explicit():
    assert set(DANGEROUS_ANCESTOR_RIGHTS) == {
        "FILE_DELETE_CHILD", "DELETE", "WRITE_DAC", "WRITE_OWNER"}
    assert set(DANGEROUS_OWNED_RIGHTS) == {
        "FILE_WRITE_DATA", "FILE_APPEND_DATA", "FILE_WRITE_EA",
        "FILE_WRITE_ATTRIBUTES", "FILE_DELETE_CHILD",
        "DELETE", "WRITE_DAC", "WRITE_OWNER"}


def test_programdata_default_ancestor_is_safe_but_unsafe_when_owned():
    # Users:(CI)(WD,AD,WEA,WA) is Windows' standard ProgramData permission.
    mask = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
    desc = descriptor(allow(mask, flags=0x02))
    assert filesystem_ace_inspection(desc, ROLE_ANCESTOR) == []
    assert filesystem_token_verdict(desc, ROLE_ANCESTOR, FakeEffectiveAccess()) == []
    assert verdict(desc)["nonadmin_writable"] is False
    assert verdict(desc, ROLE_OWNED)["nonadmin_writable"] is True




def test_programfiles_trustedinstaller_full_access_is_ancestor_only():
    """Stock Program Files grants TI Full Control and Users only RX.

    The trust exception must never leak to the stricter owned-root role.
    CREATOR OWNER's inherit-only Full Control is not effective on this root.
    """
    desc = descriptor(
        allow(FILE_ALL_ACCESS, sid=SID_TRUSTED_INSTALLER),
        allow(GENERIC_ALL, sid=SID_TRUSTED_INSTALLER,
              flags=INHERIT_ONLY_ACE),
        allow(GENERIC_ALL, sid="S-1-3-0", flags=INHERIT_ONLY_ACE),
        allow(0x001200A9, sid=USERS),
        owner=SID_TRUSTED_INSTALLER,
    )
    assert filesystem_ace_inspection(desc, ROLE_ANCESTOR) == []
    assert filesystem_token_verdict(desc, ROLE_ANCESTOR,
                                    FakeEffectiveAccess()) == []
    assert not verdict(desc)["nonadmin_writable"]
    assert verdict(desc, ROLE_OWNED)["nonadmin_writable"]


def test_untrusted_windows_service_sid_still_refused_as_ancestor():
    desc = descriptor(allow(GENERIC_ALL, sid="S-1-5-80-1-2-3-4-5"),
                      owner=SID_TRUSTED_INSTALLER)
    result = verdict(desc, ROLE_ANCESTOR)
    assert result["nonadmin_writable"]
    assert "is allowed" in str(result["problems"])


@pytest.mark.parametrize("mask", [
    FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL])
def test_programfiles_users_dangerous_grants_remain_refused(mask):
    desc = descriptor(
        allow(FILE_ALL_ACCESS, sid=SID_TRUSTED_INSTALLER),
        allow(mask, sid=USERS),
        owner=SID_TRUSTED_INSTALLER,
    )
    assert verdict(desc, ROLE_ANCESTOR)["nonadmin_writable"]


def test_drive_root_inherit_only_modify_is_not_effective_on_root():
    desc = descriptor(
        allow(FILE_APPEND_DATA | FILE_WRITE_DATA, sid=AUTH),
        allow(GENERIC_ALL, sid=AUTH, flags=INHERIT_ONLY_ACE),
        owner=SID_TRUSTED_INSTALLER)
    assert filesystem_ace_inspection(desc, ROLE_ANCESTOR) == []
    assert filesystem_token_verdict(desc, ROLE_ANCESTOR, FakeEffectiveAccess()) == []
    assert verdict(desc)["nonadmin_writable"] is False


@pytest.mark.parametrize("mask", [
    FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL])
def test_ancestor_still_rejects_delete_and_security_control(mask):
    assert verdict(descriptor(allow(mask)))["nonadmin_writable"] is True


@pytest.mark.parametrize("mask", [
    FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA,
    FILE_WRITE_ATTRIBUTES, FILE_DELETE_CHILD, DELETE,
    WRITE_DAC, WRITE_OWNER, GENERIC_ALL])
def test_owned_bootstrap_refuses_nonadmin_mutation(mask):
    assert verdict(descriptor(allow(mask)), ROLE_OWNED)["nonadmin_writable"] is True


def test_owned_root_rejects_inheritance_and_untrusted_owner():
    assert verdict(descriptor(protected=False), ROLE_OWNED)["nonadmin_writable"]
    assert verdict(descriptor(owner="S-1-5-21-1-2-3-1001"),
                   ROLE_OWNED)["nonadmin_writable"]


def test_unknown_acl_probe_fails_closed():
    assert verdict(descriptor(), unknown=True)["nonadmin_writable"]


def test_null_dacl_and_unsupported_ace_fail_closed():
    desc = {"owner": SID_LOCAL_SYSTEM, "group": SID_LOCAL_SYSTEM,
            "dacl": None, "dacl_present": True}
    assert verdict(desc)["nonadmin_writable"]
    assert verdict(descriptor({"type": 5, "sid": USERS,
                               "mask": None, "flags": 0}))["nonadmin_writable"]



class SignedAceDacl:
    """pywin32 GetAce can return a signed int for a Windows DWORD mask."""
    def __init__(self, flags):
        self.flags = flags

    def GetAceCount(self):
        return 1

    def GetAce(self, index):
        assert index == 0
        # 0xE0010000 as a signed 32-bit integer, as observed on native C:\.
        return ((ACCESS_ALLOWED_ACE_TYPE, self.flags), -536805376, AUTH)


@pytest.mark.parametrize("flags,unsafe", [
    (INHERIT_ONLY_ACE, False), (0, True)])
def test_windows_signed_generic_mask_is_parsed_without_losing_rights(flags, unsafe):
    desc = normalise_descriptor(
        SE_DACL_PRESENT | SE_DACL_PROTECTED,
        SID_LOCAL_SYSTEM, SID_LOCAL_SYSTEM, SignedAceDacl(flags), lambda sid: sid)
    assert desc["dacl"][0]["mask"] == 0xE0010000
    assert desc.get("malformed") is not True
    assert descriptor_to_sddl(desc, FILE_GENERIC_MAPPING) is not None
    assert verdict(desc)["nonadmin_writable"] is unsafe


class ConfigHost:
    """Mimics load_config in a safe read-only, no-token environment."""
    def __init__(self, path, root_acl):
        self.path = Path(path)
        self.root_acl = root_acl
        self.body = json.dumps({
            "origin": "https://example.test",
            "tenant_id": "ten_test",
            "state_dir": r"C:\ProgramData\NivXForgeM1State",
            "install_dir": r"C:\Program Files\NivXForgeM1",
            "service_exe": r"C:\Program Files\NivXForgeM1\NivXForgeSensor.exe",
            "service_args": ["--m1-service-run"],
            "certificate_policy": "windows-default",
        }).encode()

    def is_file(self, path):
        return Path(path) == self.path

    def path_ancestry(self, path):
        return [self.path.parent.parent.parent,
                self.path.parent.parent, self.path.parent, self.path]

    def path_state(self, path):
        return PATH_FILE if Path(path) == self.path else PATH_DIRECTORY

    def directory_security(self, path, role=ROLE_ANCESTOR):
        if Path(path) == self.path.parent and role == ROLE_OWNED:
            return self.root_acl
        return {"nonadmin_writable": False}

    def file_security(self, path):
        return {"nonadmin_writable": False}

    def read_bytes(self, path):
        return self.body


@pytest.mark.parametrize("root_acl", [None, {"nonadmin_writable": True}])
def test_load_config_refuses_unsafe_bootstrap_root(tmp_path, root_acl):
    path = tmp_path / "C" / "ProgramData" / "NivXForgeM1Bootstrap" / "m1-config.json"
    with pytest.raises(M1Error) as err:
        load_config(path, ConfigHost(path, root_acl))
    assert err.value.code == "CONFIG_ROOT_UNSAFE"


def test_load_config_accepts_protected_bootstrap_root(tmp_path):
    path = tmp_path / "C" / "ProgramData" / "NivXForgeM1Bootstrap" / "m1-config.json"
    config = load_config(path, ConfigHost(path, {"nonadmin_writable": False}))
    assert config.tenant_id == "ten_test"


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACLs required")
def test_native_windows_ancestor_security_read_only():
    host = WindowsHost()
    drive = os.environ.get("SystemDrive", "C:")
    root = Path(drive + "\\")
    programdata = Path(os.environ.get("ProgramData", drive + r"\ProgramData"))
    for path in (root, programdata):
        report = host.directory_security(path, role=ROLE_ANCESTOR)
        assert report is not None, "ACL UNKNOWN for {}".format(path)
        assert not report["nonadmin_writable"], (
            "Ancestor rejected {}: {}".format(path, report))


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACLs required")
def test_native_windows_programfiles_ancestor_read_only():
    """G4-A2: probe stock Program Files as an ancestor, never modify ACLs.

    The prior G4-A1 Windows CI covered C:\\ and C:\\ProgramData only.
    Report separately whether an observed refusal came from allow-ACE
    inspection or token-aware AccessCheck; both must still fail closed.
    """
    host = WindowsHost()
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    descriptor = host._read_path_descriptor(program_files)
    report = host.directory_security(program_files, role=ROLE_ANCESTOR)
    if report is None or report.get("nonadmin_writable"):
        ace = (filesystem_ace_inspection(descriptor, ROLE_ANCESTOR)
               if descriptor is not None else ["descriptor unreadable"])
        effective = (filesystem_token_verdict(descriptor, ROLE_ANCESTOR, host)
                     if descriptor is not None else ["descriptor unreadable"])
        pytest.fail(
            "G4-A2 read-only Program Files ancestor refusal: "
            f"path={program_files} report={report!r} "
            f"ace_problems={ace!r} effective_problems={effective!r}",
            pytrace=False,
        )
