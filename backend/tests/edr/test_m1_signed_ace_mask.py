"""Regression tests for G4 native Windows signed ACE-mask decoding.

Pure Python tests; no Windows privilege escalation or filesystem mutations.
Run with: python -m pytest backend/tests/edr/test_m1_signed_ace_mask.py -q
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

M1_PATH = Path(__file__).resolve().parents[3] / "agents" / "nivxforge-windows" / "nivxforge_m1.py"
SPEC = importlib.util.spec_from_file_location("nivxforge_m1_mask_under_test", M1_PATH)
m1 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m1)

TI = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
AU = "S-1-5-11"
SY = "S-1-5-18"
BA = "S-1-5-32-544"
BU = "S-1-5-32-545"
CAP = "S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176"


class StubACL:
    def __init__(self, entries):
        self.entries = entries

    def GetAceCount(self):
        return len(self.entries)

    def GetAce(self, i):
        return self.entries[i]


class DenyingNonAdminHost:
    def access_context(self):
        return {"sids": list(m1.REQUIRED_CONTEXT_SIDS)}

    def access_check(self, descriptor, context, bit, mapping):
        return False


def decode(entries):
    control = m1.SE_DACL_PRESENT | m1.SE_DACL_PROTECTED
    return m1.normalise_descriptor(control, TI, TI, StubACL(entries), lambda sid: sid)


def allow(sid, rawmask, flags=0):
    return ((m1.ACCESS_ALLOWED_ACE_TYPE, flags), rawmask, sid)


@pytest.mark.parametrize("raw, expected", [
    (-2147483648, 0x80000000),
    (-536805376, 0xE0010000),
    (-1, 0xFFFFFFFF),
    (0, 0),
    (4, 4),
    (0x7FFFFFFF, 0x7FFFFFFF),
    (0x80000000, 0x80000000),
    (0xE0010000, 0xE0010000),
    (0xFFFFFFFF, 0xFFFFFFFF),
])
def test_signed_dword_conversion(raw, expected):
    assert m1.normalise_access_mask(raw) == expected


@pytest.mark.parametrize("bad", [
    -(2**31) - 1, 2**32, None, True, False, "3758161920", 1.5, [],
])
def test_invalid_masks_refused(bad):
    assert m1.normalise_access_mask(bad) is None
    descriptor = decode([allow(AU, bad)])
    assert descriptor.get("malformed") is True
    assert m1.filesystem_ace_inspection(descriptor, m1.ROLE_ANCESTOR)


def test_real_g4_root_acl_inherit_only_signed_mask_passes():
    # From read-only G4-02 icacls/Get-Acl; no synthetic weakened ACL.
    desc = decode([
        allow(AU, 4),
        allow(AU, -536805376, flags=0x0B),
        allow(SY, 0x1F01FF, flags=0x03),
        allow(BA, 0x1F01FF, flags=0x03),
        allow(BU, 0x1200A9, flags=0x03),
        allow(CAP, 0x1000A1),
    ])
    assert "malformed" not in desc
    assert desc["dacl"][1]["mask"] == 0xE0010000
    assert m1.filesystem_ace_inspection(desc, m1.ROLE_ANCESTOR) == []
    sddl = m1.descriptor_to_sddl(desc, m1.FILE_GENERIC_MAPPING)
    assert sddl is not None
    assert "0xe0010000" not in sddl.lower()  # inherit-only ACE not effective
    verdict = m1.path_security_verdict(desc, m1.ROLE_ANCESTOR, DenyingNonAdminHost())
    assert verdict["problems"] == []
    assert verdict["nonadmin_writable"] is False


@pytest.mark.parametrize("rawmask", [
    -536805376, -1073741824, 0x40000000, -1
])
@pytest.mark.parametrize("role", [
    "ancestor", "file", "owned"
])
def test_dangerous_non_inherit_only_grants_still_refused(rawmask, role):
    desc = decode([allow(AU, rawmask)])
    verdict = m1.path_security_verdict(desc, role, DenyingNonAdminHost())
    assert verdict["nonadmin_writable"] is True
    assert verdict["problems"]


def test_indeterminate_token_access_still_refuses():
    class UnknownHost(DenyingNonAdminHost):
        def access_check(self, *args):
            return None

    desc = decode([allow(AU, 4)])
    verdict = m1.path_security_verdict(desc, m1.ROLE_ANCESTOR, UnknownHost())
    assert verdict["nonadmin_writable"] is True
    assert "indeterminate" in " ".join(verdict["problems"])


def test_incomplete_security_context_still_refuses():
    class MissingInteractiveHost(DenyingNonAdminHost):
        def access_context(self):
            return {"sids": [sid for sid in m1.REQUIRED_CONTEXT_SIDS if sid != "S-1-5-4"]}

    desc = decode([allow(AU, 4)])
    verdict = m1.path_security_verdict(desc, m1.ROLE_ANCESTOR, MissingInteractiveHost())
    assert verdict["nonadmin_writable"] is True
    assert "S-1-5-4" in " ".join(verdict["problems"])
