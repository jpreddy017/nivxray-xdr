"""P1-11 regression lock · Registry-key extractor no longer over-matches
Windows file paths.

Before this fix, `_RE_REGISTRY` accepted `\\USER[\\/]...` and
`\\USERS[\\/]...` as EDR-style hive roots without guarding against
the surrounding context. A drive-anchored path like

    drops C:\\Users\\Public\\payload.exe on host

therefore got extracted as `HKEY_USERS\\Public\\payload.exe on host`
— a registry key that never existed — and the file-path extractor
was blocked (the registry span had already been claimed).

The fix (in `services/ida/artifact_splitter.py`):
  · Negative lookbehind `(?<![\\w:.])` on the EDR-style alternative
    so `C:` and word chars cannot precede `\\HIVE`.
  · Trailing `\\b` on the hive-name capture so `\\User\\Public`
    (a file path fragment) never binds to the `USER` alternative,
    while `\\USERS\\Software\\...` still binds to `USERS`.
  · `USERS` listed BEFORE `USER` so the longer match wins.

This suite locks the fix so no future edit regresses it. Contract:
  · Legitimate registry keys (full, short, EDR-style) still extract.
  · Windows file paths never get mis-classified as registry keys.
  · Mixed prose surfaces BOTH kinds correctly.

Scope: no Verdict / CIO / Workspace changes — extractor correctness only.
"""
from __future__ import annotations

import pytest

from services.ida.artifact_splitter import split_artifacts


def _by_type(arts, kind):
    return [a for a in arts if a.type == kind]


# ══════════════════════════════════════════════════════════════════
# 1. Legitimate registry keys — MUST still extract
# ══════════════════════════════════════════════════════════════════
def test_full_hive_hklm_still_extracts():
    arts = split_artifacts(
        r"set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run for autostart")
    keys = _by_type(arts, "registry_key")
    assert len(keys) == 1
    assert keys[0].canonical.startswith("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\")


def test_full_hive_hkcu_still_extracts():
    arts = split_artifacts(
        r"Modifies HKEY_CURRENT_USER\Software\Foo\Bar for persistence")
    keys = _by_type(arts, "registry_key")
    assert len(keys) == 1
    assert keys[0].canonical.startswith("HKEY_CURRENT_USER\\Software\\Foo\\")


def test_full_hive_hkey_users_still_extracts():
    arts = split_artifacts(
        r"Modifies HKEY_USERS\S-1-5-21-XYZ\Software\Adobe for user config")
    keys = _by_type(arts, "registry_key")
    assert len(keys) == 1
    assert keys[0].canonical.startswith("HKEY_USERS\\S-1-5-21-XYZ\\")


@pytest.mark.parametrize("short,expanded", [
    ("HKLM", "HKEY_LOCAL_MACHINE"),
    ("HKCU", "HKEY_CURRENT_USER"),
    ("HKCR", "HKEY_CLASSES_ROOT"),
    ("HKU",  "HKEY_USERS"),
    ("HKCC", "HKEY_CURRENT_CONFIG"),
])
def test_short_hive_forms_still_extract(short, expanded):
    arts = split_artifacts(f"set {short}\\Software\\Foo\\Bar to X")
    keys = _by_type(arts, "registry_key")
    assert len(keys) == 1
    assert keys[0].canonical.startswith(f"{expanded}\\Software\\Foo\\")


def test_edr_style_machine_still_extracts():
    arts = split_artifacts(
        r"Registry: \MACHINE\SOFTWARE\Microsoft\Cryptography\Providers")
    keys = _by_type(arts, "registry_key")
    assert len(keys) == 1
    assert keys[0].canonical.startswith("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\")


def test_edr_style_users_still_extracts():
    arts = split_artifacts(r"Key: \USERS\S-1-5-21\Software\X")
    keys = _by_type(arts, "registry_key")
    assert len(keys) == 1
    assert keys[0].canonical.startswith("HKEY_USERS\\S-1-5-21\\Software\\")


# ══════════════════════════════════════════════════════════════════
# 2. Windows file paths — MUST NOT be mis-classified as registry keys
# ══════════════════════════════════════════════════════════════════
def test_users_public_path_is_file_path_not_registry():
    arts = split_artifacts(r"drops C:\Users\Public\payload.exe on host")
    keys  = _by_type(arts, "registry_key")
    paths = _by_type(arts, "file_path")
    assert keys == [], f"unexpected registry hit: {[k.canonical for k in keys]}"
    assert len(paths) == 1
    assert paths[0].canonical.endswith("payload.exe")


def test_users_appdata_path_is_file_path_not_registry():
    arts = split_artifacts(
        r"copies C:\Users\Bob\AppData\Roaming\evil.dll to memory")
    assert _by_type(arts, "registry_key") == []
    paths = _by_type(arts, "file_path")
    assert len(paths) == 1
    assert paths[0].canonical.endswith("evil.dll")


def test_deep_users_profile_path_not_registry():
    arts = split_artifacts(
        r"writes C:\Users\Administrator\Desktop\notes.txt on logon")
    assert _by_type(arts, "registry_key") == []
    paths = _by_type(arts, "file_path")
    assert len(paths) == 1


def test_programfiles_path_not_registry():
    arts = split_artifacts(r"reads C:\Program Files\Vendor\bin\tool.exe today")
    assert _by_type(arts, "registry_key") == []
    # NB: file_path regex intentionally stops at whitespace, so the
    # extractor emits `C:\Program` — that's the current contract.
    paths = _by_type(arts, "file_path")
    assert len(paths) == 1
    assert paths[0].canonical.startswith("C:\\Program")


def test_unc_path_is_file_path_not_registry():
    arts = split_artifacts(r"copies \\host\share\evil.exe to disk")
    assert _by_type(arts, "registry_key") == []
    paths = _by_type(arts, "file_path")
    assert len(paths) == 1
    assert paths[0].canonical.endswith("evil.exe")


def test_env_var_prefixed_path_not_registry():
    arts = split_artifacts(r"drops %APPDATA%\Roaming\evil.dll from beacon")
    assert _by_type(arts, "registry_key") == []
    paths = _by_type(arts, "file_path")
    assert len(paths) == 1


def test_mid_path_user_segment_not_registry():
    # 'user' segments deep inside a path must not trigger the EDR alt.
    arts = split_artifacts(
        r"C:\Data\user\profile\config.json is loaded on startup")
    assert _by_type(arts, "registry_key") == []


# ══════════════════════════════════════════════════════════════════
# 3. Mixed prose — BOTH kinds must surface
# ══════════════════════════════════════════════════════════════════
def test_mixed_prose_surfaces_both_path_and_registry():
    arts = split_artifacts(
        r"drops C:\Users\Public\p.exe and writes HKLM\SOFTWARE\Bad on host")
    paths = _by_type(arts, "file_path")
    keys  = _by_type(arts, "registry_key")
    assert len(paths) == 1
    assert paths[0].canonical.endswith("p.exe")
    assert len(keys) == 1
    assert keys[0].canonical.startswith("HKEY_LOCAL_MACHINE\\SOFTWARE\\")


def test_mixed_prose_multiple_paths_and_keys():
    text = (
        r"Artifacts observed: C:\Users\bob\Documents\a.pdf, "
        r"C:\ProgramData\evil.exe, HKCU\Software\X\Y, and "
        r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Bad."
    )
    arts = split_artifacts(text)
    paths = _by_type(arts, "file_path")
    keys  = _by_type(arts, "registry_key")
    # At least the 2 file paths + 2 registry keys must all surface
    assert len(paths) >= 2
    assert len(keys)  >= 2
    canon_paths = " ".join(p.canonical for p in paths)
    canon_keys  = " ".join(k.canonical for k in keys)
    assert "bob\\Documents" in canon_paths
    assert "evil.exe" in canon_paths
    assert "HKEY_CURRENT_USER\\Software\\X" in canon_keys
    assert "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\" in canon_keys


# ══════════════════════════════════════════════════════════════════
# 4. Determinism
# ══════════════════════════════════════════════════════════════════
def test_registry_vs_path_extraction_deterministic():
    text = (r"drops C:\Users\Public\p.exe and writes HKLM\SOFTWARE\X on host")
    r1 = [(a.type, a.canonical) for a in split_artifacts(text)]
    r2 = [(a.type, a.canonical) for a in split_artifacts(text)]
    assert r1 == r2
