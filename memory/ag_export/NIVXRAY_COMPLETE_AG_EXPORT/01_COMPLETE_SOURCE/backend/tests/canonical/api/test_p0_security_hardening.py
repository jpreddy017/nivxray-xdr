"""P0 Security Hardening Gate · security test suite (ADR-0010b).

Locks the seven controls:

  1. Explicit CORS origins (wildcard + credentials refused)
  2. Login rate-limit (sliding window + lockout)
  3-6. Archive extraction guards (depth · count · total-size · entry-size · ratio · path-safety)
  7. Fail-loud archive failure handling

Kept intentionally focused: each control gets a positive test and a
negative test. Regression is proven separately by running the existing
canonical suite unchanged.
"""
from __future__ import annotations
import io
import os
import time
import zipfile

import pytest

from security.cors import resolve_cors_policy
from security.rate_limit import SlidingWindowLimiter
from security.archive_guard import (
    ArchiveGuardError,
    ArchiveLimits,
    load_limits,
    safe_iter_zip_members,
)


# ─── 1 · CORS policy ─────────────────────────────────────────────────
class TestCorsPolicy:
    def test_wildcard_forces_credentials_off(self):
        origins, creds, wildcard = resolve_cors_policy({"CORS_ORIGINS": "*"})
        assert origins == ["*"]
        assert creds is False, "wildcard + credentials is spec-invalid; must be forced off"
        assert wildcard is True

    def test_missing_env_defaults_to_safe_wildcard(self):
        origins, creds, wildcard = resolve_cors_policy({})
        assert origins == ["*"]
        assert creds is False
        assert wildcard is True

    def test_explicit_allowlist_grants_credentials(self):
        origins, creds, wildcard = resolve_cors_policy({
            "CORS_ORIGINS": "https://app.example.com,https://admin.example.com/"
        })
        assert origins == ["https://app.example.com", "https://admin.example.com"]
        assert creds is True
        assert wildcard is False

    def test_whitespace_and_empty_stripped(self):
        origins, creds, wildcard = resolve_cors_policy({
            "CORS_ORIGINS": " https://a.example.com , , https://b.example.com "
        })
        assert origins == ["https://a.example.com", "https://b.example.com"]
        assert creds is True


# ─── 2 · Login rate-limit ────────────────────────────────────────────
class TestSlidingWindowLimiter:
    def _mk(self, **kw):
        # tiny knobs for fast tests
        return SlidingWindowLimiter(
            max_fails=kw.get("max_fails", 3),
            window_sec=kw.get("window_sec", 60),
            lockout_sec=kw.get("lockout_sec", 30),
        )

    def test_normal_login_allowed(self):
        lim = self._mk()
        r = lim.check("k1")
        assert r.allowed and r.reason == "ok"

    def test_repeated_failures_trigger_lockout(self):
        """Exactly ``max_fails`` failures are allowed BEFORE lockout.

        With max_fails=3:
        - Failures 1, 2, 3 all record OK (the caller will render 401).
        - After failure 3, the NEXT check() returns ``locked``.
        """
        lim = self._mk(max_fails=3)
        for _ in range(3):
            r = lim.record_failure("k2")
            assert r.allowed, "record_failure never retro-blocks the current attempt"
        # The next check must be denied.
        r = lim.check("k2")
        assert not r.allowed and r.reason == "locked"
        assert r.retry_after > 0

    def test_max_fails_401_before_429(self):
        """Owner-clarified semantic: N 401s, then 429 from N+1 onward."""
        lim = self._mk(max_fails=5)
        # 5 failures: every check() before them is allowed (renders 401).
        for i in range(5):
            assert lim.check("k5").allowed, f"attempt {i+1} pre-check must be allowed"
            lim.record_failure("k5")
        # Attempt 6: locked.
        assert not lim.check("k5").allowed

    def test_success_clears_counters(self):
        lim = self._mk()
        lim.record_failure("k3")
        lim.record_failure("k3")
        lim.record_success("k3")
        r = lim.check("k3")
        assert r.allowed and r.remaining == lim.max_fails

    def test_lockout_expires(self):
        lim = self._mk(max_fails=1, lockout_sec=1)
        lim.record_failure("k4")   # trips lockout after 1st failure
        # After the recorded failure, the NEXT check is locked.
        r = lim.check("k4")
        assert not r.allowed
        time.sleep(1.2)
        r2 = lim.check("k4")
        assert r2.allowed, "lockout should expire when its window rolls off"

    def test_independent_keys(self):
        lim = self._mk(max_fails=1)
        lim.record_failure("keyA")
        # keyB must not be affected by keyA's failure
        assert lim.check("keyB").allowed
        # keyA's lockout is now armed; the next check on keyA is locked.
        assert not lim.check("keyA").allowed


# ─── 3-7 · Archive guard ─────────────────────────────────────────────
def _zip_bytes(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


class TestArchiveGuard:
    def test_normal_zip_extracts_all_members(self):
        raw = _zip_bytes([("hello.txt", b"hello"), ("world.txt", b"world")])
        out = list(safe_iter_zip_members(raw))
        assert [n for n, _ in out] == ["hello.txt", "world.txt"]
        assert [d for _, d in out] == [b"hello", b"world"]

    def test_malformed_archive_fails_loud(self):
        with pytest.raises(ArchiveGuardError) as exc:
            list(safe_iter_zip_members(b"not-a-zip-\x00\x00"))
        assert exc.value.reason == "malformed_archive"

    def test_entry_count_exceeded(self):
        limits = ArchiveLimits(3, 2, 10 * 1024 * 1024, 1 * 1024 * 1024, 200)
        raw = _zip_bytes([(f"f{i}.txt", b"x") for i in range(5)])
        with pytest.raises(ArchiveGuardError) as exc:
            list(safe_iter_zip_members(raw, limits))
        assert exc.value.reason == "entry_count_exceeded"

    def test_total_size_exceeded(self):
        limits = ArchiveLimits(3, 100, 10, 100, 10_000)   # 10 total bytes
        raw = _zip_bytes([("a.txt", b"x" * 8), ("b.txt", b"x" * 8)])
        with pytest.raises(ArchiveGuardError) as exc:
            list(safe_iter_zip_members(raw, limits))
        assert exc.value.reason == "total_size_exceeded"

    def test_entry_too_large(self):
        limits = ArchiveLimits(3, 100, 10_000, 5, 10_000)   # 5-byte per-entry cap
        raw = _zip_bytes([("a.txt", b"x" * 8)])
        with pytest.raises(ArchiveGuardError) as exc:
            list(safe_iter_zip_members(raw, limits))
        assert exc.value.reason == "entry_too_large"

    def test_compression_ratio_exceeded(self):
        # 1 MB of zeros compresses ~1000×; cap the ratio to 50.
        big = b"\x00" * (1_000_000)
        limits = ArchiveLimits(3, 100, 10_000_000, 10_000_000, 50)
        raw = _zip_bytes([("bomb.txt", big)])
        with pytest.raises(ArchiveGuardError) as exc:
            list(safe_iter_zip_members(raw, limits))
        assert exc.value.reason == "compression_ratio_exceeded"

    def test_path_traversal_absolute(self):
        raw = _zip_bytes([("/etc/passwd", b"root:x:0")])
        with pytest.raises(ArchiveGuardError) as exc:
            list(safe_iter_zip_members(raw))
        assert exc.value.reason == "unsafe_member_name"

    def test_path_traversal_relative(self):
        raw = _zip_bytes([("../../secret", b"nope")])
        with pytest.raises(ArchiveGuardError) as exc:
            list(safe_iter_zip_members(raw))
        assert exc.value.reason == "unsafe_member_name"

    def test_path_traversal_backslash(self):
        raw = _zip_bytes([("..\\..\\secret", b"nope")])
        with pytest.raises(ArchiveGuardError) as exc:
            list(safe_iter_zip_members(raw))
        assert exc.value.reason == "unsafe_member_name"

    def test_depth_limit_enforced(self):
        limits = ArchiveLimits(1, 100, 10_000_000, 10_000_000, 10_000)
        raw = _zip_bytes([("a.txt", b"x")])
        # depth=0 is fine.
        list(safe_iter_zip_members(raw, limits, depth=0))
        # depth==max_depth is refused.
        with pytest.raises(ArchiveGuardError) as exc:
            list(safe_iter_zip_members(raw, limits, depth=1))
        assert exc.value.reason == "depth_exceeded"

    def test_defaults_are_conservative(self):
        # Confirm production defaults are within safe envelope.
        d = load_limits()
        assert d.max_depth <= 5
        assert d.max_entries <= 2048
        assert d.max_total_bytes <= 256 * 1024 * 1024
        assert d.max_entry_bytes <= 64 * 1024 * 1024
        assert d.max_compression_ratio <= 1000

    def test_guard_error_dict_is_serialisable(self):
        e = ArchiveGuardError("entry_too_large", {"member": "a.txt", "size": 999})
        d = e.to_dict()
        assert d["error"] == "archive_guard"
        assert d["reason"] == "entry_too_large"
        assert d["member"] == "a.txt"
        assert d["size"] == 999

    def test_hostile_archive_does_not_crash_worker(self):
        # Simulate several rapid hostile calls; each must raise cleanly.
        for _ in range(20):
            with pytest.raises(ArchiveGuardError):
                list(safe_iter_zip_members(b"\x00" * 128))
