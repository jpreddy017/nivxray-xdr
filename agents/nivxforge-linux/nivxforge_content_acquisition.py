"""NivXForge sensor · FILE CONTENT ACQUISITION (capability, default OFF).

`PROCESS_IMAGE_SHA256 != FILE_CONTENT_SHA256`. This module produces the
second one, and ONLY as a full acquisition record that states when the
bytes were read and whether they moved while being read. It never
substitutes the writing process's image hash for the file's content, and
it never emits a digest whose subject or version is unknown.

Hard limits live HERE, in the sensor, not on the server: a compromised
server must not be able to instruct an endpoint to hash the world.

Default OFF: without `NIVX_SENSOR_FILE_HASHING=1` every call returns
`CAPABILITY_DISABLED` and no file is ever opened.
"""
from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Dict, Optional

CAPABILITY_FLAG = "NIVX_SENSOR_FILE_HASHING"
SENSOR_ACQUIRER = "nivxforge-sensor-content-acquisition/1.0.0"
HASH_ALGORITHM = "SHA-256"
FILE_CONTENT_SHA256 = "FILE_CONTENT_SHA256"

#: Owner-approved defaults (B3 decisions 2-5).
SIZE_CEILING_BYTES = 64 * 1024 * 1024
FILES_PER_MINUTE = 120
BYTES_PER_MINUTE = 512 * 1024 * 1024
SETTLE_SECONDS = 2.0
CACHE_TTL_SECONDS = 24 * 3600
CACHE_MAX_ENTRIES = 4096
READ_CHUNK = 1024 * 1024
PER_FILE_DEADLINE_SECONDS = 5.0

#: Allow-list posture: executables, scripts, archives, shortcuts and
#: macro-bearing documents. Anything else needs an explicit opt-in.
ALLOWED_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".msi", ".msp",
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".sh", ".py", ".pl", ".rb", ".jar", ".lnk", ".zip", ".rar",
    ".7z", ".cab", ".iso", ".img", ".docm", ".xlsm", ".pptm", ".rtf",
    ".chm", ".so", ".elf", ".bin",
})
#: Never read: meaningless, unstable, or a stability risk.
EXCLUDED_FRAGMENTS = (
    "\\pagefile.sys", "\\swapfile.sys", "\\hiberfil.sys",
    "\\device\\", "\\\\.\\pipe\\", "\\system volume information\\",
    "/proc/", "/sys/", "/dev/", "/run/", "swapfile",
)
#: Privacy trees: EXCLUDED BY DEFAULT. A hash IS a content identifier, so
#: hashing a private document is an explicit operator decision.
PRIVACY_FRAGMENTS = (
    "\\documents\\", "\\desktop\\", "\\pictures\\", "\\outlook files\\",
    "\\appdata\\local\\microsoft\\outlook\\", "/home/", "/mail/",
)

ELIGIBLE_OPERATIONS = frozenset({"CREATE", "MODIFY", "WRITE", "RENAME"})


def enabled() -> bool:
    return os.environ.get(CAPABILITY_FLAG, "0").strip() in ("1", "true",
                                                            "TRUE", "yes")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _record(path: str, state: str, *, reason: str = "",
            version: str = "UNKNOWN", **extra: Any) -> Dict[str, Any]:
    return {"path": path, "acquisition_state": state,
            "content_version_state": version,
            "hash_class": FILE_CONTENT_SHA256,
            "hash_algorithm": HASH_ALGORITHM,
            "acquirer": SENSOR_ACQUIRER,
            "policy_id": "b3-default-allowlist-64MiB-120f/512MiB-2s",
            "refusal_reason": reason, **extra}


class RateBudget:
    """Per-minute file and byte budget. Exhaustion is RATE_LIMITED, never
    a silent skip."""

    def __init__(self, files_per_minute: int = FILES_PER_MINUTE,
                 bytes_per_minute: int = BYTES_PER_MINUTE):
        self.files_per_minute = files_per_minute
        self.bytes_per_minute = bytes_per_minute
        self._window = 0.0
        self._files = 0
        self._bytes = 0

    def _roll(self, now: float) -> None:
        if now - self._window >= 60:
            self._window, self._files, self._bytes = now, 0, 0

    def admits(self, size: int, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        self._roll(now)
        return (self._files < self.files_per_minute
                and self._bytes + size <= self.bytes_per_minute)

    def charge(self, size: int, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        self._roll(now)
        self._files += 1
        self._bytes += int(size)


class Acquirer:
    """Bounded, read-only content acquisition with an explicit cache."""

    def __init__(self, budget: Optional[RateBudget] = None,
                 size_ceiling: int = SIZE_CEILING_BYTES,
                 allow_privacy_trees: bool = False,
                 allowed_extensions: Optional[frozenset] = None):
        self.budget = budget or RateBudget()
        self.size_ceiling = size_ceiling
        self.allow_privacy_trees = allow_privacy_trees
        self.allowed_extensions = (allowed_extensions
                                   if allowed_extensions is not None
                                   else ALLOWED_EXTENSIONS)
        self._cache: Dict[tuple, Dict[str, Any]] = {}
        self.stats = {"attempted": 0, "acquired": 0, "refused": 0,
                      "cache_hits": 0, "bytes_hashed": 0}

    # ── eligibility, evaluated BEFORE any read ─────────────────────────
    def eligible(self, path: str, operation: str) -> tuple[bool, str, str]:
        low = (path or "").replace("/", "\\").lower() if "\\" in (path or "") \
            else (path or "").lower()
        if (operation or "").upper() not in ELIGIBLE_OPERATIONS:
            return (False, "NOT_ELIGIBLE_BY_POLICY",
                    f"operation {operation!r} leaves nothing to read")
        for fragment in EXCLUDED_FRAGMENTS:
            if fragment in low or fragment.replace("\\", "/") in low:
                return (False, "NOT_ELIGIBLE_BY_POLICY",
                        "excluded path class (pagefile / device / pipe / "
                        "pseudo-filesystem)")
        if not self.allow_privacy_trees:
            for fragment in PRIVACY_FRAGMENTS:
                if fragment in low or fragment.replace("\\", "/") in low:
                    return (False, "NOT_ELIGIBLE_BY_POLICY",
                            "privacy tree excluded by default; a hash is a "
                            "content identifier and requires an explicit "
                            "operator decision")
        ext = os.path.splitext(low)[1]
        if self.allowed_extensions and ext not in self.allowed_extensions:
            return (False, "NOT_ELIGIBLE_BY_POLICY",
                    f"extension {ext or '(none)'} is not in the acquisition "
                    f"allow-list")
        return True, "", ""

    def acquire(self, path: str, *, operation: str = "CREATE",
                event_observed_at: str = "",
                settle_seconds: float = 0.0) -> Dict[str, Any]:
        """Read and hash ONE file, or state exactly why it was not."""
        if not enabled():
            return _record(path, "CAPABILITY_DISABLED",
                           reason="sensor-side file content hashing is "
                                  "disabled on this endpoint")
        ok, state, reason = self.eligible(path, operation)
        if not ok:
            self.stats["refused"] += 1
            return _record(path, state, reason=reason)
        if settle_seconds > 0:
            time.sleep(min(settle_seconds, 30.0))
        self.stats["attempted"] += 1
        try:
            pre = os.stat(path)
        except FileNotFoundError:
            self.stats["refused"] += 1
            return _record(path, "FILE_ABSENT_AT_ACQUISITION",
                           reason="the file was gone before it could be "
                                  "read — the single most common outcome "
                                  "for a dropper, and a counted state")
        except PermissionError:
            self.stats["refused"] += 1
            return _record(path, "ACCESS_DENIED",
                           reason="the ACL or integrity level refused the "
                                  "read")
        except OSError as ex:
            self.stats["refused"] += 1
            return _record(path, "IO_ERROR", reason=str(ex)[:160])
        if pre.st_size > self.size_ceiling:
            self.stats["refused"] += 1
            return _record(path, "SIZE_LIMIT_EXCEEDED",
                           reason=(f"{pre.st_size} bytes exceeds the "
                                   f"{self.size_ceiling}-byte ceiling; a "
                                   f"partial digest is never presented as "
                                   f"a hash"),
                           size_bytes=pre.st_size)
        cache_key = (pre.st_dev, pre.st_ino, pre.st_size, pre.st_mtime_ns)
        cached = self._cache.get(cache_key)
        if cached and (time.time() - cached["_at"]) < CACHE_TTL_SECONDS:
            self.stats["cache_hits"] += 1
            # A reused digest carries the ORIGINAL acquisition time. It
            # never claims a fresh read.
            return {**cached["record"], "cache_state": "CACHE_HIT"}
        if not self.budget.admits(pre.st_size):
            self.stats["refused"] += 1
            return _record(path, "RATE_LIMITED",
                           reason="the endpoint's hashing budget for this "
                                  "minute is exhausted",
                           size_bytes=pre.st_size)
        started = time.time()
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                while chunk := handle.read(READ_CHUNK):
                    digest.update(chunk)
                    if time.time() - started > PER_FILE_DEADLINE_SECONDS:
                        self.stats["refused"] += 1
                        return _record(path, "TIMEOUT",
                                       reason="the read exceeded the "
                                              "per-file deadline")
        except FileNotFoundError:
            self.stats["refused"] += 1
            return _record(path, "FILE_ABSENT_AT_ACQUISITION",
                           reason="the file vanished during the read")
        except PermissionError:
            self.stats["refused"] += 1
            return _record(path, "ACCESS_DENIED",
                           reason="the read was refused mid-acquisition")
        except OSError as ex:
            self.stats["refused"] += 1
            return _record(path, "LOCKED_OR_SHARING_VIOLATION"
                           if getattr(ex, "errno", None) in (11, 13, 32)
                           else "IO_ERROR", reason=str(ex)[:160])
        try:
            post = os.stat(path)
        except OSError as ex:
            return _record(path, "IO_ERROR",
                           reason=f"post-read stat failed: {str(ex)[:120]}")
        acquired_at = _now()
        if (pre.st_ino, pre.st_size, pre.st_mtime_ns) != \
                (post.st_ino, post.st_size, post.st_mtime_ns):
            # A torn read. The digest describes neither version, so it is
            # DISCARDED rather than presented as an identity.
            self.stats["refused"] += 1
            return _record(path, "IO_ERROR",
                           version="CHANGED_DURING_ACQUISITION",
                           reason="the content changed while it was being "
                                  "read; the digest is discarded")
        version = "STABLE_DURING_ACQUISITION"
        if event_observed_at:
            # Was the content still the content the EVENT described?
            try:
                event_epoch = time.mktime(time.strptime(
                    event_observed_at[:19], "%Y-%m-%dT%H:%M:%S"))
                version = ("CHANGED_SINCE_EVENT"
                           if post.st_mtime > event_epoch + 1
                           else "CONSISTENT_WITH_EVENT")
            except (ValueError, OverflowError):
                version = "STABLE_DURING_ACQUISITION"
        self.budget.charge(pre.st_size)
        self.stats["acquired"] += 1
        self.stats["bytes_hashed"] += int(pre.st_size)
        record = _record(
            path, "ACQUIRED", version=version, reason="",
            sha256=digest.hexdigest(),
            hash_algorithm_version=SENSOR_ACQUIRER,
            size_bytes=int(post.st_size),
            event_observed_at=event_observed_at or None,
            acquired_at=acquired_at,
            acquisition_latency_ms=int((time.time() - started) * 1000),
            mtime_at_acquisition=int(post.st_mtime_ns),
            ctime_at_acquisition=int(post.st_ctime_ns),
            file_id=str(post.st_ino), volume_guid=str(post.st_dev),
            cache_state="CACHE_MISS")
        if len(self._cache) >= CACHE_MAX_ENTRIES:
            self._cache.pop(next(iter(self._cache)), None)
        self._cache[cache_key] = {"record": record, "_at": time.time()}
        return record
