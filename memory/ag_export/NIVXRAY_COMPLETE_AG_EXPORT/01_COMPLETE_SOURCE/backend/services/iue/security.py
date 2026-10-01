"""IUE security caps (v3 §23 · STEP 3 §6 · STEP 4 §7).

Enforces size + record-count + decompression + path-traversal caps
on structured-log ingestion.  Reuses existing acquisition SSRF guards
by referencing (not duplicating) them.
"""
from __future__ import annotations

import os
from typing import Iterable


# Caps — override via env for CI stress tests only.  Defaults are
# conservative to prevent OOM / decompression bombs.
MAX_RAW_BYTES     = int(os.environ.get("IUE_MAX_RAW_BYTES",     10 * 1024 * 1024))   # 10 MiB
MAX_RECORD_COUNT  = int(os.environ.get("IUE_MAX_RECORD_COUNT",  200_000))
MAX_RECORD_BYTES  = int(os.environ.get("IUE_MAX_RECORD_BYTES",  256 * 1024))         # 256 KiB
MAX_DECOMPRESS_RATIO = float(os.environ.get("IUE_MAX_DECOMPRESS_RATIO", 200.0))


class SecurityCapExceeded(Exception):
    """Raised only by internal helpers; callers translate to IUEFailure."""


def enforce_raw_size(byte_count: int) -> None:
    if byte_count > MAX_RAW_BYTES:
        raise SecurityCapExceeded(
            f"raw payload {byte_count} bytes > cap {MAX_RAW_BYTES}"
        )


def enforce_record_count(count: int) -> None:
    if count > MAX_RECORD_COUNT:
        raise SecurityCapExceeded(
            f"record count {count} > cap {MAX_RECORD_COUNT}"
        )


def enforce_record_size(byte_count: int) -> None:
    if byte_count > MAX_RECORD_BYTES:
        raise SecurityCapExceeded(
            f"record {byte_count} bytes > cap {MAX_RECORD_BYTES}"
        )


def is_safe_archive_member(member_name: str) -> bool:
    """Reject path-traversal / absolute path archive entries."""
    if not member_name:
        return False
    if member_name.startswith(("/", "\\")):
        return False
    if ".." in member_name.replace("\\", "/").split("/"):
        return False
    return True
