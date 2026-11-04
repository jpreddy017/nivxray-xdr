"""Supervise the file index subprocess alongside the API lifecycle.

Database tenant leases remain the concurrency authority across API replicas.
The child uses the same interpreter, source tree and inherited configuration.
"""
import asyncio
import logging
import os
from pathlib import Path
import sys

log = logging.getLogger(__name__)
_task = None
_process = None
_stopping = None
RESTART_SECONDS = 5
STOP_SECONDS = 15


async def _supervise():
    global _process
    while not _stopping.is_set():
        try:
            _process = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "scripts.edr_file_search_index",
                "--all-registered-tenants", "--follow",
                cwd=str(Path(__file__).resolve().parents[1]),
            )
            log.info("EDR file index worker started pid=%s", _process.pid)
            if _stopping.is_set() and _process.returncode is None:
                _process.terminate()
            code = await _process.wait()
            if not _stopping.is_set():
                log.warning("EDR file index worker exited code=%s; restarting", code)
        except OSError as exc:
            log.warning("EDR file index worker could not start: %s", type(exc).__name__)
        finally:
            _process = None
        if not _stopping.is_set():
            try:
                await asyncio.wait_for(_stopping.wait(), RESTART_SECONDS)
            except asyncio.TimeoutError:
                pass


async def start_file_index_worker():
    global _task, _stopping
    if os.environ.get("NIVX_EDR_FILE_INDEX_WORKER_ENABLED", "1") == "0":
        log.info("EDR file index lifecycle worker disabled by configuration")
        return
    if _task is not None and not _task.done():
        return
    _stopping = asyncio.Event()
    _task = asyncio.create_task(_supervise(), name="edr-file-index-supervisor")


async def stop_file_index_worker():
    global _task
    if _task is None:
        return
    _stopping.set()
    # Yield once so an in-flight spawn can assign its process handle.
    await asyncio.sleep(0)
    if _process is not None and _process.returncode is None:
        try:
            _process.terminate()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(asyncio.shield(_task), STOP_SECONDS)
    except asyncio.TimeoutError:
        if _process is not None and _process.returncode is None:
            try:
                _process.kill()
            except ProcessLookupError:
                pass
        await _task
    finally:
        _task = None
