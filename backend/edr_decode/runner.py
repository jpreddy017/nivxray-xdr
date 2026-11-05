"""Bounded subprocess runner, independent of shared config and thread pools.

Only static decode code runs. A service instance caps its concurrent workers.
This is not an OS/container security sandbox; deployment still needs resource
and admission controls. Explicit interpreter selection supports locked venvs.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys


class DecodeUnavailable(RuntimeError):
    pass


class ProcessDecoder:
    def __init__(self, *, expected_plugins, python_executable=None, timeout_seconds=20,
                 max_workers=2, max_input_bytes=25 * 1024 * 1024):
        if not expected_plugins or not all(isinstance(x, str) and x for x in expected_plugins):
            raise ValueError("explicit nonempty plugin expectation required")
        if timeout_seconds <= 0 or max_workers < 1 or max_input_bytes < 1:
            raise ValueError("positive resource bounds required")
        self.expected_plugins = sorted(set(expected_plugins))
        self.python = python_executable or sys.executable
        self.timeout = timeout_seconds
        self.max_input = max_input_bytes
        self.slots = asyncio.Semaphore(max_workers)
        self.active_pids = set()

    async def decode(self, command_line):
        if not isinstance(command_line, str) or len(command_line.encode("utf-8")) > self.max_input:
            raise ValueError("command exceeds input limit or is not a string")
        request = json.dumps({"command_line": command_line, "expected_plugins": self.expected_plugins,
                              "budget": {"max_depth": 12, "max_branches": 3, "wall_time_ms": 5000}}).encode()
        async with self.slots:
            process = await asyncio.create_subprocess_exec(
                self.python, "-I", str(Path(__file__).with_name("worker.py")),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"})
            self.active_pids.add(process.pid)
            try:
                output, error = await asyncio.wait_for(process.communicate(request), self.timeout)
                if process.returncode:
                    raise DecodeUnavailable("decoder worker failed")
                if len(output) > 16 * 1024 * 1024:
                    raise DecodeUnavailable("decoder report exceeds size limit")
                try:
                    response = json.loads(output)
                except (ValueError, UnicodeError) as exc:
                    raise DecodeUnavailable("invalid decoder response") from exc
                if response.get("status") != "complete":
                    raise DecodeUnavailable(response.get("reason") or "decoder not ready")
                report = response.get("report")
                if not isinstance(report, dict) or not isinstance(report.get("output"), str):
                    raise DecodeUnavailable("decoder returned no valid report")
                return report
            except asyncio.TimeoutError as exc:
                raise DecodeUnavailable("decoder deadline exceeded; worker terminated") from exc
            finally:
                if process.returncode is None:
                    process.kill()
                await process.wait()
                self.active_pids.discard(process.pid)
