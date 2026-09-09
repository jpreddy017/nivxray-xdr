"""
Async scheduler for REST-poll connectors.

One coroutine per connector, interval-driven, cancellation-safe.
"""
from __future__ import annotations

import asyncio
from typing import Callable, Dict, List

from framework.rest_poller import RestPollerConnector


class PollerScheduler:
    def __init__(self) -> None:
        self._tasks: Dict[str, asyncio.Task] = {}

    async def start(self, conn: RestPollerConnector,
                       on_envelopes: Callable) -> None:
        if conn.identity in self._tasks:
            return
        interval = int(conn.config.get("interval_seconds") or 60)

        async def _loop():
            while True:
                try:
                    envs = await conn.collect()
                    if envs:
                        await on_envelopes(conn, envs)
                except asyncio.CancelledError:
                    raise
                except Exception:                              # noqa: BLE001
                    # collector already logged into metrics; keep the
                    # loop alive so a transient vendor outage doesn't
                    # kill the connector.
                    pass
                await asyncio.sleep(interval)

        self._tasks[conn.identity] = asyncio.create_task(_loop())

    async def stop(self, identity: str) -> None:
        t = self._tasks.pop(identity, None)
        if t:
            t.cancel()
            try:    await t
            except (asyncio.CancelledError, Exception): pass

    def running(self) -> List[str]:
        return list(self._tasks.keys())
