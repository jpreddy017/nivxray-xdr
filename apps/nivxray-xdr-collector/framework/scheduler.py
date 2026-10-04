"""
Async scheduler for REST-poll connectors.

One coroutine per connector, interval-driven, cancellation-safe.
"""
from __future__ import annotations

import asyncio
from typing import Callable, Dict, List, Optional

from framework.rest_poller import RestPollerConnector


class PollerScheduler:
    def __init__(self) -> None:
        self._tasks: Dict[str, asyncio.Task] = {}

    async def start(self, conn: RestPollerConnector,
                       on_envelopes: Callable, *,
                       on_error: Optional[Callable] = None,
                       always_callback: bool = False) -> None:
        if conn.identity in self._tasks:
            return
        interval = int(conn.config.get("interval_seconds") or 60)

        async def _loop():
            while True:
                try:
                    envs = await conn.collect()
                    if envs or always_callback:
                        await on_envelopes(conn, envs)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:                       # noqa: BLE001
                    # The collector records its own metrics; a transient
                    # vendor outage must not kill the connector. A caller
                    # that needs the failure to be OBSERVABLE (health,
                    # last_error) passes `on_error` — silence is not a
                    # health report.
                    if on_error is not None:
                        try:
                            on_error(conn, exc)
                        except Exception:                      # noqa: BLE001
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
