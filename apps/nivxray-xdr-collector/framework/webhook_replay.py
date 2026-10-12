"""Shared webhook replay claims. No in-process fallback and no payload storage."""
import os
from functools import lru_cache


class ReplayStoreUnavailable(RuntimeError):
    pass


class RedisReplayStore:
    def __init__(self, url):
        if not url or not url.startswith(('redis://', 'rediss://')):
            raise ReplayStoreUnavailable('Redis replay configuration unavailable')
        try:
            from redis import Redis
            self.client = Redis.from_url(url, socket_connect_timeout=1,
                socket_timeout=1, decode_responses=True)
        except Exception:
            raise ReplayStoreUnavailable('Redis replay configuration unavailable') from None

    def claim(self, key, ttl_seconds):
        try:
            # One atomic operation, shared across workers/instances. Expiry is
            # installed with the claim, never in a separate crash-prone call.
            result = self.client.set(key, '1', nx=True, ex=ttl_seconds)
        except Exception:
            raise ReplayStoreUnavailable('Redis replay store unavailable') from None
        if result is True:
            return True
        if result is None:
            return False  # Existing claim, not an availability failure.
        raise ReplayStoreUnavailable('Redis replay result unavailable')


@lru_cache(maxsize=4)
def _configured_store(url):
    return RedisReplayStore(url)


def replay_store():
    return _configured_store(os.environ.get('NIVX_WEBHOOK_REPLAY_REDIS_URL')
                             or os.environ.get('REDIS_URL') or '')
