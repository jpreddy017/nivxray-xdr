"""Shared harness for the LIVE EDR suites.

Classification of a failure this removes: `NONDETERMINISTIC ·
EXTERNAL/LIVE_DEPENDENCY`. Eight suites in this directory authenticate
against the real preview edge in their own module-scoped fixture. Run
individually every one of them passes; run together under pytest-xdist
they start within milliseconds of each other and the edge throttles the
burst (HTTP 429), so whole suites ERRORed at the fixture with
`admin login failed: 429`. That is the edge protecting itself — correct
behaviour — being read as a product failure.

The login POST (and only the login POST) is therefore retried with
backoff, and a successful token is cached per worker process so repeated
suites do not re-authenticate at all. Nothing else is retried: a 4xx/5xx
from any product route still fails immediately, which is the point.
"""
from __future__ import annotations

import time

import pytest
import requests

_TOKEN_CACHE: dict[tuple[str, str], str] = {}
_MAX_ATTEMPTS = 6
_BACKOFF_S = (0.4, 0.9, 1.8, 3.2, 5.0)


def _is_login(url: str) -> bool:
    return url.rstrip("/").endswith("/api/auth/login")


@pytest.fixture(scope="session", autouse=True)
def _login_is_retried_and_cached():
    real_post = requests.post

    def post(url, *a, **kw):
        if not _is_login(str(url)):
            return real_post(url, *a, **kw)
        body = kw.get("json") or {}
        key = (str(url), str(body.get("email")))
        cached = _TOKEN_CACHE.get(key)
        if cached:
            return _Cached(cached)
        last = None
        for attempt in range(_MAX_ATTEMPTS):
            last = real_post(url, *a, **kw)
            if last.status_code == 200:
                try:
                    payload = last.json()
                    tok = payload.get("access_token") or payload.get("token")
                    if tok:
                        _TOKEN_CACHE[key] = tok
                except ValueError:
                    pass
                return last
            if last.status_code not in (429, 502, 503, 504):
                return last
            if attempt < len(_BACKOFF_S):
                time.sleep(_BACKOFF_S[attempt])
        return last

    requests.post = post

    # The preview edge (Cloudflare) returns 502/503/504/524 of its own when
    # the whole live suite hits it concurrently — `504: Gateway time-out`
    # HTML, not a product response. Those are retried once, briefly. A
    # product 5xx (500) is NOT retried, so a real server error still fails
    # immediately.
    real_get = requests.get
    gateway = (502, 503, 504, 524)

    def get(url, *a, **kw):
        r = real_get(url, *a, **kw)
        for delay in (0.8, 2.0):
            if r.status_code not in gateway:
                return r
            time.sleep(delay)
            r = real_get(url, *a, **kw)
        return r

    requests.get = get
    try:
        yield
    finally:
        requests.post = real_post
        requests.get = real_get


class _Cached:
    """A `requests.Response`-shaped stand-in for a cached token.

    It carries only what a login fixture reads. It cannot mask a product
    failure, because it is only ever produced after a real 200."""

    status_code = 200

    def __init__(self, token: str):
        self._token = token
        self.text = ('{"access_token": "<cached by tests/edr/conftest.py>", '
                     '"token_type": "bearer"}')

    def json(self):
        return {"access_token": self._token, "token": self._token,
                "token_type": "bearer"}
