"""P0/P1 Bug Baseline · Regression lock · SSRF protection.

Verifies that the SSRF guard in `services.ida.acquisition._is_private_host`
blocks fetches to the four categories of dangerous IP space:

  * Loopback         (127.0.0.0/8, ::1)
  * Link-local       (169.254.0.0/16 — includes cloud-metadata IP)
  * Private / RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  * Reserved         (0.0.0.0, multicast, benchmarking blocks)

Without this test, a future refactor could accidentally weaken the guard
and expose the pod to metadata-endpoint theft.  Locked as P0.
"""
from __future__ import annotations

import pytest

from services.ida.acquisition import acquire_url, _is_private_host


PRIVATE_HOSTS = [
    # Loopback
    "127.0.0.1",
    "127.0.0.53",
    "localhost",
    # Link-local — includes AWS/GCP/Azure metadata IP
    "169.254.169.254",
    "169.254.1.1",
    # RFC1918
    "10.0.0.1",
    "10.255.255.254",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.0.1",
    "192.168.1.1",
    # Reserved
    "0.0.0.0",
]


@pytest.mark.parametrize("host", PRIVATE_HOSTS)
def test_private_hosts_are_blocked_by_ssrf_guard(host: str) -> None:
    assert _is_private_host(host) is True, (
        f"SSRF guard failed to block private host {host!r}. "
        "This is a P0 security regression — do NOT ship until fixed."
    )


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://localhost:8001/api/health",
    "http://169.254.169.254/latest/meta-data/",
    "https://169.254.169.254/computeMetadata/v1/",
    "http://10.0.0.1:8080/",
    "http://192.168.1.1/",
    "http://172.16.5.4/",
])
def test_acquire_url_refuses_ssrf_targets(url: str) -> None:
    """End-to-end: `acquire_url` must return a `blocked` error, not fetch."""
    r = acquire_url(url)
    assert r.ok is False
    assert r.error_code == "private_host", (
        f"acquire_url({url!r}) did not block SSRF target. "
        f"got error_code={r.error_code!r}, ok={r.ok}. P0 security issue."
    )


def test_public_host_is_not_blocked() -> None:
    """Sanity: legitimate public hosts must still pass the guard."""
    assert _is_private_host("example.com") is False
    assert _is_private_host("8.8.8.8") is False
