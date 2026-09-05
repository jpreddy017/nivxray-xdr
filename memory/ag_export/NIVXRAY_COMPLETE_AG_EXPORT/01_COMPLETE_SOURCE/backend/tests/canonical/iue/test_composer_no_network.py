"""T1.6 · No-network / no-I/O test.

INV-2: composer runs with all outbound network blocked.
"""
import socket

import pytest

from canonical.iue import classify, RawInput


@pytest.fixture
def block_network(monkeypatch):
    """Blackhole every outbound socket to prove INV-2."""
    def _raise(*args, **kwargs):
        raise RuntimeError("network access forbidden inside IUE (INV-2)")

    monkeypatch.setattr(socket, "socket", _raise)
    monkeypatch.setattr(socket, "create_connection", _raise)
    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    monkeypatch.setattr(socket, "gethostbyname", _raise)
    yield


SAMPLES = [
    "cmd /c whoami",
    "curl http://example.com/x",
    "http://evil.com/beacon",
    b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00",
    "powershell -e SGVsbG8=",
    "wmic process call create 'cmd /c a.exe'",
]


def test_composer_runs_with_all_sockets_blocked(block_network):
    for s in SAMPLES:
        raw = RawInput(payload=s) if isinstance(s, (bytes, str)) else s
        d = classify(raw)
        # Composer completed without raising.
        assert d.input_profile.primary_type
        assert d.determinism_hash
