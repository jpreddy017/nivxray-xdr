"""Test SyslogConnector: parse dispatch + UDP + TCP end-to-end binding."""
import asyncio
import socket

import pytest

from framework.syslog import SyslogConnector, SyslogRunner


def _find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _find_free_tcp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.mark.asyncio
async def test_parse_auto_dispatch():
    conn = SyslogConnector(tenant_id="acme",
                                config={"port": 5514, "format": "auto"},
                                identity="sys-1")
    p = conn.parse("<34>Oct 11 22:14:15 mymachine su: hello")
    assert p["parser"] == "rfc3164"
    p2 = conn.parse("<34>1 2024-08-30T12:00:00Z h1 app 1 - - hello")
    assert p2["parser"] == "rfc5424"


@pytest.mark.asyncio
async def test_envelope_from_line_carries_provenance():
    conn = SyslogConnector(tenant_id="acme",
                                config={"port": 5515},
                                identity="sys-2")
    env = conn.envelope_from_line("<34>Aug 30 10:00:00 fw01 sshd: bad login",
                                          remote="10.0.0.1:5000")
    assert env.collection_method == "syslog"
    assert env.raw["remote"] == "10.0.0.1:5000"
    assert env.canonical["app"] == "sshd"


@pytest.mark.asyncio
async def test_udp_listener_receives_and_parses():
    port = _find_free_port()
    conn = SyslogConnector(tenant_id="acme",
                                config={"protocol": "udp",
                                         "host": "127.0.0.1", "port": port},
                                identity="sys-udp-1")
    received = []
    def on_line(c, line, remote):
        received.append((line, remote))

    runner = SyslogRunner()
    result = await runner.start(conn, on_line)
    assert result["ok"] is True

    # Send a datagram
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"<34>Aug 30 10:00:00 host su: message-1", ("127.0.0.1", port))
    sock.close()

    # Give the loop a moment
    await asyncio.sleep(0.2)
    await runner.stop(conn.identity)

    assert len(received) == 1
    assert "message-1" in received[0][0]
    assert conn.health.value == "connected"


@pytest.mark.asyncio
async def test_tcp_listener_receives_and_parses():
    port = _find_free_tcp_port()
    conn = SyslogConnector(tenant_id="acme",
                                config={"protocol": "tcp",
                                         "host": "127.0.0.1", "port": port},
                                identity="sys-tcp-1")
    received = []
    def on_line(c, line, remote):
        received.append((line, remote))

    runner = SyslogRunner()
    result = await runner.start(conn, on_line)
    assert result["ok"] is True

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"<34>Aug 30 10:00:00 host su: tcp-message\n")
    await writer.drain()
    writer.close()
    try:    await writer.wait_closed()
    except Exception: pass

    await asyncio.sleep(0.2)
    await runner.stop(conn.identity)

    assert any("tcp-message" in line for line, _ in received)


@pytest.mark.asyncio
async def test_bind_conflict_reports_error():
    port = _find_free_port()
    conn1 = SyslogConnector(tenant_id="acme",
                                 config={"protocol": "udp",
                                          "host": "127.0.0.1", "port": port},
                                 identity="sys-c-1")
    conn2 = SyslogConnector(tenant_id="acme",
                                 config={"protocol": "udp",
                                          "host": "127.0.0.1", "port": port},
                                 identity="sys-c-2")
    runner = SyslogRunner()
    r1 = await runner.start(conn1, lambda c, l, r: None)
    assert r1["ok"] is True
    r2 = await runner.start(conn2, lambda c, l, r: None)
    assert r2["ok"] is False
    assert "bind_failed" in r2["error"]
    await runner.stop(conn1.identity)
