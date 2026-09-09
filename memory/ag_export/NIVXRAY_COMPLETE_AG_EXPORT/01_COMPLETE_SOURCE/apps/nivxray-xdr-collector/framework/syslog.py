"""
Syslog receiver connector · Phase B.

Config:
{
  "label":     "Firewall syslog",
  "protocol":  "udp" | "tcp",
  "host":      "0.0.0.0",
  "port":      5514,
  "format":    "auto" | "rfc3164" | "rfc5424"
}

Each configured syslog instance owns a listening socket.  Ports must
be unique per collector process — the runner (`SyslogRunner`) enforces
this and refuses to bind duplicates.  Incoming lines are parsed via
`parse_syslog_auto` / `parse_rfc3164` / `parse_rfc5424`.
"""
from __future__ import annotations

import asyncio
import socket
from typing import Any, Callable, Dict, List, Optional

from framework.base    import Connector, Envelope, Health, Capability
from framework.parsers import parse_rfc3164, parse_rfc5424, parse_syslog_auto, utcnow_iso


class SyslogConnector(Connector):
    source_type: str = "syslog"
    label:       str = "Generic Syslog Receiver"
    capabilities = [Capability.DETECTIONS, Capability.NETWORK_EVENTS]

    configuration_schema = {
        "type": "object",
        "required": ["port"],
        "properties": {
            "protocol": {"type": "string", "enum": ["udp", "tcp"]},
            "host":     {"type": "string"},
            "port":     {"type": "integer", "minimum": 1, "maximum": 65535},
            "format":   {"type": "string", "enum": ["auto", "rfc3164", "rfc5424"]},
        },
    }

    def __init__(self, tenant_id: str, config: Dict[str, Any],
                 identity: Optional[str] = None):
        super().__init__(tenant_id, config)
        if identity:
            self.identity = identity
        self.label = config.get("label") or self.label
        self.health = Health.NEVER_CONNECTED

    # ── pure parsing helper (also used by the direct-inject test API) ──
    def parse(self, line: str) -> Dict[str, Any]:
        fmt = (self.config.get("format") or "auto").lower()
        if fmt == "rfc3164":  return parse_rfc3164(line)
        if fmt == "rfc5424":  return parse_rfc5424(line)
        return parse_syslog_auto(line)

    def envelope_from_line(self, line: str, remote: Optional[str] = None) -> Envelope:
        parsed = self.parse(line)
        eid = None                # syslog has no native event-id
        ts  = parsed.get("timestamp")
        return Envelope(
            tenant_id            = self.tenant_id,
            source               = self.label,
            source_event_id      = eid,
            connector_id         = self.identity,
            collector_id         = "collector-local",
            collection_method    = "syslog",
            parser_version       = f"phaseB.syslog.{parsed.get('parser', 'auto')}.1",
            source_timestamp     = str(ts) if ts else None,
            collection_timestamp = utcnow_iso(),
            event_type           = self.source_type,
            raw                  = {"line": line, "remote": remote},
            canonical            = parsed,
        )


# ── Runtime bind / listen / dispatch ───────────────────────────────
class SyslogRunner:
    """Owns UDP/TCP asyncio listeners per SyslogConnector instance."""

    def __init__(self) -> None:
        self._servers: Dict[str, Any] = {}       # identity -> transport|server
        self._locks:   Dict[str, asyncio.Lock] = {}

    async def start(self, conn: SyslogConnector,
                       on_line: Callable[[SyslogConnector, str, str], None]) -> Dict[str, Any]:
        cfg = conn.config
        proto = (cfg.get("protocol") or "udp").lower()
        host  = cfg.get("host") or "0.0.0.0"
        port  = int(cfg["port"])
        loop  = asyncio.get_running_loop()

        if conn.identity in self._servers:
            return {"ok": True, "note": "already_running"}

        try:
            if proto == "udp":
                class _UDPProto(asyncio.DatagramProtocol):
                    def datagram_received(_self, data: bytes, addr):
                        try:
                            line = data.decode("utf-8", errors="replace").rstrip("\n")
                            on_line(conn, line, f"{addr[0]}:{addr[1]}")
                        except Exception as e:                   # noqa: BLE001
                            conn.metrics.events_failed += 1
                            conn.metrics.last_error = f"{type(e).__name__}: {e}"

                transport, _ = await loop.create_datagram_endpoint(
                    _UDPProto, local_addr=(host, port))
                self._servers[conn.identity] = transport
            else:  # tcp
                async def _handle(reader: asyncio.StreamReader,
                                     writer: asyncio.StreamWriter):
                    peer = writer.get_extra_info("peername")
                    remote = f"{peer[0]}:{peer[1]}" if peer else "unknown"
                    try:
                        while not reader.at_eof():
                            raw = await reader.readline()
                            if not raw:
                                break
                            line = raw.decode("utf-8", errors="replace").rstrip("\n")
                            if line:
                                on_line(conn, line, remote)
                    except Exception as e:                       # noqa: BLE001
                        conn.metrics.events_failed += 1
                        conn.metrics.last_error = f"{type(e).__name__}: {e}"
                    finally:
                        try:    writer.close()
                        except Exception: pass

                server = await asyncio.start_server(_handle, host=host, port=port)
                self._servers[conn.identity] = server

            conn.health = Health.CONNECTED
            return {"ok": True, "protocol": proto, "host": host, "port": port}
        except OSError as e:
            conn.health = Health.ERROR
            conn.metrics.last_error = f"bind_failed: {e}"
            return {"ok": False, "error": f"bind_failed: {e}"}

    async def stop(self, identity: str) -> Dict[str, Any]:
        srv = self._servers.pop(identity, None)
        if srv is None:
            return {"ok": True, "note": "not_running"}
        try:
            if isinstance(srv, asyncio.base_events.Server):
                srv.close()
                await srv.wait_closed()
            else:
                srv.close()                     # DatagramTransport
        except Exception as e:                                  # noqa: BLE001
            return {"ok": False, "error": str(e)}
        return {"ok": True}

    def running(self) -> List[str]:
        return list(self._servers.keys())
