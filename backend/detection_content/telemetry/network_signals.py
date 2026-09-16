"""N1 · Canonical network evidence → correlation signals.

The stateful correlation engine (`routers/xdr_correlation.py`) already knows
how to sequence and count signals. What did not exist was a way to hand it
NETWORK evidence in a shape where a join means something: a DNS record and a
connection record only relate when the SAME client saw the SAME address, in
that order, inside a window.

So a DNS record with N address answers produces N signals — one per answer —
each carrying `network_peer_ip` set to that answer, and a connection record
produces one signal with `network_peer_ip` set to its destination. The
correlation rule groups on `client_ip` + `network_peer_ip`, which makes the
entity key itself the evidence of the join. A shared address alone is never
enough: the client must match too, and the DNS answer must come first.

Nothing here decides maliciousness, and nothing here writes evidence. It is
a projection of what the canonical event already states, carrying the
canonical event id so every match cites the evidence it came from.
"""
from __future__ import annotations

from typing import Any, Dict, List

#: Canonical event types this projection understands.
DNS_EVENT_TYPES = ("dns_query",)
CONNECTION_EVENT_TYPES = ("network_connect", "network_alert")


def _net(canonical: Dict[str, Any]) -> Dict[str, Any]:
    """Read BOTH canonical network shapes — the nested snort spelling and
    the flat telemetry-model spelling — so a projection is never silently
    empty for half the sources."""
    net = canonical.get("network") or {}
    if not isinstance(net, dict):
        return {}
    src = net.get("src") if isinstance(net.get("src"), dict) else {}
    dst = net.get("dst") if isinstance(net.get("dst"), dict) else {}
    return {
        "src_ip": net.get("src_ip") or src.get("ip") or "",
        "dest_ip": net.get("dest_ip") or dst.get("ip") or "",
        "dest_port": net.get("dest_port") or dst.get("port"),
        "protocol": net.get("protocol") or "",
        "dns_query": net.get("dns_query") or "",
        "dns_rcode": net.get("dns_rcode") or "",
        "dns_query_type": net.get("dns_query_type") or "",
        "dns_response_ips": list(net.get("dns_response_ips") or []),
        "flow_id": net.get("flow_id") or "",
        "community_id": net.get("community_id") or "",
        "bytes_sent": net.get("bytes_sent"),
        "conn_state": net.get("conn_state") or "",
    }


def signals_from_canonical(canonical: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Zero or more correlation signals for one canonical network event."""
    if not isinstance(canonical, dict):
        return []
    event_type = canonical.get("event_type") or ""
    net = _net(canonical)
    client_ip = net["src_ip"]
    event_id = canonical.get("event_id")
    at = canonical.get("event_time") or canonical.get("timestamp")
    host = canonical.get("host") or {}
    base: Dict[str, Any] = {
        "signal_kind": "event",
        "at": at,
        "event_kind": event_type,
        # A network observation carries no endpoint identity. The address is
        # used as the correlation key and labelled as an address, never
        # promoted into a device identity it does not have.
        "host_id": host.get("host_id") or host.get("hostname") or client_ip,
        "source_event_id": event_id,
    }

    if event_type in DNS_EVENT_TYPES:
        answers = [str(ip) for ip in net["dns_response_ips"] if ip]
        common = {
            "client_ip": client_ip,
            "dns_query": net["dns_query"],
            "dns_rcode": net["dns_rcode"],
            "dns_query_type": net["dns_query_type"],
            "canonical_event_id": event_id,
            "evidence_ref": (f"xdr_canonical_evidence/{event_id}"
                             if event_id else None),
        }
        if not answers:
            # No address answer → no domain→IP relationship exists. The
            # record is still projected so threshold content (NXDOMAIN) can
            # count it, but it carries no peer address to join on.
            return [{**base, "dst_domain": net["dns_query"],
                     "fields": {**common,
                                "dns_answer_state": "NO_ADDRESS_ANSWER"}}]
        return [{**base, "dst_ip": ip, "dst_domain": net["dns_query"],
                 "fields": {**common, "network_peer_ip": ip,
                            "dns_answer_state": "ADDRESS_ANSWERED",
                            "dns_resolved_ip": ip}}
                for ip in answers]

    if event_type in CONNECTION_EVENT_TYPES and net["dest_ip"]:
        return [{**base, "dst_ip": net["dest_ip"],
                 "fields": {
                     "client_ip": client_ip,
                     "network_peer_ip": net["dest_ip"],
                     "dest_port": net["dest_port"],
                     "protocol": net["protocol"],
                     "conn_state": net["conn_state"],
                     "bytes_sent": net["bytes_sent"],
                     "flow_id": net["flow_id"],
                     "community_id": net["community_id"],
                     "canonical_event_id": event_id,
                     "evidence_ref": (f"xdr_canonical_evidence/{event_id}"
                                      if event_id else None)}}]

    return []
