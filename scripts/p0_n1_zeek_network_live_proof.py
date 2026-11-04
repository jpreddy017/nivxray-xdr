#!/usr/bin/env python3
"""Gate N1 · Zeek network/DNS telemetry over real HTTP (PREVIEW ONLY).

The gate is not "a parser exists". It is:

  1. a REAL authenticated delivery of Zeek conn/dns JSON is accepted only
     when the collector DECLARED `zeek-json` and is authorized for it;
  2. the canonical evidence produced carries the DNS answer, the flow
     volume and field-level provenance — the things that were missing;
  3. every adversarial delivery is refused with its OWN reason code and
     produces no evidence;
  4. the DNS → resolved IP → connection relationship is established by the
     EXISTING correlation engine and CITES both canonical event ids;
  5. the NXDOMAIN burst fires only at its declared threshold, per client.

Both correlation rules ship DISABLED. This script enables them, proves the
behaviour, and disables them again — preview is left as it was found.

EVIDENCE LABELLING — the Zeek records here are TEST/SYNTHETIC records in
Zeek's documented JSON shape, delivered over the real authenticated ingest
route. They prove IMPLEMENTATION, not a live sensor. Real-source status is
reported by `--real-source-attempt`, which tries to run a genuine Zeek
binary against genuinely observed traffic and reports exactly what the
environment allowed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv                                  # noqa: E402
from pymongo import MongoClient                                 # noqa: E402

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
STAMP = int(time.time())
TEN = "default"
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")

CLIENT = "10.77.0.31"
RESOLVER = "10.77.0.1"
ANSWER = f"198.51.100.{STAMP % 200 + 10}"
DOMAIN = f"n1-proof-{STAMP}.example-cdn.net"

ok = True


def check(label, cond, detail=""):
    global ok
    ok = ok and bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}"
          + (f" — {detail}" if detail else ""))


def call(path, method="GET", token=None, key=None, tenant=None, body=None):
    h = {"User-Agent": UA, "Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if key:
        h["X-XDR-API-Key"] = key
    if tenant:
        h["X-Tenant-Id"] = tenant
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=90) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()[:500]
        try:
            return e.code, json.loads(raw)
        except Exception:                                       # noqa: BLE001
            return e.code, raw


def login(email, password):
    code, body = call("/api/auth/login", "POST",
                      body={"email": email, "password": password})
    return body.get("access_token") if code == 200 else None


# ── Zeek records (TEST/SYNTHETIC, Zeek's documented JSON shape) ────
def dns_record(query, answers, rcode="NOERROR", ts=None, uid=None,
               client=None):
    return {
        "_path": "dns", "_system_name": "zeek-proof-sensor",
        "ts": ts or (STAMP - 60), "uid": uid or f"Cn1dns{STAMP}",
        "id.orig_h": client or CLIENT, "id.orig_p": 53211,
        "id.resp_h": RESOLVER, "id.resp_p": 53, "proto": "udp",
        "trans_id": 4242, "rtt": 0.018, "query": query,
        "qclass": 1, "qclass_name": "C_INTERNET", "qtype": 1,
        "qtype_name": "A", "rcode": 0 if rcode == "NOERROR" else 3,
        "rcode_name": rcode, "AA": False, "TC": False, "RD": True,
        "RA": True, "Z": 0, "answers": answers,
        "TTLs": [60.0] * len(answers), "rejected": False,
    }


def conn_record(dest, ts=None, uid=None):
    return {
        "_path": "conn", "_system_name": "zeek-proof-sensor",
        "ts": ts or (STAMP - 48), "uid": uid or f"Cn1conn{STAMP}",
        "id.orig_h": CLIENT, "id.orig_p": 44311,
        "id.resp_h": dest, "id.resp_p": 443, "proto": "tcp",
        "service": "ssl", "duration": 9.75, "orig_bytes": 1811,
        "resp_bytes": 44210, "orig_pkts": 19, "resp_pkts": 41,
        "conn_state": "SF", "history": "ShADadFf",
        "local_orig": True, "local_resp": False,
    }


def envelope(col, sei, declared, raw):
    e = {"tenant_id": TEN, "collector_id": col, "source_event_id": sei,
         "collection_method": "syslog", "source": "zeek-proof-sensor",
         "raw": raw}
    if declared is not None:
        e["declared_source"] = declared
    return e


def provision(token):
    name = f"n1-zeek-proof-collector-{STAMP}"
    code, body = call("/api/xdr/collectors", "POST", token=token, tenant=TEN,
                      body={"name": name, "protocol": "syslog",
                            "authorized_sources": ["zeek-json"]})
    if code not in (200, 201):
        print(f"    collector create -> {code} {body}")
        return None, None
    col = (body.get("data") or {}).get("id")
    code, body = call("/api/xdr/api-keys", "POST", token=token, tenant=TEN,
                      body={"name": f"n1-zeek-key-{STAMP}",
                            "confirm_tenant_id": TEN,
                            "allow_new_tenant": False,
                            "scopes": ["collectors.enroll", "collectors.read"]})
    d = body.get("data") or {}
    key = (d.get("api_key") or d.get("key") or d.get("secret")
           or d.get("plaintext") or d.get("token") or d.get("value"))
    return col, key


def deliver(key, envelopes):
    return call("/api/xdr/ingest/telemetry", "POST", key=key, tenant=TEN,
                body={"envelopes": envelopes})


def mongo():
    return MongoClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]


def find_rule(token, name_fragment):
    _, body = call("/api/xdr/correlation/rules?limit=1000", token=token,
                   tenant=TEN)
    for r in ((body.get("data") or {}).get("rules") or []):
        if name_fragment.lower() in (r.get("name") or "").lower():
            return r
    return None


# ── real-source attempt ───────────────────────────────────────────
def real_source_attempt():
    print("\n== REAL-SOURCE ATTEMPT · genuine Zeek in this environment ==")
    findings = {}
    zeek_bin = shutil.which("zeek") or shutil.which("bro")
    findings["zeek_binary"] = zeek_bin or "NOT_INSTALLED"
    apt = subprocess.run(["apt-cache", "policy", "zeek"],
                         capture_output=True, text=True)
    findings["apt_candidate"] = (
        "none" if "Candidate: (none)" in apt.stdout else apt.stdout.strip()[:120])
    caps = subprocess.run(["capsh", "--print"], capture_output=True, text=True)
    cur = next((ln for ln in caps.stdout.splitlines()
                if ln.startswith("Current:")), "")
    findings["cap_net_raw"] = "cap_net_raw" in cur
    findings["cap_net_admin"] = "cap_net_admin" in cur
    cap_probe = "ABSENT"
    if shutil.which("tcpdump"):
        p = subprocess.run(["timeout", "6", "tcpdump", "-i", "any", "-c", "1"],
                           capture_output=True, text=True)
        cap_probe = ("CAPTURE_OK" if p.returncode == 0
                     else f"DENIED: {(p.stderr or '').strip()[:120]}")
    findings["live_capture_probe"] = cap_probe

    capturable = findings["cap_net_raw"] and cap_probe == "CAPTURE_OK"
    findings["classification"] = (
        "REAL ZEEK / PREVIEW-ENVIRONMENT SOURCE PROVEN" if (zeek_bin and capturable)
        else "EXTERNAL_ACCESS_BLOCKED")
    findings["basis"] = (
        "a genuine Zeek binary observed genuine traffic in this environment"
        if (zeek_bin and capturable) else
        "this container holds no CAP_NET_RAW (packet capture is denied by the "
        "kernel, verified by probe) and Zeek is not installable from the "
        "configured apt sources, so no genuine observation of traffic is "
        "possible here. Nothing is claimed in its place.")
    for k, v in findings.items():
        print(f"  {k}: {v}")
    return findings


def main():
    print(f"== N1 ZEEK NETWORK TELEMETRY LIVE PROOF · {BASE} ==")
    token = login(*ADMIN)
    check("admin session", bool(token))
    if not token:
        return 1
    col, key = provision(token)
    check("collector authorized for zeek-json only + ingest key",
          bool(col and key), f"collector={col}")
    if not (col and key):
        return 1

    # ── 1 · accepted deliveries ───────────────────────────────────
    print("\n== 1 · AUTHENTICATED DELIVERY (declared zeek-json) ==")
    dns_sei = f"n1:{STAMP}:dns"
    conn_sei = f"n1:{STAMP}:conn"
    code, body = deliver(key, [
        envelope(col, dns_sei, "zeek-json", dns_record(DOMAIN, [ANSWER])),
        envelope(col, conn_sei, "corelight", conn_record(ANSWER)),
    ])
    data = body.get("data") or body
    check("both Zeek records accepted", code == 200
          and data.get("accepted") == 2 and data.get("routing_blocked") == 0,
          f"{code} accepted={data.get('accepted')} "
          f"blocked={data.get('routing_blocked')}")
    outcomes = {o.get("source_event_id"): o
                for o in (data.get("reasoning") or [])}
    check("both routed to the zeek-json DSM by DECLARATION",
          all(outcomes.get(s, {}).get("selected_dsm_id") == "zeek-json"
              for s in (dns_sei, conn_sei)),
          str({s: outcomes.get(s, {}).get("selected_dsm_id")
               for s in (dns_sei, conn_sei)}))

    # ── 2 · adversarial deliveries ────────────────────────────────
    print("\n== 2 · ADVERSARIAL DELIVERIES (each refused, own reason) ==")
    code, body = deliver(key, [
        envelope(col, f"n1:{STAMP}:mis", "linux-auditd",
                 conn_record(ANSWER, uid=f"Cmis{STAMP}")),
        envelope(col, f"n1:{STAMP}:nodecl", None,
                 dns_record(DOMAIN, [ANSWER], uid=f"Cnod{STAMP}")),
        envelope(col, f"n1:{STAMP}:notauth", "cef-leef",
                 conn_record(ANSWER, uid=f"Cna{STAMP}")),
        envelope(col, f"n1:{STAMP}:badpath", "zeek-json",
                 {"_path": "ssl", "uid": f"Cssl{STAMP}",
                  "id.orig_h": CLIENT, "id.resp_h": ANSWER}),
        envelope(col, f"n1:{STAMP}:noid", "zeek-json",
                 {"_path": "conn", "ts": STAMP, "proto": "tcp"}),
    ])
    data = body.get("data") or body
    reasons = {o.get("source_event_id"): o.get("mismatch_reason")
               for o in (data.get("reasoning") or [])}
    check("no adversarial delivery produced evidence",
          data.get("accepted") == 0 and data.get("routing_blocked") == 5,
          f"accepted={data.get('accepted')} "
          f"blocked={data.get('routing_blocked')}")
    check("declared-as-auditd by a zeek-only collector → "
          "SOURCE_NOT_AUTHORIZED (the allowlist answers first)",
          reasons.get(f"n1:{STAMP}:mis") == "SOURCE_NOT_AUTHORIZED",
          str(reasons.get(f"n1:{STAMP}:mis")))
    check("no declaration → DECLARATION_REQUIRED",
          reasons.get(f"n1:{STAMP}:nodecl") == "DECLARATION_REQUIRED",
          str(reasons.get(f"n1:{STAMP}:nodecl")))
    check("declared outside the allowlist → SOURCE_NOT_AUTHORIZED",
          reasons.get(f"n1:{STAMP}:notauth") == "SOURCE_NOT_AUTHORIZED",
          str(reasons.get(f"n1:{STAMP}:notauth")))
    check("unsupported Zeek _path (ssl) → SOURCE_FORMAT_MISMATCH",
          reasons.get(f"n1:{STAMP}:badpath") == "SOURCE_FORMAT_MISMATCH",
          str(reasons.get(f"n1:{STAMP}:badpath")))
    check("record without Zeek connection identity → SOURCE_FORMAT_MISMATCH",
          reasons.get(f"n1:{STAMP}:noid") == "SOURCE_FORMAT_MISMATCH",
          str(reasons.get(f"n1:{STAMP}:noid")))

    # ── 3 · tenant crossing + duplicate replay ────────────────────
    print("\n== 3 · TENANT CROSSING ==")
    cross = envelope(col, f"n1:{STAMP}:cross", "zeek-json",
                     dns_record(DOMAIN, [ANSWER], uid=f"Cx{STAMP}"))
    cross["tenant_id"] = "nivx-live"
    code, body = deliver(key, [cross])
    detail = body.get("detail") if isinstance(body, dict) else {}
    check("an envelope naming another tenant is refused outright",
          code == 403 and (detail or {}).get("code")
          == "TENANT_ISOLATION_VIOLATION", f"{code} {detail}")
    check("the cross-tenant record produced no evidence",
          mongo()["xdr_canonical_evidence"].count_documents(
              {"network.flow_id": f"Cx{STAMP}"}) == 0)

    print("\n== 3b · DUPLICATE REPLAY ==")
    code, body = deliver(key, [
        envelope(col, dns_sei, "zeek-json", dns_record(DOMAIN, [ANSWER]))])
    data = body.get("data") or body
    check("a replayed delivery creates no second canonical event",
          data.get("duplicates") == 1 and data.get("accepted", 0) in (0, 1),
          f"duplicates={data.get('duplicates')}")

    # ── 4 · the canonical evidence itself ─────────────────────────
    print("\n== 4 · CANONICAL EVIDENCE (read-only) ==")
    db = mongo()
    dns_doc = db["xdr_canonical_evidence"].find_one(
        {"tenant_id": TEN, "network.dns_query": DOMAIN})
    conn_doc = db["xdr_canonical_evidence"].find_one(
        {"tenant_id": TEN, "network.flow_id": f"Cn1conn{STAMP}"})
    check("DNS evidence persisted", bool(dns_doc))
    check("connection evidence persisted", bool(conn_doc))
    if not (dns_doc and conn_doc):
        return 1
    dnet, cnet = dns_doc["network"], conn_doc["network"]
    check("the DNS ANSWER is canonical evidence (GAP-1)",
          dnet.get("dns_response_ips") == [ANSWER],
          str(dnet.get("dns_response_ips")))
    check("field-level provenance names the wire field",
          dnet["field_provenance"].get("dns_response_ips", "").startswith(
              "zeek:dns.log answers"),
          dnet["field_provenance"].get("dns_response_ips"))
    check("flow volume + state recorded",
          (cnet.get("bytes_sent"), cnet.get("conn_state"),
           cnet.get("duration_ms")) == (1811, "SF", 9750.0),
          f"{cnet.get('bytes_sent')}/{cnet.get('conn_state')}/"
          f"{cnet.get('duration_ms')}")
    check("activity time is the wire instant, not ingest",
          dns_doc["additional_fields"]["event_time_basis"] == "ACTIVITY_TIME"
          and dns_doc["additional_fields"]["event_time_substituted"] is False)
    check("no endpoint/process identity is invented",
          not (dns_doc.get("host") or {}).get("hostname")
          and not (conn_doc.get("process") or {}).get("name")
          and dns_doc["additional_fields"]["endpoint_identity_state"]
          == "NOT_OBSERVED")
    check("routing decision travels with the evidence",
          (dns_doc["provenance"]["routing"]["selected_dsm_id"] == "zeek-json"
           and dns_doc["provenance"]["routing"]["routing_authority"]
           == "AUTHENTICATED_COLLECTOR_DECLARATION"))

    # ── 5 · routing visibility (D21 surface, unchanged) ───────────
    print("\n== 5 · ROUTING VISIBILITY ==")
    code, body = call(
        "/api/xdr/ingest/routing/deliveries?limit=50&declared_source="
        f"zeek-json&tenant_id={TEN}", token=token)
    rows = (body.get("rows") or (body.get("data") or {}).get("rows") or [])
    zeek_rows = [r for r in rows
                 if r.get("declared_source_resolved") == "zeek-json"]
    check("the new source is visible on the existing D21 surface",
          code == 200 and bool(zeek_rows), f"{code} rows={len(zeek_rows)}")
    code, cat = call("/api/xdr/ingest/routing/catalog", token=token)
    declarable = [s.get("declared_source") for s in (cat.get("sources") or [])]
    check("zeek-json is declarable in the published catalog",
          "zeek-json" in declarable, str(declarable))

    # ── 6 · the relationship, through the EXISTING engine ─────────
    print("\n== 6 · DNS → RESOLVED IP → CONNECTION (correlation) ==")
    from detection_content.telemetry.network_signals import (
        signals_from_canonical)
    rel = find_rule(token, "DNS Answer Followed By Connection")
    burst = find_rule(token, "DNS Resolution Failure Burst")
    check("both network rules exist and ship DISABLED",
          bool(rel) and bool(burst) and not rel.get("enabled")
          and not burst.get("enabled"),
          f"rel_enabled={rel and rel.get('enabled')} "
          f"burst_enabled={burst and burst.get('enabled')}")
    if not (rel and burst):
        return 1
    call(f"/api/xdr/correlation/rules/{rel['id']}/enable", "POST",
         token=token, tenant=TEN)
    call(f"/api/xdr/correlation/rules/{burst['id']}/enable", "POST",
         token=token, tenant=TEN)

    signals = (signals_from_canonical(dns_doc)
               + signals_from_canonical(conn_doc))
    check("the projection produced one DNS-answer signal and one connection",
          len(signals) == 2
          and signals[0]["fields"]["network_peer_ip"] == ANSWER
          and signals[1]["fields"]["network_peer_ip"] == ANSWER)
    code, body = call("/api/xdr/correlation/signals", "POST", token=token,
                      tenant=TEN, body={"signals": signals})
    matches = ((body.get("data") or {}).get("matches") or [])
    supported = [m for m in matches
                 if m.get("correlation_id") == rel["id"]
                 and m.get("level") == "CORRELATION_SUPPORTED"]
    check("the relationship is SUPPORTED by the existing engine",
          bool(supported), f"{code} matches={len(matches)}")
    if supported:
        m = supported[0]
        cited = set(m.get("raw_event_ids") or [])
        check("the match CITES both canonical event ids",
              cited == {dns_doc["event_id"], conn_doc["event_id"]}, str(cited))
        check("the entity key is client + resolved address (not IP alone)",
              m.get("entity_key") == f"{CLIENT}|{ANSWER}", m.get("entity_key"))
        check("the engine emits evidence, never a verdict",
              m.get("capability_not_verdict") is True
              and "verdict" not in json.dumps(m).lower().replace(
                  "capability_not_verdict", ""))

    # A different client must NOT join the same address.
    other = dict(signals[1])
    other["fields"] = {**other["fields"], "client_ip": "10.77.0.99",
                       "network_peer_ip": ANSWER}
    other["source_event_id"] = "cev-foreign-client"
    _, body = call("/api/xdr/correlation/signals", "POST", token=token,
                   tenant=TEN, body={"signals": [other]})
    foreign = [m for m in ((body.get("data") or {}).get("matches") or [])
               if m.get("correlation_id") == rel["id"]
               and m.get("level") == "CORRELATION_SUPPORTED"]
    check("a different client does not inherit the relationship",
          not foreign, f"matches={len(foreign)}")

    # ── 7 · NXDOMAIN burst at its declared threshold ──────────────
    print("\n== 7 · NXDOMAIN BURST ==")
    threshold = int((burst.get("operators") or {}).get("threshold") or 10)
    # A client address unique to THIS run: the engine's window is real and
    # shared, so reusing an address would count an earlier run's evidence.
    nx_client = f"10.77.{(STAMP // 60) % 250}.{(STAMP % 240) + 5}"
    envs = [envelope(col, f"n1:{STAMP}:nx:{i}", "zeek-json",
                     dns_record(f"nx{i}-{STAMP}.example", [],
                                rcode="NXDOMAIN", ts=STAMP - 30 + i,
                                uid=f"Cnx{STAMP}{i}", client=nx_client))
            for i in range(threshold)]
    code, body = deliver(key, envs)
    data = body.get("data") or body
    check(f"{threshold} NXDOMAIN records accepted",
          data.get("accepted") == threshold, str(data.get("accepted")))
    nx_docs = list(db["xdr_canonical_evidence"].find(
        {"tenant_id": TEN, "network.flow_id": {"$regex": f"^Cnx{STAMP}"}}))
    check("every NXDOMAIN record is honest about having no answer",
          all(d["network"].get("dns_response_ips") == []
              and "dns_answer_absent_reason" in d["additional_fields"]
              for d in nx_docs), f"docs={len(nx_docs)}")
    nx_signals = [s for d in nx_docs for s in signals_from_canonical(d)]
    partial = nx_signals[:threshold - 1]
    _, body = call("/api/xdr/correlation/signals", "POST", token=token,
                   tenant=TEN, body={"signals": partial})
    below = [m for m in ((body.get("data") or {}).get("matches") or [])
             if m.get("correlation_id") == burst["id"]]
    check("below the declared threshold nothing fires", not below,
          f"matches={len(below)}")
    _, body = call("/api/xdr/correlation/signals", "POST", token=token,
                   tenant=TEN, body={"signals": nx_signals[threshold - 1:]})
    fired = [m for m in ((body.get("data") or {}).get("matches") or [])
             if m.get("correlation_id") == burst["id"]]
    check("at the threshold the burst is SUPPORTED and cites its evidence",
          bool(fired) and fired[0]["level"] == "CORRELATION_SUPPORTED"
          and len(fired[0].get("raw_event_ids") or []) >= threshold,
          f"cited={len(fired[0].get('raw_event_ids') or []) if fired else 0}")

    # ── 8 · leave preview as it was found ─────────────────────────
    print("\n== 8 · RESTORE ==")
    call(f"/api/xdr/correlation/rules/{rel['id']}/disable", "POST",
         token=token, tenant=TEN)
    call(f"/api/xdr/correlation/rules/{burst['id']}/disable", "POST",
         token=token, tenant=TEN)
    again = find_rule(token, "DNS Answer Followed By Connection")
    check("network content is disabled again",
          not again.get("enabled"), str(again.get("enabled")))

    findings = real_source_attempt()
    print(f"\n== RESULT: {'PASS' if ok else 'FAIL'} ==")
    print(f"== LIVE SOURCE: {findings['classification']} ==")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
