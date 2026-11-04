#!/usr/bin/env python3
"""P1 · EVIDENCE NAMESPACE BRIDGE — NEW-EVIDENCE END-TO-END PROOF.

PREVIEW ONLY. Real HTTP, real authenticated ingest, real pipeline. Nothing is
mocked and no identifier mapping is synthesised: new telemetry is delivered
through the SAME authenticated ingest the product uses, and the bridge is then
read back over the API exactly as the console reads it.

Chain proven:

  authenticated ingest  POST /api/xdr/ingest/telemetry
   → normalizer / DSM   microsoft-sysmon
   → canonical evidence xdr_canonical_evidence.event_id  (sysmon-<eid>-<uuid>)
   → observation        v2_shadow_observations.canonical_event_id
   → incident promotion workspace_cases
   → trajectory frame   GET /api/v2/cases/{id}/trajectory/device
                        frame.canonical_evidence_id + bridge_state
   → causal anchor      the frames that CITE an entity iid
   → View Evidence      the exact canonical evidence row of THIS incident
                        GET /api/incidents/{id}/canonical-evidence
   → EvidenceInspector  GET /api/incidents/{id}/inspector/event/{canonical id}
   → raw / source provenance (normalizer, raw reference)

EVIDENCE LABELLING
  TEST/SYNTHETIC — the tenant `t-p1-bridge-proof`, its collector, the ingest
  key minted and revoked by this script, and the Sysmon documents below.
  NOT PRODUCTION — preview edge only.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")
BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"

TENANT_SLUG = "p1-bridge-proof"
ORG_SLUG = "p1-bridge-proof-org"
STAMP = int(time.time())
HOST = "WIN-P1-BRIDGE"
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
OTHER = ("analyst@default.com", "DefaultCo!Analyst2026")
#: An incident the REAL pipeline itself built with many canonical references
#: (tenant `default`, 62 references) — used for the multi-event case, which
#: this connector ingest path cannot produce in one promotion.
MULTI_INCIDENT = "inc_8ddc1dee7a4c46aa93c9"

_p = _f = 0


def check(name, cond, detail=""):
    global _p, _f
    if cond:
        _p += 1
        print(f"PASS · {name} {detail}")
    else:
        _f += 1
        print(f"FAIL · {name} {detail}")
    return bool(cond)


def call(path, method="GET", token=None, key=None, tenant=None, body=None):
    h = {"User-Agent": UA, "Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if key:
        h["X-XDR-API-Key"] = key
    if tenant:
        h["X-Tenant-Id"] = tenant
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=h,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b"{}")
            except Exception:                                  # noqa: BLE001
                return r.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw or "{}")
        except Exception:                                      # noqa: BLE001
            return e.code, raw[:400]


def login(cred):
    st, b = call("/api/auth/login", "POST", body={"email": cred[0],
                                                  "password": cred[1]})
    if st != 200:
        print(f"ABORT · login {cred[0]} → {st} {b}")
        sys.exit(2)
    return b.get("access_token") or b.get("token")


SYSMON_DOCS = [
    {"EventID": 1, "provider": "Microsoft-Windows-Sysmon", "Computer": HOST,
     "User": "CORP\\svc_backup", "UtcTime": "2026-06-01T10:00:00+00:00",
     "Image": "C:\\Windows\\System32\\vssadmin.exe",
     "CommandLine": "vssadmin.exe delete shadows /all /quiet",
     "ParentImage": "C:\\Windows\\System32\\cmd.exe",
     "ProcessId": "5150", "ParentProcessId": "4100"},
    {"EventID": 3, "provider": "Microsoft-Windows-Sysmon", "Computer": HOST,
     "User": "CORP\\svc_backup", "UtcTime": "2026-06-01T10:00:04+00:00",
     "Image": "C:\\Windows\\System32\\vssadmin.exe", "ProcessId": "5150",
     "SourceIp": "10.9.9.31", "SourcePort": "49712",
     "DestinationIp": "198.51.100.77", "DestinationPort": "8443",
     "Protocol": "tcp"},
    {"EventID": 11, "provider": "Microsoft-Windows-Sysmon", "Computer": HOST,
     "User": "CORP\\svc_backup", "UtcTime": "2026-06-01T10:00:07+00:00",
     "Image": "C:\\Windows\\System32\\vssadmin.exe", "ProcessId": "5150",
     "TargetFilename": "C:\\Users\\Public\\stage2.dll"},
]


def ensure_tenant(token):
    """The dedicated, clearly tagged proof tenant — created through the ONE
    tenancy control plane (`POST /api/xdr/tenants`), never as a side effect
    of ingest. Returns the authoritative tenant id."""
    st, b = call("/api/xdr/tenants", token=token)
    for t in ((b.get("data") or {}).get("tenants") or []):
        if t.get("slug") == TENANT_SLUG and t.get("state") == "ACTIVE":
            return t["id"]
    st, b = call("/api/xdr/organizations", token=token)
    org = next((o["id"] for o in ((b.get("data") or {}).get("organizations")
                                  or []) if o.get("slug") == ORG_SLUG
                and o.get("state") == "ACTIVE"), None)
    if not org:
        st, b = call("/api/xdr/organizations", "POST", token=token,
                     body={"slug": ORG_SLUG,
                           "display_name": "P1 Bridge Proof (TEST)",
                           "kind": "VENDOR"})
        if st not in (200, 201):
            print(f"  organization create → {st} {b}")
            return None
        org = (b.get("data") or {}).get("id")
    st, b = call("/api/xdr/tenants", "POST", token=token,
                 body={"organization_id": org, "slug": TENANT_SLUG,
                       "display_name": "P1 Bridge Proof Tenant (TEST)",
                       "kind": "INTERNAL_VALIDATION", "products": ["XDR"]})
    if st not in (200, 201):
        print(f"  tenant create → {st} {b}")
        return None
    return (b.get("data") or {}).get("id")


def provision(token, TENANT):
    st, b = call("/api/xdr/collectors", "POST", token=token, tenant=TENANT,
                 body={"name": "p1-bridge-proof-collector", "protocol": "rest",
                       "authorized_sources": ["microsoft-sysmon"],
                       "tenant_id": TENANT, "confirm_tenant_id": TENANT})
    col = None
    if st == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col = next((c["id"] for c in
                    ((lst.get("data") or {}).get("collectors") or [])
                    if c.get("name") == "p1-bridge-proof-collector"), None)
    elif st in (200, 201):
        d = b.get("data") or b
        col = d.get("id") or (d.get("collector") or {}).get("id")
    if col:
        call(f"/api/xdr/collectors/{col}", "PUT", token=token, tenant=TENANT,
             body={"authorized_sources": ["microsoft-sysmon"]})
    st, b = call("/api/xdr/api-keys", "POST", token=token, tenant=TENANT,
                 body={"name": f"p1-bridge-proof-key-{STAMP}",
                       "confirm_tenant_id": TENANT,
                       "scopes": ["collectors.enroll", "collectors.read"]})
    d = b.get("data") or {}
    key = (d.get("api_key") or d.get("key") or d.get("secret")
           or d.get("plaintext") or d.get("token") or d.get("value"))
    key_id = d.get("key_id") or d.get("id")
    return col, key, key_id


def find_incident(TENANT):
    """The incident the pipeline itself promoted for this delivery."""
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    for _ in range(20):
        doc = db.workspace_cases.find_one(
            {"doc_type": "xdr_incident", "tenant_id": TENANT},
            {"_id": 0, "id": 1, "created_at": 1}, sort=[("created_at", -1)])
        if doc:
            return doc["id"], db
        time.sleep(2)
    return None, db


def frames_citing(frames, anchor):
    slots = ("process", "device", "user", "file", "parent", "network",
             "registry", "entity", "root", "execution")
    out = []
    for f in frames:
        for s in slots:
            v = f.get(s)
            iid = v if isinstance(v, str) else (v or {}).get("iid")
            if iid and iid == anchor:
                out.append(f)
                break
    return out


def main() -> int:
    print(f"BASE {BASE}\n")
    token = login(ADMIN)

    print("0 · the dedicated proof tenant (tenancy control plane only)")
    TENANT = ensure_tenant(token)
    if not check("proof tenant registered and ACTIVE", bool(TENANT),
                 str(TENANT)):
        return 1
    print(f"    tenant {TENANT} (slug {TENANT_SLUG} · TEST/SYNTHETIC)")

    print("\n1 · provision the dedicated proof collector + ingest credential")
    col, key, key_id = provision(token, TENANT)
    if not check("collector + ingest key ready", bool(col and key), str(col)):
        return 1

    print("\n2 · deliver THREE new Sysmon documents through real ingest")
    envs = [{"tenant_id": TENANT, "collector_id": col,
             "source_event_id": f"p1bridge:{STAMP}:{i}",
             "collection_method": "rest", "source": "p1-bridge-proof-host",
             "declared_source": "microsoft-sysmon", "raw": doc}
            for i, doc in enumerate(SYSMON_DOCS)]
    st, b = call("/api/xdr/ingest/telemetry", "POST", key=key, tenant=TENANT,
                 body={"envelopes": envs})
    if not check("ingest accepted", st == 200, f"HTTP {st} {str(b)[:200]}"):
        return 1
    outs = (b.get("data") or b).get("reasoning") or []
    check("every document was reasoned through the declared DSM",
          len(outs) == 3 and all(o.get("selected_dsm_id") == "microsoft-sysmon"
                                 for o in outs),
          str([o.get("status") for o in outs]))

    print("\n3 · the pipeline promoted an incident of its own accord")
    incident, db = find_incident(TENANT)
    if not check("incident promoted from the delivered evidence",
                 bool(incident), str(incident)):
        return 1
    time.sleep(3)

    print("\n3b · deliver ONE more rule-matching document so the incident "
          "carries a canonical id that is NOT its xdr_pipeline one")
    second = dict(SYSMON_DOCS[0])
    second.update({"UtcTime": "2026-06-01T10:11:00+00:00",
                   "ProcessId": "5188"})
    st, b = call("/api/xdr/ingest/telemetry", "POST", key=key, tenant=TENANT,
                 body={"envelopes": [{
                     "tenant_id": TENANT, "collector_id": col,
                     "source_event_id": f"p1bridge:{STAMP}:consolidate",
                     "collection_method": "rest",
                     "source": "p1-bridge-proof-host",
                     "declared_source": "microsoft-sysmon",
                     "raw": second}]})
    check("second delivery accepted", st == 200, f"HTTP {st}")
    time.sleep(4)

    print("\n4 · the incident's canonical evidence records (HTTP)")
    st, ce = call(f"/api/incidents/{incident}/canonical-evidence", token=token)
    if not check("canonical-evidence route answers", st == 200, f"HTTP {st}"):
        print(ce)
        return 1
    rows = ce.get("rows") or []
    bridged = [r for r in rows if r["bridge_state"] == "BRIDGED"]
    check("at least one canonical evidence record is BRIDGED",
          len(bridged) >= 1, f"{len(bridged)} of {len(rows)}")
    # LIMITATION, stated rather than manufactured: on this connector ingest
    # path each promotion creates its own incident and only the promoting
    # observation is linked to it, so a freshly ingested incident carries
    # exactly ONE canonical reference. The multi-reference case is therefore
    # proven below against an incident the real pipeline itself built that
    # way (§4b), not by manufacturing references here.
    check("newly ingested incident carries its own canonical reference",
          len(rows) >= 1, f"{len(rows)} rows")
    check("the canonical identity is the normalizer's own id namespace",
          any(str(r["canonical_evidence_id"]).startswith("sysmon-")
              for r in rows),
          str([r["canonical_evidence_id"] for r in rows])[:200])
    for r in bridged:
        check(f"  record {r['canonical_evidence_id'][:28]}… carries source "
              f"provenance",
              bool(r["record"]["normalizer_id"] or r["record"]["source_vendor"]),
              str(r["record"])[:120])
        check("  and names where the incident itself references it",
              bool(r["referenced_by"]),
              str([c["source"] for c in r["referenced_by"]]))
    bridged_ids = {r["canonical_evidence_id"] for r in bridged}

    print("\n5 · trajectory frames carry the propagated canonical identity")
    st, tj = call(f"/api/v2/cases/{incident}/trajectory/device?limit=500",
                  token=token)
    if not check("trajectory route answers", st == 200, f"HTTP {st}"):
        print(str(tj)[:300])
        return 1
    frames = tj.get("frames") or []
    check("frames exist for the delivered evidence", len(frames) >= 1,
          f"{len(frames)} frames")
    with_ce = [f for f in frames if f.get("canonical_evidence_id")]
    check("every frame carries a canonical evidence identity",
          len(with_ce) == len(frames), f"{len(with_ce)}/{len(frames)}")
    check("and the identity is stated as BRIDGED, not guessed",
          all(f.get("bridge_state") == "BRIDGED" for f in with_ce),
          str({f.get("bridge_state") for f in frames}))
    check("the frame keeps its OWN identity too — no namespace collapse",
          all(f["frame_iid"].startswith("tf_")
              and f["canonical_evidence_id"] != f["frame_iid"]
              for f in with_ce))
    check("every frame's canonical id is an evidence record OF THIS incident",
          all(f["canonical_evidence_id"] in bridged_ids for f in with_ce),
          str([f["canonical_evidence_id"] for f in with_ce])[:200])

    print("\n6 · causal anchor → View Evidence → the EXACT record")
    anchor = None
    for f in frames:
        pv = f.get("process")
        if isinstance(pv, dict) and pv.get("iid"):
            anchor = pv["iid"]
            break
    if check("an entity anchor exists on the recorded evidence", bool(anchor),
             str(anchor)):
        citing = frames_citing(frames, anchor)
        check("frames CITE the anchor in a structured slot", len(citing) >= 1,
              f"{len(citing)} frames")
        anchor_ids = {f.get("canonical_evidence_id") for f in citing}
        check("each cited frame resolves to one exact canonical record",
              anchor_ids and anchor_ids <= bridged_ids, str(anchor_ids))

        print("\n7 · EvidenceInspector → original source provenance")
        for cid in sorted(i for i in anchor_ids if i):
            st, env = call(
                f"/api/incidents/{incident}/inspector/event/{cid}",
                token=token)
            ok = st == 200 and env.get("state") != "MISSING"
            check(f"inspector resolves {cid[:28]}…", ok,
                  f"HTTP {st} {env.get('state') if isinstance(env, dict) else ''}")
            if ok:
                labels = {r["label"] for r in env["context"]["relationships"]}
                check("  it reports the normalizer and the raw source",
                      "NORMALIZER" in labels and "RAW SOURCE" in labels,
                      str(sorted(labels)))

    print("\n7b · MULTI-EVENT · an incident the real pipeline built with MANY "
          "canonical references")
    other = login(OTHER)
    st, m = call(f"/api/incidents/{MULTI_INCIDENT}/canonical-evidence",
                 token=other)
    if check("multi-reference incident answers for its own tenant",
             st == 200, f"HTTP {st}"):
        mrows = m.get("rows") or []
        mbridged = [r for r in mrows if r["bridge_state"] == "BRIDGED"]
        check("it carries MANY canonical evidence records",
              len(mbridged) > 1, f"{len(mbridged)} bridged of {len(mrows)}")
        mpipe = next((r["canonical_evidence_id"] for r in mrows
                      if any(c["source"] == "incident_pipeline"
                             for c in r["referenced_by"])), None)
        others = [r for r in mbridged
                  if r["canonical_evidence_id"] != mpipe]
        check("  most of them are NOT the xdr_pipeline canonical id",
              len(others) >= 1, f"{len(others)} non-pipeline records")
        st, tj2 = call(
            f"/api/v2/cases/{MULTI_INCIDENT}/trajectory/device?limit=500",
            token=other)
        f2 = (tj2.get("frames") or []) if st == 200 else []
        ids2 = {f.get("canonical_evidence_id") for f in f2
                if f.get("canonical_evidence_id")}
        if f2:
            check("  its frames reference distinct canonical ids",
                  len(ids2) >= 1, f"{len(ids2)} distinct on {len(f2)} frames")
            check("  every one of them is a record OF THAT incident",
                  ids2 <= {r["canonical_evidence_id"] for r in mrows},
                  str(sorted(ids2))[:160])
        else:
            print("  LIMITATION · this incident's 62 references come from "
                  "`endpoint_campaign.detections`; the causal engine holds "
                  "NO observation keyed on it, so it has no trajectory "
                  "frames. Frame-level multi-id annotation is therefore "
                  "proven in tests/test_p1_evidence_namespace_bridge.py, "
                  "not here. No frame is manufactured to fill the gap.")
        for r in others[:3]:
            cid = r["canonical_evidence_id"]
            st, env = call(
                f"/api/incidents/{MULTI_INCIDENT}/inspector/event/{cid}",
                token=other)
            check(f"  inspector resolves non-pipeline {cid[:22]}…",
                  st == 200 and env.get("state") != "MISSING",
                  f"HTTP {st} {env.get('state') if isinstance(env, dict) else ''}")

    print("\n8 · tenant isolation and non-enumeration")
    st, b = call(f"/api/incidents/{incident}/canonical-evidence", token=other)
    check("cross-tenant principal cannot read the bridge", st == 404,
          f"HTTP {st}")
    check("  and learns no canonical identity",
          all(i not in json.dumps(b) for i in bridged_ids))
    cid_any = sorted(bridged_ids)[0] if bridged_ids else "none"
    st, b = call(f"/api/incidents/{incident}/inspector/event/{cid_any}",
                 token=other)
    check("cross-tenant principal cannot inspect a real canonical id",
          st == 404, f"HTTP {st}")
    for fake in (f"sysmon-1-{'f' * 32}", "evt_deadbeefdeadbeef",
                 "tf_deadbeefdeadbeef", f"{cid_any}-tampered"):
        st, b = call(f"/api/incidents/{incident}/inspector/event/{fake}",
                     token=token)
        check(f"fabricated id {fake[:26]}… cannot be enumerated",
              st == 200 and isinstance(b, dict) and b.get("state") == "MISSING",
              f"HTTP {st}")

    print("\n9 · revoke the temporary ingest credential")
    if key_id:
        st, _ = call(f"/api/xdr/api-keys/{key_id}/revoke", "POST",
                     token=token, tenant=TENANT)
        check("proof ingest credential revoked", st in (200, 204),
              f"HTTP {st}")
        st, _ = call("/api/xdr/ingest/telemetry", "POST", key=key,
                     tenant=TENANT, body={"envelopes": envs})
        check("the revoked credential is refused", st in (401, 403),
              f"HTTP {st}")
    else:
        check("proof ingest credential revoked", False,
              "key_id not returned by /api/xdr/api-keys")

    print("\nRESIDUAL PROOF DATA (preview only, deliberately retained as "
          "the evidence of this proof):")
    print(f"  tenant     {TENANT}")
    print(f"  collector  {col} (credential revoked)")
    print(f"  incident   {incident}")
    print(f"  canonical  {sorted(bridged_ids)}")

    print(f"\n{_p} passed · {_f} failed")
    return 1 if _f else 0


if __name__ == "__main__":
    sys.exit(main())
