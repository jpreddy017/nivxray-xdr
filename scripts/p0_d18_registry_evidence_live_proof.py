#!/usr/bin/env python3
"""D18 · registry evidence over real HTTP (PREVIEW ONLY).

    raw registry observation
      -> canonical registry entity
      -> declared evaluated field
      -> predicate
      -> matched observed value
      -> evidence_ref
      -> detection

Delivered through the authenticated, DECLARED (D15) ingest path:

  1. Sysmon EventID 13 writing HKLM\\…\\CurrentVersion\\Run  -> DET-PS-001
     fires on OBSERVED registry evidence, cited on registry.key_path
  2. Windows Security 4657 modifying the same Run value      -> same rule,
     same citation class, different source
  3. a benign Sysmon 13 theme write                          -> registry
     evidence recorded, NO persistence detection
  4. `reg add …\\Run` as a process command line              -> DET-PS-005
     (INFERENCE) fires and cites process.command_line, and NO registry
     entity is manufactured

TEST/SYNTHETIC payloads. NOT LIVE — no real Windows host is connected.
Nothing touches production.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")
BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
STAMP = int(time.time())
TENANT = "t-d18-registry"
RUN_KEY = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
VALUE = f"Updater{STAMP}"
DATA = f"C:\\temp\\evil-{STAMP}.exe"
CMD = f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run " \
      f"/v CliOnly{STAMP} /d C:\\temp\\cli-{STAMP}.exe /f"

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
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


SOURCES = ["microsoft-sysmon", "windows-security-evd"]


def env(col, sei, declared, raw):
    return {"tenant_id": TENANT, "collector_id": col,
            "source_event_id": sei, "collection_method": "rest",
            "source": "d18-proof-host", "declared_source": declared,
            "raw": raw}


def main() -> int:
    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]
    print("login: 200\n1 · provision TEST collector + key")
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=TENANT, body={
                          "name": "d18-proof-collector", "protocol": "rest",
                          "authorized_sources": SOURCES,
                          "tenant_id": TENANT, "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True})
    if code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col = next((c["id"] for c in
                    ((lst.get("data") or {}).get("collectors") or [])
                    if c.get("name") == "d18-proof-collector"), None)
    elif code in (200, 201):
        d = body.get("data") or body
        col = d.get("id") or (d.get("collector") or {}).get("id")
    else:
        print(f"  collector create -> {code} {body}")
        return 1
    if col:
        call(f"/api/xdr/collectors/{col}", "PUT", token=token, tenant=TENANT,
             body={"authorized_sources": SOURCES})
    code, body = call("/api/xdr/api-keys", "POST", token=token,
                      tenant=TENANT, body={
                          "name": f"d18-proof-key-{STAMP}",
                          "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True,
                          "scopes": ["collectors.enroll", "collectors.read"]})
    _d = body.get("data") or {}
    key = (_d.get("api_key") or _d.get("key") or _d.get("secret")
           or _d.get("plaintext") or _d.get("token") or _d.get("value"))
    check("collector + ingest key ready", bool(col and key), col)
    if not key:
        return 1

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ev = db.xdr_canonical_evidence
    matches = db.xdr_detection_matches

    print("\n2 · deliver observed registry telemetry + a benign write + a "
          "command-line request")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [
                          env(col, f"d18:{STAMP}:sysmon13",
                              "microsoft-sysmon", {
                                  "EventID": 13,
                                  "provider": "Microsoft-Windows-Sysmon",
                                  "Computer": "WIN-SRV-18",
                                  "User": "CORP\\admin",
                                  "UtcTime": "2026-06-01T10:00:00+00:00",
                                  "Image": "C:\\Windows\\System32\\reg.exe",
                                  "ProcessId": "5150",
                                  "EventType": "SetValue",
                                  "TargetObject": f"{RUN_KEY}\\{VALUE}",
                                  "Details": DATA}),
                          env(col, f"d18:{STAMP}:win4657",
                              "windows-security-evd", {
                                  "EventID": 4657,
                                  "provider": "Microsoft-Windows-Security-"
                                              "Auditing",
                                  "channel": "Security",
                                  "Computer": "WIN-DC-18",
                                  "TimeCreated": "2026-06-01T10:00:02+00:00",
                                  "EventData": {
                                      "ObjectName": RUN_KEY,
                                      "ObjectValueName": VALUE,
                                      "OperationType": "%%1905",
                                      "NewValue": DATA,
                                      "NewValueType": "REG_SZ",
                                      "ProcessName":
                                          "C:\\Windows\\System32\\reg.exe",
                                      "ProcessId": "0x141e",
                                      "SubjectUserName": "admin",
                                      "SubjectDomainName": "CORP",
                                      "HandleId": "0x2d8"}}),
                          env(col, f"d18:{STAMP}:benign",
                              "microsoft-sysmon", {
                                  "EventID": 13,
                                  "provider": "Microsoft-Windows-Sysmon",
                                  "Computer": "WIN-SRV-18",
                                  "User": "CORP\\user1",
                                  "UtcTime": "2026-06-01T10:00:04+00:00",
                                  "Image": "C:\\Windows\\explorer.exe",
                                  "ProcessId": "900",
                                  "EventType": "SetValue",
                                  "TargetObject":
                                      "HKCU\\Software\\Microsoft\\Windows\\"
                                      f"CurrentVersion\\Themes\\Theme{STAMP}",
                                  "Details": "dark"}),
                          env(col, f"d18:{STAMP}:cli",
                              "microsoft-sysmon", {
                                  "EventID": 1,
                                  "provider": "Microsoft-Windows-Sysmon",
                                  "Computer": "WIN-SRV-18",
                                  "User": "CORP\\admin",
                                  "UtcTime": "2026-06-01T10:00:06+00:00",
                                  "Image": "C:\\Windows\\System32\\reg.exe",
                                  "ProcessId": "5151",
                                  "CommandLine": CMD})]})
    check("ingest accepted", code == 200, f"HTTP {code} {str(body)[:200]}")
    if code != 200:
        return 1
    data = body.get("data") or body
    outs = {o.get("source_event_id"): o for o in (data.get("reasoning") or [])}
    print("  outcomes: " + str([(k.rsplit(':', 1)[-1], o.get("status"),
                                 o.get("detection"),
                                 o.get("detections_matched"))
                                for k, o in outs.items()]))
    check("all four were reasoned",
          all(o.get("status") == "REASONED" for o in outs.values()),
          str([o.get("status") for o in outs.values()]))
    time.sleep(2)

    print("\n3 · observed registry evidence, with per-field provenance")
    row = ev.find_one({"tenant_id": TENANT,
                       "source_product": "Sysmon",
                       "registry.target_object": f"{RUN_KEY}\\{VALUE}"},
                      sort=[("_id", -1)])
    check("canonical registry evidence exists", bool(row))
    if not row:
        return 1
    reg = row.get("registry") or {}
    m = (row.get("additional_fields") or {}).get("registry_mapping") or {}
    print(f"  registry: key={reg.get('key_path')!r} value="
          f"{reg.get('value_name')!r} action={reg.get('action')!r} "
          f"hive={reg.get('hive')!r}")
    check("the key path is the observed Run key",
          reg.get("key_path") == RUN_KEY, str(reg.get("key_path")))
    check("the value name and data are the observed ones",
          reg.get("value_name") == VALUE and reg.get("value_data") == DATA)
    check("the operation comes from Sysmon's own EventType",
          reg.get("action") == "set_value")
    check("the evidence class is declared",
          m.get("evidence_class") == "OBSERVED_REGISTRY_TELEMETRY",
          str(m.get("evidence_class")))
    fields = m.get("fields") or {}
    check("every mapped field carries a state and a source",
          fields and all(f.get("state") and f.get("source")
                         for f in fields.values()),
          str(sorted(fields)))
    check("the key/value split is declared DERIVED, not observed",
          (fields.get("key_path") or {}).get("state") == "DERIVED"
          and (fields.get("key_path") or {}).get("basis"))
    check("the value TYPE is NOT_OBSERVED for Sysmon, with a reason",
          (fields.get("value_type") or {}).get("state") == "NOT_OBSERVED"
          and (fields.get("value_type") or {}).get("reason"))
    assoc = m.get("associations") or {}
    check("the acting process, device and user are associated",
          (assoc.get("process") or {}).get("value")
          == "C:\\Windows\\System32\\reg.exe"
          and (assoc.get("device") or {}).get("value") == "WIN-SRV-18"
          and (assoc.get("identity") or {}).get("value") == "CORP\\admin",
          str({k: v.get("value") for k, v in assoc.items()}))
    check("the raw reference points back at the source record",
          (m.get("raw_reference") or {}).get("target_object")
          == f"{RUN_KEY}\\{VALUE}")
    check("D12 semantics unchanged: Sysmon states the activity time",
          (row.get("additional_fields") or {}).get("event_time_basis")
          == "ACTIVITY_TIME")
    check("D14 unchanged: the authenticated tenant owns it",
          row.get("tenant_id") == TENANT)

    print("\n4 · the declared field is what the detection cites")
    cit = matches.find_one({"tenant_id": TENANT, "rule_id": "DET-PS-001",
                            "canonical_event_id": row.get("event_id")},
                           sort=[("_id", -1)])
    check("the persistence rule fired on OBSERVED registry evidence",
          bool(cit))
    if cit:
        print(f"  citation: {cit.get('declaration_state')} / "
              f"{cit.get('citation_completeness')} · "
              f"{[c['canonical_field'] for c in cit.get('matched_conditions') or []]}")
        check("it is DECLARED and complete",
              cit.get("declaration_state") == "DECLARED"
              and cit.get("citation_completeness") == "CITED")
        cited = cit.get("matched_conditions") or []
        check("every cited field is a registry field",
              cited and all(c["canonical_field"].startswith("registry.")
                            for c in cited),
              str([c["canonical_field"] for c in cited]))
        check("the cited value is the key the source actually observed",
              any(RUN_KEY.lower() in str(c.get("observed_value", "")).lower()
                  for c in cited))
        check("the evidence_ref resolves to that evidence",
              bool(ev.find_one({"event_id": cit.get("canonical_event_id")})))
        check("the declaration version travelled with the match",
              cit.get("rule_version") == "2", str(cit.get("rule_version")))

    print("\n5 · Windows 4657 proves the same thing from a second source")
    w = ev.find_one({"tenant_id": TENANT,
                     "event_type": "registry_value_modified"},
                    sort=[("_id", -1)])
    check("4657 produced canonical registry evidence", bool(w))
    if w:
        wreg = w.get("registry") or {}
        check("its key/value/type are the observed ones",
              wreg.get("key_path") == RUN_KEY
              and wreg.get("value_name") == VALUE
              and wreg.get("value_type") == "REG_SZ", str(wreg))
        check("its operation came from OperationType %%1905",
              wreg.get("action") == "set_value")
        check("EVTX still refuses to claim an activity time",
              (w.get("additional_fields") or {}).get("event_time_basis")
              == "OBSERVATION_TIME")
        check("the same rule fired on it",
              bool(matches.find_one({"tenant_id": TENANT,
                                     "rule_id": "DET-PS-001",
                                     "canonical_event_id":
                                         w.get("event_id")})))

    print("\n6 · benign registry activity is recorded, NOT detected")
    b = ev.find_one({"tenant_id": TENANT,
                     "registry.key_path":
                         {"$regex": "CurrentVersion\\\\\\\\Themes"}},
                    sort=[("_id", -1)])
    if not b:
        b = ev.find_one({"tenant_id": TENANT,
                         "registry.value_name": f"Theme{STAMP}"},
                        sort=[("_id", -1)])
    check("the benign write produced registry evidence", bool(b),
          str((b or {}).get("registry", {}).get("key_path")))
    if b:
        check("and no persistence detection was raised for it",
              matches.count_documents(
                  {"canonical_event_id": b.get("event_id"),
                   "rule_id": "DET-PS-001"}) == 0)

    print("\n7 · a command line is NOT registry telemetry")
    c = ev.find_one({"tenant_id": TENANT, "process.command_line": CMD},
                    sort=[("_id", -1)])
    check("the process evidence exists", bool(c))
    if c:
        creg = c.get("registry") or {}
        check("NO registry entity was manufactured from the command line",
              not creg.get("key_path") and not creg.get("action")
              and not creg.get("target_object"), str(creg))
        check("no registry mapping was attached either",
              "registry_mapping" not in (c.get("additional_fields") or {}))
        check("the observed-registry rule stayed silent",
              matches.count_documents(
                  {"canonical_event_id": c.get("event_id"),
                   "rule_id": "DET-PS-001"}) == 0)
        infer = matches.find_one({"canonical_event_id": c.get("event_id"),
                                  "rule_id": "DET-PS-005"})
        check("the INFERENCE rule fired instead", bool(infer))
        if infer:
            fields = [x["canonical_field"]
                      for x in infer.get("matched_conditions") or []]
            print(f"  inference citation: {fields}")
            check("and it cites the command line, not the registry",
                  fields and all(f == "process.command_line"
                                 for f in fields), str(fields))

    print("\n" + ("D18 REGISTRY EVIDENCE: PASS" if ok
                  else "D18 REGISTRY EVIDENCE: FAIL"))
    print("TEST/SYNTHETIC payloads. NOT LIVE. Preview only, nothing "
          "deployed.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
