#!/usr/bin/env python3
"""GATE 5 + GATE 7 + connector productization · live end-to-end proof.

Drives the REAL HTTP surface on the preview host:

  Management -> Downloads -> release -> group -> policy -> deployment
  -> install (enrol) -> register -> policy DELIVERED -> ACK -> APPLIED
  -> second ACK -> VERIFIED -> new version -> OUT_OF_SYNC

and then Gate 7:

  exclusion set -> exclusion -> self-approval refused -> approved by a
  second operator -> enforcement-proof shows the engine bypassed

Every assertion is about what the SERVER reported. Nothing is asserted
locally.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("NIVX_BASE") or ""
if not BASE:
    with open("/app/frontend/.env") as fh:
        for line in fh:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE = line.split("=", 1)[1].strip()
API = BASE.rstrip("/") + "/api"
TENANT = os.environ.get("NIVX_TENANT", "default")

ADMIN = ("admin@nivxray.com", os.environ.get("NIVXPW",
                                             "uulVDp5cCSB3Hva99s7UUAwK"))
APPROVER = ("approver@nivxray.com",
            os.environ.get("NIVX_APPROVER_PASSWORD",
                           "AppRoVe-Excl-2026-nvx"))

FAILURES: list[str] = []


def call(method: str, path: str, *, token=None, tenant=True, body=None,
         expect=200):
    url = f"{API}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0 (NivXForge-Gate-Proof)")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if tenant:
        req.add_header("X-Tenant-Id", TENANT)
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            status, payload = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, payload = e.code, e.read().decode()
    try:
        parsed = json.loads(payload)
    except ValueError:
        parsed = {"_raw": payload[:400]}
    if status != expect:
        FAILURES.append(f"{method} {path} -> {status} (expected {expect}): "
                        f"{json.dumps(parsed)[:300]}")
    return status, parsed


def check(label: str, condition: bool, detail: str = "") -> None:
    print(("  PASS  " if condition else "  FAIL  ") + label
          + (f"   [{detail}]" if detail else ""))
    if not condition:
        FAILURES.append(f"{label} {detail}")


def login(creds):
    _s, d = call("POST", "/auth/login", tenant=False,
                 body={"email": creds[0], "password": creds[1]})
    return d.get("access_token") or d.get("token")


def main() -> int:
    stamp = str(int(time.time()))
    admin = login(ADMIN)
    check("admin authenticated", bool(admin))
    approver = login(APPROVER)
    check("second operator authenticated", bool(approver),
          "run scripts/seed_edr_approver.py first" if not approver else "")

    print("\n── connector release catalog ──")
    _s, rel = call("GET", "/edr/connector/releases", token=admin)
    published = [r for r in rel["releases"]
                 if r["artifact_state"] == "PUBLISHED"]
    check("at least one release reports a real published artifact",
          bool(published), f"published={len(published)}/{rel['count']}")
    check("no release requires a per-endpoint rebuild",
          all(not r["rebuild_required_per_endpoint"]
              for r in rel["releases"]))
    unpublished = [r for r in rel["releases"]
                   if r["artifact_state"] != "PUBLISHED"]
    check("releases without an artifact say ARTIFACT_NOT_PUBLISHED",
          all(r["artifact_state"].startswith("ARTIFACT_")
              for r in unpublished),
          f"{[r['artifact_state'] for r in unpublished]}")
    release_id = published[0]["release_id"]
    artifact_identity = published[0]["artifact_identity"]

    print("\n── group + policy authority ──")
    _s, group = call("POST", "/edr/groups", token=admin,
                     body={"name": f"E2E Windows {stamp}",
                           "description": "gate 5 live proof"})
    group_id = group["id"]
    _s, pol = call("POST", "/edr/policies", token=admin, body={
        "name": f"E2E Detect Only {stamp}", "os": "WINDOWS",
        "description": "gate 5 live proof",
        "config": {"mode": "DETECT_ONLY", "report_interval_seconds": 30,
                   "collect_process_events": True}})
    policy_id = pol["policy"]["id"]
    digest_v1 = pol["version"]["config_digest"]
    check("new policy starts at CREATED", pol["state"] == "CREATED",
          pol["state"])
    _s, asg = call("POST", f"/edr/policies/{policy_id}/assign", token=admin,
                   body={"scope_type": "GROUP", "scope_id": group_id})
    check("assignment reports ASSIGNED and nothing more",
          asg["state"] == "ASSIGNED", asg["state"])

    print("\n── deployment context around the RELEASED artifact ──")
    _s, dep = call("POST", "/edr/connector/deployments", token=admin, body={
        "release_id": release_id, "group_id": group_id,
        "label": f"e2e {stamp}", "ttl_seconds": 3600})
    check("deployment resolved the group's policy",
          dep["policy_preview"].get("policy_id") == policy_id,
          str(dep["policy_preview"]))
    check("deployment did not rebuild the connector",
          dep["artifact"]["artifact_identity"] == artifact_identity
          and dep["artifact"]["rebuild_required_per_endpoint"] is False)
    check("enrolment credential returned exactly once",
          bool(dep.get("enrollment_token")))
    token_plain = dep["enrollment_token"]

    print("\n── install = enrol, with the group carried by the credential ──")
    _s, enrolled = call("POST", "/edr/agent/enroll", tenant=False, body={
        "tenant_id": TENANT, "enrollment_token": token_plain,
        "hostname": f"E2E-WIN-{stamp}", "platform": "WINDOWS",
        "sensor_version": "0.1.0-windows",
        "machine_guid": f"e2e-{stamp}-guid"})
    endpoint_id = enrolled.get("endpoint_id")
    check("computer registered into the administrator's group",
          enrolled.get("group_id") == group_id,
          f"group={enrolled.get('group_id')} basis="
          f"{enrolled.get('placement_basis')}")
    credential = enrolled.get("agent_credential")
    _s, sess = call("POST", "/edr/agent/session", tenant=False, body={
        "tenant_id": TENANT, "agent_credential": credential})
    session = sess.get("session_token")
    check("connector opened an authenticated session", bool(session))

    print("\n── delivery is not application ──")
    _s, rows = call("GET", f"/edr/policies/deployment?policy_id={policy_id}",
                    token=admin)
    mine = next((r for r in rows["endpoints"]
                 if r["endpoint_id"] == endpoint_id), {})
    check("before any fetch the endpoint is PENDING_DELIVERY",
          mine.get("state") == "PENDING_DELIVERY", str(mine.get("state")))

    _s, fetched = call("GET", "/edr/agent/policy", token=session,
                       tenant=False)
    check("fetching the policy reports DELIVERED",
          fetched.get("state") == "DELIVERED", str(fetched.get("state")))
    check("delivered version carries the exact config digest",
          fetched["policy"]["config_digest"] == digest_v1)
    _s, rows = call("GET", f"/edr/policies/deployment?policy_id={policy_id}",
                    token=admin)
    mine = next((r for r in rows["endpoints"]
                 if r["endpoint_id"] == endpoint_id), {})
    check("DELIVERED is NOT reported as applied",
          mine.get("state") == "DELIVERED"
          and mine.get("confirmed_by_endpoint") is False,
          f"{mine.get('state')} confirmed={mine.get('confirmed_by_endpoint')}")

    print("\n── only an endpoint ACK can produce APPLIED ──")
    _s, bad = call("POST", "/edr/agent/policy-ack", token=session,
                   tenant=False, body={
                       "policy_id": policy_id, "version": 1,
                       "config_digest": "cfg_" + "0" * 32, "applied": True,
                       "running_config_digest": "cfg_" + "0" * 32})
    check("an ACK for a digest we never delivered is refused as APPLIED",
          bad["outcome"] == "RECORDED_OUT_OF_SYNC"
          and bad["effective"]["state"] != "APPLIED",
          f"{bad['outcome']} -> {bad['effective']['state']}")

    _s, ack = call("POST", "/edr/agent/policy-ack", token=session,
                   tenant=False, body={
                       "policy_id": policy_id, "version": 1,
                       "config_digest": digest_v1, "applied": True,
                       "running_config_digest": digest_v1,
                       "connector_version": "0.1.0-windows"})
    check("a correct ACK produces APPLIED",
          ack["outcome"] == "RECORDED_APPLIED"
          and ack["effective"]["state"] == "APPLIED",
          f"{ack['outcome']} -> {ack['effective']['state']}")
    check("APPLIED is confirmed by the endpoint",
          ack["effective"]["confirmed_by_endpoint"] is True)

    _s, ack2 = call("POST", "/edr/agent/policy-ack", token=session,
                    tenant=False, body={
                        "policy_id": policy_id, "version": 1,
                        "config_digest": digest_v1, "applied": True,
                        "running_config_digest": digest_v1})
    check("a later independent ACK produces VERIFIED",
          ack2["outcome"] == "RECORDED_VERIFIED"
          and ack2["effective"]["state"] == "VERIFIED",
          f"{ack2['outcome']} -> {ack2['effective']['state']}")

    print("\n── a new version makes the endpoint OUT_OF_SYNC ──")
    _s, v2 = call("POST", f"/edr/policies/{policy_id}/versions", token=admin,
                  body={"config": {"mode": "DETECT_ONLY",
                                   "report_interval_seconds": 45,
                                   "collect_process_events": True},
                        "notes": "cadence change"})
    check("version 2 has a different digest",
          v2["version"]["config_digest"] != digest_v1)
    _s, rows = call("GET", f"/edr/policies/deployment?policy_id={policy_id}",
                    token=admin)
    mine = next((r for r in rows["endpoints"]
                 if r["endpoint_id"] == endpoint_id), {})
    check("the endpoint is OUT_OF_SYNC until it acknowledges v2",
          mine.get("state") == "OUT_OF_SYNC", str(mine.get("state")))

    print("\n── failure is recorded as FAILED, never as APPLIED ──")
    _s, failed = call("POST", "/edr/agent/policy-ack", token=session,
                      tenant=False, body={
                          "policy_id": policy_id, "version": 2,
                          "config_digest": v2["version"]["config_digest"],
                          "applied": False,
                          "failure_reason": "e2e simulated apply failure"})
    check("a reported apply failure becomes FAILED",
          failed["effective"]["state"] == "FAILED",
          str(failed["effective"]["state"]))

    print("\n── GATE 7 · exclusions ──")
    _s, exset = call("POST", "/edr/exclusions/sets", token=admin, body={
        "name": f"E2E set {stamp}", "os": "WINDOWS",
        "description": "gate 7 live proof"})
    set_id = exset["set_id"]
    _s, taxonomy = call("GET", "/edr/exclusions/taxonomy", token=admin)
    check("endpoint engines honestly declare they are not implemented",
          any(e["engine"].startswith("endpoint.") and not e["implemented"]
              for e in taxonomy["engines"]))

    _s, base_proof = call("GET", "/edr/exclusions/enforcement-proof?sample=400",
                          token=admin)
    baseline_matched = base_proof["baseline_outcomes"].get("FINDINGS", 0)
    check("the fabric produces real findings before any exclusion",
          baseline_matched > 0, f"FINDINGS={baseline_matched}")

    # The exclusion value is derived from REAL matched evidence in this
    # environment, so the proof is never tuned to a hardcoded string.
    _s, matched = call("GET", "/edr/events?detection=matched&limit=1",
                       token=admin)
    excl_type, excl_value, excl_match = "PROCESS_COMMANDLINE", None, "CONTAINS"
    if matched.get("events"):
        _s, one = call("GET", f"/edr/events/{matched['events'][0]['raw_id']}",
                       token=admin)
        try:
            env = json.loads(one["event"]["payload"])
        except (ValueError, KeyError, TypeError):
            env = {}
        if env.get("image_path"):
            excl_type, excl_value, excl_match = "PATH", env["image_path"], "EXACT"
        elif env.get("sha256"):
            excl_type, excl_value, excl_match = ("FILE_HASH", env["sha256"],
                                                 "EXACT")
        elif env.get("command_line"):
            excl_value = env["command_line"][:40]
    check("a real matched-evidence attribute was found to exclude on",
          bool(excl_value), f"{excl_type}={excl_value}")

    _s, excl = call("POST", "/edr/exclusions", token=admin, body={
        "set_id": set_id, "type": excl_type, "value": excl_value or "msiexec",
        "match": excl_match,
        "reason": "e2e proof that an exclusion changes a real engine",
        "affected_engines": ["server.deterministic.rule",
                             "endpoint.prevention"],
        "scope": {"type": "TENANT", "ids": []}})
    exclusion_id = excl["exclusion_id"]
    check("a new exclusion is PENDING_APPROVAL and inert",
          excl["approval_state"] == "PENDING_APPROVAL")
    _s, mid_proof = call("GET", "/edr/exclusions/enforcement-proof?sample=400",
                         token=admin)
    check("an UNAPPROVED exclusion changes nothing",
          mid_proof["evidence_bypassed"] == 0
          and mid_proof["approved_exclusions_consulted"] == 0,
          f"bypassed={mid_proof['evidence_bypassed']}")

    call("POST", f"/edr/exclusions/{exclusion_id}/approval", token=admin,
         body={"decision": "APPROVED"}, expect=409)
    check("self-approval is refused", True)

    _s, approved = call("POST", f"/edr/exclusions/{exclusion_id}/approval",
                        token=approver, body={"decision": "APPROVED",
                                              "note": "e2e"})
    check("a second operator can approve",
          approved["approval_state"] == "APPROVED")

    _s, proof = call("GET", "/edr/exclusions/enforcement-proof?sample=400",
                     token=admin)
    check("the approved exclusion is consulted by the engine",
          proof["approved_exclusions_consulted"] >= 1)
    check("the exclusion ACTUALLY bypassed the engine",
          proof["changed_engine_behaviour"] is True
          and proof["evidence_bypassed"] > 0,
          f"bypassed={proof['evidence_bypassed']} "
          f"suppressed_findings={proof['findings_suppressed']}")
    states = {e["truth_state"] for e in proof["examples"]}
    check("bypass is reported with a preserved truth state",
          states.issubset({"EXCLUDED", "NOT_EVALUATED_DUE_TO_EXCLUSION"})
          and bool(states), str(states))

    _s, listed = call("GET", f"/edr/exclusions?set_id={set_id}", token=admin)
    mine = next((e for e in listed["exclusions"]
                 if e["exclusion_id"] == exclusion_id), {})
    points = {p["engine"]: p["truth_state"]
              for p in (mine.get("enforcement") or [])}
    check("server enforcement reports SERVER_EXCLUSION_APPLIED",
          points.get("server.deterministic.rule")
          == "SERVER_EXCLUSION_APPLIED", str(points))
    check("endpoint enforcement is NOT claimed",
          points.get("endpoint.prevention") in (
              "EXCLUSION_NOT_SUPPORTED_BY_ENGINE",
              "EXCLUSION_PENDING_POLICY"), str(points))

    print("\n── revocation restores the engine ──")
    call("POST", f"/edr/exclusions/{exclusion_id}/revoke", token=admin,
         body={"reason": "e2e cleanup"})
    _s, after = call("GET", "/edr/exclusions/enforcement-proof?sample=400",
                     token=admin)
    check("a revoked exclusion stops affecting the engine",
          after["evidence_bypassed"] == 0,
          f"bypassed={after['evidence_bypassed']}")

    print("\n── GATE 11 · events explorer ──")
    _s, page1 = call("GET", "/edr/events?limit=5&sort=desc", token=admin)
    check("events are returned with a cursor", page1["count"] > 0
          and (page1["next_cursor"] or not page1["has_more"]),
          f"count={page1['count']}")
    if page1.get("next_cursor"):
        _s, page2 = call(
            "GET", f"/edr/events?limit=5&sort=desc"
                   f"&cursor={page1['next_cursor']}", token=admin)
        ids1 = {e["raw_id"] for e in page1["events"]}
        ids2 = {e["raw_id"] for e in page2["events"]}
        check("keyset pagination does not repeat rows",
              not (ids1 & ids2), f"overlap={len(ids1 & ids2)}")
    _s, det = call("GET", "/edr/events?detection=matched&limit=5", token=admin)
    check("the detection filter is applied server-side",
          all(e["detection"]["outcome"] == "DETECTION_MATCHED"
              for e in det["events"]), f"count={det['count']}")
    _s, fac = call("GET", "/edr/events/facets?hours=24", token=admin)
    check("facets report real activity coverage",
          isinstance(fac.get("activity"), dict),
          f"activity={fac.get('activity')}")
    if page1["events"]:
        _s, one = call("GET", f"/edr/events/{page1['events'][0]['raw_id']}",
                       token=admin)
        check("event detail returns the verbatim payload and derivations",
              one["event"].get("payload") is not None
              and "derivations" in one["event"])
    _s, refused = call("GET", "/edr/events?limit=5", token=admin, tenant=False,
                       expect=403)
    check("an events query with no tenant is refused", True)

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"FAILURES ({len(FAILURES)}):")
        for f in FAILURES:
            print("  - " + f)
        return 1
    print("ALL LIVE ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
