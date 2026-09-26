#!/usr/bin/env python3
"""P0-F.7 acceptance proof · ONE intrusion, traceable end to end.

It does not accept that the page renders. It takes a real, already
validated malicious endpoint campaign and proves that every link in the
chain resolves against the SAME authoritative records the investigation
and response planes use:

  endpoint → process activity → detection rule → raw evidence →
  canonical evidence → process identity → IUE → ICE → VEEE verdict →
  consolidated incident → response command → independent verification

and that the story is a PROJECTION, not a second store: each field it
shows is compared field-by-field against the source collection it claims
to have read.

    python3 /app/scripts/p0_f7_campaign_story_proof.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv  # noqa: E402
from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

load_dotenv("/app/backend/.env")
API = next(l.split("=", 1)[1].strip()
           for l in Path("/app/frontend/.env").read_text().splitlines()
           if l.startswith("REACT_APP_BACKEND_URL"))
FAILURES: list[str] = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label} {detail}")
    if not ok:
        FAILURES.append(label)


def call(path, body=None, bearer=None):
    r = urllib.request.Request(
        f"{API}{path}",
        data=(json.dumps(body).encode() if body is not None else None),
        headers={"Content-Type": "application/json",
                 "User-Agent": "NivXForge-P0F7-Proof/1.0",
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})})
    with urllib.request.urlopen(r, timeout=90) as resp:
        return json.loads(resp.read())


async def main():
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    pw = next(l.split("`")[1] for l in
              Path("/app/memory/test_credentials.md").read_text().splitlines()
              if l.startswith("- **Password**"))
    admin = call("/api/auth/login", {"email": "admin@nivxray.com",
                                     "password": pw})["access_token"]

    print("\n=== 1 · pick a REAL validated endpoint campaign (no fixtures)")
    inc = None
    async for cand in db["workspace_cases"].find(
            {"endpoint_campaign.max_label": "MALICIOUS",
             "tenant_id": "default"}).sort("created_at", -1):
        camp = cand["endpoint_campaign"]
        # It must be a genuinely enrolled endpoint, not a unit-test
        # fixture, and its detections must carry raw evidence ids.
        ep = await db["edr_endpoints"].find_one(
            {"tenant_id": "default",
             "endpoint_id": camp.get("endpoint_id")})
        if ep and all(d.get("raw_event_id")
                      for d in camp.get("detections") or [{}]):
            inc = cand
            break
    if not inc:
        print("   no MALICIOUS endpoint campaign on record — run "
              "scripts/p0_f_detection_proof.py first")
        sys.exit(2)
    camp = inc["endpoint_campaign"]
    print(f"   {inc['incident_number']} {inc['id']} · {camp['max_label']} "
          f"{camp['max_score']} · {len(camp['detections'])} detections · "
          f"{camp['endpoint_id']}")

    story = call(f"/api/edr/campaign-story?incident_id={inc['id']}",
                 bearer=admin)
    check("the story is declared a read model over named sources",
          story.get("read_model") is True
          and "workspace_cases.endpoint_campaign" in story["sources"]
          and "edr_raw_events" in story["sources"])

    print("\n=== 2 · the story is a PROJECTION of the incident record")
    check("incident identity matches workspace_cases exactly",
          story["incident"]["incident_number"] == inc["incident_number"]
          and story["incident"]["state"] == inc["incident_state"]
          and story["incident"]["priority"] == inc["incident_priority"])
    check("the campaign facts are copied, not recomputed",
          story["incident"]["campaign"]["max_label"] == camp["max_label"]
          and story["incident"]["campaign"]["max_score"] == camp["max_score"]
          and story["incident"]["campaign"]["detection_count"]
          == len(camp["detections"])
          and sorted(story["incident"]["campaign"]["rule_ids"])
          == sorted(camp["rule_ids"]))
    check("every consolidated detection appears once",
          len(story["activities"]) == len(camp["detections"]))

    print("\n=== 3 · provenance resolves against the AUTHORITATIVE stores")
    acts = story["activities"]
    raw_ok = canon_ok = iid_ok = rule_ok = 0
    for a in acts:
        pv = a["provenance"]
        raw = await db["edr_raw_events"].find_one({"raw_id":
                                                   pv["raw_event_id"]})
        if raw:
            raw_ok += 1
            ev = json.loads(raw["payload"])
            same = (ev.get("pid") == a["process"]["pid"]
                    and ev.get("command_line")
                    == a["process"]["command_line"])
            if not same:
                FAILURES.append("raw payload disagrees with the story")
        if pv["process_iid"]:
            obs = await db["v2_shadow_observations"].find_one(
                {"event.process.iid": pv["process_iid"]},
                {"event.provenance.ingest_job_id": 1, "canonical_event_id": 1,
                 "event.process": 1})
            if obs:
                canon_ok += 1
                if ((obs["event"]["provenance"]["ingest_job_id"]
                     == pv["raw_event_id"])):
                    iid_ok += 1
        if a["rule_ids"] and set(a["rule_ids"]) <= set(camp["rule_ids"]):
            rule_ok += 1
    check("every raw_event_id in the story exists in edr_raw_events",
          raw_ok == len(acts), f"{raw_ok}/{len(acts)}")
    check("every process identity exists in the canonical evidence plane",
          canon_ok == len(acts), f"{canon_ok}/{len(acts)}")
    check("each process identity is bound to the SAME raw event",
          iid_ok == len(acts), f"{iid_ok}/{len(acts)}")
    check("every rule shown is one the incident actually recorded",
          rule_ok == len(acts), f"{rule_ok}/{len(acts)}")
    a0 = acts[0]
    print("   chain[0]: " + " → ".join(str(x) for x in (
        a0["provenance"]["raw_event_id"],
        a0["provenance"]["canonical_event_id_in_evidence_plane"],
        a0["provenance"]["process_iid"],
        ",".join(a0["rule_ids"]), a0["verdict"])))

    print("\n=== 4 · verdict reasoning comes from the EXISTING engines")
    pipe = inc.get("xdr_pipeline") or {}
    r = story["reasoning"]
    check("the IUE id is the incident's own",
          r["iue_id"] == pipe.get("iue_id") and bool(r["iue_id"]))
    check("the VEEE record is copied verbatim",
          r["veee"] == (pipe.get("veee") or {}) and bool(r["veee"]))
    check("VEEE contributors are shown, so the score is explainable",
          len(r["veee"].get("contributors") or []) >= 1,
          json.dumps(r["veee"].get("contributors"))[:160])
    check("ICE correlation state is stated either way",
          r["ice_state"] in ("MATCHED", "NO_MATCH")
          or bool(r["ice_matches"]))
    check("no second verdict engine is introduced",
          story["engine_id"].endswith("campaign_story")
          and r["engines"]["detection"] == pipe.get("engine_id"))

    print("\n=== 5 · response and INDEPENDENT verification")
    resp_ids = [x["command_id"] for x in story["responses"]]
    check("every response shown exists in edr_response_commands",
          all([await db["edr_response_commands"].find_one(
              {"command_id": cid}) for cid in resp_ids])
          if resp_ids else True, f"{len(resp_ids)} correlated")
    for x in story["responses"]:
        src = await db["edr_response_commands"].find_one(
            {"command_id": x["command_id"]})
        if x["state"] != src["state"]:
            FAILURES.append("response state disagrees with the record")
        if x["proof"]["success_claimed"] and not (
                (src.get("verification") or {}).get("probe")):
            FAILURES.append("a response is claimed proven with no probe")
    check("no response is claimed successful without post-action evidence",
          "a response is claimed proven with no probe" not in FAILURES)
    check("the response link states its own strength honestly",
          all("NOT_INCIDENT_KEYED" in x["link_strength"]
              for x in story["responses"]) if resp_ids else True)
    verified = [x for x in story["responses"]
                if x["proof"]["success_claimed"]]
    check("at least one response in this campaign is INDEPENDENTLY verified",
          len(verified) >= 1, f"{len(verified)} verified of {len(resp_ids)}")
    if verified:
        pr = (verified[0]["verification"] or {}).get("probe") or {}
        check("the verification evidence is post-action endpoint evidence",
              pr.get("method") == "post_action_proc_read"
              or "post_action" in str(verified[0]["verification"]["method"]),
              json.dumps(verified[0]["verification"]["finding"])[:140])

    print("\n=== 6 · absence is NAMED, never filled in")
    states = {k for a in acts for k in a["evidence_states"].values()}
    print("   states in use: " + ", ".join(sorted(states)))
    check("the six-state vocabulary is used, not a boolean",
          states <= {"OBSERVED", "NOT_OBSERVED", "NOT_COLLECTED",
                     "NOT_SUPPORTED", "PARSER_FAILED", "UNKNOWN", "OK"}
          and len(states) >= 3)
    check("process exit is never claimed (the sensor polls)",
          all(a["evidence_states"]["process_exit"] == "NOT_SUPPORTED"
              for a in acts))
    check("the evidence plane's own epistemic state is carried through",
          all(a.get("epistemic_state") for a in acts))
    gaps = {g["gap"] for g in story["gaps"]}
    check("the response→incident link is declared a gap, not implied",
          "response_to_incident_binding" in gaps)
    check("sub-poll-interval execution is declared a visibility gap",
          "sub_poll_interval_execution" in gaps)
    print("   gaps: " + ", ".join(sorted(gaps)))

    print("\n=== 7 · the analyst's seven questions are answerable")
    n = " ".join(story["narrative"])
    for q, ok in (
            ("what happened", "observed" in n and "UTC" in n),
            ("which process caused it", any(a["process"]["command_line"]
                                            for a in acts)),
            ("what detected it", bool(camp["rule_ids"])),
            ("why malicious/suspicious", "Why it was judged" in n),
            ("what evidence supports the verdict",
             bool(a0["provenance"]["raw_event_id"]
                  and a0["provenance"]["process_iid"])),
            ("what response was taken", bool(resp_ids)),
            ("was the response verified", len(verified) >= 1)):
        check(f"'{q}?' is answered from the records", ok)

    print("\n=== 8 · NEGATIVE · nothing is invented for a non-endpoint case")
    other = await db["workspace_cases"].find_one(
        {"endpoint_campaign": {"$exists": False},
         "id": {"$regex": "^inc_"}})
    if other:
        try:
            call(f"/api/edr/campaign-story?incident_id={other['id']}",
                 bearer=admin)
            check("a non-endpoint incident yields no invented story", False)
        except urllib.error.HTTPError as e:
            d = json.loads(e.read())["detail"]
            check("a non-endpoint incident yields no invented story",
                  e.code == 404
                  and d["error"] == "NOT_AN_ENDPOINT_CAMPAIGN", d["error"])
    try:
        call("/api/edr/campaign-story?incident_id=inc_does_not_exist",
             bearer=admin)
        check("an unknown incident is refused", False)
    except urllib.error.HTTPError as e:
        check("an unknown incident is refused", e.code == 404)
    try:
        call(f"/api/edr/campaign-story?incident_id={inc['id']}")
        check("the story requires authentication", False)
    except urllib.error.HTTPError as e:
        check("the story requires authentication", e.code in (401, 403))

    print("\n" + "=" * 62)
    print(f"incident under proof: {inc['incident_number']} ({inc['id']})")
    print("RESULT:", "ALL CHECKS PASSED" if not FAILURES
          else f"{len(FAILURES)} FAILED: {FAILURES}")
    sys.exit(1 if FAILURES else 0)


asyncio.run(main())
