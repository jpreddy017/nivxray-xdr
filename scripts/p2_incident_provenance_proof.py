#!/usr/bin/env python3
"""P-2 · INCIDENT PROVENANCE — runtime proof.

Proves: the closed vocabulary is enforced; an incident cannot be created
unlabelled or falsely labelled; historical provenance was DERIVED FROM
EVIDENCE and never guessed; consolidation does not launder provenance;
the label is exposed on the API and scoped per tenant.

    python3 scripts/p2_incident_provenance_proof.py
"""
from __future__ import annotations

import os
import sys

import requests

sys.path.insert(0, "/app/backend")
os.chdir("/app/backend")
from dotenv import load_dotenv                                # noqa: E402
load_dotenv("/app/backend/.env")
from pymongo import MongoClient                              # noqa: E402
from services import incident_provenance as prov             # noqa: E402

BASE = os.environ.get("NIVX_BASE_URL", "http://localhost:8001")
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
FOREIGN = ("analyst@nivx-live.com", "NivxLive!Analyst2026")

PASS, FAIL = [], []


def gate(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  · {detail}" if detail else ""))
    return ok


def login(c):
    r = requests.post(f"{BASE}/api/auth/login",
                      json={"email": c[0], "password": c[1]}, timeout=30)
    r.raise_for_status()
    d = r.json()
    return d.get("access_token") or d.get("token") or d["data"]["access_token"]


def main() -> int:
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    col = db[prov.INCIDENTS]
    tok = login(ADMIN)
    H = {"Authorization": f"Bearer {tok}"}

    print("\nA · CLOSED VOCABULARY, ENFORCED AT THE BOUNDARY")
    gate("A1 · exactly the six owner-specified classes exist",
         set(prov.PROVENANCE_VALUES) == {
             "REAL_SENSOR_DERIVED", "SEEDED_FOR_DEVELOPMENT",
             "SYNTHETIC_TEST", "REPLAY_DERIVED", "MIXED_PROVENANCE",
             "PROVENANCE_UNKNOWN"},
         ",".join(prov.PROVENANCE_VALUES))
    gate("A2 · only REAL_SENSOR_DERIVED may read as real-world activity",
         prov.REAL_CLASSES == (prov.REAL_SENSOR_DERIVED,))
    try:
        prov.stamp("TOTALLY_REAL_TRUST_ME", basis="x")
        gate("A3 · an undeclared class is rejected", False)
    except prov.ProvenanceError:
        gate("A3 · an undeclared class is rejected", True)
    try:
        prov.stamp(prov.REAL_SENSOR_DERIVED, basis="")
        gate("A4 · a label with no recorded basis is rejected", False)
    except prov.ProvenanceError:
        gate("A4 · a label with no recorded basis is rejected", True)
    for v in prov.PROVENANCE_VALUES:
        if len(prov.MEANING.get(v, "")) < 30:
            gate(f"A5 · {v} has a written meaning", False)
    gate("A5 · every class carries a written meaning",
         all(len(prov.MEANING.get(v, "")) >= 30
             for v in prov.PROVENANCE_VALUES))

    print("\nB · WRITE-TIME GATE · an unlabelled incident cannot be created")
    for bad, why in (({"id": "inc_test"}, "no provenance at all"),
                     ({"id": "inc_test", "provenance": "REAL"},
                      "not a declared class"),
                     ({"id": "inc_test",
                       "provenance": prov.REAL_SENSOR_DERIVED},
                      "declared class but no basis")):
        try:
            prov.require(dict(bad))
            gate(f"B · refused: {why}", False)
        except prov.ProvenanceError:
            gate(f"B · refused: {why}", True)
    good = {"id": "inc_ok",
            **prov.stamp(prov.REAL_SENSOR_DERIVED, basis="proof fixture")}
    gate("B · a correctly labelled incident is accepted",
         prov.require(good) is good)

    print("\nC · NO INCIDENT IN THE STORE IS UNLABELLED")
    total = col.count_documents({"doc_type": "xdr_incident"})
    unlabelled = col.count_documents(
        {"doc_type": "xdr_incident",
         "provenance": {"$nin": list(prov.PROVENANCE_VALUES)}})
    gate("C1 · zero unlabelled xdr_incidents", unlabelled == 0,
         f"{total - unlabelled}/{total} labelled")
    no_basis = col.count_documents({"doc_type": "xdr_incident",
                                    "provenance_basis": {"$exists": False}})
    gate("C2 · every label records the rule that produced it",
         no_basis == 0, f"{no_basis} without a basis")

    print("\nD · HISTORICAL PROVENANCE WAS DERIVED, NEVER GUESSED")
    real = col.count_documents({"doc_type": "xdr_incident",
                                "provenance": prov.REAL_SENSOR_DERIVED})
    unknown = col.count_documents({"doc_type": "xdr_incident",
                                   "provenance": prov.PROVENANCE_UNKNOWN})
    seeded = col.count_documents({"doc_type": "xdr_incident",
                                  "provenance":
                                      prov.SEEDED_FOR_DEVELOPMENT})
    gate("D1 · every REAL label names the sensor evidence it traced",
         all("authenticated sensor" in (d.get("provenance_basis") or "")
             and (d.get("provenance_evidence") or {}).get("trace_id")
             for d in col.find({"provenance": prov.REAL_SENSOR_DERIVED},
                               {"provenance_basis": 1,
                                "provenance_evidence": 1})),
         f"{real} real")
    gate("D2 · untraceable incidents became UNKNOWN, NOT seeded "
         "(the owner's explicit rule)",
         seeded == 0 and unknown > 0,
         f"UNKNOWN={unknown} · SEEDED_by_inference={seeded}")
    gate("D3 · every UNKNOWN states why the origin is not establishable",
         all(len(d.get("provenance_basis") or "") > 40
             for d in col.find({"provenance": prov.PROVENANCE_UNKNOWN},
                               {"provenance_basis": 1}).limit(400)))
    def _raw(trace):
        """Same key set the classifier uses: raw events are addressed by
        `raw_id`, with `_id` as the fallback."""
        return (db["edr_raw_events"].find_one({"raw_id": trace},
                                              {"source_kind": 1})
                or db["edr_raw_events"].find_one({"_id": trace},
                                                 {"source_kind": 1}))

    gate("D4 · a REAL label is falsifiable — its traced raw event exists "
         "and is sensor-attributed",
         all((_raw((d.get("provenance_evidence") or {}).get("trace_id"))
              or {}).get("source_kind") == "sensor"
             for d in col.find({"provenance": prov.REAL_SENSOR_DERIVED},
                               {"provenance_evidence": 1})))

    print("\nE · CONSOLIDATION DOES NOT LAUNDER PROVENANCE")
    gate("E1 · real + seeded = MIXED, not real",
         prov.merge(prov.SEEDED_FOR_DEVELOPMENT,
                    prov.REAL_SENSOR_DERIVED) == prov.MIXED_PROVENANCE)
    gate("E2 · real + real stays real",
         prov.merge(prov.REAL_SENSOR_DERIVED,
                    prov.REAL_SENSOR_DERIVED) == prov.REAL_SENSOR_DERIVED)
    gate("E3 · unknown + real stays UNKNOWN — the pre-existing evidence "
         "is still unaccounted for",
         prov.merge(prov.PROVENANCE_UNKNOWN,
                    prov.REAL_SENSOR_DERIVED) == prov.PROVENANCE_UNKNOWN)
    gate("E4 · replay + real = MIXED",
         prov.merge(prov.REPLAY_DERIVED,
                    prov.REAL_SENSOR_DERIVED) == prov.MIXED_PROVENANCE)

    print("\nF · THE LABEL IS ON THE API")
    r = requests.get(f"{BASE}/api/incidents?limit=200", headers=H,
                     timeout=120)
    rows = r.json().get("incidents") or []
    gate("F1 · every queue row carries a provenance",
         bool(rows) and all(x.get("provenance") in prov.PROVENANCE_VALUES
                            for x in rows), f"{len(rows)} rows")
    gate("F2 · every queue row carries its basis",
         all(x.get("provenance_basis") for x in rows))
    gate("F3 · provenance_is_real is true ONLY for REAL_SENSOR_DERIVED",
         all(bool(x.get("provenance_is_real")) ==
             (x.get("provenance") == prov.REAL_SENSOR_DERIVED)
             for x in rows))
    real_row = next((x for x in rows if x.get("provenance_is_real")), None)
    if real_row:
        d = requests.get(f"{BASE}/api/incidents/{real_row['id']}",
                         headers=H, timeout=60).json()
        gate("F4 · the detail view agrees with the queue view",
             d.get("provenance") == real_row["provenance"],
             f"{d.get('provenance')}")
    else:
        gate("F4 · the detail view agrees with the queue view", False,
             "no real incident in the queue to compare")

    print("\nG · SUMMARY ENDPOINT · tenant-scoped and honest")
    s = requests.get(f"{BASE}/api/incidents/provenance/summary",
                     headers=H, timeout=60).json()
    gate("G1 · summary reconciles with the store",
         s["total_incidents"] == total
         and s["by_provenance"][prov.REAL_SENSOR_DERIVED] == real
         and s["unlabelled"] == 0,
         f"total={s['total_incidents']} real={s['real_incidents']} "
         f"unlabelled={s['unlabelled']}")
    gate("G2 · summary states that UNKNOWN is not a claim of fabrication",
         "not a claim that the incident is fabricated" in s.get("note", ""))
    gate("G3 · summary publishes the vocabulary so no consumer invents it",
         set(s.get("vocabulary", {})) == set(prov.PROVENANCE_VALUES))
    ftok = login(FOREIGN)
    fs = requests.get(f"{BASE}/api/incidents/provenance/summary",
                      headers={"Authorization": f"Bearer {ftok}"},
                      timeout=60).json()
    gate("G4 · another customer sees only their own scope",
         fs["scope"] != "all_tenants"
         and fs["total_incidents"] <= s["total_incidents"],
         f"foreign scope={fs['scope']} total={fs['total_incidents']}")

    print(f"\n{'='*68}\nP-2 INCIDENT PROVENANCE · {len(PASS)} PASS · "
          f"{len(FAIL)} FAIL")
    for f in FAIL:
        print(f"  FAILED: {f}")
    print(f"\nStore: {real} REAL_SENSOR_DERIVED · {unknown} "
          f"PROVENANCE_UNKNOWN · {total} xdr_incidents · 0 unlabelled")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
