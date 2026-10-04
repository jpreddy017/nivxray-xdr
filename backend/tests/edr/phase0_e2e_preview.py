"""Phase 0 · PREVIEW-ONLY end-to-end proof of the Windows chain.

Writes to the PREVIEW database under a throwaway tenant, then cleans up.
Production is never contacted. Run:  python3 -m tests.edr.phase0_e2e_preview
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from deps import db, init_database, validate_config               # noqa: E402
from edr_plane import raw_events as raw                        # noqa: E402
from edr_plane.canonical_bridge import bridge                  # noqa: E402
from edr_plane.trajectory_window import _group_and_key         # noqa: E402

from tests.edr import fixtures_windows_eventlog as fx          # noqa: E402

TENANT = "ten_phase0_preview_probe"
ENDPOINT = "ep_phase0_preview_probe"


async def _one(payload: str) -> dict:
    ev = raw.RawEndpointEvent.build(
        tenant_id=TENANT, source=ENDPOINT, source_kind="sensor",
        sensor_version="0.2.0-windows", endpoint_ref=ENDPOINT,
        payload=payload, event_time=None, received_from_ip="127.0.0.1",
        trust_state="AUTHENTICATED")
    ev.authentication = {"authenticated_endpoint_id": ENDPOINT}
    await raw.append(db, ev)
    return await bridge(db, raw_id=ev.raw_id, tenant_id=TENANT,
                        payload=payload, endpoint_id=ENDPOINT,
                        hostname=fx.HOST,
                        authentication={"authenticated_endpoint_id": ENDPOINT},
                        source_kind="sensor",
                        sensor_version="0.2.0-windows",
                        nivx_received_at=ev.ingest_time)


async def main() -> int:
    validate_config()
    init_database()
    await _cleanup()
    ok = True
    for name, payload in sorted(fx.ALL_SUPPORTED.items()):
        res = await _one(payload)
        canon = res.get("canonicalized")
        det = (res.get("detection") or {})
        print(f"{name:14s} canonical={canon} class={res.get('activity_type')}"
              f" evaluated={det.get('evaluated')}"
              f" finding_plane={'yes' if det.get('finding_plane') else 'no'}")
        ok = ok and bool(canon)

    # The parse-failure truth fix, on the real path.
    bad = await _one(fx.UNSUPPORTED_PROVIDER)
    print(f"{'refused':14s} canonical={bad.get('canonicalized')}"
          f" evaluation_state={bad.get('evaluation_state')}"
          f" finding_plane={'yes' if bad.get('finding_plane') else 'no'}")
    ok = ok and bad.get("evaluation_state") == "NOT_EVALUATED"

    groups: dict[str, int] = {}
    async for doc in db["v2_shadow_observations"].find({"tenant_id": TENANT}):
        g = _group_and_key(doc.get("event") or {})[0]
        groups[g] = groups.get(g, 0) + 1
    print("trajectory lane groups:", json.dumps(groups, sort_keys=True))
    ok = ok and set(groups) >= {"PROCESS", "FILE", "NETWORK", "REGISTRY",
                                "DNS", "AUTHENTICATION"}

    evals = await db["edr_finding_evaluations"].count_documents(
        {"tenant_id": TENANT})
    print("evaluation-state rows:", evals)
    await _cleanup()
    print("PHASE0_E2E:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


async def _cleanup() -> None:
    for coll in ("edr_raw_events", "v2_shadow_observations", "edr_findings",
                 "edr_finding_evaluations", "xdr_detection_matches"):
        await db[coll].delete_many({"tenant_id": TENANT})


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
