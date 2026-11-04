"""End-to-end proof of the durable delivery receipt protocol (no fakes).

Requires a RUNNING backend and Mongo:

    cd /app/backend && set -a && . ./.env && set +a && \
        python ../apps/nivxray-xdr-collector/scripts/e2e_durable_receipt_proof.py

It creates its own synthetic tenant, collector, credential and evidence, and
deletes all of them again. It never touches a real endpoint, a real
credential or the delivery backlog.

TEST/SYNTHETIC only: synthetic tenant, synthetic collector, temp SQLite.
Proves the critical case over the WIRE (no fakes):
  backend committed -> endpoint lost the response -> restart ->
  reconciliation finds authoritative evidence -> local row DELIVERED/VERIFIED
  with no retransmission.
"""
import asyncio
import hashlib
import os
import secrets
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone

sys.path.insert(0, "/app/apps/nivxray-xdr-collector")
sys.path.insert(0, "/app/backend")

from pymongo import MongoClient

BASE = "http://localhost:8001"
RUN = uuid.uuid4().hex[:8]
TENANT = f"ten_e2e_{RUN}"
ORG = f"org_e2e_{RUN}"
COLLECTOR = f"col-e2e-{RUN}"
SOURCE = "windows-security-evd"
SEI = f"sei-e2e-{RUN}"
RAW = {"EventID": 4688, "RecordId": 4242}

os.environ["NIVX_COLLECTOR_ID"] = COLLECTOR
os.environ["NIVX_INGEST_URL"] = f"{BASE}/api/xdr/ingest/telemetry"
os.environ["NIVX_INGEST_AUTH_MODE"] = "api_key"

from framework import receipts                                   # noqa: E402
from framework.base import Envelope                              # noqa: E402
from framework.durable_delivery import DurableDeliveryWorker     # noqa: E402
from framework.outbox import Outbox, OutboxStatus, RestartRecovery  # noqa: E402
from framework.receipt_client import ReceiptClient               # noqa: E402

db = MongoClient(os.environ["MONGO_URL"])[os.environ.get("DB_NAME")
                                          or "test_database"]
now = datetime.now(timezone.utc).isoformat()
raw_key = "nvx_" + secrets.token_hex(24)
os.environ["NIVX_INGEST_TOKEN"] = raw_key
state = tempfile.mkdtemp(prefix="e2e-durable-")

db["organizations"].insert_one({"id": ORG, "slug": ORG, "display_name": ORG,
                                "kind": "CUSTOMER", "state": "ACTIVE",
                                "created_at": now, "updated_at": now,
                                "created_by": "e2e"})
db["tenants"].insert_one({"id": TENANT, "organization_id": ORG,
                          "slug": TENANT, "display_name": TENANT,
                          "kind": "CUSTOMER", "state": "ACTIVE",
                          "products": ["xdr"], "created_at": now,
                          "updated_at": now, "created_by": "e2e"})
db["xdr_collectors"].insert_one({"id": COLLECTOR, "tenant_id": TENANT,
                                 "name": COLLECTOR,
                                 "authorized_sources": [SOURCE],
                                 "state": "CONNECTED"})
db["xdr_api_keys"].insert_one({
    "id": f"key_{uuid.uuid4().hex[:20]}", "tenant_id": TENANT,
    "name": f"e2e-{RUN}", "prefix": raw_key[:12],
    "hash": hashlib.sha256(raw_key.encode()).hexdigest(),
    "scopes": ["collectors.enroll"], "enabled": True, "revoked_at": None,
    "expires_at": None, "created_at": now, "updated_at": now,
    "last_used_at": None, "last_used_ip": None, "use_count": 0})

key = receipts.delivery_key(tenant_id=TENANT, collector_id=COLLECTOR,
                            source=SOURCE, source_event_id=SEI, raw=RAW)
event_id = f"evt_{uuid.uuid4().hex[:16]}"
db["xdr_ingest_dedupe"].insert_one({
    "key": key, "tenant_id": TENANT, "collector_id": COLLECTOR,
    "source": SOURCE, "source_event_id": SEI,
    "payload_digest": receipts.payload_digest(RAW),
    "status": "COMPLETED", "stage": "COMPLETED", "delivery_count": 1,
    "duplicate_count": 0, "trace_id": f"tr_{RUN}",
    "canonical_event_id": event_id, "raw_row_id": None})
db["xdr_canonical_evidence"].insert_one({
    "event_id": event_id, "tenant_id": TENANT, "ingest_time": now,
    "source_event_id": SEI})


class NeverCalled:
    """Any transmission during reconciliation is a failure of the protocol."""
    url = os.environ["NIVX_INGEST_URL"]
    auth_mode = "api_key"
    token = raw_key
    timeout = 10.0
    calls = []

    def configured(self):
        return True

    async def deliver(self, envelopes):
        NeverCalled.calls.append(list(envelopes))
        raise AssertionError("reconciliation must never retransmit")


def envelope():
    return Envelope(tenant_id=TENANT, source=SOURCE, source_event_id=SEI,
                    connector_id=f"conn-{RUN}", collector_id=COLLECTOR,
                    collection_method="windows-eventlog",
                    parser_version="1.0.0", source_timestamp=now,
                    collection_timestamp=now, event_type="process_creation",
                    raw=RAW, canonical={"event": "process_creation"},
                    declared_source=SOURCE)


failures = []
try:
    outbox = Outbox(path=state, restart_recovery=RestartRecovery.RECONCILE)
    rid, _ = outbox.record(envelope())
    outbox.set_delivery_key(rid, key)
    outbox.mark_delivering([rid])          # dispatched, response lost
    outbox.close()

    reopened = Outbox(path=state, restart_recovery=RestartRecovery.RECONCILE)
    row = reopened.by_id(rid)
    if row.status != OutboxStatus.UNKNOWN_COMMIT_STATE:
        failures.append(f"restart status is {row.status}")

    worker = DurableDeliveryWorker(reopened, NeverCalled(), ReceiptClient(),
                                   collector=COLLECTOR)
    os.environ["NIVX_RECEIPT_URL"] = f"{BASE}/api/xdr/ingest/delivery/receipts"
    result = asyncio.run(worker.reconcile_once())
    row = reopened.by_id(rid)

    print("receipt surface :", worker.receipts.url)
    print("reconcile result:", {k: v for k, v in result.items()
                                if k not in ("note",)})
    print("local status    :", row.status)
    print("receipt         :", None if not row.receipt else {
        "basis": row.receipt["basis"],
        "disposition": row.receipt["disposition"],
        "bucket": row.receipt["bucket"],
        "canonical": row.receipt["canonical"],
        "evidence_ref": row.receipt["evidence_ref"],
        "canonical_event_id": row.receipt["canonical_event_id"],
        "delivery_key_matches": row.receipt["delivery_key"] == key,
        "authority": row.receipt["authority"],
    })
    print("transmissions   :", len(NeverCalled.calls))

    if row.status != OutboxStatus.DELIVERED:
        failures.append(f"row is {row.status}, expected delivered")
    if not receipts.is_verified_delivery(row.receipt):
        failures.append("receipt does not authorise a delivery")
    if row.receipt["canonical_event_id"] != event_id:
        failures.append("wrong canonical event bound")
    if NeverCalled.calls:
        failures.append("a retransmission happened")
    if db["xdr_ingest_dedupe"].count_documents({"key": key}) != 1:
        failures.append("more than one claim exists")
    if db["xdr_canonical_evidence"].count_documents(
            {"event_id": event_id}) != 1:
        failures.append("more than one canonical event exists")
    reopened.close()
finally:
    db["organizations"].delete_many({"id": ORG})
    db["tenants"].delete_many({"id": TENANT})
    db["xdr_collectors"].delete_many({"id": COLLECTOR})
    db["xdr_api_keys"].delete_many({"tenant_id": TENANT})
    db["xdr_ingest_dedupe"].delete_many({"tenant_id": TENANT})
    db["xdr_canonical_evidence"].delete_many({"tenant_id": TENANT})
    shutil.rmtree(state, ignore_errors=True)

print("\nVERDICT:", "PASS" if not failures else f"FAIL {failures}")
sys.exit(0 if not failures else 1)
