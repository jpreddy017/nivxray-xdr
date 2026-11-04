"""Synthetic recovery checks; never connect to an application database."""
from types import SimpleNamespace
from datetime import datetime, timezone, timedelta
import mongomock
from bson import ObjectId
import pytest
from scripts import edr_file_search_index as worker
from services.edr.global_file_index import COLLECTION, CHECKPOINTS

@pytest.fixture
def db(monkeypatch):
    database = mongomock.MongoClient().db
    monkeypatch.setattr(mongomock.collection.Cursor, 'max_time_ms', lambda self, ms: self, raising=False)
    def resolve(ref, scope):
        row = database.edr_endpoints.find_one({'endpoint_id': ref, 'tenant_id': scope['tenant_ids'][0]})
        if not row: return None
        return SimpleNamespace(identity=row, predicate=lambda _: {'tenant_id': row['tenant_id'], 'collector_id': ref})
    monkeypatch.setattr(worker.eq, 'resolve_endpoint', resolve)
    return database

def seed(db, oid, endpoint='ep_a', tenant='t1'):
    db.v2_shadow_observations.insert_one({'_id': oid, 'observation_id': str(oid), 'tenant_id': tenant,
      'collector_id': endpoint, 'event': {'kind': 'process_create', 'ts': '2026-11-04T02:00:00Z',
      'process': {'image': 'cmd.exe', 'pid': 123}}})

def endpoint(db, name='ep_a', tenant='t1'):
    db.edr_endpoints.insert_one({'endpoint_id': name, 'tenant_id': tenant, 'hostname': name})

def test_old_ids_and_repaired_identity_are_recovered_without_source_changes(db):
    endpoint(db)
    old = ObjectId.from_datetime(datetime(2026, 1, 1, tzinfo=timezone.utc))
    current = ObjectId()
    seed(db, current)
    assert worker.acquire(db, 't1', 'a')
    worker.batch(db, 't1', owner='a')
    seed(db, old, 'ep_late')
    source_before = list(db.v2_shadow_observations.find())
    assert worker.batch(db, 't1', owner='a') == (0, 0)
    worker.batch(db, 't1', owner='a', reconcile=True)
    assert db[CHECKPOINTS].find_one({'_id':'t1'})['unresolved'] == 1
    endpoint(db, 'ep_late')
    worker.batch(db, 't1', owner='a', reconcile=True)
    assert db[COLLECTION].count_documents({}) == 2
    assert db[CHECKPOINTS].find_one({'_id':'t1'})['unresolved'] == 0
    worker.batch(db, 't1', owner='a', reconcile=True)
    assert db[COLLECTION].count_documents({}) == 2
    assert list(db.v2_shadow_observations.find()) == source_before
    assert db[COLLECTION].find_one({'endpoint_id':'ep_a'})['process_pid'] == 123

def test_reconcile_resumes_under_lease_and_excludes_other_tenants(db):
    endpoint(db); endpoint(db, 'ep_foreign', 't2')
    seed(db, ObjectId()); seed(db, ObjectId()); seed(db, ObjectId(), 'ep_foreign', 't2')
    assert worker.acquire(db, 't1', 'a')
    worker.batch(db, 't1', size=1, owner='a', reconcile=True)
    assert db[CHECKPOINTS].find_one({'_id':'t1'})['reconcile_after']
    db[CHECKPOINTS].update_one({'_id':'t1'}, {'$set':{'lease_until':datetime.now(timezone.utc)-timedelta(seconds=1)}})
    assert worker.acquire(db, 't1', 'b')
    with pytest.raises(worker.LeaseBusy): worker.batch(db, 't1', owner='a', reconcile=True)
    worker.batch(db, 't1', owner='b', reconcile=True)
    assert db[COLLECTION].count_documents({}) == 2
    assert db[COLLECTION].count_documents({'tenant_id':'t2'}) == 0
    assert db[CHECKPOINTS].find_one({'_id':'t1'})['reconcile_after'] is None
