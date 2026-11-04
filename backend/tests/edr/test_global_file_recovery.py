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


def test_deleted_source_withdraws_tokens_preserves_evidence_and_restores(db):
    endpoint(db); oid=ObjectId(); seed(db, oid)
    worker.batch(db, 't1')
    saved=db.v2_shadow_observations.find_one({'_id':oid})
    indexed=db[COLLECTION].find_one()
    # Simulate external source retention only in this disposable database.
    db.v2_shadow_observations.delete_one({'_id':oid})
    worker.reconcile_index(db, 't1')
    stale=db[COLLECTION].find_one({'_id':indexed['_id']})
    assert stale['tokens']==[] and stale['previous_tokens']==indexed['tokens']
    assert stale['invalidation_reason']=='source_unavailable'
    assert stale['path']==indexed['path']
    assert db[COLLECTION].count_documents({'tokens':'name:cmd.exe'})==0
    db.v2_shadow_observations.insert_one(saved)
    worker.reconcile_index(db, 't1')
    assert db[COLLECTION].find_one()['tokens']==indexed['tokens']
    assert 'invalidation_reason' not in db[COLLECTION].find_one()
    assert db.v2_shadow_observations.find_one({'_id':oid})==saved

def test_changed_path_and_removed_identity_withdraw_old_matches(db):
    endpoint(db); oid=ObjectId(); seed(db, oid)
    worker.batch(db, 't1')
    db.v2_shadow_observations.update_one({'_id':oid},{'$set':{'event.process.image':'new.exe'}})
    worker.batch(db, 't1', reconcile=True)
    worker.reconcile_index(db, 't1')
    assert db[COLLECTION].count_documents({'tokens':'name:cmd.exe'})==0
    assert db[COLLECTION].count_documents({'tokens':'name:new.exe'})==1
    before=db.v2_shadow_observations.find_one({'_id':oid})
    db.edr_endpoints.delete_many({})
    worker.reconcile_index(db, 't1')
    assert db[COLLECTION].count_documents({'tokens':{'$ne':[]}})==0
    assert db.v2_shadow_observations.find_one({'_id':oid})==before

def test_validation_is_bounded_resumable_and_tenant_scoped(db):
    endpoint(db); endpoint(db, 'ep_foreign', 't2')
    seed(db, ObjectId()); seed(db, ObjectId()); seed(db,ObjectId(),'ep_foreign','t2')
    worker.batch(db,'t1'); worker.batch(db,'t2')
    foreign=db[COLLECTION].find_one({'tenant_id':'t2'})
    db.v2_shadow_observations.delete_many({'tenant_id':'t1'})
    assert worker.acquire(db,'t1','a')
    assert worker.reconcile_index(db,'t1',size=1,owner='a')==1
    assert db[CHECKPOINTS].find_one({'_id':'t1'})['validation_after']
    db[CHECKPOINTS].update_one({'_id':'t1'},{'$set':{'lease_until':datetime.now(timezone.utc)-timedelta(seconds=1)}})
    assert worker.acquire(db,'t1','b')
    with pytest.raises(worker.LeaseBusy):
        worker.reconcile_index(db,'t1',owner='a')
    worker.reconcile_index(db,'t1',owner='b')
    assert db[COLLECTION].count_documents({'tenant_id':'t1','tokens':{'$ne':[]}})==0
    assert db[COLLECTION].find_one({'tenant_id':'t2'})==foreign
    assert db[CHECKPOINTS].find_one({'_id':'t1'})['validation_after'] is None

def test_source_read_failure_does_not_withdraw_or_advance(db,monkeypatch):
    from pymongo.errors import AutoReconnect
    endpoint(db); seed(db,ObjectId()); worker.batch(db,'t1')
    before=list(db[COLLECTION].find())
    def fail(*args,**kwargs): raise AutoReconnect('synthetic failure')
    monkeypatch.setattr(db.v2_shadow_observations,'find_one',fail)
    with pytest.raises(AutoReconnect): worker.reconcile_index(db,'t1')
    assert list(db[COLLECTION].find())==before
    assert not db[CHECKPOINTS].find_one({'_id':'t1'}).get('validation_after')
