"""Opt-in integration: isolated synthetic DB only; never opens the application DB."""
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from bson import ObjectId
from pymongo import MongoClient
from services.edr import device_identity as identity
from services.edr import endpoint_query as eq
from services.edr.global_file_index import COLLECTION, CHECKPOINTS, ensure_indexes, search, coverage_status
from scripts.edr_file_search_index import acquire, renew, batch, LeaseBusy
import deps

@pytest.fixture
def db(monkeypatch):
    uri = os.environ.get('EDR_TEST_MONGO_URL')
    if not uri:
        pytest.skip('EDR_TEST_MONGO_URL required for real MongoDB checks')
    client = MongoClient(uri, serverSelectionTimeoutMS=3000)
    name = 'edr_file_index_test_' + uuid4().hex
    database = client[name]
    monkeypatch.setattr(deps, 'sync_collection', lambda name: database[name])
    monkeypatch.setattr(identity, 'sync_collection', lambda name: database[name])
    monkeypatch.setattr(identity, '_obs', database.v2_shadow_observations)
    yield database
    client.drop_database(name)
    client.close()


def seed(db, ep='ep_test_a', tenant='index-test', oid=None):
    db.edr_endpoints.update_one({'endpoint_id':ep}, {'$set':{
        'endpoint_id':ep, 'tenant_id':tenant, 'hostname':ep+'-host', 'device_iid':ep+'-device'}}, upsert=True)
    oid = oid or ObjectId()
    db.v2_shadow_observations.insert_one({'_id':oid, 'tenant_id':tenant,
        'collector_id':ep, 'observation_id':str(oid), 'event':{
            'iid':str(oid), 'device_iid':ep+'-device', 'kind':'process_create',
            'ts':'2026-11-04T02:00:00Z', 'raw':{'computer':ep+'-host'},
            'process':{'image':r'C:\Windows\System32\wevtutil.exe'}}})
    return oid


def test_real_mongo_resume_incremental_lease_authorization_and_index(db):
    tenant='index-test'; scope={'all_tenants':False,'tenant_ids':[tenant]}
    first=seed(db); seed(db,'ep_test_b'); seed(db,'ep_foreign','other-test')
    ensure_indexes(db[COLLECTION])
    assert acquire(db,tenant,'worker-a')
    assert not acquire(db,tenant,'worker-b')
    assert batch(db,tenant,size=1,owner='worker-a')[0] == 1
    assert db[CHECKPOINTS].find_one({'_id':tenant})['after'] == str(first)
    # Simulate a crash and lease expiry; another process resumes the checkpoint.
    db[CHECKPOINTS].update_one({'_id':tenant},{'$set':{'lease_until':datetime.now(timezone.utc)-timedelta(seconds=1)}})
    assert acquire(db,tenant,'worker-b')
    with pytest.raises(LeaseBusy): renew(db,tenant,'worker-a')
    assert batch(db,tenant,owner='worker-b')[0] == 1
    assert db[COLLECTION].count_documents({}) == 2
    seed(db)
    assert batch(db,tenant,owner='worker-b')[0] == 1
    assert batch(db,tenant,owner='worker-b') == (0,0)
    result=search(db[COLLECTION],tenant,scope,eq.resolve_endpoint,'name:wevtutil.exe',1793757600000,1793757601000)
    assert [(x['endpoint_id'],x['matching_events']) for x in result['devices']] == [('ep_test_a',2),('ep_test_b',1)]
    assert coverage_status(db[CHECKPOINTS].find_one({'_id':tenant}))['status'] == 'current'
    plan=db[COLLECTION].find({'tenant_id':tenant,'tokens':'name:wevtutil.exe','time_ms':{'$gte':1793757600000}}).explain()
    assert 'IXSCAN' in str(plan['queryPlanner']['winningPlan'])
    with pytest.raises(PermissionError):
        search(db[COLLECTION],tenant,scope,eq.resolve_endpoint,'name:wevtutil.exe',1793757600000,1793757601000,endpoint='ep_foreign')


def test_freshness_states():
    now=datetime.now(timezone.utc)
    cp={'checked_at':now.isoformat(),'caught_up_at_check':True,'owner':'private-worker-id'}
    assert coverage_status(cp,now)['status']=='current'
    assert 'owner' not in coverage_status(cp,now)
    assert coverage_status(cp,now+timedelta(seconds=61))['status']=='stale'
    assert coverage_status(dict(cp,worker_status='error'),now)['status']=='error'
    assert coverage_status(dict(cp,unresolved=1),now)['status']=='partial'
    assert coverage_status(dict(cp,caught_up_at_check=False),now)['status']=='catching_up'


def test_reconcile_old_id_real_mongo(db):
    tenant='index-test'
    seed(db)
    ensure_indexes(db[COLLECTION])
    assert acquire(db,tenant,'replay')
    batch(db,tenant,owner='replay')
    old=ObjectId.from_datetime(datetime(2020,1,1,tzinfo=timezone.utc))
    seed(db,oid=old)
    assert batch(db,tenant,owner='replay') == (0,0)
    batch(db,tenant,owner='replay',reconcile=True)
    assert db[COLLECTION].count_documents({}) == 2
    batch(db,tenant,owner='replay',reconcile=True)
    assert db[COLLECTION].count_documents({}) == 2
    assert db.v2_shadow_observations.count_documents({}) == 2


def test_device_iid_only_evidence_is_indexed_with_authoritative_endpoint(db):
    oid=seed(db)
    db.v2_shadow_observations.update_one({'_id':oid},{'$unset':{'collector_id':''}})
    before=db.v2_shadow_observations.find_one({'_id':oid})
    ensure_indexes(db[COLLECTION])
    assert acquire(db,'index-test','iid-worker')
    batch(db,'index-test',owner='iid-worker')
    assert db[COLLECTION].find_one()['endpoint_id']=='ep_test_a'
    assert db.v2_shadow_observations.find_one({'_id':oid})==before
