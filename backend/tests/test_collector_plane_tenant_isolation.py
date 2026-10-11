"""Real guards and handlers; synthetic identities, temporary SQLite, no network."""
import hashlib
import importlib.util
import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt
import mongomock
import pytest
from fastapi import Depends, FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'apps/nivxray-xdr-collector'))
from framework.base import Envelope
from framework.outbox import Outbox, OutboxStatus
from framework.store import ConnectorStore
from framework.webhook import WebhookConnector
from routes import connectors, outbox, data_sources, telemetry_health, collectors
from routers import collector_authz as ca, xdr_rbac as rb, xdr_collectors as plural
from services import session_context as sc

SECRET = 'synthetic-assessment-jwt-key-32-bytes'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*a, **k):
        raise AssertionError('External network forbidden in collector security tests')
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)
    monkeypatch.setattr(socket, 'create_connection', blocked)


@pytest.fixture(params=['human', 'key', 'service'])
def rig(request, monkeypatch, tmp_path):
    monkeypatch.setattr(rb, '_JWT_SECRET', SECRET)
    async def verified(creds):
        try:
            claims = jwt.decode(creds.credentials, SECRET, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            raise HTTPException(401)
        return {'email': claims['sub'], 'tenant_id': 'ten_a', 'role': 'analyst'}
    monkeypatch.setattr(rb, '_deps_current_user', verified)
    monkeypatch.setattr(rb, '_c_users', lambda: object())
    monkeypatch.setattr(rb, 'check_access', lambda tenant, *a, **k: {'allow': tenant == 'ten_a'})
    monkeypatch.setattr(rb, 'emit_audit', lambda **k: None)
    monkeypatch.setattr(sc, 'resolve_tenant_scope', lambda email: {
        'authorized': True, 'all_tenants': False, 'tenant_ids': ['ten_a']})
    monkeypatch.setattr(ca.tenant_registry, 'authoritative', lambda tenant, **k: tenant)
    monkeypatch.setenv('NIVX_COLLECTOR_TEST_PLANE', '1')
    monkeypatch.delenv('MONGO_URL', raising=False)
    db = mongomock.MongoClient().db
    monkeypatch.setattr(rb, '_c_api_keys', lambda: db.keys)
    monkeypatch.setattr(rb, '_throttle', lambda *a, **k: {})
    monkeypatch.setattr(rb, '_audit_machine_denial', lambda *a, **k: None)
    raw_key = 'nvx_' + 'a' * 48
    db.keys.insert_one({'id': 'test-key-a', 'tenant_id': 'ten_a',
        'hash': hashlib.sha256(raw_key.encode()).hexdigest(), 'enabled': True,
        'revoked_at': None, 'expires_at': None, 'scopes': ['collectors.*']})
    app = FastAPI()
    prefix = '/api/xdr/collector'
    guard = ca.collector_guard
    headers = {'Authorization': 'Bearer ' + jwt.encode({'sub': 'a@synthetic.test'}, SECRET),
               'X-Tenant-Id': 'ten_a'}
    if request.param == 'key':
        headers = {'X-XDR-API-Key': raw_key, 'X-Tenant-Id': 'ten_a'}
    if request.param == 'service':
        # Load the actual standalone fallback, without the backend import shim.
        spec = importlib.util.spec_from_file_location('standalone_assessment_authz',
            ROOT / 'apps/nivxray-xdr-collector/framework/authz.py')
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'routers.collector_authz': None}):
            spec.loader.exec_module(module)
        guard = module.collector_guard
        prefix = '/api/xdr'
        monkeypatch.setenv('COLLECTOR_CONTROL_SERVICE_CREDENTIAL', 'synthetic-service-only')
        headers = {'Authorization': 'Bearer synthetic-service-only',
                   'X-Authenticated-Tenant': 'ten_a', 'X-Tenant-Id': 'ten_a'}
    app.state.collector_mount_prefix = prefix
    store = ConnectorStore(state_dir=str(tmp_path / 'configs'))
    records = {t: store.create(t, 'webhook', t, {'secret_id': t}) for t in ('ten_a', 'ten_b')}
    ob = Outbox(path=str(tmp_path / 'outbox'))
    ids = {}
    for tenant, rec in records.items():
        ids[tenant], _ = ob.record(Envelope(tenant_id=tenant, source=tenant,
            source_event_id=tenant, connector_id=rec.id, collector_id='synthetic',
            collection_method='webhook', parser_version='test', source_timestamp=None,
            collection_timestamp='2026-10-11T00:00:00Z', event_type='webhook',
            raw={'synthetic': tenant}, canonical={}))
        ob._conn.execute('UPDATE envelopes SET status=? WHERE id=?',
                         (OutboxStatus.DEAD_LETTER, ids[tenant]))
    calls = []
    async def side_effect(*a, **k):
        calls.append('runtime')
        return {'ok': True}
    async def inject_effect(*a, **k):
        calls.append('inject')
        return []
    app.state.store = store
    app.state.instances = {r.id: WebhookConnector(t, r.config, r.id) for t, r in records.items()}
    app.state.runtime = SimpleNamespace(outbox=ob, start=side_effect, stop=side_effect,
        handle_inject=inject_effect, worker=SimpleNamespace(tick_once=side_effect))
    app.state.registry = SimpleNamespace(register_instance=lambda *a: None,
        list_ids=lambda: list(app.state.instances))
    for router in (connectors.router, outbox.router, data_sources.router,
                   telemetry_health.router, collectors.router):
        app.include_router(router, prefix=prefix, dependencies=[Depends(guard)])
    db.collectors.insert_many([{'id': t, 'tenant_id': t, 'name': t} for t in records])
    monkeypatch.setattr(plural, '_coll', lambda: db.collectors)
    app.include_router(plural.router)
    yield SimpleNamespace(app=app, prefix=prefix, headers=headers, records=records,
        ids=ids, ob=ob, store=store, calls=calls, kind=request.param)
    ob.close()


async def send(rig, method, path, **kwargs):
    async with AsyncClient(transport=ASGITransport(app=rig.app), base_url='http://test') as c:
        return await c.request(method, rig.prefix + path,
            headers=kwargs.pop('headers', rig.headers), **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize('method,suffix,body', [
    ('GET', '', None), ('PATCH', '', {'label': 'attempt'}), ('DELETE', '', None),
    ('POST', '/test', None), ('POST', '/start', None), ('POST', '/stop', None),
    ('POST', '/inject', {'payload': {'synthetic': True}})])
async def test_foreign_connector_matches_missing_and_has_no_side_effects(rig, method, suffix, body):
    before = rig.records['ten_b'].redacted()
    foreign = await send(rig, method, '/connectors/' + rig.records['ten_b'].id + suffix, json=body)
    missing = await send(rig, method, '/connectors/missing' + suffix, json=body)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()
    assert rig.records['ten_b'].redacted() == before
    assert not rig.calls


@pytest.mark.asyncio
async def test_own_connector_read_update_create_delete_succeed(rig):
    path = '/connectors/' + rig.records['ten_a'].id
    assert (await send(rig, 'GET', path)).status_code == 200
    assert (await send(rig, 'PATCH', path, json={'label': 'own'})).status_code == 200
    created = await send(rig, 'POST', '/connectors', json={
        'source_type': 'webhook', 'label': 'own-new', 'config': {'secret_id': 'new'}})
    assert created.status_code == 201
    assert created.json()['tenant_id'] == 'ten_a'
    assert (await send(rig, 'DELETE', path)).status_code == 200


@pytest.mark.asyncio
async def test_own_connector_controls_and_enabled_test_plane_succeed(rig):
    path = '/connectors/' + rig.records['ten_a'].id
    for action in ('start', 'stop', 'test'):
        assert (await send(rig, 'POST', path + '/' + action)).status_code == 200
    headers = {**rig.headers, 'X-Debug-Inject': '1'}
    assert (await send(rig, 'POST', path + '/inject', headers=headers,
                       json={'payload': {'synthetic': True}})).status_code == 200
    assert rig.calls == ['runtime', 'runtime', 'inject']


@pytest.mark.asyncio
@pytest.mark.parametrize('claim', ['header', 'authenticated_header', 'query', 'body'])
async def test_conflicting_tenant_claims_denied(rig, claim):
    headers = dict(rig.headers)
    query, body = {}, {'label': 'attempt'}
    if claim == 'header': headers['X-Tenant-Id'] = 'ten_b'
    if claim == 'authenticated_header': headers['X-Authenticated-Tenant'] = 'ten_b'
    if claim == 'query': query['tenant_id'] = 'ten_b'
    if claim == 'body': body['tenant_id'] = 'ten_b'
    response = await send(rig, 'PATCH', '/connectors/' + rig.records['ten_a'].id,
                          headers=headers, params=query, json=body)
    assert response.status_code == 403
    assert rig.records['ten_a'].label == 'ten_a'
    assert not rig.calls


@pytest.mark.asyncio
async def test_outbox_evidence_replay_and_global_drain_are_isolated(rig):
    for suffix, method in [('', 'GET'), ('/replay', 'POST')]:
        foreign = await send(rig, method, '/outbox/' + rig.ids['ten_b'] + suffix)
        missing = await send(rig, method, '/outbox/missing' + suffix)
        assert foreign.status_code == missing.status_code == 404
        assert foreign.json() == missing.json()
    assert rig.ob.by_id(rig.ids['ten_b']).status == OutboxStatus.DEAD_LETTER
    assert (await send(rig, 'GET', '/outbox/' + rig.ids['ten_a'])).json()['raw'] == {'synthetic': 'ten_a'}
    assert (await send(rig, 'POST', '/outbox/' + rig.ids['ten_a'] + '/replay')).status_code == 200
    assert (await send(rig, 'POST', '/outbox/drain-once')).status_code == 403
    assert not rig.calls


@pytest.mark.asyncio
async def test_lists_and_health_are_tenant_scoped(rig):
    assert [r['tenant_id'] for r in (await send(rig, 'GET', '/connectors')).json()['connectors']] == ['ten_a']
    assert [r['tenant_id'] for r in (await send(rig, 'GET', '/outbox')).json()['envelopes']] == ['ten_a']
    assert (await send(rig, 'GET', '/outbox', params={'connector_id': rig.records['ten_b'].id})).json()['count'] == 0
    assert [r['tenant_id'] for r in (await send(rig, 'GET', '/data-sources')).json()['data_sources']] == ['ten_a']
    health = (await send(rig, 'GET', '/telemetry-health')).json()
    assert rig.records['ten_b'].id not in str(health)
    assert health['outbox']['counts'][OutboxStatus.DEAD_LETTER] == 1
    assert health['worker']['state'] == 'not_available'
    assert (await send(rig, 'GET', '/outbox/health')).json()['outbox']['counts'][OutboxStatus.DEAD_LETTER] == 1
    assert (await send(rig, 'GET', '/collectors')).json()['collectors'][0]['active_connectors'] == 1


@pytest.mark.asyncio
async def test_anonymous_and_bad_credentials_denied(rig):
    assert (await send(rig, 'GET', '/connectors', headers={})).status_code in (401, 403)
    assert (await send(rig, 'GET', '/connectors', headers={'Authorization': 'Bearer invalid'})).status_code in (401, 403)


@pytest.mark.asyncio
async def test_duplicate_tenant_headers_denied(rig):
    headers = list(rig.headers.items()) + [('X-Tenant-Id', 'ten_b')]
    assert (await send(rig, 'GET', '/connectors', headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_permission_or_service_context_required(rig, monkeypatch):
    if rig.kind == 'service':
        headers = {k: v for k, v in rig.headers.items() if k != 'X-Authenticated-Tenant'}
        assert (await send(rig, 'GET', '/connectors', headers=headers)).status_code == 403
    elif rig.kind == 'human':
        monkeypatch.setattr(rb, 'check_access', lambda *a, **k: {'allow': False, 'reason': 'no grant'})
        assert (await send(rig, 'GET', '/connectors')).status_code == 403
    else:
        keys = rb._c_api_keys()
        keys.update_one({'id': 'test-key-a'}, {'$set': {'revoked_at': '2026-10-11'}})
        assert (await send(rig, 'GET', '/connectors')).status_code == 403


@pytest.mark.asyncio
async def test_plural_collector_scope_preserved(rig):
    app = FastAPI()  # Standalone /collectors has a different route contract.
    app.include_router(plural.router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
        if rig.kind == 'service':
            assert (await c.get('/api/xdr/collectors/ten_a', headers=rig.headers)).status_code == 401
            return
        assert (await c.get('/api/xdr/collectors/ten_a', headers=rig.headers)).status_code == 200
        assert (await c.get('/api/xdr/collectors/ten_b', headers=rig.headers)).status_code == 404
