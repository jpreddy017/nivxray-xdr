"""Synthetic webhook security proofs; network blocked, atomic Redis double."""
import asyncio
import hashlib
import hmac
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from framework import webhook, webhook_replay
from framework.webhook import WebhookConnector
from framework.webhook_replay import RedisReplayStore, ReplayStoreUnavailable
from routes.webhooks import router

NOW = 1800000000
SECRET = 'synthetic-hmac-only'


class AtomicRedis:
    """Models Redis SET NX EX atomically, shared by independent clients."""
    def __init__(self):
        self.rows = {}
        self.lock = threading.Lock()
        self.calls = []
        self.now = NOW
        self.down = False

    def set(self, key, value, *, nx, ex):
        with self.lock:
            if self.down:
                raise ConnectionError('synthetic unavailable')
            self.calls.append((key, value, nx, ex))
            assert nx is True and isinstance(ex, int) and ex > 0
            if key in self.rows and self.rows[key] > self.now:
                return None
            self.rows[key] = self.now + ex
            return True


def store(server):
    adapter = object.__new__(RedisReplayStore)
    adapter.client = server
    return adapter


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    def blocked(*a, **k):
        raise AssertionError('External network forbidden')
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)
    monkeypatch.setattr(webhook.time, 'time', lambda: NOW)
    server = AtomicRedis()
    monkeypatch.setattr(webhook, 'replay_store', lambda: store(server))
    return server


def connector(tenant='tenant-a', secret_id='synthetic-endpoint', identity='instance-1', signature=None):
    cfg = {'secret_id': secret_id, 'credentials': {'hmac_secret': SECRET}}
    if signature is not None:
        cfg['signature'] = signature
    return WebhookConnector(tenant, cfg, identity)


def signed(body=b'{"synthetic":true}', timestamp=str(NOW), prefix='sha256=', algo='sha256'):
    digest = hmac.new(SECRET.encode(), timestamp.encode() + b'.' + body,
                      getattr(hashlib, algo)).hexdigest()
    return {'X-Timestamp': timestamp, 'X-Hub-Signature-256': prefix + digest}


def test_unsigned_always_refused_even_with_legacy_dev_bypass(monkeypatch, isolated):
    monkeypatch.setenv('XDR_COLLECTOR_ENV', 'test')
    monkeypatch.setenv('XDR_WEBHOOK_ALLOW_UNSIGNED_DEV', '1')
    c = WebhookConnector('tenant-a', {'secret_id': 'synthetic'})
    assert c.verify(b'{}', {}) == {'ok': False, 'reason': 'hmac_secret_not_configured'}
    assert not isolated.calls


@pytest.mark.parametrize('timestamp,reason', [
    ('', 'missing_timestamp_header'), ('nan', 'malformed_timestamp'),
    ('inf', 'malformed_timestamp'), ('-inf', 'malformed_timestamp'),
    ('invalid', 'malformed_timestamp'), (str(NOW-301), 'expired_timestamp'),
    (str(NOW+301), 'future_timestamp')])
def test_invalid_timestamps_never_claim(isolated, timestamp, reason):
    headers = signed(timestamp=timestamp)
    assert connector().verify(b'{"synthetic":true}', headers)['reason'] == reason
    assert not isolated.calls


@pytest.mark.parametrize('alteration', ['body', 'timestamp', 'signature', 'body_only'])
def test_authentication_covers_exact_original_bytes(isolated, alteration):
    body = b'{ "synthetic": true }'
    headers = signed(body)
    if alteration == 'body': body = b'{"synthetic":true}'
    if alteration == 'timestamp': headers['X-Timestamp'] = str(NOW+1)
    if alteration == 'signature': headers['X-Hub-Signature-256'] = 'sha256='+'0'*64
    if alteration == 'body_only':
        headers['X-Hub-Signature-256'] = 'sha256='+hmac.new(SECRET.encode(),body,hashlib.sha256).hexdigest()
    assert connector().verify(body, headers)['reason'] == 'signature_mismatch'
    assert not isolated.calls


@pytest.mark.parametrize('variant', ['same', 'bare', 'upper_hex'])
def test_prefix_and_case_variants_are_the_same_replay(isolated, variant):
    body = b'{"synthetic":true}'
    headers = signed(body)
    assert connector().verify(body, headers)['ok']
    if variant == 'bare': headers['X-Hub-Signature-256'] = headers['X-Hub-Signature-256'][7:]
    if variant == 'upper_hex': headers['X-Hub-Signature-256'] = 'sha256='+headers['X-Hub-Signature-256'][7:].upper()
    # A different connector instance/identity still sees the shared claim.
    assert connector(identity='restarted').verify(body, headers)['reason'] == 'replayed_request'
    assert isolated.calls[0][0] == isolated.calls[1][0]
    assert SECRET not in isolated.calls[0][0] and 'tenant-a' not in isolated.calls[0][0]


def test_parallel_instances_have_one_winner(isolated):
    body = b'{"synthetic":true}'
    barrier = threading.Barrier(16)
    def verify(index):
        barrier.wait()
        return connector(identity=str(index)).verify(body, signed(body))
    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(verify, range(16)))
    assert sum(r['ok'] for r in results) == 1
    assert sum(r.get('reason') == 'replayed_request' for r in results) == 15


def test_tenant_and_endpoint_namespaces_are_independent(isolated):
    body = b'{"synthetic":true}'
    for tenant, sid in [('tenant-a','one'),('tenant-b','one'),('tenant-a','two')]:
        assert connector(tenant, sid).verify(body, signed(body))['ok']
    assert len(isolated.rows) == 3


def test_future_timestamp_claim_covers_whole_acceptance_window(isolated, monkeypatch):
    body = b'{"synthetic":true}'
    headers = signed(body, str(NOW+300))
    assert connector().verify(body, headers)['ok']
    assert isolated.calls[0][3] == 601
    isolated.now = NOW+600
    monkeypatch.setattr(webhook.time, 'time', lambda: NOW+600)
    assert connector().verify(body, headers)['reason'] == 'replayed_request'
    isolated.now = NOW+602
    monkeypatch.setattr(webhook.time, 'time', lambda: NOW+602)
    assert connector().verify(body, headers)['reason'] == 'expired_timestamp'


def test_store_failure_refuses_then_recovers(isolated):
    isolated.down = True
    body = b'{"synthetic":true}'
    assert connector().verify(body, signed(body))['reason'] == 'replay_store_unavailable'
    isolated.down = False
    assert connector().verify(body, signed(body))['ok']


def test_missing_redis_configuration_has_no_fallback(monkeypatch):
    monkeypatch.delenv('REDIS_URL', raising=False)
    monkeypatch.delenv('NIVX_WEBHOOK_REPLAY_REDIS_URL', raising=False)
    monkeypatch.setattr(webhook, 'replay_store', webhook_replay.replay_store)
    assert connector().verify(b'{"synthetic":true}', signed())['reason'] == 'replay_store_unavailable'


def test_adapter_uses_configured_redis_with_timeouts(monkeypatch, isolated):
    import redis
    observed = {}
    def from_url(url, **kwargs):
        observed.update(url=url, **kwargs)
        return isolated
    monkeypatch.setattr(redis.Redis, 'from_url', from_url)
    adapter = RedisReplayStore('rediss://synthetic.invalid:6379/3')
    assert adapter.claim('synthetic-key', 601)
    assert not adapter.claim('synthetic-key', 601)
    assert observed['socket_timeout'] == observed['socket_connect_timeout'] == 1


def test_unexpected_redis_reply_fails_closed():
    adapter = store(SimpleNamespace(set=lambda *a, **k: False))
    with pytest.raises(ReplayStoreUnavailable): adapter.claim('test', 601)


def test_existing_custom_header_and_sha1_contract(isolated):
    body = b'{"synthetic":true}'
    headers = signed(body, algo='sha1', prefix='custom=')
    headers['x-custom'] = headers.pop('X-Hub-Signature-256')
    c = connector(signature={'header':'X-Custom','algo':'sha1','prefix':'custom='})
    assert c.verify(body, headers)['ok']


@pytest.mark.asyncio
async def test_http_failures_never_deliver_and_parallel_requests_deliver_once(isolated):
    app = FastAPI()
    c = connector()
    delivered = []
    async def deliver(*args): delivered.append(args)
    app.state.instances = {'one': c}
    app.state.runtime = SimpleNamespace(deliver=deliver)
    app.include_router(router, prefix='/api/xdr')
    body = b'{"synthetic":true}'
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
        assert (await client.post('/api/xdr/webhooks/synthetic-endpoint',content=body)).status_code == 401
        isolated.down = True
        assert (await client.post('/api/xdr/webhooks/synthetic-endpoint',content=body,headers=signed(body))).status_code == 503
        assert not delivered
        isolated.down = False
        results = await asyncio.gather(*[client.post('/api/xdr/webhooks/synthetic-endpoint',
            content=body,headers=signed(body)) for _ in range(8)])
        assert sum(r.status_code == 200 for r in results) == 1
        assert len(delivered) == 1
        assert delivered[0][1][0].raw == {'synthetic': True}


@pytest.mark.asyncio
async def test_ambiguous_endpoint_mapping_refuses_before_authentication(isolated):
    app = FastAPI()
    app.state.instances = {'a':connector('tenant-a'), 'b':connector('tenant-b')}
    app.include_router(router, prefix='/api/xdr')
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
        assert (await client.post('/api/xdr/webhooks/synthetic-endpoint',content=b'{}')).status_code == 404
    assert not isolated.calls
