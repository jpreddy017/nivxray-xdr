"""Real FastAPI route + existing JWT dependency + spawned Universal Decoder.
Only the auth-record store is synthetic; no live DB or customer data is used.
"""
import base64
import json
import secrets
import subprocess
from pathlib import Path

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import deps
from routers.ops import router
from services.decoder import automatic_worker

@pytest.fixture
def client(monkeypatch):
    key = secrets.token_hex(32)
    monkeypatch.setattr(deps, 'JWT_SECRET', key)
    class Users:
        async def find_one(self, query, projection):
            if query['email'] in ('a@synthetic.invalid', 'b@synthetic.invalid'):
                return {'email': query['email'], 'role': 'analyst'}
    class DB:
        users = Users()
    monkeypatch.setattr(deps, 'db', DB())
    app = FastAPI()
    app.include_router(router, prefix='/api')
    with TestClient(app) as c:
        def headers(person='a'):
            return {'Authorization': 'Bearer ' + jwt.encode({'sub': person+'@synthetic.invalid'}, key, algorithm='HS256'), 'X-Tenant-Id': 'synthetic-'+person}
        yield c, headers


def test_authentication_is_required(client):
    c, _ = client
    assert c.post('/api/analyze/command', json={'input':'whoami', 'automatic':True}).status_code in (401,403)
    assert c.post('/api/analyze/command', headers={'Authorization':'Bearer invalid'}, json={'input':'whoami', 'automatic':True}).status_code == 401


def test_real_frontend_contract_to_authenticated_route_and_back(client):
    c, headers = client
    contract = Path(__file__).resolve().parents[2] / 'apps/nivxray-xdr/src/xdr/pages/commandIntelligenceContract.js'
    original = ' \tpowershell -enc '+base64.b64encode('Write-Output "hello"'.encode('utf-16le')).decode()+'\r\n'
    js = 'import {commandRequest} from '+json.dumps(contract.as_uri())+'; process.stdout.write(JSON.stringify(commandRequest(JSON.parse(process.argv[1]))));'
    request = json.loads(subprocess.check_output(['node','--input-type=module','-e',js,json.dumps(original)], text=True))
    response = c.post('/api/analyze/command', headers=headers(), json=request)
    assert response.status_code == 200, response.text
    report = response.json()
    assert report['original_command'] == original
    assert report['canonical_decoded_artifact']['text'] == 'Write-Output "hello"'
    assert report['mitre'] == []
    js = 'import {validateCommandResult} from '+json.dumps(contract.as_uri())+'; validateCommandResult(JSON.parse(process.argv[1]),JSON.parse(process.argv[2]));'
    subprocess.run(['node','--input-type=module','-e',js,json.dumps(report),json.dumps(original)], check=True)


def test_pure_analysis_has_no_cross_request_or_tenant_cache(client):
    c, headers = client
    for person in ('a','b','a'):
        value = base64.b64encode(('Write-Output "'+person+'"').encode()).decode()
        report = c.post('/api/analyze/command',headers=headers(person),json={'input':value,'automatic':True}).json()
        assert report['canonical_decoded_artifact']['text'] == 'Write-Output "'+person+'"'


def test_validation_and_worker_failures_are_explicit(client, monkeypatch):
    c, headers = client
    for bad in ('', 'é'*9000):
        r = c.post('/api/analyze/command',headers=headers(),json={'input':bad,'automatic':True})
        assert r.status_code == 422
    def busy(_): raise RuntimeError('Command analysis is busy; retry shortly')
    monkeypatch.setattr(automatic_worker,'analyze_isolated',busy)
    assert c.post('/api/analyze/command',headers=headers(),json={'input':'whoami','automatic':True}).status_code == 503
    def timeout(_): raise TimeoutError('Worker budget reached')
    monkeypatch.setattr(automatic_worker,'analyze_isolated',timeout)
    assert c.post('/api/analyze/command',headers=headers(),json={'input':'whoami','automatic':True}).status_code == 504


def test_legacy_contract_remains_available(client):
    c, headers = client
    r = c.post('/api/analyze/command',headers=headers(),json={'input':'whoami'})
    assert r.status_code == 200
    assert 'parsed_structure' in r.json()
    assert 'schema_version' not in r.json()


def _stall(connection, text):
    import time
    time.sleep(10)


def test_timeout_kills_and_reaps_worker(monkeypatch):
    import multiprocessing
    before = {p.pid for p in multiprocessing.active_children()}
    monkeypatch.setattr(automatic_worker, '_child', _stall)
    monkeypatch.setattr(automatic_worker, 'WORKER_SECONDS', .1)
    with pytest.raises(TimeoutError): automatic_worker.analyze_isolated('whoami')
    assert {p.pid for p in multiprocessing.active_children()} == before
    assert automatic_worker._CAPACITY.acquire(blocking=False)
    automatic_worker._CAPACITY.release()


def test_capacity_rejects_without_queue():
    assert automatic_worker._CAPACITY.acquire(blocking=False)
    assert automatic_worker._CAPACITY.acquire(blocking=False)
    try:
        with pytest.raises(RuntimeError, match='busy'): automatic_worker.analyze_isolated('whoami')
    finally:
        automatic_worker._CAPACITY.release(); automatic_worker._CAPACITY.release()


def test_worker_setup_failure_releases_capacity(monkeypatch):
    def unavailable(_):
        raise RuntimeError('spawn unavailable')
    monkeypatch.setattr(automatic_worker.multiprocessing, 'get_context', unavailable)
    for _ in range(3):
        with pytest.raises(RuntimeError, match='spawn unavailable'):
            automatic_worker.analyze_isolated('whoami')
    assert automatic_worker._CAPACITY.acquire(blocking=False)
    assert automatic_worker._CAPACITY.acquire(blocking=False)
    automatic_worker._CAPACITY.release()
    automatic_worker._CAPACITY.release()
