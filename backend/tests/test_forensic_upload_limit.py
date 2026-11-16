from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from request_hardening import RequestHardeningMiddleware

def client():
    app=FastAPI()
    app.add_middleware(RequestHardeningMiddleware)
    @app.api_route('/{path:path}', methods=['POST','PUT'])
    async def receive(request: Request):
        return {'bytes':len(await request.body())}
    return TestClient(app)

def test_saved_snapshot_size_reaches_route():
    payload=b'x'*3646540
    response=client().post('/api/edr/agent/command-result',content=payload)
    assert response.status_code==200
    assert response.json()['bytes']==len(payload)

def test_snapshot_envelope_boundary():
    c=client()
    assert c.post('/api/edr/agent/command-result',content=b'x'*(16*1024*1024)).status_code==200
    response=c.post('/api/edr/agent/command-result',content=b'x'*(16*1024*1024+1))
    assert response.status_code==413
    assert response.json()['limit']==16*1024*1024

def test_unrelated_paths_keep_small_cap():
    for path in ['/api/edr/agent/command-results','/api/edr/agent/command-result/other','/api/decode/smart']:
        assert client().post(path,content=b'x'*(600*1024)).status_code==413

def test_non_post_keeps_small_cap():
    assert client().put('/api/edr/agent/command-result',content=b'x'*(600*1024)).status_code==413
