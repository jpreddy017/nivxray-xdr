import json
from services.edr.forensic_profiles import result_receipt, ACTION

def test_large_snapshot_receipt_does_not_echo_evidence():
    doc={'action':ACTION,'command_id':'cmd_8033c23dacef4fc8b010','state':'EXECUTED','sensor_result':{'outcome':'EXECUTED','evidence':{'sha256':'a'*64,'rows':'x'*3646540}}}
    receipt=result_receipt(doc)
    assert len(json.dumps(receipt))<512
    assert receipt['evidence_sha256']=='a'*64
    assert receipt['outcome']=='EXECUTED'
    assert len(doc['sensor_result']['evidence']['rows'])==3646540

def test_replay_acknowledges_original_digest():
    doc={'action':ACTION,'command_id':'cmd_test','state':'EXECUTED','idempotent_replay':True,'sensor_result':{'outcome':'EXECUTED','evidence':{'sha256':'original'}}}
    assert result_receipt(doc)['evidence_sha256']=='original'
    assert result_receipt(doc)['idempotent_replay'] is True

def test_other_actions_preserve_contract():
    doc={'action':'ISOLATE_HOST','state':'EXECUTED','sensor_result':{'evidence':{}}}
    assert result_receipt(doc) is doc

def test_agent_route_returns_compact_receipt(monkeypatch):
    import asyncio
    from types import SimpleNamespace
    from routers import edr_response as route
    async def saved(*args, **kwargs):
        return {'action':ACTION,'command_id':'cmd_test','state':'EXECUTED','sensor_result':{'outcome':'EXECUTED','evidence':{'sha256':'persisted','rows':'x'*3646540}}}
    monkeypatch.setattr(route.resp,'record_result',saved)
    monkeypatch.setattr(route,'sensor_tenant',lambda tenant:tenant)
    response=asyncio.run(route.command_result(route.ResultBody(command_id='cmd_test',outcome='EXECUTED',detail='test',evidence={}),SimpleNamespace(tenant_id='fixture',endpoint_id='fixture')))
    assert response['evidence_sha256']=='persisted'
    assert len(json.dumps(response))<512
