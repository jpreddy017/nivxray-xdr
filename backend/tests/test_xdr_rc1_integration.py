"""RC1 cross-feature contract probes; synthetic stores, external networking blocked."""
import pytest
from test_rbac_selected_customer import env, get
from routers import xdr_scope
from services import session_context as sc

@pytest.fixture
def combined(env, monkeypatch):
    env.client.app.include_router(xdr_scope.router)
    class Cases:
        def aggregate(self, pipeline): return []
        def find_one(self, query, projection=None):
            return {"id":"A-incident","tenant_id":"A"} if query.get("id")=="A-incident" else None
    monkeypatch.setattr(sc, "_cases", Cases())
    return env

@pytest.mark.parametrize("tenant,can_secret",[("A",True),("B",False)])
def test_scope_selection_and_rbac_projection_use_selected_customer(combined,tenant,can_secret):
    e=combined
    selection=e.client.post('/api/xdr/scope/select',json={"kind":"tenant","tenant_id":tenant},headers=e.headers)
    assert selection.status_code==200
    assert selection.json()['data']['tenant_ids']==[tenant]
    effective=get(e,'/api/xdr/rbac/me/effective',tenant=tenant)
    assert effective.status_code==200
    assert effective.json()['data']['tenant']==tenant
    assert ('secrets.read' in effective.json()['data']['permissions']) is can_secret
    assert get(e,tenant=tenant).status_code==(200 if can_secret else 403)

def test_no_incidents_does_not_hide_authorized_b8_customers(combined):
    result=combined.client.get('/api/xdr/scope/authorized',headers=combined.headers)
    assert result.status_code==200
    d=result.json()['data']
    assert d['tenants']==[]
    assert {r['customer'] for r in d['authorized_tenants']}=={'A','B'}
    assert d['authorized_count']==2

def test_c_and_forged_admin_role_do_not_expand_customer_authority(combined):
    combined.user['role']='admin'
    assert combined.client.post('/api/xdr/scope/select',json={"kind":"tenant","tenant_id":"C"},headers=combined.headers).status_code==403
    assert get(combined,'/api/xdr/rbac/me/effective',tenant='C').status_code==403

def test_incident_bound_scope_remains_a_when_b_requested(combined):
    response=combined.client.post('/api/xdr/scope/select',json={"kind":"tenant","tenant_id":"B","incident_id":"A-incident"},headers=combined.headers)
    assert response.status_code==403
    assert response.json()['detail']['locked'] is True
    assert response.json()['detail']['tenant_ids']==[]
    allowed=combined.client.post('/api/xdr/scope/select',json={"kind":"tenant","tenant_id":"A","incident_id":"A-incident"},headers=combined.headers)
    assert allowed.status_code==200
    assert allowed.json()['data']['tenant_ids']==['A']
    assert allowed.json()['data']['locked'] is True

def test_inactive_customer_selection_and_rbac_must_agree(combined):
    combined.tenants['B']['state']='SUSPENDED'
    assert get(combined,'/api/xdr/rbac/me/effective',tenant='B').status_code==403
    result=combined.client.post('/api/xdr/scope/select',json={"kind":"tenant","tenant_id":"B"},headers=combined.headers)
    assert result.status_code==403, 'Scope selection must reject the same inactive customer that RBAC rejects'
