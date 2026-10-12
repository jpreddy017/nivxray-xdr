"""Synthetic RC1-P1 negative scope/registry tests. Reuses network-blocked RC1 fixture."""
import pytest
from test_xdr_rc1_integration import combined
from test_rbac_selected_customer import env, get
from services import session_context as sc, tenant_registry as registry


def select(e, **body):
    return e.client.post('/api/xdr/scope/select',json=body,headers=e.headers)


@pytest.mark.parametrize('failure',['SUSPENDED','DISABLED','unknown','organization','registry','stale_grant'])
@pytest.mark.parametrize('kind',['tenant','group','all_authorized','incident'])
def test_every_scope_filters_invalid_customer_and_matches_rbac(combined,monkeypatch,failure,kind):
    e=combined
    if failure in ['SUSPENDED','DISABLED']:e.tenants['B']['state']=failure
    elif failure=='unknown':e.tenants.pop('B')
    elif failure=='organization':
        e.tenants['B']['organization_id']='OB'
        monkeypatch.setattr(registry,'get_organization',lambda key:{'state':'DISABLED'} if key=='OB' else {'state':'ACTIVE'})
    elif failure=='registry':
        original=registry.get_tenant
        def lookup(key):
            if key=='B':raise RuntimeError('synthetic registry failure')
            return original(key)
        monkeypatch.setattr(registry,'get_tenant',lookup)
    else:e.user['tenant_ids']=['A']
    class Cases:
        def find_one(self,*args,**kwargs):return {'id':'B-incident','tenant_id':'B'}
        def aggregate(self,*args,**kwargs):return []
    monkeypatch.setattr(sc,'_cases',Cases())
    assert get(e,'/api/xdr/rbac/me/effective',tenant='B').status_code in [403,503]
    if kind=='tenant':
        response=select(e,kind='tenant',tenant_id='B');assert response.status_code==403
    elif kind=='incident':
        response=select(e,kind='all_authorized',incident_id='B-incident');assert response.status_code==403
    elif kind=='group':
        response=select(e,kind='group',group_tenant_ids=['A','B','C','GHOST','A'])
        assert response.status_code==200
        assert response.json()['data']['tenant_ids']==['A']
        assert set(response.json()['data']['denied_tenant_ids'])=={'B','C','GHOST'}
        assert select(e,kind='group',group_tenant_ids=['B','C','GHOST']).status_code==403
    else:
        response=select(e,kind='all_authorized');assert response.status_code==200
        assert response.json()['data']['tenant_ids']==['A']
    assert select(e,kind='tenant',tenant_id='A').status_code==200
    assert get(e,'/api/xdr/rbac/me/effective',tenant='A').status_code==200


@pytest.mark.parametrize('kind',['tenant','group','all_authorized','incident'])
def test_total_registry_outage_never_authorizes_any_scope(combined,monkeypatch,kind):
    def down(key):raise RuntimeError('synthetic registry unavailable')
    monkeypatch.setattr(registry,'get_tenant',down)
    bodies={'tenant':{'kind':'tenant','tenant_id':'A'},'group':{'kind':'group','group_tenant_ids':['A','B']},'all_authorized':{'kind':'all_authorized'},'incident':{'kind':'all_authorized','incident_id':'A-incident'}}
    assert select(combined,**bodies[kind]).status_code==403
    assert get(combined,'/api/xdr/rbac/me/effective',tenant='A').status_code==503
    projection=combined.client.get('/api/xdr/scope/authorized',headers=combined.headers)
    assert projection.status_code==200
    assert projection.json()['data']['authorized_tenants']==[]
    assert not projection.json()['data']['default_scope']['authorized']


@pytest.mark.parametrize('target',['B','C','GHOST'])
def test_platform_designation_cannot_override_registry(combined,monkeypatch,target):
    combined.user['authority_scope']='PLATFORM'
    combined.tenants['B']['state']='SUSPENDED'
    monkeypatch.setattr(registry,'list_organizations',lambda **kw:[{'id':'O','state':'ACTIVE'}])
    monkeypatch.setattr(registry,'list_tenants',lambda **kw:[combined.tenants['A'],combined.tenants['B']])
    assert select(combined,kind='tenant',tenant_id=target).status_code==403
    assert select(combined,kind='all_authorized').json()['data']['tenant_ids']==['A']


def test_platform_enumeration_revalidates_rows_against_registry(combined,monkeypatch):
    combined.user['authority_scope']='PLATFORM'
    monkeypatch.setattr(registry,'list_organizations',lambda **kw:[{'id':'O','state':'ACTIVE'}])
    monkeypatch.setattr(registry,'list_tenants',lambda **kw:[{'id':'GHOST','state':'ACTIVE','organization_id':'O'}])
    assert select(combined,kind='all_authorized').status_code==403


@pytest.mark.parametrize('body',[{'kind':'all_authorized','tenant_id':'B'},{'kind':'tenant','tenant_id':'A','group_tenant_ids':['B']},{'kind':'group','tenant_id':'A','group_tenant_ids':['B']}])
def test_conflicting_scope_shapes_are_denied(combined,body):
    assert select(combined,**body).status_code==403


@pytest.mark.parametrize('query',['tenant_id=C','tenant=B','tenant_id=A&tenant_id=B','tenant_id='])
def test_query_selector_cannot_override_body(combined,query):
    assert combined.client.post('/api/xdr/scope/select?'+query,json={'kind':'tenant','tenant_id':'A'},headers=combined.headers).status_code==403


def test_body_alias_is_rejected_instead_of_ignored(combined):
    assert select(combined,kind='tenant',tenant_id='A',customer_id='C').status_code==422


@pytest.mark.parametrize('header',['C','GHOST',''])
def test_foreign_current_context_cannot_hide_behind_authorized_body(combined,header):
    headers={**combined.headers,'X-Tenant-Id':header}
    assert combined.client.post('/api/xdr/scope/select',json={'kind':'tenant','tenant_id':'A'},headers=headers).status_code==403


def test_duplicate_conflicting_context_headers_denied(combined):
    headers=list(combined.headers.items())+[('X-Tenant-Id','A'),('X-Tenant-Id','B')]
    assert combined.client.post('/api/xdr/scope/select',json={'kind':'tenant','tenant_id':'A'},headers=headers).status_code==403


def test_legitimate_mssp_a_to_b_switch_accepts_valid_current_context(combined):
    headers={**combined.headers,'X-Tenant-Id':'A'}
    result=combined.client.post('/api/xdr/scope/select',json={'kind':'tenant','tenant_id':'B'},headers=headers)
    assert result.status_code==200 and result.json()['data']['tenant_ids']==['B']
    assert get(combined,'/api/xdr/rbac/me/effective',tenant='B').json()['data']['tenant']=='B'


def test_b8_picker_keeps_active_customers_with_no_incidents(combined):
    combined.tenants['B']['state']='SUSPENDED'
    d=combined.client.get('/api/xdr/scope/authorized',headers=combined.headers).json()['data']
    assert d['tenants']==[] and [r['customer'] for r in d['authorized_tenants']]==['A']
    assert d['authorized_count']==1 and d['default_scope']['tenant_ids']==['A']


def test_empty_platform_registry_denies_all_authorized(combined,monkeypatch):
    combined.user['authority_scope']='PLATFORM'
    monkeypatch.setattr(registry,'list_organizations',lambda **kw:[])
    monkeypatch.setattr(registry,'list_tenants',lambda **kw:[])
    assert select(combined,kind='all_authorized').status_code==403


def test_no_caller_can_expand_universe_with_unknown_scope_kind(combined):
    assert sc.effective_scope(combined.user['email'],kind='unsupported')['authorized'] is False
