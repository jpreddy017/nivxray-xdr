"""Real Mongo scope/RBAC acceptance; explicit loopback-only disposable database.
Run explicitly with XDR_RC2_TEST_MONGO_URI. No default/shared database fallback.
"""
import copy
import secrets
import socket
import uuid
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pymongo import MongoClient

import deps
from routers import xdr_rbac as rb, xdr_scope, xdr_audit_log as audit
from services import session_context as sc, tenant_registry as registry


@pytest.fixture
def mongo_env(monkeypatch):
    import os
    uri=os.environ.get('XDR_RC2_TEST_MONGO_URI','')
    parsed=urlparse(uri)
    assert parsed.scheme=='mongodb' and parsed.hostname=='127.0.0.1' and parsed.port
    assert not parsed.username and not parsed.password and parsed.path in ('','/')
    original=socket.socket.connect
    def local_only(sock,address):
        assert isinstance(address,tuple) and address[0]=='127.0.0.1' and address[1]==parsed.port, 'External network forbidden'
        return original(sock,address)
    monkeypatch.setattr(socket.socket,'connect',local_only)
    client=MongoClient(uri,serverSelectionTimeoutMS=2000,connectTimeoutMS=2000)
    client.admin.command('ping')
    name='xdr_rc2_test_'+uuid.uuid4().hex
    database=client[name]
    database.organizations.insert_one({'id':'O','state':'ACTIVE'})
    database.tenants.insert_many([{'id':t,'state':'ACTIVE','organization_id':'O'} for t in ['A','B','C']])
    profiles={'admin':['A'],'analyst':['A'],'mssp':['A','B']}
    for profile,tenants in profiles.items():
        email=profile+'@synthetic.test.invalid'
        database.users.insert_one({'email':email,'tenant_id':'A','tenant_ids':tenants,'role':'analyst','enabled':True})
        for tenant in tenants:
            uid=profile+'-'+tenant;rid='role-'+uid
            permissions=['console.soc.access','incidents.read','investigations.read','users.read']
            if profile=='admin':permissions+=['console.admin.access','users.delete','secrets.read']
            if profile=='mssp' and tenant=='A':permissions+=['secrets.read']
            database.xdr_users.insert_one({'id':uid,'email':email,'tenant_id':tenant,'enabled':True})
            database.xdr_roles.insert_one({'id':rid,'name':rid,'permissions':permissions,'enabled':True})
            database.xdr_user_roles.insert_one({'id':'assignment-'+uid,'tenant_id':tenant,'user_id':uid,'role_id':rid,'scope':{}})
    database.workspace_cases.insert_many([{'id':t+'-incident','tenant_id':t,'incident_state':'open','doc_type':'xdr_incident'} for t in ['A','B','C']])
    # Authentication keeps the real JWT/principal handler. Its async lookup
    # adapter reads the real Mongo collection, not an in-memory record stub.
    class AsyncUsers:
        async def find_one(self,query,projection=None):return database.users.find_one(query,projection)
    monkeypatch.setattr(deps,'db',SimpleNamespace(users=AsyncUsers()))
    monkeypatch.setattr(deps,'sync_collection',lambda collection:database[collection])
    monkeypatch.setattr(registry,'sync_collection',lambda collection:database[collection])
    monkeypatch.setattr(rb,'_db',lambda:database)
    monkeypatch.setattr(audit,'_get_coll',lambda:database.xdr_audit_log)
    monkeypatch.setattr(sc,'_cases',database.workspace_cases)
    # Use the supported signing configuration with an ephemeral synthetic
    # key; do not replace audit emission or signature calculation.
    monkeypatch.setenv('XDR_AUDIT_MASTER_SECRET',secrets.token_hex(32))
    monkeypatch.setattr(audit,'_KEY_CACHE',{})
    monkeypatch.setattr(deps,'JWT_SECRET',secrets.token_hex(32));monkeypatch.setattr(rb,'_JWT_SECRET',deps.JWT_SECRET)
    app=FastAPI();app.include_router(rb.router);app.include_router(xdr_scope.router)
    def headers(profile='mssp',tenant=None):
        result={'Authorization':'Bearer '+deps.create_token(profile+'@synthetic.test.invalid')}
        if tenant:result['X-Tenant-Id']=tenant
        return result
    try:
        with TestClient(app) as http:yield SimpleNamespace(db=database,http=http,headers=headers)
    finally:
        assert name.startswith('xdr_rc2_test_')
        client.drop_database(name);client.close()


@pytest.mark.parametrize('profile,allowed',[('admin',['A']),('analyst',['A']),('mssp',['A','B'])])
def test_real_mongo_profile_customer_scope(mongo_env,profile,allowed):
    e=mongo_env
    for tenant in ['A','B','C']:
        scope=e.http.post('/api/xdr/scope/select',json={'kind':'tenant','tenant_id':tenant},headers=e.headers(profile))
        effective=e.http.get('/api/xdr/rbac/me/effective',headers=e.headers(profile,tenant))
        assert scope.status_code==(200 if tenant in allowed else 403)
        assert effective.status_code==(200 if tenant in allowed else 403)
        if tenant in allowed:assert effective.json()['data']['tenant']==tenant


def test_actual_mongo_mssp_permissions_remain_different(mongo_env):
    e=mongo_env
    a=e.http.get('/api/xdr/rbac/me/effective',headers=e.headers(tenant='A')).json()['data']
    b=e.http.get('/api/xdr/rbac/me/effective',headers=e.headers(tenant='B')).json()['data']
    assert 'secrets.read' in a['permissions'] and 'secrets.read' not in b['permissions']
    assert 'console.admin.access' not in a['permissions'] and 'console.admin.access' not in b['permissions']


@pytest.mark.parametrize('profile',['admin','analyst','mssp'])
def test_actual_resource_ids_cannot_cross_customers(mongo_env,profile):
    e=mongo_env
    foreign=e.http.get('/api/xdr/rbac/users/mssp-B/effective',headers=e.headers(profile,'A'))
    missing=e.http.get('/api/xdr/rbac/users/nonexistent/effective',headers=e.headers(profile,'A'))
    assert foreign.status_code==missing.status_code==404
    assert foreign.json()==missing.json()
    rows=e.http.get('/api/xdr/rbac/users',headers=e.headers(profile,'A')).json()['data']['users']
    assert all(row['tenant_id']=='A' for row in rows)


def test_foreign_mutation_preserves_mongo_record_and_assignments(mongo_env):
    e=mongo_env
    before=e.db.xdr_users.find_one({'id':'mssp-B'})
    assignments=list(e.db.xdr_user_roles.find({'user_id':'mssp-B'}))
    foreign=e.http.delete('/api/xdr/rbac/users/mssp-B',headers=e.headers('admin','A'))
    missing=e.http.delete('/api/xdr/rbac/users/nonexistent',headers=e.headers('admin','A'))
    assert foreign.status_code==missing.status_code==404 and foreign.json()==missing.json()
    assert e.db.xdr_users.find_one({'id':'mssp-B'})==before
    assert list(e.db.xdr_user_roles.find({'user_id':'mssp-B'}))==assignments


def test_analyst_cannot_mutate_even_same_customer(mongo_env):
    e=mongo_env
    before=e.db.xdr_users.find_one({'id':'admin-A'})
    assert e.http.delete('/api/xdr/rbac/users/admin-A',headers=e.headers('analyst','A')).status_code==403
    assert e.db.xdr_users.find_one({'id':'admin-A'})==before
    assert e.db.xdr_audit_log.count_documents({'action':'ACCESS_DENIED','tenant_id':'A'})>=1


@pytest.mark.parametrize('kind',['tenant','group','all_authorized','incident'])
def test_real_mongo_suspension_excluded_from_all_scope_forms(mongo_env,kind):
    e=mongo_env;e.db.tenants.update_one({'id':'B'},{'$set':{'state':'SUSPENDED'}})
    assert e.http.get('/api/xdr/rbac/me/effective',headers=e.headers(tenant='B')).status_code==403
    body={'tenant':{'kind':'tenant','tenant_id':'B'},'group':{'kind':'group','group_tenant_ids':['A','B','C']},'all_authorized':{'kind':'all_authorized'},'incident':{'kind':'all_authorized','incident_id':'B-incident'}}[kind]
    result=e.http.post('/api/xdr/scope/select',json=body,headers=e.headers())
    if kind in ['tenant','incident']:assert result.status_code==403
    else:assert result.status_code==200 and result.json()['data']['tenant_ids']==['A']


@pytest.mark.parametrize('mode',['missing','disabled'])
def test_real_mongo_membership_invalidation_clears_permissions(mongo_env,mode):
    e=mongo_env
    assert e.http.get('/api/xdr/rbac/me/effective',headers=e.headers(tenant='B')).status_code==200
    if mode=='missing':e.db.xdr_users.delete_one({'id':'mssp-B'})
    else:e.db.xdr_users.update_one({'id':'mssp-B'},{'$set':{'enabled':False}})
    result=e.http.get('/api/xdr/rbac/me/effective',headers=e.headers(tenant='B'))
    assert result.status_code==200 and result.json()['data']['permissions']==[]
    assert result.json()['data']['basis'] in ['USER_NOT_PROVISIONED','USER_DISABLED']


def test_real_mongo_revoked_grant_is_not_cached(mongo_env):
    e=mongo_env
    assert e.http.post('/api/xdr/scope/select',json={'kind':'tenant','tenant_id':'B'},headers=e.headers()).status_code==200
    e.db.users.update_one({'email':'mssp@synthetic.test.invalid'},{'$set':{'tenant_ids':['A']}})
    assert e.http.post('/api/xdr/scope/select',json={'kind':'tenant','tenant_id':'B'},headers=e.headers()).status_code==403
    assert e.http.get('/api/xdr/rbac/me/effective',headers=e.headers(tenant='B')).status_code==403


def test_real_mongo_foreign_incident_and_conflicting_claims_denied(mongo_env):
    e=mongo_env
    assert e.http.post('/api/xdr/scope/select',json={'kind':'all_authorized','incident_id':'C-incident'},headers=e.headers()).status_code==403
    assert e.http.post('/api/xdr/scope/select?tenant_id=C',json={'kind':'tenant','tenant_id':'A'},headers=e.headers()).status_code==403
    assert e.http.get('/api/xdr/rbac/me/effective?tenant_id=B',headers=e.headers(tenant='A')).status_code==403
