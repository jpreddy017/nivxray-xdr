"""Synthetic JWT/storage tests; no server startup, network or real credentials."""
import copy
import secrets
from types import SimpleNamespace
import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from pymongo.errors import DuplicateKeyError
import deps
from services import dashboard_lenses as lenses, tenant_registry as registry
from routers import auto_investigate_jobs as route, decoded_artifacts as api
from v2.jobs import store
from v2 import decoded_artifacts as cache

class Cursor:
    def __init__(self, rows): self.rows=copy.deepcopy(rows)
    def sort(self,*a): return self
    def limit(self,n): self.rows=self.rows[:n];return self
    async def to_list(self,n): return self.rows[:n]

class Collection:
    def __init__(self): self.rows=[];self.queries=[]
    def match(self,row,q): return all(row.get(k)==v for k,v in q.items())
    async def find_one(self,q,projection=None):
        self.queries.append(copy.deepcopy(q));return next((copy.deepcopy(r) for r in self.rows if self.match(r,q)),None)
    async def insert_one(self,row):
        if any(r['_id']==row['_id'] for r in self.rows):raise DuplicateKeyError('synthetic duplicate')
        self.rows.append(copy.deepcopy(row))
    async def update_one(self,q,update):
        for row in self.rows:
            if self.match(row,q):
                row['provenance']['hit_count']+=1
                for k,v in update.get('$push',{}).items(): row['provenance'][k.split('.')[1]].extend(v['$each'])
    def find(self,q,projection=None):
        self.queries.append(copy.deepcopy(q));return Cursor([r for r in self.rows if self.match(r,q)])
    async def count_documents(self,q): return len([r for r in self.rows if self.match(r,q)])
    def aggregate(self,stages):
        self.queries.append(stages[0]['$match']); rows=[r for r in self.rows if self.match(r,stages[0]['$match'])]
        if '$group' in stages[1]: return Cursor([{'total_hits':sum(r['provenance']['hit_count'] for r in rows),'avg_layers':0}] if rows else [])
        return Cursor(rows)

@pytest.fixture
def boundary(monkeypatch):
    users={p+'@synthetic.invalid':{'email':p+'@synthetic.invalid','tenant_ids':[t],'role':'analyst'} for p,t in [('alice','A'),('bob','B'),('peer','A')]}
    class Users:
        async def find_one(self,q,projection=None):return copy.deepcopy(users.get(q.get('email')))
    class Grants:
        def find_one(self,q,projection=None):return copy.deepcopy(users.get(q.get('email')))
    monkeypatch.setattr(deps,'sync_collection',lambda name:Grants())
    monkeypatch.setattr(registry,'get_tenant',lambda t:{'id':t,'state':'ACTIVE','organization_id':'O'} if t in ['A','B'] else None)
    monkeypatch.setattr(registry,'get_organization',lambda o:{'id':o,'state':'ACTIVE'})
    key=secrets.token_hex(32);monkeypatch.setattr(deps,'JWT_SECRET',key)
    jobs,artifacts=Collection(),Collection();db=SimpleNamespace(users=Users())
    monkeypatch.setattr(deps,'db',db);monkeypatch.setattr(store,'db',{store.COLL:jobs});monkeypatch.setattr(cache,'db',{cache.COLL:artifacts})
    async def worker(*args):pass
    monkeypatch.setattr(route,'_run_worker',worker)
    app=FastAPI();app.include_router(route.router,prefix='/api');app.include_router(api.router,prefix='/api')
    def token(p='alice',**claims):return jwt.encode({'sub':p+'@synthetic.invalid',**claims},key,algorithm='HS256')
    def headers(p='alice',tenant=None):return {'Authorization':'Bearer '+token(p),**({'X-Tenant-Id':tenant} if tenant is not None else {})}
    with TestClient(app) as client:yield client,headers,token,jobs,artifacts,users

def test_job_authentication_and_owner_isolation(boundary):
    c,h,token,jobs,artifacts,users=boundary
    assert c.post('/api/v2/auto-investigate/jobs',json={'incident_text':'whoami'}).status_code in [401,403]
    r=c.post('/api/v2/auto-investigate/jobs',headers=h(),json={'incident_text':'whoami'});assert r.status_code==200
    job=r.json()['job_id'];assert jobs.rows[0]['tenant_id']=='A' and jobs.rows[0]['created_by']=='alice@synthetic.invalid'
    path='/api/v2/auto-investigate/jobs/'+job
    assert c.get(path,headers=h()).status_code==200
    assert c.get(path,headers=h('bob')).status_code==404
    assert c.get(path,headers=h('peer')).status_code==404
    assert c.get(path,headers=h(tenant='B')).status_code==403
    assert all(q.get('tenant_id') and q.get('created_by') for q in jobs.queries)

@pytest.mark.parametrize('field',['tenant_id','role','user_email','module'])
def test_job_body_authority_fields_are_rejected(boundary,field):
    c,h,*_=boundary
    assert c.post('/api/v2/auto-investigate/jobs',headers=h(),json={'incident_text':'whoami',field:'B'}).status_code==422

@pytest.mark.parametrize('claims',[{'tenant_id':'B','role':'admin'},{'role':'soc_manager'}])
def test_ws_verified_stored_owner_not_token_authority(boundary,claims):
    c,h,token,jobs,*_=boundary
    job=c.post('/api/v2/auto-investigate/jobs',headers=h(),json={'incident_text':'whoami'}).json()['job_id']
    jobs.rows[0].update(status='complete',result={'observed':'synthetic'})
    with c.websocket_connect('/api/v2/auto-investigate/jobs/'+job+'/ws?token='+token(**claims)) as ws:
        assert ws.receive_json()['type']=='progress'
        assert ws.receive_json()['result']=={'observed':'synthetic'}

@pytest.mark.parametrize('person',['bob','peer','unknown'])
def test_ws_foreign_or_deleted_owner_refused_before_accept(boundary,person):
    c,h,token,jobs,*_=boundary
    job=c.post('/api/v2/auto-investigate/jobs',headers=h(),json={'incident_text':'whoami'}).json()['job_id']
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect('/api/v2/auto-investigate/jobs/'+job+'/ws?token='+token(person)):pass
    assert e.value.code in [4401,4404]

def test_legacy_unowned_job_is_not_adopted(boundary):
    c,h,token,jobs,*_=boundary
    jobs.rows.append({'_id':'legacy','created_by':'alice@synthetic.invalid','status':'complete','result':{'secret':'synthetic'}})
    assert c.get('/api/v2/auto-investigate/jobs/legacy',headers=h()).status_code==404

def test_scope_conflicts_suspended_and_missing_principal_fail_closed(boundary,monkeypatch):
    c,h,token,jobs,artifacts,users=boundary
    assert c.get('/api/v2/decoded-artifacts?tenant_id=B',headers=h(tenant='A')).status_code==403
    assert c.get('/api/v2/decoded-artifacts',headers=h(tenant='')).status_code==403
    monkeypatch.setattr(registry,'get_tenant',lambda t:{'id':t,'state':'SUSPENDED','organization_id':'O'})
    assert c.get('/api/v2/decoded-artifacts',headers=h()).status_code in [403,409]
    users.pop('alice@synthetic.invalid')
    assert c.get('/api/v2/decoded-artifacts',headers=h()).status_code==401
    assert artifacts.queries==[]

@pytest.mark.asyncio
async def test_same_command_tenant_version_cache_and_immutable_report(boundary):
    c,h,token,jobs,artifacts,users=boundary
    original='  whoami\n'; report={'trace':[],'output':'first'}
    digest,first=await cache.upsert_artifact(command_binary='cmd',command_line=original,report_dict=report,tenant_id='A',job_id='A-job')
    report['output']='caller-mutation';assert first
    assert await cache.get_artifact(digest,command_binary="cmd",tenant_id='B') is None
    assert await cache.get_artifact(digest,command_binary="cmd",tenant_id='A',pipeline_version='new-version') is None
    assert (await cache.get_artifact(digest,command_binary="cmd",tenant_id='A'))['report']['output']=='first'
    _,first=await cache.upsert_artifact(command_binary='cmd',command_line=original,report_dict={'output':'replacement'},tenant_id='A',job_id='A-job2');assert not first
    await cache.upsert_artifact(command_binary='cmd',command_line=original,report_dict={'output':'tenant-B'},tenant_id='B',job_id='B-job')
    assert (await cache.get_artifact(digest,command_binary="cmd",tenant_id='A'))['report']['output']=='first'
    assert len(artifacts.rows)==2 and len({r['_id'] for r in artifacts.rows})==2
    assert 'B-job' not in (await cache.get_artifact(digest,command_binary="cmd",tenant_id='A'))['provenance']['seen_in_jobs']
    assert (await cache.stats(tenant_id='A'))['total_artifacts']==1
    assert len(await cache.list_recent(tenant_id='A'))==1

@pytest.mark.asyncio
async def test_artifact_integrity_and_database_errors_fail_closed(boundary,monkeypatch):
    *_,artifacts,users=boundary
    digest,_=await cache.upsert_artifact(command_binary='cmd',command_line='whoami',report_dict={'output':'first'},tenant_id='A')
    artifacts.rows[0]['report']['output']='corrupt'
    with pytest.raises(ValueError,match='integrity'):await cache.get_artifact(digest,command_binary="cmd",tenant_id='A')
    async def failed(row):raise RuntimeError('database unavailable')
    monkeypatch.setattr(artifacts,'insert_one',failed)
    with pytest.raises(RuntimeError):await cache.upsert_artifact(command_binary='cmd',command_line='new',report_dict={},tenant_id='A')

@pytest.mark.asyncio
async def test_legacy_global_cache_is_not_reused(boundary):
    c,h,token,jobs,artifacts,*_=boundary
    digest=cache.sha256_of('whoami');artifacts.rows.append({'_id':digest,'sha256':digest,'report':{'output':'legacy'}})
    assert await cache.get_artifact(digest,command_binary="cmd",tenant_id='A') is None
    assert await cache.list_recent(tenant_id='A')==[]
    assert c.get('/api/v2/decoded-artifacts/'+digest,headers=h()).status_code==404

@pytest.mark.asyncio
@pytest.mark.parametrize('text',['\ud800','x'*16385])
async def test_bad_input_not_promoted_to_cache(boundary,text):
    with pytest.raises((UnicodeError,ValueError)):await cache.upsert_artifact(command_binary='cmd',command_line=text,report_dict={},tenant_id='A')

@pytest.mark.asyncio
async def test_cache_missing_tenant_has_no_query(boundary):
    *_,artifacts,users=boundary
    with pytest.raises(ValueError):await cache.get_artifact('0'*64,tenant_id='')
    assert artifacts.queries==[]

@pytest.mark.parametrize('token_kind',['invalid','expired','password_change'])
def test_ws_authentication_gates_before_job_read(boundary,token_kind):
    c,h,token,jobs,artifacts,users=boundary
    if token_kind=='password_change':users['alice@synthetic.invalid']['must_change_password']=True
    value='invalid' if token_kind=='invalid' else token(exp=1) if token_kind=='expired' else token()
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect('/api/v2/auto-investigate/jobs/unknown/ws?token='+value):pass
    assert e.value.code==4401 and jobs.queries==[]

@pytest.mark.asyncio
async def test_cache_exact_limit_and_input_hash_integrity(boundary):
    *_,artifacts,users=boundary
    original='é'*8192
    digest,_=await cache.upsert_artifact(command_binary='cmd',command_line=original,report_dict={},tenant_id='A')
    assert (await cache.get_artifact(digest,command_binary="cmd",tenant_id='A'))['original_command']==original
    artifacts.rows[0]['original_command']='tampered'
    with pytest.raises(ValueError,match='integrity'):await cache.get_artifact(digest,command_binary="cmd",tenant_id='A')

@pytest.mark.asyncio
async def test_cache_parser_profile_does_not_cross_reuse(boundary):
    digest,_=await cache.upsert_artifact(command_binary="cmd",command_line="whoami",report_dict={},tenant_id="A")
    assert await cache.get_artifact(digest,command_binary="powershell",tenant_id="A") is None

@pytest.mark.parametrize('text',['x'*65,'é'*33,'\ud800'])
def test_job_input_rejected_before_worker_or_storage(boundary,text,monkeypatch):
    monkeypatch.setattr(route,"MAX_INCIDENT_BYTES",64)
    c,h,token,jobs,*_=boundary
    # Model gate includes UTF-8 byte limits and invalid Unicode.
    with pytest.raises((ValueError,UnicodeError)):
        route.JobIn(incident_text=text)
    assert jobs.rows==[]

def test_stream_rechecks_revoked_grants_before_result(boundary,monkeypatch):
    c,h,token,jobs,artifacts,users=boundary
    job=c.post('/api/v2/auto-investigate/jobs',headers=h(),json={'incident_text':'whoami'}).json()['job_id']
    jobs.rows[0].update(status='complete',result={'private':'synthetic'})
    original=route._authorize_ws;calls=[]
    async def changed(value):
        calls.append(value)
        if len(calls)==3:users['alice@synthetic.invalid']['tenant_ids']=['B']
        return await original(value)
    monkeypatch.setattr(route,'_authorize_ws',changed)
    with c.websocket_connect('/api/v2/auto-investigate/jobs/'+job+'/ws?token='+token()) as ws:
        assert ws.receive_json()['type']=='progress'
        with pytest.raises(WebSocketDisconnect) as e:ws.receive_json()
        assert e.value.code==4403

def test_ws_authority_unavailable_is_explicit_and_never_reads_job(boundary,monkeypatch):
    c,h,token,jobs,*_=boundary
    class Down:
        async def find_one(self,*a,**kw):raise RuntimeError('synthetic unavailable')
    monkeypatch.setattr(deps,'db',SimpleNamespace(users=Down()))
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect('/api/v2/auto-investigate/jobs/unknown/ws?token='+token()):pass
    assert e.value.code==4503 and jobs.queries==[]
