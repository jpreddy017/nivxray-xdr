import asyncio
from types import SimpleNamespace
import deps
from routers import edr_trajectory_v3 as route
class Cursor:
    def __init__(self,docs): self.docs=docs
    def sort(self,*args): return self
    def limit(self,n): self.docs=self.docs[:n]; return self
    def __aiter__(self):
        async def generate():
            for doc in self.docs: yield doc
        return generate()
class Store:
    def __init__(self,docs): self.docs=docs; self.query=None
    def find(self,query,*args): self.query=query; return Cursor(self.docs)
def setup(monkeypatch,docs):
    store=Store(docs)
    monkeypatch.setattr(deps,'db',{'v2_shadow_observations':store})
    monkeypatch.setattr(route,'STORES',['v2_shadow_observations'])
    async def endpoint(*args): return SimpleNamespace(identity={'tenant_id':'t1','endpoint_id':'ep1'})
    monkeypatch.setattr(route,'_resolved',endpoint)
    monkeypatch.setattr(route,'resolve_file_identity',lambda *args:None)
    return store
def run():
    return asyncio.run(route.trajectory_file_facts('ep1',sha256='a'*64,path='C:/cmd.exe',user={},tenant_id='t1'))
def test_unresolved_is_incomplete(monkeypatch):
    setup(monkeypatch,[{}]); r=run()
    assert r['state']=='LOOKUP_INCOMPLETE'
    assert r['unresolved_records']==1 and not r['prevalence_complete']
def test_hash_does_not_broaden_to_path(monkeypatch):
    s=setup(monkeypatch,[]); r=run()
    assert s.query['$or']==[{'event.process.sha256':'a'*64},{'event.file.sha256':'a'*64}]
    assert r['state']=='NO_EVIDENCE_IN_THIS_CUSTOMER' and r['prevalence_complete']
def test_scan_budget(monkeypatch):
    setup(monkeypatch,[{}]*5001); r=run()
    assert r['state']=='LOOKUP_INCOMPLETE' and r['truncated']
    assert r['unresolved_records']==5000
