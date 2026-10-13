"""Deterministic tenant/response boundary tests; no DB or provider connection."""
import copy
import ast
from pathlib import Path
import pytest
from detection_content import xdr_ice as ice, xdr_response_fabric as fabric
from detection_content import xdr_response_decision as decision

class Cursor:
    def __init__(self,rows):self.rows=rows
    def __aiter__(self):self.iterator=iter(self.rows);return self
    async def __anext__(self):
        try:return copy.deepcopy(next(self.iterator))
        except StopIteration:raise StopAsyncIteration

class Collection:
    def __init__(self,rows=()):self.rows=list(rows);self.queries=[]
    def matches(self,row,q):
        return all(any(self.matches(row,p) for p in v) if k=='$or' else row.get(k)==v for k,v in q.items())
    def find(self,q,*args):self.queries.append(q);return Cursor([r for r in self.rows if self.matches(r,q)])
    async def find_one(self,q,*args):self.queries.append(q);return next((copy.deepcopy(r) for r in self.rows if self.matches(r,q)),None)
    async def count_documents(self,q):self.queries.append(q);return sum(self.matches(r,q) for r in self.rows)
    async def insert_one(self,row):self.rows.append(copy.deepcopy(row))

@pytest.mark.asyncio
async def test_inline_rules_and_matches_are_tenant_partitioned():
    def rule(name,tenant):return {'rule_id':name,'name':name,'tenant_id':tenant,'enabled':True,'operators.type':'EVENT_MATCH','conditions':[{'match':{'event_kind':'process'}}]}
    rules=Collection([rule('A-rule','A'),rule('B-rule','B'),rule('shared','*'),rule('unowned',None)])
    matches=Collection();db={'xdr_correlation_rules':rules,'xdr_correlation_matches':matches}
    out=await ice.correlate(db,{'tenant_id':'A','event_id':'event-A','event_type':'process'}, {},'trace-A',tenant_id='A')
    assert {m['rule_id'] for m in out['matches']}=={'A-rule','shared'}
    assert all(m['tenant_id']=='A' for m in matches.rows)
    assert out['enabled_rules_total']==2

@pytest.mark.asyncio
@pytest.mark.parametrize('canonical,tenant',[({},None),({'tenant_id':'B'},'A')])
async def test_correlation_scope_refusal_precedes_database(canonical,tenant):
    out=await ice.correlate({},canonical,{},'trace',tenant_id=tenant)
    assert out['state']=='BLOCKED_SCOPE' and out['matches']==[]

@pytest.mark.asyncio
async def test_response_context_queries_only_owned_evidence():
    db={name:Collection() for name in ['workspace_cases','xdr_canonical_evidence','xdr_correlation_matches','xdr_response_executions','xdr_integrations']}
    db['workspace_cases'].rows=[{'id':'incident','tenant_id':'A','xdr_pipeline':{'canonical_event_id':'shared-id','ice_matches':['shared-match']}}]
    db['xdr_canonical_evidence'].rows=[{'event_id':'shared-id','tenant_id':'B','secret':'foreign'}]
    db['xdr_correlation_matches'].rows=[{'match_id':'shared-match','tenant_id':'B','secret':'foreign'}]
    await decision.build_response_context(db,'incident',tenant_id='A')
    assert all(q.get('tenant_id')=='A' for c in db.values() for q in c.queries)

@pytest.mark.asyncio
async def test_dry_run_never_calls_executor_even_with_available_action(monkeypatch):
    db={name:Collection() for name in ['workspace_cases','xdr_intelligence_observations','xdr_response_executions','xdr_integrations']}
    db['workspace_cases'].rows=[{'id':'incident','tenant_id':'A'}]
    async def context(db,ident,*,tenant_id):return {'state':'READY','incident_id':ident,'entities':[]}
    async def forbidden(*a,**kw):raise AssertionError('automatic response execution forbidden')
    monkeypatch.setattr(fabric,'build_response_context',context)
    monkeypatch.setattr(fabric,'execute_action',forbidden)
    monkeypatch.setattr(fabric,'decide',lambda *a:{'decision':'DIRECT_ACTION_AVAILABLE','required_action':'synthetic','action_entry':{}})
    monkeypatch.setattr(fabric,'evaluate_approval',lambda *a:{'state':'AUTO_APPROVED'})
    from detection_content import xdr_closed_loop as loop
    monkeypatch.setattr(loop,'recommend_with_observations',lambda *a:[])
    out=await fabric.orchestrate(db,'incident',tenant_id='A',dry_run=True)
    assert out['execution'] is None
    assert all(q.get('tenant_id')=='A' for c in db.values() for q in c.queries)

@pytest.mark.asyncio
async def test_response_foreign_incident_refused_before_context(monkeypatch):
    db={'workspace_cases':Collection([{'id':'incident','tenant_id':'B'}])}
    async def forbidden(*a,**k):raise AssertionError('foreign context accessed')
    monkeypatch.setattr(fabric,'build_response_context',forbidden)
    assert (await fabric.orchestrate(db,'incident',tenant_id='A'))['state']=='BLOCKED'

def test_telemetry_pipeline_pins_dry_run_and_tenant():
    source=Path(__file__).resolve().parents[1]/'detection_content/xdr_pipeline.py'
    calls=[n for n in ast.walk(ast.parse(source.read_text())) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='response_orchestrate']
    assert len(calls)==1
    kw={k.arg:k.value for k in calls[0].keywords}
    assert isinstance(kw['dry_run'],ast.Constant) and kw['dry_run'].value is True
    assert 'tenant_id' in kw and 'principal_id' in kw
