from __future__ import annotations
import ast, types, unittest, sys
from pathlib import Path
from unittest.mock import AsyncMock, patch
SOURCE=Path(__file__).resolve().parents[1]/'backend/routers/edr.py'
class HttpError(Exception):
    def __init__(self, status_code, detail):self.status_code=status_code
class Tests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.legacy=AsyncMock(return_value={'time_range':{},'lane_axis':{},'observations_all_time':7,'matched_in_window':2})
        self.page=AsyncMock(return_value={'contract':'paged','events':[{'id':'stored-event'}]})
        self.ep=AsyncMock(return_value={'endpoint_id':'ep-one'})
        self.res=types.SimpleNamespace(identity={'endpoint_id':'ep-one','tenant_id':'tenant-one'},refs=['ep-one'],predicate=lambda _: {'tenant_id':'tenant-one','endpoint_id':'ep-one'},descriptor=lambda:{'resolved':True})
        tw=types.SimpleNamespace(query_window=self.legacy,empty_state=lambda **kw:kw)
        e3=types.SimpleNamespace(device_trajectory=self.page)
        v3=types.SimpleNamespace(build=lambda data,**kw:{'events':[], 'paged_source':data})
        graph=types.SimpleNamespace(build_graph=lambda *a,**kw:types.SimpleNamespace(to_dict=lambda:{}))
        self.modules={'deps':types.SimpleNamespace(db={'edr_endpoints':types.SimpleNamespace(find_one=self.ep)}),'edr_plane':types.SimpleNamespace(trajectory_window=tw),'edr_plane.trajectory':types.SimpleNamespace(projection=graph),'edr_trajectory':types.SimpleNamespace(production_service=e3,v3_presentation=v3)}
        def augment(out,**kw):out['dt2']={}
        self.env=dict(Depends=lambda _:None,get_current_user=None,edr_tenant=None,HTTPException=HttpError,
          eq=types.SimpleNamespace(resolve_endpoint=lambda *a:self.res),_tenant_scope=lambda *a:{'tenant_ids':['tenant-one']},
          _identity_with_display_hostname=lambda ident,ep:ident,_computer_header=lambda ident,ep,out:{'observations_all_time':out.get('observations_all_time')},dt2=types.SimpleNamespace(augment=augment,DT2_CONTRACT_VERSION='test'))
        node=next(n for n in ast.parse(SOURCE.read_text()).body if isinstance(n,ast.AsyncFunctionDef) and n.name=='endpoint_trajectory_window')
        node.decorator_list=[]
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(SOURCE),'exec'),self.env)
    async def call(self,**kw):
        with patch.dict('sys.modules',self.modules):
            return await self.env['endpoint_trajectory_window']('ep-one',user={},tenant_id='tenant-one',time_start='start',time_end='end',**kw)
    async def test_v3_avoids_complete_projection_preserves_paged_read(self):
        out=await self.call(presentation='v3')
        self.legacy.assert_not_awaited();self.page.assert_awaited_once()
        self.assertEqual(self.page.call_args.kwargs['time_start'],'start')
        self.assertEqual(self.page.call_args.kwargs['tenant_id'],'tenant-one')
        self.assertEqual(self.page.call_args.kwargs['refs'],['ep-one'])
        self.assertIsNone(out['computer']['observations_all_time'])
        self.assertNotIn('dt2',out)
        self.assertEqual(out['v3']['paged_source'],self.page.return_value)
    async def test_default_contract_keeps_legacy_projection(self):
        out=await self.call()
        self.legacy.assert_awaited_once();self.page.assert_awaited_once()
        self.assertEqual(out['computer']['observations_all_time'],7)
        self.assertIn('dt2',out)
    async def test_invalid_contract_refused(self):
        with self.assertRaises(HttpError) as c:await self.call(presentation='invalid')
        self.assertEqual(c.exception.status_code,422)
        self.legacy.assert_not_awaited();self.page.assert_not_awaited()
    async def test_populated_real_v3_presentation_parity(self):
        sys.path.insert(0,str(SOURCE.parents[1]))
        from edr_trajectory import v3_presentation
        self.modules['edr_trajectory'].v3_presentation=v3_presentation
        self.modules['edr_plane.fabric']=types.SimpleNamespace(store=types.SimpleNamespace(read=lambda *a,**k:([],None)))
        self.modules['edr_trajectory.attack']=types.SimpleNamespace(annotate_row=lambda _:None)
        self.page.return_value={'contract':'e3.dt.production.v1','state':'AVAILABLE','page':{
          'items':[{'event_id':'observed-1','kind':'PROCESS_START','process_key':'process-1','process':{'pid':100,'image':'observed.exe'},'observed_at':'2026-10-31T00:00:00Z','observed_ms':1793404800000},
                   {'event_id':'observed-2','kind':'FILE_CREATE','file':{'path':'C:/observed.txt'},'observed_at':'2026-10-31T00:00:01Z','observed_ms':1793404801000}],
          'next_cursor':'opaque-page-cursor','has_more':True,'provenance':{'stores_read':['test-store']}},'lanes':[], 'density':{'days':[{'day':'2026-10-31','count':2}]}}
        combined=(await self.call())['v3']
        paged=(await self.call(presentation='v3'))['v3']
        self.assertEqual(len(paged['events']),2)
        self.assertEqual(paged['e3_preview']['older_cursor'],'opaque-page-cursor')
        self.assertTrue(paged['e3_preview']['remaining_older'])
        self.assertEqual(paged['events'][0]['image'],'observed.exe')
        self.assertEqual(paged['events'][1]['file'],'C:/observed.txt')
        # Only intentionally unrequested whole-history header aggregates differ.
        combined.pop('computer');paged.pop('computer')
        self.assertEqual(combined,paged)
if __name__=='__main__':unittest.main()
