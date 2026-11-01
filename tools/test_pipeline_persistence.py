"""Execute the actual cache function with controlled decoder/store boundaries."""
import ast
import asyncio
import hashlib
import logging
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, Mock
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[1] / 'backend/v2/jobs/pipeline.py'
class Report:
    def model_dump(self):
        return {'trace': [{'decoder': 'test'}]}

class PersistenceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tree = ast.parse(SOURCE.read_text())
        node = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == '_decode_with_cache')
        self.write = AsyncMock()
        self.read = AsyncMock(return_value=None)
        self.report = Report()
        self.env = dict(asyncio=asyncio, log=logging.getLogger('test'),
            _artifact_get=self.read, _artifact_upsert=self.write,
            _sha256_of=lambda s: hashlib.sha256(s.encode()).hexdigest(),
            _try_archetypes=None, AnalystReport=lambda **kw:self.report,
            _run_single_command=lambda cmd:(self.report, {'status':'complete'}))
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), self.env)
    async def run_decode(self):
        return await self.env['_decode_with_cache']({'binary':'cmd', 'command_line':'echo test'}, 'job-test')
    async def test_fresh_write_failure_propagates(self):
        error = RuntimeError('write not acknowledged')
        self.write.side_effect = error
        with self.assertRaises(RuntimeError) as caught: await self.run_decode()
        self.assertIs(caught.exception,error)
    async def test_success_preserves_report_and_status(self):
        report,status,hit,layers = await self.run_decode()
        self.assertIs(report,self.report);self.assertEqual(status['status'],'complete')
        self.assertFalse(hit);self.assertEqual(layers,[])
        self.write.assert_awaited_once()
        self.assertEqual(self.write.call_args.kwargs['report_dict'],self.report.model_dump())
    async def test_cached_write_failure_propagates(self):
        self.read.return_value={'report':self.report.model_dump(),'pipeline_version':'v9-ps-semantic-intelligence'}
        self.write.side_effect=RuntimeError('cached write failed')
        with self.assertRaisesRegex(RuntimeError,'cached write failed'):await self.run_decode()
    async def test_cancellation_propagates(self):
        self.write.side_effect=asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):await self.run_decode()
    async def test_no_report_does_not_persist(self):
        self.env['_run_single_command']=lambda cmd:(None,{'status':'failed'})
        report,status,_,_=await self.run_decode()
        self.assertIsNone(report);self.assertEqual(status['status'],'failed')
        self.write.assert_not_awaited()

    async def test_worker_records_failed_not_complete(self):
        self.write.side_effect=RuntimeError('write not acknowledged')
        router=SOURCE.parents[2] / 'routers/auto_investigate_jobs.py'
        node=next(n for n in ast.parse(router.read_text()).body if isinstance(n,ast.AsyncFunctionDef) and n.name=='_run_worker')
        store=SimpleNamespace(mark_complete=AsyncMock(),mark_failed=AsyncMock())
        pubsub=SimpleNamespace(publish=AsyncMock(),close_job=Mock())
        async def pipeline(*args,**kwargs):
            return await self.run_decode()
        env=dict(run_investigation_with_progress=pipeline,store=store,pubsub=pubsub,
                 log=logging.getLogger('worker-test'),asyncio=SimpleNamespace(sleep=AsyncMock()))
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(router),'exec'),env)
        with self.assertLogs('worker-test',level='ERROR'):
            await env['_run_worker']('job-test','echo test',None)
        store.mark_complete.assert_not_awaited()
        store.mark_failed.assert_awaited_once_with('job-test','write not acknowledged')
        self.assertEqual(pubsub.publish.call_args.args[1]['status'],'failed')
        pubsub.close_job.assert_called_once_with('job-test')

if __name__=='__main__':unittest.main()
