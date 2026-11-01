import asyncio
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'backend'
sys.path.insert(0, str(ROOT))
from edr_plane import stage_timing as timing


class TimingTests(unittest.TestCase):
    def test_success_and_failure(self):
        stages = {}
        with timing.measure(stages, 'parse'):
            pass
        self.assertEqual(stages['parse']['state'], 'COMPLETED')
        self.assertGreaterEqual(stages['parse']['duration_ms'], 0)
        with self.assertRaises(ValueError):
            with timing.measure(stages, 'normalize'):
                raise ValueError('failure')
        self.assertEqual(stages['normalize']['state'], 'FAILED')
        self.assertNotIn('completed_at', stages['normalize'])
        with timing.measure(None, 'legacy'):
            pass

    def test_worker_success_failure_and_lease_fencing(self):
        # Run the real worker with isolated I/O, without importing the engines.
        import edr_plane
        raw = ModuleType('edr_plane.raw_events')
        bridge = ModuleType('edr_plane.canonical_bridge')
        sys.modules[raw.__name__] = raw
        sys.modules[bridge.__name__] = bridge
        edr_plane.raw_events = raw
        edr_plane.canonical_bridge = bridge
        pymongo = ModuleType("pymongo")
        pymongo.ReturnDocument = SimpleNamespace(AFTER=True)
        sys.modules["pymongo"] = pymongo
        from edr_plane import processing_queue as q

        class Collection:
            def __init__(self): self.writes = []; self.owned = True
            async def update_one(self, query, update):
                self.writes.append((query, update))
                return SimpleNamespace(modified_count=int(self.owned))
        col = Collection()
        db = {q.COLLECTION: col}
        async def claim(*a, **k):
            return {'tenant_id':'t', 'raw_id':'r', 'attempts':3}
        async def get(*a, **k):
            return {'payload':'{}','authentication':{'endpoint_id':'ep'},'ingest_time':'2026-11-01T00:00:00Z'}
        failed = False
        async def run_bridge(*a, **k):
            with timing.measure(k['stage_timings'], 'parse_and_normalize'):
                if failed: raise ValueError('bad input')
            return {'canonicalized': True}
        q.claim = claim; raw.get = get; bridge.bridge = run_bridge
        out = asyncio.run(q.process_one(db))
        self.assertTrue(out['processed'])
        query, update = col.writes[-1]
        self.assertEqual(query['attempts'], 3)
        self.assertEqual(query['tenant_id'], 't')
        self.assertIn('$gt', query['lease_until'])
        recorded = update['$set']['processing_timings']
        self.assertEqual(recorded['attempt'], 3)
        self.assertEqual(recorded['stages']['parse_and_normalize']['state'], 'COMPLETED')
        self.assertEqual(len(col.writes), 1, 'no extra timing write')
        failed = True
        out = asyncio.run(q.process_one(db))
        self.assertEqual(out['state'], 'RETRY')
        recorded = col.writes[-1][1]['$set']['processing_timings']
        self.assertEqual(recorded['stages']['parse_and_normalize']['state'], 'FAILED')
        self.assertEqual(recorded['stages']['canonical_bridge']['state'], 'FAILED')
        col.owned = False
        out = asyncio.run(q.process_one(db))
        self.assertFalse(out['retry_recorded'])


if __name__ == '__main__':
    unittest.main()
