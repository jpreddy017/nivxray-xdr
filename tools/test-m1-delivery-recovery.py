"""Synthetic SQLite and scheduling regressions; no endpoint or network access."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


AGENT = Path(__file__).resolve().parents[1] / "agents/nivxforge-windows"


class JournalRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {
            "NIVXFORGE_SENSOR_STATE": self.tmp.name,
            "NIVX_SENSOR_JOURNAL_MIN_FREE_BYTES": "1",
            "NIVX_SENSOR_JOURNAL_MAX_BYTES": str(512 * 1024 * 1024),
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        sys.path.insert(0, str(AGENT))
        self.addCleanup(sys.path.remove, str(AGENT))
        spec = importlib.util.spec_from_file_location("journal_recovery", AGENT / "nivxforge_journal.py")
        self.journal_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.journal_module)
        self.journal = self.journal_module.Journal(self.tmp.name)
        self.addCleanup(self.journal.close)

    def seed(self, count=3):
        events = [{"observed_at": "2026-10-01T00:00:00Z", "winlog": {
            "record_id": i, "time_created": "2026-10-01T00:00:00Z",
            "channel": "test", "xml": "synthetic"}}
            for i in range(1, count + 1)]
        self.journal.commit_page("test", events, count)

    def test_batch_ack_has_one_durable_transaction(self):
        self.seed(50)
        trace = []
        self.journal._db.set_trace_callback(trace.append)
        self.journal.mark_accepted(list(range(1, 51)))
        self.assertEqual(sum(s.startswith("BEGIN") for s in trace), 1)
        self.assertEqual(sum(s == "COMMIT" for s in trace), 1)
        self.assertEqual(self.journal.depth(), 0)
        self.journal.close()
        self.journal = self.journal_module.Journal(self.tmp.name)
        self.addCleanup(self.journal.close)
        self.assertEqual(self.journal.counts_by_state(), {"BACKEND_ACCEPTED": 50})

    def test_partial_ack_write_failure_rolls_back_and_can_retry(self):
        self.seed()
        self.journal._db.execute("CREATE TRIGGER fail_ack BEFORE UPDATE ON evidence "
            "WHEN NEW.journal_sequence=2 AND NEW.state='BACKEND_ACCEPTED' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic disk failure'); END")
        with self.assertRaises(sqlite3.DatabaseError):
            self.journal.mark_accepted([1, 2, 3])
        self.assertEqual(self.journal.depth(), 3)
        self.assertFalse(self.journal._db.in_transaction)
        self.journal._db.execute("DROP TRIGGER fail_ack")
        self.journal.mark_accepted([1, 2, 3])
        self.assertEqual(self.journal.depth(), 0)
        self.assertEqual(self.journal.cursor("test"), 3)

    def test_capacity_recovery_clears_current_halt_preserves_history(self):
        self.seed()
        with patch.dict(os.environ, {"NIVX_SENSOR_JOURNAL_MAX_BYTES": "1"}):
            self.assertFalse(self.journal.admits_acquisition()[0])
            self.assertTrue(self.journal.halted)
        self.assertTrue(self.journal.admits_acquisition()[0])
        self.assertFalse(self.journal.halted)
        self.assertIsNone(self.journal.halt_reason)
        self.assertNotIn("ACQUISITION_HALTED_JOURNAL_FULL", self.journal.health()["states"])
        self.assertEqual(self.journal.depth(), 3)
        self.assertEqual(self.journal.cursor("test"), 3)
        self.assertEqual(self.journal.gauges()["acquisition_halted_journal_full"], 1)
        self.assertIn("acquisition_halted_at", self.journal.gauges())


    def test_quarantine_survives_ack_and_reclaim(self):
        self.seed()
        self.journal.quarantine(1, "rejected")
        self.journal.mark_accepted([2])
        self.journal.reclaim()
        self.assertEqual(self.journal.quarantined(), 1)
        self.assertEqual(self.journal.depth(), 1)
        self.assertEqual(self.journal.cursor("test"), 3)

class SchedulingTests(unittest.TestCase):
    def test_backoff_and_periodic_normal_wait(self):
        import ast
        tree = ast.parse((AGENT / 'nivxforge_m1.py').read_text())
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'delivery_wait')
        scope = {}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), '<tested helper>', 'exec'), scope)
        wait = scope['delivery_wait']
        good = {'sent':50,'queue_depth':1000,'failed':0}
        count = 0
        for _ in range(19):
            delay, count = wait(good,30,count)
            self.assertEqual(delay,5)
        self.assertEqual(wait(good,30,count),(30,0))
        for report in [None, {}, {'sent':50,'queue_depth':3}, {'sent':0,'queue_depth':3,'failed':0}, {'sent':50,'queue_depth':3,'failed':1}, {'sent':50,'queue_depth':0,'failed':0}]:
            self.assertEqual(wait(report,30,5),(30,0))

class ServiceWiringTests(unittest.TestCase):
    def test_actual_service_loop_uses_wait_and_stops(self):
        import ast
        from types import SimpleNamespace
        tree = ast.parse((AGENT / 'nivxforge_m1.py').read_text())
        helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'delivery_wait')
        loop = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'SvcDoRun')
        waits=[]
        def wait(event, delay):
            waits.append(delay)
            return 0
        sensor=SimpleNamespace(run=Mock(return_value={'sent':50,'queue_depth':300,'failed':0}))
        scope={'sensor':sensor,'config':SimpleNamespace(origin='https://unused.invalid',interval=30),
               'win32event':SimpleNamespace(WaitForSingleObject=wait,WAIT_OBJECT_0=0)}
        exec(compile(ast.Module(body=[helper,loop], type_ignores=[]), '<service methods>', 'exec'), scope)
        scope['SvcDoRun'](SimpleNamespace(stop_event=object()))
        self.assertEqual(waits,[5000])
        sensor.run.assert_called_once_with('https://unused.invalid',30,once=True)

if __name__ == '__main__': unittest.main()
