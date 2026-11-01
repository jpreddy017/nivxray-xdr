"""Synthetic SQLite and scheduling regressions; no endpoint or network access."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


AGENT = Path(__file__).resolve().parents[3] / "agents/nivxforge-windows"


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
        spec = importlib.util.spec_from_file_location("sensor_recovery_test", AGENT / "nivxforge_sensor.py")
        self.sensor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.sensor)
        self.sensor.use_state_dir(self.tmp.name)
        self.journal = self.sensor.nvx_journal.Journal(self.tmp.name)
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
        self.journal = self.sensor.nvx_journal.Journal(self.tmp.name)
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

    def run_one_wait(self, report):
        class StopLoop(Exception):
            pass
        journal = Mock()
        with patch.object(self.sensor, "_read_identity", return_value={}), \
             patch.object(self.sensor.nvx_journal, "open_journal", return_value=journal), \
             patch.object(self.sensor, "_cycle", return_value=report), \
             patch.object(self.sensor.time, "sleep", side_effect=StopLoop) as wait, \
             patch.object(self.sensor.TRANSPORT, "close"):
            with self.assertRaises(StopLoop):
                self.sensor.run("https://unused.invalid", interval=30)
            journal.close.assert_called_once()
            return wait.call_args.args[0]

    def test_progressing_backlog_does_not_sleep_a_full_report_interval(self):
        self.assertEqual(self.run_one_wait({"queue_depth": 200, "sent": 50, "failed": 0}), 1)

    def test_refused_delivery_keeps_normal_retry_wait(self):
        self.assertEqual(self.run_one_wait({"queue_depth": 200, "sent": 50, "failed": 1}), 30)

    def test_no_progress_keeps_normal_retry_wait(self):
        self.assertEqual(self.run_one_wait({"queue_depth": 200, "sent": 0, "failed": 0}), 30)

    def test_empty_queue_keeps_normal_poll_wait(self):
        self.assertEqual(self.run_one_wait({"queue_depth": 0, "sent": 50, "failed": 0}), 30)


if __name__ == "__main__":
    unittest.main()
