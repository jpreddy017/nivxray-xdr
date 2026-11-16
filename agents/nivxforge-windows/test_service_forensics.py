"""Regression: fresh-install service must not interrupt an in-flight snapshot."""
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import nivxforge_setup as setup
import windows_snapshot_worker as snapshot

class ServiceWorkerLifetime(unittest.TestCase):
    def test_snapshot_survives_cycles_and_telemetry_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            delivered = threading.Event()
            calls = []
            workers = []
            commands = [{"command_id":"cmd_0123456789abcdefabcd",
                         "action":snapshot.ACTION,
                         "target":{"categories":["os_version"]}}]
            original = snapshot.Worker
            class TestWorker(original):
                def __init__(self, *args):
                    super().__init__(*args); workers.append(self)
                def http(self, path, body=None):
                    if path.endswith("/session"): return {"session_token":"fixture"}
                    if path.endswith("/forensic-commands"):
                        result=list(commands);commands.clear();return {"commands":result}
                    if path.endswith("/command-result"):
                        calls.append(body);delivered.set();return {"state":"EXECUTED"}
                    return {}
            def query(key, timeout, cancelled):
                # A real worker thread overlaps many telemetry cycles.
                until=time.monotonic()+0.25
                while time.monotonic()<until:
                    if cancelled(): return {"state":"INTERRUPTED","rows":[]}
                    time.sleep(.01)
                return {"state":"COLLECTED","rows":[{"fixture":True}]}
            cycles=[]
            def telemetry(*args, **kwargs):
                self.assertFalse(kwargs["manage_forensics"])
                cycles.append(1)
                if len(cycles)==2: raise RuntimeError("fixture transient telemetry failure")
            def stop(milliseconds):
                if milliseconds: delivered.wait(.02)
                return delivered.is_set() or len(cycles)>100
            with patch.object(snapshot,"Worker",TestWorker), patch.object(snapshot.collector,"run_query",query), patch.object(setup.sensor,"STATE_DIR",Path(directory)), patch.object(setup.sensor,"_read_identity",return_value={"tenant_id":"fixture","endpoint_id":"ep_fixture","agent_credential":"fixture"}), patch.object(setup.sensor,"run",side_effect=telemetry), patch.object(setup,"_service_log"):
                setup._run_service_cycles("https://fixture.invalid",5,stop)
            self.assertTrue(delivered.is_set())
            self.assertGreater(len(cycles),2)
            self.assertEqual(len(workers),1)
            self.assertFalse(workers[0].thread.is_alive())
            self.assertEqual(calls[0]["outcome"],"EXECUTED")
            self.assertEqual(calls[0]["evidence"]["categories"][0]["state"],"COLLECTED")

    def test_missing_enrollment_keeps_service_alive(self):
        cycles=[]
        def stop(ms):
            if ms: cycles.append(1)
            return len(cycles)>=3
        with patch.object(setup.sensor,"_read_identity",side_effect=SystemExit("not enrolled")), patch.object(setup.sensor,"run",side_effect=SystemExit("not enrolled")) as run, patch.object(setup,"_service_log"), patch.object(snapshot,"Worker") as worker:
            setup._run_service_cycles("https://fixture.invalid",5,stop)
        self.assertEqual(run.call_count,3)
        worker.assert_not_called()

    def test_stop_before_first_cycle_does_not_start_worker(self):
        with patch.object(setup.sensor,"run") as run, patch.object(snapshot,"Worker") as worker:
            setup._run_service_cycles("https://fixture.invalid",5,lambda ms:True)
        run.assert_not_called();worker.assert_not_called()

if __name__=="__main__": unittest.main()
