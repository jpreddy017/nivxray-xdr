import contextlib
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch
import nivxforge_m1 as m1
import nivxforge_m1_upgrade as up


class Host:
    def __init__(self, config):
        self.c = config
        self.state = m1.SERVICE_RUNNING
        self.start = m1.SERVICE_AUTO_START
        self.pid = 10
        self.stops = 0
        self.ack = True
        self.stop_ok = True
        self.unsafe = False
        self.linked = False
    def path_ancestry(self, p): return [Path(p)]
    def is_reparse_point(self, p): return self.linked
    def file_security(self, p, **kw): return {'nonadmin_writable': self.unsafe}
    directory_security = file_security
    def is_file(self, p): return Path(p).is_file()
    def read_bytes(self, p): return Path(p).read_bytes()
    def write_new_file(self, p, b):
        with Path(p).open('xb') as f: f.write(b)
    def replace_file(self, p, b): Path(p).write_bytes(b)
    def create_directory_protected(self, p): Path(p).mkdir()
    def copy_payload(self, src, dst, manifest):
        for name in manifest:
            target=Path(dst)/name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(Path(src)/name,target)
    def service_qc(self, name):
        return {'bin_path':m1._bin_path(self.c),'account':'LocalSystem','state':self.state,
                'pid':self.pid if self.state==m1.SERVICE_RUNNING else 0,'start_type_code':self.start}
    def service_security(self, name): return {}
    def process_identity(self, pid): return {'pid':pid,'created':1}
    def process_exited(self, pid, identity): return self.state != m1.SERVICE_RUNNING
    def service_set_start_type(self, name, val): self.start=val
    def service_stop(self, name):
        self.stops+=1
        if not self.stop_ok:return 'UNCERTAIN'
        self.state=m1.SERVICE_STOPPED
        return 'STOPPED'
    def service_start(self, name):
        self.state=m1.SERVICE_RUNNING;self.pid+=1
        if Path(self.c.service_exe).read_bytes()==b'new':
            # Simulate newly acquired evidence. Rollback MUST retain it.
            (self.c.state_dir/'new-evidence.json').write_text('new evidence')
            (self.c.state_dir/'m1-runtime-health.json').write_text(json.dumps({
                'at_epoch':time.time(),'pid':self.pid,'sensor_version':'0.6.0-windows',
                'endpoint_id':'ep_fixture','backend_acknowledged':self.ack,
                'forensic_worker_started':True}))
    def verify_running_image(self, name, expected, expected_sha256=None):
        return {'verdict':'MATCH' if self.state==m1.SERVICE_RUNNING and m1.file_digest(Path(expected))==expected_sha256 else 'NO_MATCH'}
    def now_utc(self):return 'fixture'
    def exclusive_lock(self):return contextlib.nullcontext(True)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.install=self.root/'sensor';self.install.mkdir()
        self.state=self.root/'state';self.state.mkdir()
        (self.install/'NivXForgeSensor.exe').write_bytes(b'old')
        (self.state/'identity.json').write_text(json.dumps({'tenant_id':'ten_fixture','endpoint_id':'ep_fixture','agent_credential':'fixture-not-a-real-credential'}))
        (self.state/'outbox.jsonl').write_bytes(b'queued evidence\n')
        (self.state/'outbox.offset').write_bytes(b'0')
        self.config_path=self.root/'m1-config.json'
        raw={'origin':'https://example.invalid','tenant_id':'ten_fixture',
             'state_dir':str(self.state),'install_dir':str(self.install),
             'service_exe':str(self.install/'NivXForgeSensor.exe'),
             'service_args':['--m1-service-run','--m1-config',str(self.config_path),'--state-dir',str(self.state)],
             'certificate_policy':'windows-default'}
        self.config_path.write_text(json.dumps(raw))
        self.c=m1.M1Config(raw,self.config_path,m1.file_digest(self.config_path),{})
        self.host=Host(self.c)
        self.owner=m1.Ownership(self.root/m1.OWNERSHIP_FILENAME,self.host)
        record=self.owner.create('fixture-install',self.c)
        for name in ('install_dir','state_dir','payload','enrollment'):
            self.owner.mark(record,name,m1.CREATE_CONFIRMED)
        self.owner.mark(record,'service',m1.ACTIVATION_VERIFIED,{'bin_path':m1._bin_path(self.c),'service_image':{'sha256':m1.file_digest(Path(self.c.service_exe))}})
        self.old_owner=self.owner.path.read_bytes()
        self.payload=self.root/'release';self.payload.mkdir()
        (self.payload/'NivXForgeSensor.exe').write_bytes(b'new')
        self.manifest={'NivXForgeSensor.exe':{'size':3,'sha256':hashlib.sha256(b'new').hexdigest()}}
        self.load=patch.object(m1,'load_config',return_value=self.c);self.load.start();self.addCleanup(self.load.stop)
        self.security=patch.object(m1,'service_security_verdict',return_value={'safe':True});self.security.start();self.addCleanup(self.security.stop)
    def apply(self):return up.upgrade(self.config_path,self.host,self.payload,self.manifest,'0.6.0-windows',timeout=0)
    def test_plan_is_read_only(self):
        before={str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(up.plan(self.config_path,self.host)['result'],'READY_FOR_STAGING')
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.assertEqual(self.host.stops,0)
    def test_success_preserves_identity_queue_config_and_service(self):
        identity=(self.state/'identity.json').read_bytes();config=self.config_path.read_bytes()
        result=self.apply()
        self.assertEqual(result['result'],'VERIFIED')
        self.assertEqual((self.state/'identity.json').read_bytes(),identity)
        self.assertEqual(self.config_path.read_bytes(),config)
        self.assertEqual((self.state/'outbox.jsonl').read_bytes(),b'queued evidence\n')
        self.assertEqual(self.host.state,m1.SERVICE_RUNNING)
        self.assertEqual(self.host.start,m1.SERVICE_AUTO_START)
        backup=Path(result['backup'])
        self.assertEqual((backup/'previous-payload/NivXForgeSensor.exe').read_bytes(),b'old')
        self.assertEqual((backup/'state-backup/identity.json').read_bytes(),identity)
    def test_backend_failure_restores_old_code_without_rewinding_new_evidence(self):
        self.host.ack=False
        with self.assertRaises(m1.M1Error):self.apply()
        self.assertEqual(Path(self.c.service_exe).read_bytes(),b'old')
        self.assertTrue((self.state/'new-evidence.json').exists())
        self.assertEqual(self.owner.path.read_bytes(),self.old_owner)
        self.assertEqual(json.loads((self.root/up.OP_FILE).read_text())['phase'],'ROLLED_BACK')
    def test_explicit_rollback_retains_live_state(self):
        self.apply();self.assertEqual(up.rollback(self.config_path,self.host)['result'],'ROLLED_BACK')
        self.assertEqual(Path(self.c.service_exe).read_bytes(),b'old')
        self.assertTrue((self.state/'new-evidence.json').exists())
    def test_tampered_payload_does_not_stop_service(self):
        (self.payload/'NivXForgeSensor.exe').write_bytes(b'tampered')
        with self.assertRaises(m1.M1Error):self.apply()
        self.assertEqual(self.host.stops,0)
    def test_unconfirmed_ownership_refuses(self):
        record=self.owner.read();record['resources']['service']['state']=m1.CREATE_OUTCOME_UNKNOWN;self.owner.save(record)
        with self.assertRaises(m1.M1Error):up.plan(self.config_path,self.host)
    def test_identity_tenant_mismatch_refuses(self):
        (self.state/'identity.json').write_text('{"tenant_id":"other"}')
        with self.assertRaises(m1.M1Error):up.plan(self.config_path,self.host)
    def test_old_binary_drift_refuses(self):
        Path(self.c.service_exe).write_bytes(b'unknown')
        with self.assertRaises(m1.M1Error):self.apply()
        self.assertEqual(self.host.stops,0)
    def test_unsafe_acl_and_reparse_refuse(self):
        self.host.unsafe=True
        with self.assertRaises(m1.M1Error):up.plan(self.config_path,self.host)
        self.host.unsafe=False;self.host.linked=True
        with self.assertRaises(m1.M1Error):up.plan(self.config_path,self.host)
    def test_stop_uncertainty_never_replaces_payload(self):
        self.host.stop_ok=False
        with self.assertRaises(m1.M1Error):self.apply()
        self.assertEqual(Path(self.c.service_exe).read_bytes(),b'old')
        self.assertEqual(json.loads((self.root/up.OP_FILE).read_text())['phase'],'RECOVERY_REQUIRED')
    def test_interruption_after_old_payload_move_has_explicit_recovery(self):
        original=up.save
        def crash(root,op,host,phase):
            if phase=='OLD_MOVED':raise KeyboardInterrupt()
            return original(root,op,host,phase)
        with patch.object(up,'save',side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):self.apply()
        self.assertFalse(self.install.exists())
        self.assertEqual(up.rollback(self.config_path,self.host)['result'],'ROLLED_BACK')
        self.assertEqual(Path(self.c.service_exe).read_bytes(),b'old')
    def test_pending_transaction_blocks_new_upgrade(self):
        (self.root/up.OP_FILE).write_text('{"phase":"STARTING"}')
        with self.assertRaises(m1.M1Error):self.apply()
        self.assertEqual(self.host.stops,0)
    def test_stale_or_wrong_process_health_is_not_success(self):
        self.apply();op=json.loads((self.root/up.OP_FILE).read_text())
        p=self.state/'m1-runtime-health.json';r=json.loads(p.read_text());r['pid']=-1;p.write_text(json.dumps(r))
        self.assertFalse(up.healthy(self.c,op,self.host))
    def test_rollback_refuses_replaced_service_image(self):
        self.apply();Path(self.c.service_exe).write_bytes(b'other installer')
        with self.assertRaises(m1.M1Error):up.rollback(self.config_path,self.host)
        self.assertEqual(Path(self.c.service_exe).read_bytes(),b'other installer')


if __name__=='__main__':unittest.main()
