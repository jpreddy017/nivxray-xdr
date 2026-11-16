"""Installer refusal boundaries and real Windows state ACL checks."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import nivxforge_setup as setup

class PreflightTests(unittest.TestCase):
    def test_unsafe_backend_is_rejected(self):
        for value in ('https://user:secret@example.com', 'https://example.com/path',
                      'https://example.com?token=x', 'https://example.com#fragment',
                      'https://example.com:bad', 'https://example.com --state-dir x',
                      'https://example.com/"x', 'https://[broken'):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                setup._assert_backend(value)
        self.assertEqual(setup._assert_backend(setup.DEFAULT_BACKEND + '/'), setup.DEFAULT_BACKEND)

    def test_invalid_inputs_never_stop_or_stage(self):
        with tempfile.TemporaryDirectory() as root:
            identity = Path(root) / 'identity.json'
            with patch.object(setup.sensor, 'IDENTITY_FILE', identity), \
                 patch.object(setup, '_assert_admin'), \
                 patch.object(setup, '_service_config', return_value=''), \
                 patch.object(setup, '_stop_service_and_wait') as stop, \
                 patch.object(setup, '_stage_service_host') as stage, \
                 patch.object(setup.sensor, 'enrol') as enrol:
                for tenant, token, interval in [(None, True, 30), ('test', True, 30),
                                                ('ten_valid', False, 30),
                                                ('ten_valid', True, 0),
                                                ('ten_valid', True, -1)]:
                    with self.subTest(tenant=tenant, token=token, interval=interval):
                        with self.assertRaises(SystemExit):
                            setup.install(setup.DEFAULT_BACKEND, tenant, token, interval, False)
                identity.write_text(json.dumps(dict(tenant_id='ten_old', endpoint_id='ep_x',
                                                     credential_id='cred_x', agent_credential='fixture')))
                with self.assertRaisesRegex(SystemExit, 'differs'):
                    setup.install(setup.DEFAULT_BACKEND, 'ten_other', True, 30, False)
                for malformed in ('[]', 'null', '{"tenant_id": 42}'):
                    identity.write_text(malformed)
                    with self.assertRaises(SystemExit):
                        setup.install(setup.DEFAULT_BACKEND, None, False, 30, False)
                stop.assert_not_called()
                stage.assert_not_called()
                enrol.assert_not_called()

    def test_acl_command_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as root, \
             patch.object(setup.sensor, 'STATE_DIR', Path(root)), \
             patch.object(setup.subprocess, 'run') as run:
            run.return_value.returncode = 5
            with self.assertRaisesRegex(SystemExit, 'could not be secured'):
                setup._protect_state_dir()

    @unittest.skipUnless(os.name == 'nt', 'real Windows ACL required')
    def test_native_protected_acl_and_explicit_world_grant(self):
        import subprocess
        with tempfile.TemporaryDirectory() as root, \
             patch.object(setup.sensor, 'STATE_DIR', Path(root) / 'state'):
            try:
                setup._protect_state_dir()
            except BaseException:
                import win32security as ws
                sd = ws.GetNamedSecurityInfo(str(setup.sensor.STATE_DIR), ws.SE_FILE_OBJECT,
                    ws.OWNER_SECURITY_INFORMATION | ws.DACL_SECURITY_INFORMATION)
                print('ACL_DIAGNOSTIC', ws.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner()),
                      sd.GetSecurityDescriptorControl(),
                      [sd.GetSecurityDescriptorDacl().GetAce(i)
                       for i in range(sd.GetSecurityDescriptorDacl().GetAceCount())])
                raise
            self.assertTrue(setup._restricted_state_acl(setup.sensor.STATE_DIR))
            subprocess.run(['icacls', str(setup.sensor.STATE_DIR), '/grant',
                            '*S-1-1-0:(R)'], check=True, capture_output=True)
            self.assertFalse(setup._restricted_state_acl(setup.sensor.STATE_DIR))
            with self.assertRaisesRegex(SystemExit, 'could not be secured'):
                setup._protect_state_dir()

if __name__ == '__main__':
    unittest.main()
