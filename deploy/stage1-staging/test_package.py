import copy
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import yaml
import prepare
import preflight


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.compose = {k: 'registry.local/image@sha256:' + 'a' * 64
                        for k in ('MONGO_IMAGE', 'BACKEND_IMAGE', 'NGINX_IMAGE')}
        self.compose['STAGING_FRONTEND_ORIGIN'] = 'https://stage1-console.owner-staging.net'
        self.mongo = {'MONGO_INITDB_DATABASE': 'nivxray_stage1_staging',
                      'MONGO_INITDB_ROOT_USERNAME': 'root',
                      'MONGO_INITDB_ROOT_PASSWORD': 'synthetic-root-password',
                      'STAGING_MONGO_USER': 'stage1',
                      'STAGING_MONGO_PASSWORD': 'synthetic-app-password'}
        self.backend = {'MONGO_URL': 'mongodb://stage1:synthetic-app-password@mongodb:27017/nivxray_stage1_staging?authSource=nivxray_stage1_staging',
                        'EDR_ENROLLMENT_TOKEN_TTL_SECONDS': '600',
                        'EDR_AGENT_SESSION_TTL_SECONDS': '600', 'JWT_EXPIRE_HOURS': '1'}
        for i, k in enumerate(('JWT_SECRET', 'EDR_AUTH_PEPPER', 'XDR_AUDIT_MASTER_SECRET',
                               'XDR_SECRETS_MASTER', 'NIVXRAY_SIGNING_SECRET', 'XDR_ROOT_KEY')):
            self.backend[k] = str(i) * 40

    def test_valid_synthetic_config(self):
        preflight.validate(self.compose, self.backend, self.mongo)

    def test_production_origins_refused(self):
        for value in ('https://nivxray.nivxforge.com', 'https://xdr.nivxforge.com',
                      'https://xdr.nivxray.com', 'http://localhost:8001',
                      'https://user:password@staging.net', 'https://stage1-api.invalid'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                prepare.origin(value)

    def test_production_mongo_and_root_refused(self):
        for uri in ('mongodb://production:27017/customer',
                    'mongodb+srv://stage1:password@production.net/db',
                    self.backend['MONGO_URL'].replace('stage1:', 'root:')):
            bad = dict(self.backend, MONGO_URL=uri)
            with self.assertRaises(ValueError):
                preflight.validate(self.compose, bad, self.mongo)

    def test_mutable_image_refused(self):
        with self.assertRaises(ValueError):
            preflight.validate(dict(self.compose, BACKEND_IMAGE='backend:latest'), self.backend, self.mongo)

    def test_shared_secret_refused(self):
        with self.assertRaises(ValueError):
            preflight.validate(self.compose, dict(self.backend, JWT_SECRET=self.backend['XDR_ROOT_KEY']), self.mongo)

    def test_source_selection_excludes_credentials_state_and_stage2(self):
        for path in ('backend/.env', 'backend/xdr_state/outbox.db', 'backend/tests/test.py',
                     'frontend/src/App.jsx', 'backend/nci_v2/../.env',
                     'agents/sensor.py', 'backend/private.key', 'backend/exports/report.pdf'):
            self.assertFalse(prepare.included(path), path)
        self.assertTrue(prepare.included('backend/services/decoder/automatic_worker.py'))
        self.assertTrue(prepare.included('apps/nivxray-xdr/yarn.lock'))

    def test_network_and_response_boundary(self):
        manifest = yaml.safe_load((prepare.HERE / 'compose.yml').read_text())
        self.assertTrue(manifest['networks']['private']['internal'])
        self.assertEqual(manifest['services']['backend']['networks'], ['private'])
        self.assertEqual(manifest['services']['mongodb']['networks'], ['private'])
        self.assertNotIn('ports', manifest['services']['backend'])
        self.assertNotIn('ports', manifest['services']['mongodb'])
        self.assertEqual(set(manifest['services']), {'backend', 'mongodb', 'gateway'})
        environment = manifest['services']['backend']['environment']
        self.assertEqual(environment['XDR_RESPONSE_SERVICE_URL'], '')
        self.assertEqual(environment['AUTO_INVESTIGATE_V1'], 'off')
        self.assertTrue(manifest['services']['backend']['read_only'])

    def test_private_env_file_and_unknown_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            p = pathlib.Path(directory) / 'backend.env'
            p.write_text('XDR_RESPONSE_SERVICE_URL=https://production.net\n')
            p.chmod(0o600)
            with self.assertRaises(ValueError):
                preflight.read_env(p, 'backend.env.example')

    def test_export_exact_source_and_csp(self):
        with tempfile.TemporaryDirectory() as directory:
            dest = pathlib.Path(directory) / 'context'
            prepare.export(dest, 'https://stage1-api.owner-staging.net')
            record = json.loads((dest / 'source-manifest.json').read_text())
            self.assertEqual(record['source']['commit'], prepare.SOURCE['commit'])
            self.assertFalse((dest / 'backend/nci_v2').exists())
            self.assertFalse((dest / 'backend/xdr_state/outbox.db').exists())
            frontend = dest / prepare.SOURCE['frontend']
            csp = json.loads((frontend / 'vercel.json').read_text())['headers'][0]['headers'][0]['value']
            self.assertIn('https://stage1-api.owner-staging.net', csp)
            self.assertNotIn('nivxray.nivxforge.com', csp)
            self.assertEqual((dest / 'backend/services/decoder/automatic_worker.py').read_bytes(),
                prepare.git('show', prepare.SOURCE['commit'] + ':backend/services/decoder/automatic_worker.py'))

    def test_repeat_export_same_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ('first', 'second'):
                prepare.export(pathlib.Path(directory) / name, 'https://stage1-api.owner-staging.net')
            self.assertEqual((pathlib.Path(directory) / 'first/source-manifest.json').read_bytes(),
                             (pathlib.Path(directory) / 'second/source-manifest.json').read_bytes())


if __name__ == '__main__':
    unittest.main()
