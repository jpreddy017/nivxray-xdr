"""No-network staging safety regression tests for deployment wrapper."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).parent
import sys
sys.path.insert(0, str(ROOT))
import entrypoint as g
import smoke


def good():
    return {
        "NIVX_G4_STAGING_ONLY": "1", "NIVX_DEPLOYMENT_ENV": "production",
        "DB_NAME": "nivx_g4_staging",
        "NIVX_G4_PUBLIC_ORIGIN": "https://g4-api.example.net",
        "NIVX_G4_MONGO_HOST": "g4-mongo.railway.internal",
        "MONGO_URL": ("mongodb://g4_user:private@g4-mongo.railway.internal:27017/"
                      "nivx_g4_staging?authSource=nivx_g4_staging"),
        "JWT_SECRET": "a" * 36, "ADMIN_EMAIL": "g4-admin@example.net",
        "ADMIN_PASSWORD": "G4localpasswordlongerthan32characters",
        "EMERGENT_LLM_KEY": "G4_INTERNAL_TEST_KEY",
        "EDR_AUTH_PEPPER": "b" * 36, "XDR_AUDIT_MASTER_SECRET": "c" * 36,
        "XDR_SECRETS_MASTER": "d" * 36, "NIVXRAY_SIGNING_SECRET": "e" * 36,
        "XDR_ROOT_KEY": "f" * 36, "EDR_ENROLLMENT_TOKEN_TTL_SECONDS": "600",
        "EDR_AGENT_SESSION_TTL_SECONDS": "300", "PORT": "8001",
        "XDR_RESPONSE_SERVICE_URL": "", "AUTO_INVESTIGATE_V1": "off",
        "NIVX_FILES_SWEEP_ENABLED": "0",
    }


class GuardTests(unittest.TestCase):
    def test_valid_isolated_staging(self):
        g.validate(good())

    def test_block_production_domains(self):
        for host in ("nivxray.nivxforge.com", "edr.nivxforge.com", "xdr.nivxforge.com"):
            with self.subTest(host=host), self.assertRaises(g.ConfigurationRefused):
                g.validate({**good(), "NIVX_G4_PUBLIC_ORIGIN": "https://" + host})

    def test_block_preview_domain(self):
        with self.assertRaises(g.ConfigurationRefused):
            g.validate({**good(), "NIVX_G4_PUBLIC_ORIGIN":
                        "https://greeting-app-5782.preview.emergentagent.com"})

    def test_block_fake_example_domain(self):
        with self.assertRaises(g.ConfigurationRefused):
            g.validate({**good(), "NIVX_G4_PUBLIC_ORIGIN": "https://edr-lab.nivxforge.example"})

    def test_block_ip_and_loopback(self):
        for origin in ("https://8.8.8.8", "https://localhost"):
            with self.subTest(origin=origin), self.assertRaises(g.ConfigurationRefused):
                g.validate({**good(), "NIVX_G4_PUBLIC_ORIGIN": origin})

    def test_block_wrong_database(self):
        for key, value in (
            ("DB_NAME", "test_database"),
            ("MONGO_URL", "mongodb://g4:password@g4-mongo.railway.internal:27017/prod?authSource=admin"),
            ("NIVX_G4_MONGO_HOST", "prod-db.railway.internal"),
        ):
            with self.subTest(key=key), self.assertRaises(g.ConfigurationRefused):
                g.validate({**good(), key: value})

    def test_block_no_stage_marker(self):
        with self.assertRaises(g.ConfigurationRefused):
            g.validate({**good(), "NIVX_G4_STAGING_ONLY": "0"})

    def test_block_dev_security(self):
        with self.assertRaises(g.ConfigurationRefused):
            g.validate({**good(), "NIVX_DEPLOYMENT_ENV": "development"})

    def test_block_response_execution(self):
        with self.assertRaises(g.ConfigurationRefused):
            g.validate({**good(), "XDR_RESPONSE_SERVICE_URL": "https://response.production"})

    def test_block_shared_secrets(self):
        with self.assertRaises(g.ConfigurationRefused):
            g.validate({**good(), "EDR_AUTH_PEPPER": "a" * 36})

    def test_block_missing_ttl(self):
        with self.assertRaises(g.ConfigurationRefused):
            g.validate({**good(), "EDR_AGENT_SESSION_TTL_SECONDS": ""})

    def test_no_secrets_in_refusal(self):
        with self.assertRaises(g.ConfigurationRefused) as cm:
            g.validate({**good(), "MONGO_URL": "mongodb://secretuser:secretpass@mongo/production"})
        self.assertNotIn("secretuser", str(cm.exception))
        self.assertNotIn("secretpass", str(cm.exception))

    def test_block_automation(self):
        with self.assertRaises(g.ConfigurationRefused):
            g.validate({**good(), "AUTO_INVESTIGATE_V1": "on"})


class SmokeTests(unittest.TestCase):
    @staticmethod
    def fake_endpoint(url, timeout):
        if url.endswith("/api/health"):
            return {"status": "ok"}
        if url.endswith("/api/health/deep"):
            return {"status": "ok", "checks": {"mongo": "ok"}}
        return {"paths": {path: {method: {}} for method, path in smoke.REQUIRED}}

    def test_smoke_pass(self):
        with patch.object(smoke, "get_json", side_effect=self.fake_endpoint):
            self.assertEqual(smoke.check("https://g4-api.example.net", 5), [])

    def test_readiness_degraded_is_not_pass(self):
        def degraded(url, timeout):
            if url.endswith("/api/health/deep"):
                return {"status": "degraded", "checks": {"mongo": "failed"}}
            return self.fake_endpoint(url, timeout)
        with patch.object(smoke, "get_json", side_effect=degraded):
            self.assertIn("DEEP_READINESS_NOT_OK", smoke.check("https://g4-api.example.net", 5))

    def test_missing_agent_routes_not_pass(self):
        def no_routes(url, timeout):
            if url.endswith("/openapi.json"):
                return {"paths": {}}
            return self.fake_endpoint(url, timeout)
        with patch.object(smoke, "get_json", side_effect=no_routes):
            self.assertIn("AGENT_ENDPOINT_CONTRACT_INCOMPLETE",
                          smoke.check("https://g4-api.example.net", 5))

    def test_smoke_refuses_production(self):
        with self.assertRaises(g.ConfigurationRefused):
            smoke.check("https://nivxray.nivxforge.com", 5)


if __name__ == "__main__":
    unittest.main()
