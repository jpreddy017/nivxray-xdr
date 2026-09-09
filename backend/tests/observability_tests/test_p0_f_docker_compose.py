"""P0-F · Docker Compose production floor acceptance tests.

Sprint 1 · owner-locked closure rule.

The compose file itself is the production-floor deliverable.  This
test proves it is:
    · syntactically valid YAML
    · a valid docker-compose v3 shape
    · references files that exist in the repo
    · declares the invariants owner locked (non-root, healthchecks,
      env-driven ADMIN_PASSWORD, Prometheus reachability)

We DO NOT launch Docker inside this pod (no docker socket).  Where
Docker CLI parsing is available (developer laptop / CI), a separate
integration step should run `docker compose config` — the compose
file uses `${ADMIN_PASSWORD:?...}` so a missing env-var fails
compose-parse-time, exactly as the acceptance criterion demands.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml


DEPLOY_ROOT = Path(__file__).resolve().parents[3] / "deploy"


@pytest.fixture(scope="module")
def compose_doc() -> dict:
    p = DEPLOY_ROOT / "docker-compose.yml"
    assert p.exists(), "deploy/docker-compose.yml missing"
    return yaml.safe_load(p.read_text())


def test_deploy_directory_present():
    for name in ("backend.Dockerfile", "frontend.Dockerfile",
                 "docker-compose.yml", ".env.example", "README.md"):
        p = DEPLOY_ROOT / name
        assert p.exists(), f"deploy/{name} missing"


def test_compose_declares_three_services(compose_doc):
    services = compose_doc.get("services", {})
    assert set(services.keys()) == {"mongodb", "backend", "frontend"}, (
        f"unexpected services: {sorted(services.keys())}")


def test_backend_service_wires_metrics_env(compose_doc):
    backend = compose_doc["services"]["backend"]
    env = backend.get("environment", {})
    assert env.get("OBSERVABILITY_METRICS_ENABLED") == "1"
    # LOG_LEVEL uses `${LOG_LEVEL:-INFO}` shell-expansion default so
    # operators can override without editing the compose file.
    log_level_value = env.get("LOG_LEVEL", "")
    assert "LOG_LEVEL" in log_level_value or log_level_value in {
        "DEBUG", "INFO", "WARNING", "ERROR"
    }, f"LOG_LEVEL wiring unexpected: {log_level_value!r}"


def test_backend_admin_password_is_required_at_parse_time(compose_doc):
    """The compose file MUST use ${ADMIN_PASSWORD:?...} so a missing
    env var fails at parse time — no accidental deployment with a
    blank admin password."""
    src = (DEPLOY_ROOT / "docker-compose.yml").read_text()
    assert "${ADMIN_PASSWORD:?" in src, (
        "ADMIN_PASSWORD must be required at parse time (${ADMIN_PASSWORD:?...})"
    )


def test_every_service_has_healthcheck(compose_doc):
    for name, spec in compose_doc["services"].items():
        assert "healthcheck" in spec, f"{name} missing healthcheck"
        hc = spec["healthcheck"]
        assert "test" in hc, f"{name}.healthcheck missing test"


def test_backend_depends_on_mongo_healthy(compose_doc):
    dep = compose_doc["services"]["backend"].get("depends_on", {})
    assert dep.get("mongodb", {}).get("condition") == "service_healthy"


def test_frontend_depends_on_backend_healthy(compose_doc):
    dep = compose_doc["services"]["frontend"].get("depends_on", {})
    assert dep.get("backend", {}).get("condition") == "service_healthy"


def test_mongo_uses_named_volume_for_persistence(compose_doc):
    vols = compose_doc["services"]["mongodb"].get("volumes", [])
    assert any("nivxray-mongo-data" in str(v) for v in vols), (
        "mongo persistence via nivxray-mongo-data named volume missing"
    )
    top = compose_doc.get("volumes", {})
    assert "nivxray-mongo-data" in top


def test_backend_dockerfile_declares_non_root(monkeypatch):
    src = (DEPLOY_ROOT / "backend.Dockerfile").read_text()
    assert "USER nivxray" in src, "backend must run as non-root user"
    assert "HEALTHCHECK" in src, "backend Dockerfile missing HEALTHCHECK"


def test_frontend_dockerfile_declares_healthcheck():
    src = (DEPLOY_ROOT / "frontend.Dockerfile").read_text()
    assert "HEALTHCHECK" in src


def test_env_example_lacks_admin_password_default():
    src = (DEPLOY_ROOT / ".env.example").read_text()
    # ADMIN_PASSWORD line must exist and be blank (no leaked value).
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("ADMIN_PASSWORD="):
            assert s == "ADMIN_PASSWORD=", (
                "deploy/.env.example must not carry a default ADMIN_PASSWORD"
            )
            break
    else:
        pytest.fail("ADMIN_PASSWORD key missing from deploy/.env.example")


def test_readme_documents_metrics_scrape_target():
    readme = (DEPLOY_ROOT / "README.md").read_text()
    assert "/api/metrics" in readme
    assert "prometheus" in readme.lower()
