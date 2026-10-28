#!/usr/bin/env python3
"""G4-only backend entrypoint. Refuses unsafe config before importing application.

The frozen M1 installer and backend application source remain unmodified.
Network isolation must be independently verified at the hosting layer.
"""
from __future__ import annotations

import ipaddress
import os
import re
import sys
from urllib.parse import parse_qs, urlsplit

STAGING_DB = "nivx_g4_staging"
PRODUCTION_HOSTS = frozenset({
    "nivxray.nivxforge.com", "xdr.nivxforge.com",
    "edr.nivxforge.com", "nivxforge.com", "app.nivxforge.com",
})
FORBIDDEN_SUFFIXES = (".example", ".invalid", ".test", ".localhost")


class ConfigurationRefused(ValueError):
    """Safe-to-log refusal; never contains secret values."""


def _hostname(value: str, *, must_be_public: bool) -> str:
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError:
        raise ConfigurationRefused("G4_INVALID_API_ORIGIN") from None
    if (parsed.scheme != "https" or not host or parsed.username is not None
            or parsed.password is not None or port not in (None, 443)
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ConfigurationRefused("G4_INVALID_API_ORIGIN")
    if (host in PRODUCTION_HOSTS or any(host.endswith(x) for x in FORBIDDEN_SUFFIXES)
            or "preview.emergentagent.com" in host or "localhost" in host
            or host.startswith("preview.") or host.startswith("greeting-app-")):
        raise ConfigurationRefused("G4_FORBIDDEN_API_ORIGIN")
    if must_be_public:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or "." not in host:
                raise ConfigurationRefused("G4_INVALID_PUBLIC_HOST") from None
        else:
            raise ConfigurationRefused("G4_IP_ORIGIN_REFUSED")
    return host


def _mongo_host(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        _ = parsed.port
    except ValueError:
        raise ConfigurationRefused("G4_INVALID_MONGO_URI") from None
    if (parsed.scheme not in {"mongodb", "mongodb+srv"} or not hostname
            or not parsed.username or not parsed.password
            or parsed.path != "/" + STAGING_DB or parsed.fragment):
        raise ConfigurationRefused("G4_INVALID_MONGO_URI")
    opts = parse_qs(parsed.query, keep_blank_values=True)
    if opts.get("authSource") != [STAGING_DB]:
        raise ConfigurationRefused("G4_DB_AUTH_SOURCE_REFUSED")
    return hostname


def validate(env: dict[str, str]) -> None:
    if env.get("NIVX_G4_STAGING_ONLY") != "1":
        raise ConfigurationRefused("G4_STAGE_MARKER_ABSENT")
    if env.get("NIVX_DEPLOYMENT_ENV") != "production":
        raise ConfigurationRefused("G4_STRICT_SECURITY_MODE_REQUIRED")
    if env.get("DB_NAME") != STAGING_DB:
        raise ConfigurationRefused("G4_DATABASE_NAME_REFUSED")
    _hostname(env.get("NIVX_G4_PUBLIC_ORIGIN", ""), must_be_public=True)
    actual = _mongo_host(env.get("MONGO_URL", ""))
    expected = env.get("NIVX_G4_MONGO_HOST", "").rstrip(".").lower()
    if not expected or actual != expected or actual in PRODUCTION_HOSTS:
        raise ConfigurationRefused("G4_MONGO_HOST_MISMATCH")
    if env.get("XDR_RESPONSE_SERVICE_URL", ""):
        raise ConfigurationRefused("G4_RESPONSE_SERVICE_FORBIDDEN")
    if env.get("AUTO_INVESTIGATE_V1", "off").lower() not in {"off", "0", "false"}:
        raise ConfigurationRefused("G4_AUTOMATION_FORBIDDEN")
    if env.get("NIVX_FILES_SWEEP_ENABLED", "0") not in {"0", "false", "off"}:
        raise ConfigurationRefused("G4_SWEEP_FORBIDDEN")
    required = ("JWT_SECRET", "ADMIN_EMAIL", "ADMIN_PASSWORD", "EMERGENT_LLM_KEY",
                "EDR_AUTH_PEPPER", "XDR_AUDIT_MASTER_SECRET", "XDR_SECRETS_MASTER",
                "NIVXRAY_SIGNING_SECRET", "XDR_ROOT_KEY")
    if any(not env.get(key, "").strip() for key in required):
        raise ConfigurationRefused("G4_REQUIRED_SECRET_OR_ACCOUNT_MISSING")
    keys = ("JWT_SECRET", "EDR_AUTH_PEPPER", "XDR_AUDIT_MASTER_SECRET",
            "XDR_SECRETS_MASTER", "NIVXRAY_SIGNING_SECRET", "XDR_ROOT_KEY")
    values = [env[key] for key in keys]
    if (len(set(values)) != len(values) or any(len(value) < 32 for value in values)
            or any(any(bad in value.lower() for bad in
                       ("placeholder", "changeme", "example", "dummy")) for value in values)):
        raise ConfigurationRefused("G4_CRYPTOGRAPHIC_SECRETS_UNSAFE")
    for key, upper in (("EDR_ENROLLMENT_TOKEN_TTL_SECONDS", 86400),
                       ("EDR_AGENT_SESSION_TTL_SECONDS", 3600)):
        raw = env.get(key, "")
        if not raw.isdecimal() or not 0 < int(raw) <= upper:
            raise ConfigurationRefused("G4_AUTH_TTL_REFUSED")
    port = env.get("PORT", "8001")
    if not port.isdecimal() or not (1024 <= int(port) <= 65535):
        raise ConfigurationRefused("G4_PORT_REFUSED")


def main() -> None:
    try:
        validate(dict(os.environ))
    except ConfigurationRefused as exc:
        print("G4_STAGING_CONFIG_REFUSED:" + str(exc), file=sys.stderr)
        raise SystemExit(78) from None
    port = os.environ.get("PORT", "8001")
    print("G4_STAGING_CONFIG_ACCEPTED: starting isolated API", flush=True)
    os.execvp("uvicorn", ["uvicorn", "server:app", "--host", "0.0.0.0",
                          "--port", port, "--workers", "1"])


if __name__ == "__main__":
    main()
