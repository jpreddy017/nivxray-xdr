"""NivXForge configuration.

All environment variables MUST use the `FORGE_` prefix. This is the
Workspace Protection boundary — Workspace uses its own env namespace
(existing keys) and MUST not be read by nivxforge code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


FORGE_ENV_PREFIX = "FORGE_"
FORGE_ROUTE_PREFIX = "/nivxforge"          # mounted under /api → /api/nivxforge/*
FORGE_COLLECTION_PREFIX = "forge_"         # every Mongo collection nivxforge writes


@dataclass(frozen=True)
class ForgeConfig:
    """Runtime configuration for the NivXForge package.

    Only reads env vars that start with FORGE_. Never falls back to
    Workspace env vars — that is a Workspace Protection violation.
    """

    enabled: bool = False    # Phase 0 default: dormant. Flip via FORGE_ENABLED=true.


def load() -> ForgeConfig:
    return ForgeConfig(
        enabled=(os.environ.get(f"{FORGE_ENV_PREFIX}ENABLED", "").lower() == "true"),
    )
