"""
DIE · Preprocessor · Artifact Classifier & Router
─────────────────────────────────────────────────
The Classifier normalises the *subtype* of an artifact after the
extractor emits it (e.g. hash → md5/sha1/sha256, url → scheme,
executable → exe / dll / rmm / lolbin).

The Router labels each artifact with the *downstream analyzer*
that should own it (``die`` for commands, ``registry`` for
registry, ``ioc`` for URLs/IPs/hashes, ``lolbas`` for LOLBins …).
The label lands on ``artifact.attributes['route']``.

Deterministic — same input, same routing decisions.
"""
from __future__ import annotations
from typing import List
from .models import Artifact


# Downstream analyzer buckets.
ROUTE_DIE          = "die"          # commands / executables / lolbins
ROUTE_REGISTRY     = "registry"     # HKLM / HKCU …
ROUTE_IOC          = "ioc"          # URL / IP / hash / domain
ROUTE_FILESYSTEM   = "filesystem"   # file paths / UNC
ROUTE_ENV          = "env"          # env vars
ROUTE_SCHEDULE     = "schedule"     # scheduled tasks
ROUTE_SERVICE      = "service"      # windows services
ROUTE_NETWORK      = "network"      # network endpoints
ROUTE_UNKNOWN      = "unknown"


_TYPE_TO_ROUTE = {
    "command":         ROUTE_DIE,
    "executable":      ROUTE_DIE,
    "dll":             ROUTE_DIE,
    "lolbin":          ROUTE_DIE,
    "registry":        ROUTE_REGISTRY,
    "url":             ROUTE_IOC,
    "ip":              ROUTE_IOC,
    "hash":            ROUTE_IOC,
    "file_path":       ROUTE_FILESYSTEM,
    "unc_path":        ROUTE_FILESYSTEM,
    "env_var":         ROUTE_ENV,
    "scheduled_task":  ROUTE_SCHEDULE,
    "service":         ROUTE_SERVICE,
    "network_endpoint": ROUTE_NETWORK,
    "process":         ROUTE_DIE,
    "unknown":         ROUTE_UNKNOWN,
}


# RMM canonical set used to tag executables/lolbins as "rmm" so
# the Attack Story surface flags them prominently.
_RMM_SET = {
    "anydesk", "screenconnect", "simplehelp", "splashtop",
    "optitune", "teamviewer", "atera", "kaseya", "connectwise",
    "n-able", "quickassist",
}


def classify(artifacts: List[Artifact]) -> List[Artifact]:
    """Refine subtype and mark RMM/lolbin flavours."""
    for a in artifacts:
        norm = (a.normalized_text or "").lower()

        # RMM detection on both lolbins and command artifacts.
        if a.type in ("lolbin", "executable", "command"):
            exe = (a.attributes.get("executable") or "").lower() or norm
            if exe.replace(".exe", "").strip() in _RMM_SET:
                a.attributes.setdefault("category", "rmm")
                if a.type == "executable" and not a.subtype:
                    a.subtype = "rmm"

        # Hash subtype refinement in case the extractor left it None.
        if a.type == "hash" and not a.subtype:
            length = len(norm.replace(" ", ""))
            a.subtype = {32: "md5", 40: "sha1", 64: "sha256"}.get(length, "unknown")

    return artifacts


def route(artifacts: List[Artifact]) -> List[Artifact]:
    for a in artifacts:
        a.attributes["route"] = _TYPE_TO_ROUTE.get(a.type, ROUTE_UNKNOWN)
    return artifacts
