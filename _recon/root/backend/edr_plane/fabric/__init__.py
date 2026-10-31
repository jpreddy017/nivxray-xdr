"""GATE 3 · NivXForge Detection & Prevention Fabric (bounded skeleton).

Importing this package registers the analyzers that exist TODAY. There is
exactly one, and it projects the platform's own deterministic detections
into the frozen Finding contract. No ML model exists, is shipped or is
executed; no correlation engine exists. Both facts are stated by the
fabric itself through `registry.declared_capabilities()`.
"""
from edr_plane.fabric import contracts, registry, store  # noqa: F401
from edr_plane.fabric.analyzers import deterministic_rule  # noqa: F401

__all__ = ["contracts", "registry", "store", "deterministic_rule"]
