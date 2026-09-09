"""NivXRay backend services layer.

Shared, endpoint-agnostic backend services. Consumers (routers, workers,
CLIs) call these instead of re-implementing the underlying deterministic
pipeline. Adding services here is preferred over cross-router imports.
"""
