"""NivXForge — Enterprise Autonomous Cyber Investigation Platform.

Phase 0 · Platform Foundation (Feb-2026).

This package is architecturally isolated from the NivXRay Workspace.
Governance references:
  - /app/memory/PRODUCT_CHARTER.md   (permanent principles)
  - /app/memory/NORTH_STAR.md        (aspirational architecture)
  - /app/memory/IMPLEMENTATION_ROADMAP.md   (active work — Phase 0 lives here)

Isolation rules (enforced by tests/test_workspace_isolation.py):
  - No module inside nivxforge/ may import from Workspace modules
    (routers/, server.py, operations.py, engine/, v2/, analysis_core.py,
    wrapper_archetypes.py, magic_decoder.py, command_analyzer.py, etc.).
  - All API routes MUST be mounted under /api/nivxforge/.
  - All env vars MUST use the FORGE_ prefix.
  - All Mongo collections MUST use the forge_ prefix.

This is a foundational package. It intentionally contains NO analytical
features. Features enter only via the IMPLEMENTATION_ROADMAP.md entry gate.
"""

__version__ = "0.1.0-phase0"
