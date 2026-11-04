"""NivXForge EDR — the endpoint security plane (Wave 0 substrate).

Package name note: this deliberately does NOT live inside backend/nivxforge/,
which is an isolation-enforced package (no Workspace imports, /api/nivxforge/
routes only, FORGE_ env, forge_ collections). NivXForge EDR must reach the
authoritative NivXRay engines and the existing /api/edr surface, so it lives
alongside them as `edr_plane`.

Authority: ``docs/architecture/NIVXFORGE_EDR_MASTER_DIRECTIVE.md``.

This package owns the ENDPOINT specialisation only: sensor contracts,
endpoint telemetry, the immutable raw-event substrate, the capability
registry and the endpoint control plane.

It deliberately owns NO reasoning engine. IUE / ICE / IKG / VEEE / Verdict
/ Decoder / IEDDE / UAIE / Detection / Correlation / Security State remain
the authoritative NivXRay engines and are REUSED, never duplicated
(directive §3).
"""
