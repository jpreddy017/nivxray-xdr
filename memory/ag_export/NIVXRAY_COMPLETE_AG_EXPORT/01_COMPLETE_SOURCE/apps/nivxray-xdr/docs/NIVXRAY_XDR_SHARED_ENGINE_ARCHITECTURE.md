# NivXRay XDR — Shared Engine Architecture

**Guiding principle:** NivXRay Tool is the authoritative source of security
engineering.  NivXRay XDR is the operational XDR experience that consumes
those capabilities through APIs, shared libraries and adapters — never a
parallel reimplementation.

## Target architecture

```
                     ┌───────────────────────────────────┐
                     │  NivXRay Tool (authoritative)      │
                     │  · Evidence Engine · SSOT · IKG    │
                     │  · Verdict Engine · Correlation    │
                     │  · Command Intelligence · Decoders │
                     │  · MITRE / STIX · Golden corpus    │
                     │  · Investigation report / Analyst  │
                     └───────────────┬───────────────────┘
                                     │  existing /api/* surface
                                     │  (read-mostly for XDR)
                                     ▼
                     ┌───────────────────────────────────┐
                     │  NivXRay XDR (this repo)           │
                     │  Collector   Detection   Response  │
                     │      │            │           │    │
                     │      │            │           │    │
                     │      └─── Investigation ─────┘    │
                     │            Canvas / Timeline /    │
                     │            Attack Story / MITRE   │
                     └───────────────┬───────────────────┘
                                     │  ONLY authorised write:
                                     │  POST /api/xdr/response-evidence
                                     ▼
                            Evidence → SSOT → IKG
```

## Layer contract (who owns what)

| Layer | Owner | Notes |
| --- | --- | --- |
| Detection Rules (Sigma) | XDR authoring · base runtime (future) | XDR persists rules, evaluates test cases locally.  Live-telemetry execution binds to the base's engine when wired. |
| Evidence               | Base                                  | XDR consumes via `/api/analyze/*` + Stage-2 output. |
| SSOT / Verdict / IKG   | Base                                  | XDR NEVER writes; only reads. |
| Response execution     | XDR (own service, own SQLite)         | Isolated so a bad response deploy cannot corrupt investigation truth. |
| Response evidence      | Base (via authorised sink)            | The single XDR→base write.  Idempotent · provenance-validated. |
| Investigation UI       | XDR                                   | Presentation layer over base authoritative data + XDR response chain. |

## Adoption methods

The Adoption Matrix uses six formal methods:

| Method | Meaning | Example |
| --- | --- | --- |
| `CONSUME` | Call an existing base HTTP route | Verdict Stage-2, IOC intel, decoder |
| `PROXY` | Thin XDR route that forwards to a base route (for CORS, auth injection, or tenant scoping) | Response evidence backfill by incident id |
| `SHARED_LIBRARY` | Import a Python module from base | Canonical evidence schema types |
| `ADAPTER` | Wrap a new telemetry source into the base's evidence schema | Collector connectors |
| `EXTEND` | Add a capability to base (owner-authorised only) | Response evidence sink |
| `EXTERNAL` | Adopt an open standard/library | Sigma, MITRE ATT&CK, STIX/TAXII, js-yaml |

## Honesty invariants

- **AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED** — surfaced verbatim in the UI whenever a base capability exists but the XDR consumer isn't wired.  Never fabricate a call.
- **NOT IMPLEMENTED** — for capabilities that don't exist anywhere yet.
- **EXTERNAL DEPENDENCY REQUIRED** — when a real integration (vendor API, TI feed) is not deployed.

## Testing invariant

A capability is not "adopted" until:
- **Wire test** — a green integration test proves the XDR consumer talks to the base route/library.
- **Regression test** — the relevant base golden-corpus / benchmark suite is still green.
- **Honesty test** — the UI surfaces the correct honest banner when the adapter is disconnected.

## Non-adoption examples (explicit)

- No proprietary detection DSL (adopted Sigma).
- No proprietary MITRE technique table (base+official taxonomy).
- No re-implemented decoder in XDR (calls base `/api/analyze`).
- No parallel Verdict Engine.  There is exactly one.

## Registry file
See `NIVXRAY_CAPABILITY_REGISTRY.json` for the machine-readable inventory
consumed by the XDR shell + Admin console.
