# NivXForge EDR · Documentation

NivXForge EDR is an independent endpoint detection and response product.
It has its own console, its own navigation and its own evidence stores.
It **feeds** NivXRay XDR through a canonical detection-source contract;
it never depends on XDR for an EDR operation.

**Documentation rule (binding):** a guide describes what is
IMPLEMENTED. A capability that does not exist is either absent from
these documents or explicitly marked `NOT IMPLEMENTED`. No planned
behaviour is documented as available.

## Published guides

| Guide | Covers | Status |
|---|---|---|
| [Quick Start](QUICK_START.md) | first computer onboarded and reporting in ~10 minutes | PUBLISHED |
| [User Guide](USER_GUIDE.md) | the console, its surfaces and the truth vocabulary | PUBLISHED |
| [Windows Connector Deployment Guide](CONNECTOR_DEPLOYMENT_GUIDE.md) | releases, groups, deployment context, install, upgrade | PUBLISHED |
| [Policy Guide](POLICY_GUIDE.md) | the nine-state policy lifecycle and how APPLIED is proven | PUBLISHED |
| [Exclusions Guide](EXCLUSIONS_GUIDE.md) | declared protection blind spots and their six truth states | PUBLISHED |
| [Events Guide](EVENTS_GUIDE.md) | the estate-wide event explorer and its filters | PUBLISHED |

## Planned guides — NOT YET WRITTEN

These are listed so the shape of the documentation set is visible. They
are written only once the capability behind them passes its
implementation tests.

Device Trajectory · Command Intelligence · Response · Hunting and Live
Query · Administration · API reference · NivXForge EDR ↔ NivXRay XDR
integration · Troubleshooting · Compatibility matrix · Release notes ·
Upgrade and rollback.

## Capability status at a glance

| Surface | Route | Status |
|---|---|---|
| Dashboard | `/edr` | IMPLEMENTED |
| Computers | `/edr/computers` | IMPLEMENTED |
| Detections | `/edr/detections` | IMPLEMENTED |
| Events | `/edr/events` | IMPLEMENTED |
| Device Trajectory | `/edr/device-trajectory` | IMPLEMENTED |
| Process Tree | `/edr/process-tree` | IMPLEMENTED |
| Campaign Story | `/edr/campaign-story` | IMPLEMENTED |
| Response | `/edr/response` | IMPLEMENTED |
| Policies | `/edr/policies` | IMPLEMENTED |
| Exclusions | `/edr/exclusions` | IMPLEMENTED |
| Downloads | `/edr/management/downloads` | IMPLEMENTED |
| Hunt · Files · Network · Forensics · Live Query · Audit | — | **NOT IMPLEMENTED** — the console renders each destination disabled with its reason |
