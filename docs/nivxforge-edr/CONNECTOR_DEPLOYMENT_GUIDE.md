# NivXForge EDR · Windows Connector Deployment Guide

## The architectural rule

**A connector is a released product artifact.** It is produced once per
legitimate release, its identity is disclosed, and the same bytes are
installed on every device.

**Deployment context is separate from the artifact.** Choosing a
version and a group produces an install invocation and a bounded
enrolment credential *around* the released artifact. It never
recompiles the connector, and the artifact SHA-256 is identical across
every deployment — the API returns it so you can verify that yourself.

This is what lets one NivXForge Connector be distributed to hundreds or
thousands of endpoints without a rebuild.

## The release catalog

`Management → Downloads` lists every release with:

| Field | Meaning |
|---|---|
| connector version, architecture, OS | the release identity |
| channel | `STABLE` / `PREVIEW` / `BETA` |
| support status | e.g. `PREVIEW_NOT_FOR_PRODUCTION`, `NOT_RELEASED` |
| release date, end of support | lifecycle dates as declared |
| code signing status | recorded, not assumed |
| supported OS | as declared for the release |
| release notes | what is in the release |
| artifact identity | SHA-256 composite of the released files |
| declared capability | what this release can and cannot do |

### Artifact states

| State | Meaning |
|---|---|
| `PUBLISHED` | the artifact exists on disk, its identity is recorded, and it carries no credential shape |
| `ARTIFACT_NOT_PUBLISHED` | no artifact has been produced for this release — **no download is offered and none is fabricated** |
| `ARTIFACT_INCOMPLETE` | the release declares files that are not present |
| `ARTIFACT_REFUSED_EMBEDDED_CREDENTIAL` | a file contains something shaped like a credential; a redistributable connector must never carry one |

Only `PUBLISHED` releases offer a download or accept a deployment.

### Current catalog

| Release | State | Notes |
|---|---|---|
| NivXForge Windows Connector 0.1.0 x64 | `PUBLISHED`, `PREVIEW_NOT_FOR_PRODUCTION`, `UNSIGNED` | process collection, authenticated telemetry, heartbeat, policy fetch + ACK |
| NivXForge Windows Connector arm64 | `ARTIFACT_NOT_PUBLISHED` / `NOT_RELEASED` | — |
| NivXForge Linux Connector 0.1.0 x64 | `ARTIFACT_NOT_PUBLISHED` | release metadata only |

## Declared capability of release 0.1.0

| Capability | Declared |
|---|---|
| process event collection | yes |
| authenticated telemetry | yes |
| heartbeat + declared cadence | yes |
| policy fetch and acknowledgement | yes |
| endpoint prevention | **no** |
| file / network / registry collection | **no** |
| endpoint-side exclusions | **no** |
| offline local inference | **no** |

The policy authority reads this table. A policy that asks for something
the release does not declare is recorded as requested and reported as
`NOT_SUPPORTED_BY_CONNECTOR` — never drawn as protection.

## The administrator workflow

```
Management → Downloads → Windows Connector → Version → Group
  → applicable Policy (resolved from the group, not chosen separately)
  → Create deployment → Download the released artifact ONCE
  → Install on each computer → Register → Computer appears
  → Policy DELIVERED → ACK → APPLIED → Telemetry → CONNECTED
```

The policy is **resolved from the group**, not selected independently.
That is deliberate: a computer can never land in one group and a
contradicting policy.

## Creating a deployment

`POST /api/edr/connector/deployments`

```json
{ "release_id": "nvf-connector-windows-0.1.0-x64",
  "group_id": "grp_…",
  "label": "Wave 1 · finance laptops",
  "ttl_seconds": 86400 }
```

Returns the deployment record, the resolved policy preview, the
unchanged artifact identity, `rebuild_required_per_endpoint: false`,
and the one-time enrolment credential **in that response only**. It is
not stored and is never re-disclosed. Lost it? Create another
deployment.

## Installing

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-NivXForgeSensor.ps1 `
  -BackendUrl 'https://<backend>' -TenantId '<tenant>' `
  -EnrollmentToken '<one-time credential>'
```

What the installer does:

1. refuses to run without Administrator rights,
2. stages the connector into `C:\Program Files\NivXForge\sensor`,
3. creates `C:\ProgramData\NivXForge\sensor` with an ACL limited to
   SYSTEM + Administrators (the per-device credential lives there),
4. enrols **once** — the platform mints `endpoint_id` from durable
   machine attributes and returns the device credential,
5. registers and starts the connector as a SYSTEM scheduled task,
6. prints the endpoint identity and never prints a secret.

## Re-run, upgrade and uninstall

| Invocation | Behaviour |
|---|---|
| re-run, no flags | keeps the existing identity and credential, refreshes program files, restarts the task. One computer keeps ONE identity across upgrades and reinstalls. |
| `-ReEnroll` | requires a NEW enrolment credential and replaces the local one. The platform mints the SAME `endpoint_id` from the same machine attributes, so it refreshes the credential of the same computer and never creates a second Computers entry. |
| `-Uninstall` | stops and removes the task and program files. The state directory (identity + journal) is kept unless `-Purge` is given, so evidence is not destroyed silently. |

## Verifying a deployment

* `Management → Downloads → Deployments` — every deployment shows its
  release, group, resolved policy, artifact identity and
  `Rebuilt: NO`.
* Compare the `X-NivXForge-Sha256` response header of the artifact
  download against the release's recorded SHA-256.
* `Computers` — status and its basis sentence.
* `Policies` — the per-computer lifecycle state.

## Known limits of this wave

* The 0.1.0 artifact is `UNSIGNED` and the release is
  `PREVIEW_NOT_FOR_PRODUCTION`. Code signing is recorded, not claimed.
* Production storage and distribution architecture (CDN, signed
  packages, MSI) is **not** implemented and is separately gated. The
  artifact is served through the authenticated API today; the storage
  provider is a deployment concern and is intentionally replaceable.
* No macOS release exists.
