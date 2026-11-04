# NivXForge Connector Productization — EVIDENCE

Status: **PASS (release + deployment lifecycle)** · 2026-09-26
Production storage/distribution architecture (signed packages, MSI,
CDN) remains separately gated.

## The owner decision, implemented literally

> The connector is a released product artifact; enrolment/deployment
> context is separate from compiling the connector.

* `edr_plane/connector/catalog.py` — the **release catalog**: release
  id, product, connector version, architecture, OS, channel, support
  status, release date, end of support, signing status, supported OS,
  requirements, release notes, declared capability, and the artifact
  identity read from disk.
* `routers/edr_connector.py` — releases, artifact download, and
  **deployment context** created *around* a released artifact.
* `pages/EdrDownloadsPage.jsx` — the Cisco-class administrator
  experience.

The previously proposed "generic installer URL + fresh token as the
permanent architecture" was **not** adopted.

## One build, many devices

`POST /api/edr/connector/deployments` returns the artifact identity
unchanged and `rebuild_required_per_endpoint: false`. Live proof:

| Assertion | Result |
|---|---|
| at least one release reports a real published artifact | PASS · `published=1/3` |
| no release requires a per-endpoint rebuild | PASS |
| releases without an artifact say `ARTIFACT_NOT_PUBLISHED` | PASS · 2 of 3 |
| deployment resolved the **group's** policy (not an independent choice) | PASS |
| deployment did not rebuild the connector (identical artifact identity) | PASS |
| the enrolment credential is returned exactly once | PASS |
| the computer registered into the administrator's group (`placement_basis=CONNECTOR_DEPLOYMENT`) | PASS |

## How the group travels without touching the artifact

The installer takes `-BackendUrl`, `-TenantId`, `-EnrollmentToken` and
**no group argument**. `POST /deployments` stamps `group_id`,
`deployment_id` and `release_id` onto the minted enrolment credential
server-side; `edr_enrollment.enroll` reads it and calls
`assign_deployment_placement`. That reproduces Cisco's "choose a Group
when you obtain the connector" without putting a group into the bytes.

## Artifact truth

| State | Behaviour |
|---|---|
| `PUBLISHED` | artifact on disk, identity recorded, scanned free of credential shapes; download offered |
| `ARTIFACT_NOT_PUBLISHED` | **no download offered and none fabricated** |
| `ARTIFACT_INCOMPLETE` | declared files absent |
| `ARTIFACT_REFUSED_EMBEDDED_CREDENTIAL` | a file contains a credential shape; a redistributable connector must never carry one |

Current catalog: Windows 0.1.0 x64 `PUBLISHED` /
`PREVIEW_NOT_FOR_PRODUCTION` / `UNSIGNED`; Windows arm64 and
Linux 0.1.0 `ARTIFACT_NOT_PUBLISHED`.

## Storage is a deployment concern

The artifact is served through the authenticated API from the build
directory. Emergent Object Storage was deliberately **not** made an
architectural requirement: the provider is replaceable and production
distribution is a separate gate.

## Capability is the single source of truth

`catalog.capabilities()` is read by the policy authority
(`unsupported_settings`) and by the exclusion plane
(`endpoint_truth_state`). Neither can claim enforcement the released
artifact does not perform.
