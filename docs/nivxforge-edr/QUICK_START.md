# NivXForge EDR · Quick Start

Goal: one computer onboarded, reporting authenticated telemetry, and
carrying a policy it has actually acknowledged.

## Before you start

* A NivXForge EDR operator account.
* A **customer (tenant)** selected in the console header. NivXForge has
  no default tenant: a tenant-scoped request without an explicit tenant
  is refused with `TENANT_REQUIRED`. That is deliberate.
* A Windows host you can run an elevated PowerShell on, with Python
  3.11+ available.

## 1 · Create a group

`Policies → New group`. A group is the placement a computer joins. Give
it a name; optionally bind a policy now (you can bind one later).

## 2 · Create a policy

`Policies → New policy`. The console offers the settings the released
connector actually honours. Mode is `DETECT_ONLY`: the released
connector collects and reports and enforces nothing, so `PREVENT` would
be recorded as requested and reported as **NOT ENFORCED**.

Creating a policy writes an immutable **version 1** with a
**config digest**. That digest is what the endpoint must later
acknowledge.

## 3 · Assign the policy to the group

On the policy, choose the group and press **Assign**. The response says
`ASSIGNED` and nothing more. Assignment does not deliver anything and
does not make a computer protected.

## 4 · Create a deployment

`Management → Downloads` → pick the published connector release →
**Deploy this version** → choose the group → **Create deployment**.

You get:

* the **released artifact identity** (SHA-256) — unchanged, because the
  connector is never rebuilt for a group or an endpoint,
* an **install invocation** carrying a one-time enrolment credential.
  The credential is shown once and is not stored.

Download the artifact **once**. The same bytes install on every
computer.

## 5 · Install

Elevated PowerShell on the target computer, in the folder you
downloaded the artifact into:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-NivXForgeSensor.ps1 `
  -BackendUrl 'https://<your-edr-backend>' `
  -TenantId   '<your-tenant>' `
  -EnrollmentToken '<the one-time credential>'
```

The installer refuses to run without Administrator rights. It enrols
once; the platform mints the endpoint identity from durable machine
attributes and returns a per-device credential that never leaves the
machine.

The **group you chose travels with the enrolment credential**,
server-side. The installer takes no group argument, which is why one
artifact serves every wave.

## 6 · Watch the truth appear

`Computers` — the computer appears. It becomes **CONNECTED** only after
authenticated telemetry arrives inside the connector's own declared
cadence. Enrolment alone is never CONNECTED.

`Policies → <your policy>` — the per-computer row walks:

```
PENDING_DELIVERY → DELIVERED → ACKNOWLEDGED → APPLIED → VERIFIED
```

`DELIVERED` means the platform handed the version over. It does **not**
mean the computer applied it. Only the connector's acknowledgement of
the exact policy id, version and config digest produces `APPLIED`, and
a later independent check-in reporting the same running digest produces
`VERIFIED`.

`Events` — the estate-wide event stream, with your new computer in the
computer filter.

## What you will NOT see, and why

* **Prevention.** The released connector enforces nothing. The policy
  reports the request and marks it `NOT_SUPPORTED_BY_CONNECTOR`.
* **File, network or registry events on Windows.** The Windows release
  observes process activity. The Events page reports which activity
  classes were actually observed and lists the rest as NOT OBSERVED
  rather than implying none occurred.
* **Endpoint-side exclusions.** Exclusions are enforced server-side in
  the detection fabric today. Endpoint enforcement reports
  `EXCLUSION_NOT_SUPPORTED_BY_ENGINE` until a connector release declares
  the capability.
