# NivXRay XDR — standalone tool

This directory is the **separate application boundary** for NivXRay
XDR.  It is independently buildable and consumes the existing
NivXRay platform through authenticated HTTP APIs.

## Boundary rules (owner-locked · 2026-08-29)

- **Independently buildable** — this app must not depend on the
  original `/app/frontend` React SPA at build or runtime.
- **Consumes only** — every backend interaction is an authenticated
  API call against the existing NivXRay platform.  No parallel SSOT,
  no duplicate engines (Workspace / Device Trajectory / Process Tree
  / Command Intelligence / MITRE / Verdict / Evidence).
- **`/analyst` and `/edr/trajectory` in the original NivXRay
  application remain UNTOUCHED.**
- **Cisco Device Trajectory fidelity is a separate future slice** —
  do NOT co-mingle it with the separation work.

## Structure (target)

```
/app/apps/nivxray-xdr/
  ├── package.json              (independent — vite + react + rr)
  ├── vite.config.js
  ├── .env                      (REACT_APP_NIVXRAY_API_URL etc.)
  ├── index.html
  ├── src/
  │   ├── main.jsx
  │   ├── App.jsx
  │   ├── shell/                (XdrShell.jsx, sidebar tree)
  │   ├── pages/                (Dashboard, Incidents queue+detail)
  │   ├── nivxforge/            (EDR Console + pages)
  │   ├── lib/                  (auth, api client, incidentsApi)
  │   ├── styles/               (xdr-console.css, nivxforge.css)
  │   └── testIds.js
  └── public/
```

## Migration source

Extracted **by ownership** from `/app/frontend/src/` — see
`/app/memory/XDR_SEPARATION_HANDOFF.md` for the file inventory.

## Regression protection

- Existing `/app/backend` test baseline: **808 / 0 / 4**.  Preserve
  it through every step of the extraction.
- After each file moved, verify both applications still build
  independently before continuing.

## Non-negotiables

1. Adapter, not new SSOT
2. Ownership map before any file move
3. Both apps independently buildable at the end
4. No modification of `/analyst` or `/edr/trajectory`
5. No duplicate engines
6. Cisco Trajectory fidelity is a separate slice
