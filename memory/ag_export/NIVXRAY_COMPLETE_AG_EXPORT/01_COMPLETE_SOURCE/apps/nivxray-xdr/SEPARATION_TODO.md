## NivXRay XDR — separation-session TODO (fresh context)

**Do these in order.  Do NOT skip the ownership map.**

1. **Ownership map** — for every file under
   `frontend/src/xdr/**`, `frontend/src/nivxforge/**`,
   `frontend/src/components/incidents/**`,
   `frontend/src/constants/incidentTestIds.js`,
   `frontend/src/lib/incidentsApi.js`
   classify as:
     - XDR-owned  → move to `apps/nivxray-xdr/src/`
     - Shared    → decide: keep in base app OR extract to shared package
     - Base-app-owned → keep in `/app/frontend/src`

2. **Scaffold Vite config + entry**
   - `apps/nivxray-xdr/vite.config.js` (proxy `/api` → NivXRay backend)
   - `apps/nivxray-xdr/index.html`
   - `apps/nivxray-xdr/src/main.jsx` (React root)
   - `apps/nivxray-xdr/src/App.jsx` (router)

3. **Move XDR-owned files** (per ownership map) preserving
   git history via `git mv`.  Rewrite imports to use the new
   relative paths.  DO NOT copy — move.

4. **Wire auth + API client**
   - `apps/nivxray-xdr/src/lib/api.js` — axios instance targeting
     `import.meta.env.VITE_NIVXRAY_API_URL` (falls back to `/api`).
   - `apps/nivxray-xdr/src/lib/auth.jsx` — reuses
     `POST /api/auth/login`, stores token in localStorage.
     **Do not re-implement login server-side.**

5. **Verify original app still builds**
   ```
   cd /app/frontend && yarn build
   ```
   Then verify `/analyst` and `/edr/trajectory` still render.

6. **Verify XDR app builds independently**
   ```
   cd /app/apps/nivxray-xdr && yarn install && yarn build
   ```

7. **Run backend regression**
   ```
   cd /app/backend && python -m pytest tests/canonical -q
   ```
   Must remain **808 passed / 0 failed / 4 skipped**.

8. **Remove XDR routes from `/app/frontend/src/App.js`**
   ONLY AFTER the standalone app is proven to work.

9. **Deployment model** — configure the preview to serve
   `apps/nivxray-xdr/dist` at `/xdr/` subpath (or a separate
   subdomain).  Do NOT change the existing preview until both apps
   build cleanly.

10. **Duplication audit** — grep the new app to confirm zero
    imports of Device Trajectory / Process Tree engines / Verdict
    engine / Command Intelligence decoder.  All access must go
    through HTTP APIs.

11. **Cisco Device Trajectory fidelity is a SEPARATE slice.**
    Do not start it in the separation session.
