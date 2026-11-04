# NivXRay — Cut a Release + Redeploy to Prod

> **Why this doc exists**
> The main agent cannot cut GitHub releases or trigger the Emergent
> production deploy from inside the preview container — those are actions
> only the repository owner (you) can perform. This checklist is the
> exact sequence to run so the `docs-screenshots` workflow captures fresh
> pictures from prod, generates PDF/HTML/DOCX bundles, and attaches them
> to the release.

---

## 0 · Preflight (30 seconds)

Confirm the GH Actions workflow secrets are configured. Repo → **Settings**
→ **Secrets and variables** → **Actions** → **Repository secrets**:

| Secret | Value |
| --- | --- |
| `NIVXRAY_BASE_URL` | `https://nivxray.nivxforge.com` (your prod host) |
| `NIVXRAY_ADMIN_EMAIL` | your admin email (deploy-specific, do NOT commit) |
| `NIVXRAY_ADMIN_PASSWORD` | your admin password (deploy-specific, do NOT commit) |

> ⚠️ **Never commit admin credentials to this file or any repo file.**
> Generate a fresh strong password per deployment (`python -c 'import
> secrets; print(secrets.token_urlsafe(18))'`) and store it ONLY in the
> Actions Secret store above. The seeded admin is created with
> `must_change_password=true` when `ADMIN_FORCE_PASSWORD_CHANGE=true` is
> set in the backend `.env`, so the first login is forced to rotate the
> password before any other API call succeeds.

Optional (only needed if the workflow reads prod Mongo):

| Secret | Value |
| --- | --- |
| `NIVXRAY_MONGO_URL` | (skip — exports don't need DB access) |
| `NIVXRAY_DB_NAME` | (skip) |

If any are missing, the workflow will still run but the "Preflight" step
will show HTTP 401 and screenshots may be blank.

---

## 1 · Cut a Test Release on GitHub (2 min)

1. Push the latest preview commits from Emergent → GitHub via the
   **Save to GitHub** button in the Emergent chat input.
2. In GitHub, go to **Releases** → **Draft a new release**.
3. Choose a tag, e.g. `docs-2026-02-16` (creating a new tag on the fly is
   fine — pick the branch that has the pair-figure fix).
4. Title: `Docs refresh — GRAPH + CHAIN pair figure`.
5. Body (optional):
   ```
   - PDF: side-by-side GRAPH + CHAIN figure per payload (P2 done)
   - Triggers docs-screenshots workflow to attach fresh PDFs/HTML/DOCX
   ```
6. Click **Publish release**.

This fires the `release: [published]` trigger on
`.github/workflows/docs-screenshots.yml`.

---

## 2 · Watch the workflow (5–10 min)

1. Repo → **Actions** tab → **Docs Screenshots** → the run kicked off by
   your release.
2. Green steps you should see, in order:
   - `Preflight — verify backend is reachable` → `HTTP 200`
   - `Capture screenshots` → walks every YAML with a `capture:` block
   - `List captured artefacts` → dozens of `.png` lines
   - `Generate guide exports` → prints file sizes for 12 artefacts
   - `Upload guide exports as workflow artifact`
   - `Attach guide exports to the GitHub Release` → **only runs on release trigger**
3. On the release page (**Releases** → your new tag), the "Assets" list
   should now include:
   ```
   nivxray-user-guide.pdf         ~6.8 MB
   nivxray-user-guide.html
   nivxray-user-guide.docx
   nivxray-admin-guide.pdf
   nivxray-admin-guide.html
   nivxray-admin-guide.docx
   nivxray-developer-guide.pdf
   nivxray-developer-guide.html
   nivxray-developer-guide.docx
   nivxray-all-guide.pdf          ~6.8 MB
   nivxray-all-guide.html
   nivxray-all-guide.docx
   ```
4. Download `nivxray-all-guide.pdf` from the release and confirm:
   - Cover page renders
   - 5W1H flow diagram + pipeline + attack-graph anatomy pages present
   - **NEW**: on payload pages, the "GRAPH + CHAIN — visual evidence" 
     figure appears with two panels side-by-side.

---

## 3 · Redeploy to Prod (1 min)

1. In Emergent chat, click **Deploy** at the top-right of the platform.
2. Pick **Production** target.
3. Confirm.
4. Wait for the green ✓ (typically 60–90s).
5. Visit `https://nivxray.nivxforge.com/docs` — sign in with admin,
   click any payload page, download the PDF from the analyst-facing
   button. Same "GRAPH + CHAIN" figure must appear.

---

## 4 · Rollback (only if something goes wrong)

- **Bad release** → GitHub → Releases → your tag → **Delete release**.
  The workflow doesn't self-clean; you may want to also delete the
  auto-committed screenshot refresh commit if the pictures look wrong.
- **Bad prod deploy** → Emergent chat → **Rollback** (free). Point back
  to the previous checkpoint; no code needs to change.

---

## Dry-run already done (Feb 2026)

The main agent regenerated all 12 artefacts locally against preview
before this checklist was written:

```
docs/exports/nivxray-user-guide.pdf         6.8 MB
docs/exports/nivxray-admin-guide.pdf        4.7 MB
docs/exports/nivxray-developer-guide.pdf    4.7 MB
docs/exports/nivxray-all-guide.pdf          6.8 MB
+ 8 HTML/DOCX siblings
```

All 104 docs tests + 18 PDF tests are green on the branch you're about
to release.
