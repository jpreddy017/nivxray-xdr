# Stabilization Round · KB + Intelligence Wiring + Regression
Date: 2026-06 · Scope: owner directive "CONTINUE AND FIX EVERYTHING LISTED"

## 1 · Production promotion — STILL BLOCKED (credential)
No Vercel credential in the pod env, any `.env`, `/app/.emergent` or
`/run/secrets`. `npx` present, no `vercel` CLI, no `.vercel` link, `git remote -v`
empty. `api.vercel.com` reachable (403 unauthenticated). Nothing deployed.
Required: `VERCEL_TOKEN` (+ `VERCEL_TEAM_ID`) in `/app/backend/.env`
(gitignored `*.env`, untracked → never reaches GitHub or a bundle).
Fix needed in the dashboard OR by me with a token:
`nivxray-xdr-production` Root Directory → `apps/nivxray-xdr`;
`NIVX_PRODUCT_SCOPE=xdr`; `XDR_PROD_API_ORIGIN=https://nivxray.nivxforge.com`.
Rollback target retained: `index-LG3aU4C2.js` / `XdrShell-D5KuqOEH.js` (18,794 B).

## 2 · Knowledge Base false-empty — FIXED
Root cause: two response-contract mismatches in `XdrKbPage.jsx`, not tenancy.
`/api/kb/entries` returns `{total, items, limit, skip}`; the page read
`data.entries` then fell back to the raw object, which is not an array →
`setEntries([])`. Stats read `total_entries`/`distinct_tags`/`last_update`;
the service emits `total`/`by_severity`/`by_verdict`/`top_mitre`. Rows read
`tags`/`updated_at`; items carry `mitre_ids`/`last_seen`.
Before → after (live): `TOTAL ENTRIES 0` + "NO ENTRIES — the KB is empty or
unreachable" → **334**, `MALICIOUS VERDICTS 135`, `TOP ATT&CK T1059.001 · 186`,
**100 rows**, and an honest page-cap line: "100 of 100 loaded · 334 total in the
KB (the service caps a page at 100)". Empty state now names the endpoint.
Also fixed a real precedence bug introduced mid-edit: `.toLowerCase()` bound to
only the last template literal in the search filter.

## 3 · Intelligence wiring — FIXED (4 surfaces, real APIs, zero seeded data)
Replaced `XdrReservedPage` (which rendered hardcoded `0`s under "No
intelligence sources are configured for this tenant").
| Surface | APIs | Live result |
|---|---|---|
| `/xdr/intelligence/threat` | `/threat-intel/stats`, `/sources`, `/feeds/status`, `/iocs` | **105,052** indicators · **9 of 11** configured · **3** reporting errors (`HTTP 429/403/401 from source` surfaced verbatim) · by-type 58,279 ip · 31,835 url · 3,231 domain · 2,170 sha256 · 1,082 md5 · 748 sha1 · 11 source rows · 100 indicator rows |
| `/xdr/intelligence/iocs` | `/ioc/health`, `POST /ioc/enrich/one` | **7 of 7** providers LIVE with governing env var and detail; accepts `?q=`/`?incident_id=` from the incident IOC pointer and pre-fills (verified `8.8.8.8`) |
| `/xdr/intelligence/command` | `POST /analyze/command` | renders; supports the service's `needs_choice` → `force_decode_span` resubmit path |
| `/xdr/intelligence/malware` | `GET /documents` | **38 shown · 38 total**, read-only; submission absence stated with the reason (chunked-upload/object-storage decision) |
Rail rows `ti/ioc/command/malware` un-disabled. Pivot rows for
hash/ip/domain/url/process/file/artifact now navigate to these real routes,
carrying value + kind. Provenance rule kept: enrichment output with no provider
attribution renders `PROVENANCE MISSING`, never a verdict. No metric is a
literal; a metric with no API renders `—`, never `0`.

## 4 · Regression — PASS
24 routes across all 8 primaries: origin stays on the XDR host, `xdr-main`
mounted, Ribbon present, **1** browser tab throughout, `/xdr` → Control Center,
direct refresh on `/xdr/intelligence/threat` survives. Four admin routes first
reported `shell=False` — that was a **Cloudflare bot challenge** after ~19 rapid
navigations (challenge page captured); re-checked slowly, all four PASS with
`cloudflare_challenge=False`.
Gates: nav integrity **1916 PASS** · branding **51 PASS** · production build +
guard **PASS**. Backend `rc5/api` + `canonical/incidents` + auth hardening:
**37 passed / 1 skipped / 1 failed / 69 errors** — the 1 failure
(`test_row_projection_shape`) and the 69 errors are pre-existing and were left
alone per instruction.
Guard refinement: the forbidden-literal scan now strips the first argument of
`api.*()` calls, because `api.get("/documents")` is an API path, not navigation.
Comment/docstring stripping added earlier for the same reason.

## 5 · Cisco visual work — not started (correctly last)

## Left unchanged deliberately
`scripts/refuse-root-deployment.sh`, root `vercel.json`, the 69 RC5 fixture
errors, `test_row_projection_shape`, the 147 pre-existing
`test_capability_registry_matches_base.mjs` failures, NivXForge EDR,
NivXMachines, Workspace NivXMachines, production/tenant data, DNS, auth
architecture, PR #1.

## Known cosmetic item (not a defect)
The Ribbon overlays the bottom of page content, as Cisco's ribbon does. If you
want content to reflow above it instead, that is a one-line layout change.

## Residual honest gaps (data, not code)
`/api/documents` items carry no verdict → Malware "Verdict" column is `—` for
all 38. `/api/incidents` carries no `priority_score` → Ribbon shows `NOT SCORED`
rather than inventing a band. `/api/ioc/health` has no cache field → `—`.
