# P0 — API key created but not visible in the list (2026-06)

## Root cause — my defect, and it is a tenant-context leak, NOT a persistence failure

Every handler in `backend/routers/xdr_api_keys.py` resolves its tenant through
`_principal(request)` (lines 54-61), which reads **`X-Tenant-Id`** and falls
back to **`"default"`**:

```python
ten = (req.headers.get("X-Tenant-Id")
       or getattr(req.state, "tenant_id", None) or "default")
```

- `POST ""`          → binds `tenant_id = ten`
- `GET ""`           → `q = {"tenant_id": ten}`      (line 202)
- `GET/{id}`, `rotate`, `revoke`, `delete` → `find_one({"id": …, "tenant_id": ten})`

My earlier change added `X-Tenant-Id` to the **create call only**. The list,
rotate, revoke and delete calls sent no header, so they resolved to
`"default"`. The key was therefore written under `nivx-prod-1` and the list
queried `default` → `PROVISIONED 0`.

**The key WAS durably persisted.** `_coll().insert_one(...)` is line **179**,
the plaintext is returned at lines **186-191** — insert strictly precedes the
reveal, and a failed insert raises before any reveal. So the acceptance
invariant "never reveal a plaintext if persistence failed" was already
satisfied and needed no change. `allow_new_tenant=true` bound `nivx-prod-1`
correctly. Nothing was lost or hidden by RBAC.

## Files changed — 1
`apps/nivxray-xdr/src/xdr/admin/ApiKeysBody.jsx` only.
No backend change. No auth/RBAC change. No schema change. No other product.

## Old → new behaviour
| | Old | New |
|---|---|---|
| list / rotate / revoke / delete | no `X-Tenant-Id` → tenant `default` | send `X-Tenant-Id: <tenant>` |
| tenant on the surface | implicit `default`, invisible | explicit `TENANT` field (`xdr-api-key-tenant-context`), reloads on change |
| after create | list queried the wrong tenant → 0 rows | surface follows `res.data.tenant_id`, so the new key appears immediately |
| create modal | tenant typed from scratch | pre-filled from the surface tenant; **confirm field still required** |
| empty state | "FOR THIS TENANT" | "FOR TENANT '<tenant>'" — names which tenant is empty |

Preserved unchanged: one-time reveal, rotate, revoke, delete, hero stats,
double tenant confirmation, `allow_new_tenant`, styles.

## Targeted tests — all pass

### API contract (preview, throwaway tenant, cleaned up)
```
POST  → id key_f1fc…  tenant_id defect-repro-24134
        scopes ['collectors.enroll','collectors.read']
        expires 2026-10-10T23:59:59Z   plaintext returned: True
GET without X-Tenant-Id → count = 0     ← the defect, reproduced exactly
GET with    X-Tenant-Id → count = 1, correct scopes + expiry
POST /revoke with header → {"ok":true,"revoked":true} → enabled=False
DELETE with header → 200 (cleanup)
```

### Real browser, fixed UI (preview, throwaway tenant `acceptance-ui-7781`)
```
tenant context input present ....... 1
empty state for the new tenant ..... 1
modal tenant PREFILLED ............. 'acceptance-ui-7781'
mismatched confirm → warning 1, submit disabled True
matching confirm  → submit enabled True
one-time reveal modal .............. 1  (plaintext len 52, shown once)
after "I've stored the key" + Refresh:
  rows container 1 · empty state 0
  PROVISIONED 1 · ACTIVE 1 · REVOKED 0
  row shows name, prefix, collectors.enroll + collectors.read,
  ACTIVE, expiry 2026-10-10
```
Throwaway key deleted afterwards; tenant left at 0 keys.

## Exposed-key disposition
The agent has **no production credential** and cannot revoke it server-side.
The plaintext was never requested, received or stored here — and must not be.

Per the metadata the owner reported, the record exists in production as
tenant **`nivx-prod-1`**, name **`nivx-prod-1`**, scopes
`collectors.enroll collectors.read`, expiry `2026-10-10T23:59:59Z`.
**Once this fix is live**: API Keys page → set `TENANT` to `nivx-prod-1` → the
key appears → click **Revoke** (the ✷ Ban icon) on that row only. Revocation is
checked on every request (`revoked_at`), so it stops verifying immediately.
Do not delete any other row.

## Production rollout — one file again
| | Value |
|---|---|
| Branch | `conflict_310826_2116` |
| Current remote hash (verified now) | `509e04e5c9afa6c5789b5040e9589226fb9f9b5ecf2d2777e7dc86c98e912b6b` |
| Patch | `memory/xdr_frontend_patch/ApiKeysBody.tenant-context.patch` — `patch -p1` **DRY RUN CLEAN** against the actual remote file |
| Replacement file | `memory/xdr_frontend_patch/ApiKeysBody.jsx.final2` |
| **Expected new hash** | **`cdef74d1764fb731f19a793657742f086f74b404390fe6eae7efcf3380d132c3`** |
| Size / lines | 21,329 bytes · 474 lines |
| Files changed | **1** |
| Rollback | revert the single commit; or promote the previous Vercel deployment |

## Safe to proceed with collector enrolment?
**Not yet.** Two things first, in order:
1. Commit this one-file fix and let Vercel rebuild XDR.
2. Revoke the exposed `nivx-prod-1` key, then mint ONE fresh replacement and
   confirm it appears immediately in the list with the right tenant, scopes and
   expiry.

Then enrolment is safe. No fake data in production at any point.
