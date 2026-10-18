# EDR access loop · publication package

Two candidates, both on the **published** baseline
`publish/n3a-telemetry-bson` @ `d065fd674eca239c6a62af8322bb394d3bc45a53`
(the branch GitHub already has and Vercel builds). **PR #16 is not touched.**

| | candidate | commit | tree | files |
|---|---|---|---|---|
| **A — recommended** | `publish/edr-access-loop-frontend` | `f70a3814f218e51591be5411bab536f6ef9f5e82` | `bc685e92c7ba4e23b91bd50770205d06bdb31e7c` | 3 (console only) |
| B — full | `publish/edr-access-loop` | `05e8a41386476350b508b2cc6558e9b209adcf4f` | `65a4da24d4d25d339e0074facd04acbb698122e8` | 4 (adds the backend test) |

Local review candidate both derive from:
`eac0192b6f81be84165b55d302b0ac201d5762ef` on `engineering/edr-access-loop`
(tree `4a484f2077838f197b6eecc1adf9695fd38d7ec9`).

**Why A is recommended, in one line:** B's backend test pins
`403 TENANT_REQUIRED` for an unnamed customer, and this baseline does not
produce that code unless `NIVX_TENANT_REGISTRY_ENFORCE` is on — so B ships a
test that fails on its own base. See §4.

## Files

```
A (3)   M apps/nivxray-xdr/src/lib/secureRequests.js                   +51 / -7
        M apps/nivxray-xdr/src/xdr/access/AccessProvider.jsx            +9 / -2
        A apps/nivxray-xdr/src/lib/__tests__/edrAccessLoop.test.jsx   +192 / -0
                                                       3 files, +249 / -4

B (4)   = the above, plus
        A backend/tests/test_edr_tenant_required_is_not_permission_denial.py
                                                       4 files, +364 / -4
```

No other path is touched. No `.env`, no binary, no generated file, no
dependency change, no production configuration.

## Refusal classification — exactly two codes

`secureRequests.js`:

```js
const TENANT_SELECTION_CODES = new Set(["TENANT_REQUIRED", "TENANT_NOT_RESOLVED"]);
```

* **Selection conditions** (no latch, no abort, request still rejects to its
  caller): `TENANT_REQUIRED`, `TENANT_NOT_RESOLVED` — and only these.
* **Still a page denial, fail closed**: `ACCESS_DENIED`,
  `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`, `TENANT_NOT_FOUND`,
  `TENANT_NOT_ACTIVE`, any other code, a string `detail`, and a 403 with no
  structured body at all. The classifier reads `detail.code` only; prose is
  never parsed.
* **401 unchanged**: token and email cleared, tenant authority sealed,
  `invalidateSecurity("expired")`.

Tests assert each of those branches by name.

## Verification

```bash
sha256sum -c SHA256SUMS
git bundle verify edr-access-loop-console.bundle     # requires d065fd67…

git clone https://github.com/jpreddy017/nivxray-xdr.git && cd nivxray-xdr
git fetch ../edr-access-loop-console.bundle \
  'refs/heads/publish/edr-access-loop-frontend:refs/heads/publish/edr-access-loop-frontend'
git switch publish/edr-access-loop-frontend
git rev-parse HEAD^{tree}        # bc685e92c7ba4e23b91bd50770205d06bdb31e7c
git diff --stat d065fd67..HEAD   # 3 files changed, 249 insertions(+), 4 deletions(-)

cd apps/nivxray-xdr && yarn install && yarn test
# observed on this baseline: 11 files, 138 passed
# targeted: edrAccessLoop 14 · securityState 13 · RouteSafety 13 · Rc1CrossFeature 5 = 45 passed
```

Both candidates' trees were reproduced independently from the patches alone
(`read-tree` + `apply --cached` + `write-tree`) and matched.

## Files in this package

| file | purpose |
|---|---|
| `edr-access-loop-console.bundle` | candidate A, thin bundle (prerequisite `d065fd67`) |
| `edr-access-loop-full.bundle` | candidate B, thin bundle |
| `0001-EDR-access-loop-console-….patch` | candidate A as a `git am` patch |
| `console-3-files.patch` | candidate A net diff (review) |
| `full-4-files.patch` | candidate B net diff (review) |
| `MANIFEST.txt` | SHAs, per-file hashes, test and gate results |
| `SHA256SUMS` | checksums of every file above |
