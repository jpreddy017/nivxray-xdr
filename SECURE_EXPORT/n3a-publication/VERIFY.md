# S1 publication package — apply and verify

Contents of this package, and nothing else:

| file | purpose |
|---|---|
| `n3a-s1.bundle` | git bundle: the 3 commits with full git provenance (preferred route) |
| `0001-…patch` `0002-…patch` `0003-…patch` | the same 3 commits as `git am`-able patches (fallback route) |
| `s1-combined-8-files.patch` | the net 8-file diff, for review only |
| `MANIFEST.txt` | base/candidate/tree SHAs, per-file git-blob and sha256 hashes |
| `SECURITY-SCAN.txt` | what was scanned for and what was found |
| `SHA256SUMS` | checksums of every file above |

**Target:** `jpreddy017/nivxray-xdr`
**Base:** `engineering/stage1-staging-package` @ `ce8732ba9c7d0deb1d02825855bfe644550be07b`
**Result must be:** commit `d065fd674eca239c6a62af8322bb394d3bc45a53`, tree
`5cef61aa71dc36ebb7398810c6432cc60dc5daab`

---

## 0 · Check the package itself

```bash
sha256sum -c SHA256SUMS
git bundle verify n3a-s1.bundle     # expect: "okay" + requires ce8732ba…
```

## 1 · Apply — bundle route (preferred, preserves provenance)

```bash
git clone https://github.com/jpreddy017/nivxray-xdr.git && cd nivxray-xdr
git fetch ../n3a-s1.bundle 'refs/heads/publish/n3a-telemetry-bson:refs/heads/publish/n3a-telemetry-bson'
git switch publish/n3a-telemetry-bson
```

The bundle is **thin**: it names `ce8732ba…` as a prerequisite and carries only
3 commits, 5 trees and 8 blobs. If the clone does not contain the base commit,
the fetch refuses rather than inventing history.

## 2 · Apply — patch route (fallback)

```bash
git switch -c publish/n3a-telemetry-bson ce8732ba9c7d0deb1d02825855bfe644550be07b
git am 0001-*.patch 0002-*.patch 0003-*.patch
```

Author, date and the `(cherry picked from commit …)` provenance line of each
original validated commit are preserved. The committer identity — and therefore
the commit SHAs — will differ from §1 if you re-apply as yourself; **the tree
SHA will not**, which is the identity that matters (§3).

## 3 · Verify the result

```bash
git rev-parse HEAD              # 1: d065fd674eca239c6a62af8322bb394d3bc45a53
git rev-parse HEAD^{tree}       # must be 5cef61aa71dc36ebb7398810c6432cc60dc5daab
git diff --stat ce8732ba..HEAD  # must be: 8 files changed, 762 insertions(+), 16 deletions(-)
git diff --name-only ce8732ba..HEAD   # must match MANIFEST.txt exactly
```

Per-file hashes:

```bash
while read -r st path blob sha256 bytes; do
  [ -f "$path" ] && echo "$sha256  $path"
done < <(awk '/^  [MA] /{print $1,$2,$3,$4,$5}' MANIFEST.txt) | sha256sum -c -
```

**Stop if the tree SHA differs.** A different tree means the base moved or the
patch was altered; nothing in this package should be reconciled by hand.

## 4 · Run the tests

The 14 N-3A regression tests need a database and process-local secrets. The
harness in this package supplies both — it generates every secret per run with
`secrets.token_urlsafe(48)` and starts a disposable `mongod`, so nothing is
pre-authorised and no value from this repository is trusted.

```bash
# requires: python3.11, mongod on PATH, backend requirements installed
python3 tools/security-harness/run.py --suite tests/test_n3a_telemetry_bson_serialization.py
# expect: 14 passed
```

Observed on this exact candidate: **14 passed in 11.63s**.

What the tests hold the code to: a stored nested `ObjectId`, a `Decimal128`
and a non-UTF-8 `Binary` each used to turn `GET /api/telemetry/frontend/recent`
into an unauthenticated HTTP 500; each now returns valid JSON whose value is the
documented conversion. Field names, key order, `limit`, ordering and the
response envelope are asserted unchanged, and one test asserts the helper
**raises** rather than silently dropping a value it cannot convert.

## 5 · Open the pull request

Base `engineering/stage1-staging-package`, compare `publish/n3a-telemetry-bson`.

Two statements the PR body should carry, because they are true and easy to
overstate:

* The **mandatory 126-test security gate cannot be claimed on this branch** —
  `tools/rocket-validation/run.py` is not published in this repository. That
  gate result (126 tests, 0 failures, 0 errors, 1 pre-existing skip) is local
  evidence for the validated commit `38e294c6` only, not upstream CI coverage.
* `GET /api/telemetry/frontend/recent` **remains unauthenticated**. This change
  removes a crash, not an open surface; the authentication question is tracked
  separately as N-2 and is deliberately out of scope here.

## 6 · What this package deliberately does not contain

F1 (legacy `v2` namespace retirement), N-1 (audit provenance), N-5 (tenant
authority fixtures) and the CI gate wiring are **not** included. N-3A does not
depend on them: it applies cleanly onto a tree that still contains
`backend/v2/`. They remain validated locally, awaiting a separate decision.

`deploy/stage1-staging/` — the frozen staging package — is untouched.
No merge, deploy, re-pin or production change is implied by applying this.

**RELEASE STATUS: NO-GO.** Publishing a reviewed fix does not lift a HOLD.
