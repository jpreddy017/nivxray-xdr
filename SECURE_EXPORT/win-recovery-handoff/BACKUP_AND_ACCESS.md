# DATABASE ACCESS AND BACKUP · what is actually available

Answering the question you asked before giving me a backup reference: **there
is no Atlas snapshot id for you to give.** The hosting was checked rather than
assumed, and D5 changes shape as a result.

## 1 · Where the production database lives

The production MongoDB for an Emergent-deployed app **is MongoDB Atlas — but
the Atlas project and cluster are owned and managed by Emergent, not by you.**
By default it is a shared managed cluster. You therefore have **no Atlas
console, no Backup tab and no snapshot id**, which is exactly why the earlier
plan's "paste the Atlas snapshot id" step could never have been satisfied. I
was wrong to keep asking for it.

Two independent checks agree on the consequence, and differ usefully on detail:

* **Platform documentation:** Atlas, Emergent-managed, shared by default;
  upgradeable to dedicated or migratable to your own Atlas project.
* **Deployment tooling (read-only, this deployment):** `MONGO_URL` is bound and
  non-empty and is a **platform-managed system key that is regenerated on every
  deploy**; its value is never returned to tooling, so the scheme and host
  suffix are **unverified from that side** rather than confirmed. It also
  reports **no backup, snapshot, restore or PITR facility** of any kind, and no
  visibility of shared-versus-dedicated topology.

Practical consequence of the regeneration: **copy `MONGO_URL` fresh when you
start, and re-copy it if any deploy happens while this work is in flight.**

What you *do* get is the connection string and a database manager:

* **Manage Publishes → Database tab** — the production `MONGO_URL`
* **Manage Publishes → Database → "Go to database"** — the Database Manager at
  `mongoview.emergent.host`

You can upgrade to a dedicated database, or migrate to your own Atlas cluster,
if you later want real snapshots under your control.

## 2 · The supported backup mechanism · THIS REPLACES D5's SNAPSHOT

There is **no automated snapshot, no point-in-time restore and no restore
button**. The supported, verifiable backup is a dump you take and keep:

**Option A — Database Manager (no tooling needed)**
`Manage Publishes → Database → Go to database` → **"Dump DB"** for the whole
database, or **"Export all"** per collection. Download links are valid for
**4 days**, so download immediately and keep the file somewhere durable.

**Option B — `mongodump` (preferred: scoped, hashable, restorable)**

```bash
MONGO_URL='<paste from Manage Publishes → Database>'
DB=greeting-app-5782-test_database

mongodump --uri="$MONGO_URL" --gzip \
  --archive=edr-predelete-$(date +%Y%m%d).archive.gz \
  --nsInclude="$DB.edr_*" \
  --nsInclude="$DB.xdr_canonical_evidence" \
  --nsInclude="$DB.v2_shadow_observations"
```

That covers every collection this cleanup touches, including the retained
configuration and audit, and excludes the rest of the database.

**Verify it before trusting it** — an unverified dump is not a backup:

```bash
ls -l edr-predelete-*.archive.gz
sha256sum edr-predelete-*.archive.gz
mongorestore --archive=edr-predelete-*.archive.gz --gzip --dryRun -v | tail -20
```

`mongodump` prints `done dumping <ns> (N documents)` per collection — check
`edr_raw_events` reads **1,877,149** and `edr_processing_queue` **1,718,750**
against the inventory before you rely on the file.

Then record the filename and hash in the script:

```js
const BACKUP = "edr-predelete-20261020.archive.gz sha256:<hash>";
```

The script refuses to arm while `BACKUP` is empty. The field used to want an
Atlas snapshot id; it now wants this, because this is the thing that actually
exists.

**Restore path, if it is ever needed:**

```bash
mongorestore --uri="$MONGO_URL" --gzip \
  --archive=edr-predelete-20261020.archive.gz \
  --nsInclude="$DB.edr_*" \
  --nsInclude="$DB.xdr_canonical_evidence" \
  --nsInclude="$DB.v2_shadow_observations"
```

No `--drop`: the documents were deleted, so they restore into the existing
collections and the indexes stay as they are. Platform **rollback reverts code
and container only — never database state**, so this archive is the only
rollback that exists. For a cluster-level problem the route is
`support@emergent.sh`; they perform any managed restore, not you.

## 3 · How to run the read-only dry run

Two supported routes.

**Route 1 — external `mongosh` (the one to use: it runs the real script)**

```bash
MONGO_URL='<paste from Manage Publishes → Database>'
mongosh "$MONGO_URL" --file edr_dev_reset.mongosh.js        # dry by default
mongosh "$MONGO_URL" --file edr_d4_impact_report.mongosh.js # read-only report
```

Both files already target `greeting-app-5782-test_database` and tenant
`ten_e759b7288598bd882e3dcac49d` by name, so no editing is needed to run them
read-only. If the connection is refused rather than rejected, that is the Atlas
IP allowlist: Emergent's egress ranges are listed at
`https://app.emergent.sh/ip-addresses`, and adding your own address is a
support request.

**Route 2 — Database Manager** (`mongoview.emergent.host`) browses and queries
collections, which is enough to spot-check a count, but it does not run a
multi-step script. **Note its edit mode applies changes immediately with no
undo** — do not use it for the cleanup itself.

## 4 · Bulk deletes at this scale

The platform publishes no documented limit or guidance for million-document
deletes, so the script does not depend on one: sweeps above 200,000 documents
run in committed 50,000-row chunks with progress printed, and a re-run resumes
where it stopped. Expect the 1.88M raw-event sweep to take several minutes on a
shared cluster. If your session drops mid-sweep, nothing is corrupted — re-run
the armed script and it continues.

## 5 · Exact steps needed from you

1. `Manage Publishes → Database` → copy the production `MONGO_URL`.
2. Take the dump (Option B above), then verify size, sha256, `--dryRun` and the
   per-collection document counts.
3. Send me the archive filename + sha256, and the `done dumping` lines for
   `edr_raw_events` and `edr_processing_queue`.
4. Run `mongosh "$MONGO_URL" --file edr_dev_reset.mongosh.js` and send me the
   dry-run output. It writes nothing.
5. I confirm the dry run matches the approved scope, hand you the armed file,
   and we proceed through purge → reset → enrolment → telemetry acceptance.

Nothing in steps 1-4 deletes, purges, enrols or restarts anything.
