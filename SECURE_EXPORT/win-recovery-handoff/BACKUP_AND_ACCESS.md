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

**Option B — `mongodump` (preferred: hashable, restore-tested)**

```bash
MONGO_URL='<paste from Manage Publishes → Database>'
DB=greeting-app-5782-test_database

mongodump --uri="$MONGO_URL" --db="$DB" --gzip \
  --archive=edr-predelete-$(date +%Y%m%d).archive.gz
```

**Note: `mongodump` has no `--nsInclude`** — that option belongs to
`mongorestore`. An earlier draft of this document used it and the command
failed with `unknown option 'nsInclude'`; it was fixed by running it, not by
reading about it. The dump is therefore whole-database, which is the stronger
backup anyway: every collection this cleanup touches, plus everything it does
not.

**Verify it before trusting it** — an unverified dump is not a backup:

```bash
ls -l  edr-predelete-*.archive.gz
sha256sum edr-predelete-*.archive.gz
mongorestore --uri="$MONGO_URL" --gzip --archive=edr-predelete-*.archive.gz \
  --dryRun --nsInclude="$DB.*"
```

The dry run must end with `dry run completed`. `mongodump` also prints
`done dumping <ns> (N documents)` per collection — check `edr_raw_events` reads
**1,877,149** and `edr_processing_queue` **1,718,750** against the inventory
before you rely on the file.

Rehearsed end to end against a database with the same schema: 361,757 raw
events dumped to a 235 MB gzip archive, sha256 computed, `mongorestore
--dryRun` reported `dry run completed` with 0 failures. Expect roughly
**1.5-3 GB** for production's 1.88M raw events plus the 1.7M queue.

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

Here `--nsInclude` *is* valid, and it keeps the restore to the collections the
cleanup touched. No `--drop`: the documents were deleted, so they restore into
the existing collections and the indexes stay as they are. Platform **rollback
reverts code and container only — never database state**, so this archive is
the only rollback that exists. For a cluster-level problem the route is
`support@emergent.sh`; they perform any managed restore, not you.

## 2a · One command for all of it

`edr_backup_and_dryrun.sh` in this package does steps 1-5 in order: ping, dump,
size + sha256, `mongorestore --dryRun`, the per-collection counts, then the
reset script in its default dry-run mode. It contains no delete and never arms
anything.

```bash
MONGO_URL='<paste>' ./edr_backup_and_dryrun.sh
```

It stops with a distinct message if the connection fails, so a network block is
never mistaken for a credential problem.

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

This pod already has `mongodump`, `mongorestore` and `mongosh` installed and
64 GB free, and the whole sequence is rehearsed. **The only thing missing is
the connection string:** the deployment tooling never returns secret values,
and `MONGO_URL` is not present anywhere in this pod — only the local preview
database is. So either:

**Route A — you paste `MONGO_URL` to me.** I run `edr_backup_and_dryrun.sh`,
publish the archive at `/api/transfer/edr-predelete?token=…`, and hold until
you confirm you have downloaded it. The string is a credential, it will appear
in the chat, and it rotates on the next deploy regardless.

**Route B — you run it.** Four commands on your own machine:

```bash
MONGO_URL='<paste from Manage Publishes → Database>'
DB=greeting-app-5782-test_database

mongodump --uri="$MONGO_URL" --db="$DB" --gzip --archive=edr-predelete.archive.gz
sha256sum edr-predelete.archive.gz && ls -l edr-predelete.archive.gz
mongorestore --uri="$MONGO_URL" --gzip --archive=edr-predelete.archive.gz \
  --dryRun --nsInclude="$DB.*"
mongosh "$MONGO_URL" --file edr_dev_reset.mongosh.js
```

Send me: the sha256 and size, the `dry run completed` line, the
`done dumping` counts for `edr_raw_events` and `edr_processing_queue`, and the
full dry-run output. I reconcile it against 4,224,353 and return GO/NO-GO.

Nothing in either route deletes, purges, enrols or restarts anything. The last
command is dry by default — it prints the plan and exits without writing.

## 6 · Connection attempt from this pod · BLOCKED by the Atlas allowlist

Attempted 2026-10-20 with the connection string from Manage Publishes →
Database. Exact failure:

```
MongoServerSelectionError: Server selection timed out after 30000 ms.
It looks like this is a MongoDB Atlas cluster. Please ensure that your
Network Access List allows connections from your IP.
```

Diagnosed rather than guessed:

* **DNS/SRV resolves correctly** — `_mongodb._tcp.customer-apps.1fntml.mongodb.net`
  returns all three shard hosts on 27017. So this is not DNS and not a
  malformed URI.
* **TCP 27017 times out** to `customer-apps-shard-00-00` and `-00-01`
  (`TimeoutError: timed out`), which is a silently dropped packet — the
  signature of an IP allowlist, not of a refused connection or bad credentials.
* **This pod's egress IP is `35.193.209.116`.** It is not on the cluster's
  Network Access List.
* The credentials were never transmitted, because no server was ever reached,
  so nothing about their validity was tested either way.

Two ways forward: run the four commands from your own machine (section 5,
Route B), or have Emergent support add `35.193.209.116` to the Network Access
List and I run it here. The preview pod is a different network from the
deployed app, which is why the app itself connects fine while this pod cannot.

**Secret hygiene:** the string was written to a `0600` file, used once, and
securely deleted. One further exposure was found and removed: the Linux dev
sensor's local `outbox.jsonl` had captured the `mongosh` command line verbatim,
including the password, via process telemetry. That line is scrubbed
(`grep -c` now returns 0). Treat the string as exposed in chat regardless and
rotate it — it is regenerated on the next deploy in any case.
