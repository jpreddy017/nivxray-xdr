# File Trajectory · preview closure of the four owner checks

Tested commit: **`3db78b9a`** (from `e44fc0f4`) · production promotion remains on hold.
Clickable: `https://greeting-app-5782.preview.emergentagent.com/edr/files?sha256=17a623f303e2489770e64a9eab9420c66e576ec5ad215ea7c46ec392a2212f49&path=/var/tmp`
(select customer *Preview Runtime (legacy default)* = tenant `default` first).

Screenshots in this directory:
`file-trajectory-vartmp-filter-3db78b9a.jpeg` · `file-trajectory-creation-selected-3db78b9a.jpeg` · `file-trajectory-device-pivot-gap-3db78b9a.jpeg`

---

## 1 · Path filtering across the full history — fixed

The filter ran in the browser over the rows one capped read returned. The 12
`/var/tmp` creations of `17a623f3…` are older than its newest 300 executions, so
filtering for `/var/tmp` matched nothing while File details listed those exact
paths — it read as "never created there".

Now a server re-read (`?path_contains=`, carried in the page URL as `?path=`),
applied across every authorized sighting **before** the per-endpoint limit.

| check | result |
|---|---|
| `/var/tmp` on `17a623f3…` | **24 of 809** sightings match — 12 `File created` + 12 `Process observed` |
| displayed vs matched | all 24 returned and drawn; header reads `SIGHTINGS 24 of 809` |
| stated on screen | "24 of 809 sightings have a path containing “/var/tmp” — matched across every sighting in this customer, not only the newest ones" |
| older creation reachable | oldest creation `2026-09-08 00:35:30Z`, `raw_98b8aec512212938f62fd84a`, far outside the newest 300 — selectable and openable |
| filtered zero | states the whole history was matched, so it is a real zero for that path |
| every path still listed | File details shows all 14 paths under a filter, because that is where an analyst learns the `/var/tmp` copies exist |

## 2 · What each digest identifies — traced to the sensor

`agents/nivxforge-linux/nivxforge_sensor.py`:

- `collect_files` (L457-513) walks the watched directory; a path absent from the
  previous poll is `CREATE`, and `sha256: _sha256_file(p)` hashes **that same
  path** (L488 → L211). So a `FILE/CREATE` digest **is** the file created at the
  displayed path, read at observation time. The WRITER is never attributed
  (`not_observed: ["actor_process"]`), and creation outside `--watch` is unseen.
- `collect_processes` (L225-296) reads `/proc/<pid>/exe` and hashes that link
  target (L285), so a `PROCESS_OBSERVED` digest is the executed image at
  `image_path`. One row per `(pid, start_ticks)` the poll actually saw —
  processes that start and exit inside an interval are never observed.

Labelling follows the trace: polling records read **"Process observed"**, counts
are described as observations and never as launches, and every sighting now
carries a **Path source** row naming the field and what the digest is of.

### Reconciling 14 recorded paths with the counts

| event type | sightings | path field | distinct paths |
|---|---|---|---|
| `PROCESS/PROCESS_OBSERVED` | 797 | `image_path` | 14 |
| `FILE/CREATE` | 12 | `path` | 12 |

Union is 14: `/usr/bin/sleep`, `/tmp/nvxg7c90398809`, and 12
`/var/tmp/nivxforge-watch/nivx-p03-proof-*` files that were each **created and
then executed**, so they appear under both fields. Both examples were captured
from the same served build.

Also corrected: FILE events carry `size` (68,432 bytes here), so "file size not
collected" was wrong. It is collected on FILE events, absent on process
observations, and the detail pane now shows it.

## 3 · Individual sightings reachable — and the device gap explained

Selecting the oldest `File created` row from Event history drove the detail pane
to **that exact evidence id** (`raw_98b8aec512212938f62fd84a`, not the grouped
marker's newest member), and its pivot carried this sighting's own endpoint and
observed time:

```
/edr/device-trajectory?device=ep_2d57cbe6f80152062109
  &at=2026-09-08T00:35:30.688220+00:00&sha256=17a623f3…&sighting=raw_98b8aec…&tenant=default
```

Following it, the canvas reported **no activity for 2026-09-08**. Checked rather
than assumed:

- `xdr_canonical_evidence` — 26,000+ observations on 2026-10-18 for this
  endpoint, **zero** on 2026-09-08 (`/trajectory/hours` returns all-zero).
- `v2_shadow_observations` — **no records at all** for this endpoint.
- `edr_raw_events` — **31,589** events for this endpoint on 2026-09-08.

So the empty canvas is a canonicalisation gap, not a contradiction. The pivot
now carries the evidence id; an empty canvas re-reads that one sighting **by id,
regardless of limit**, and keeps it on screen — what it was, where, when, its
size — with the reason the two surfaces disagree and a link back to the file's
sightings. A sighting that cannot be re-read in the acting customer asserts
nothing; the panel stays away when the canvas does have events.

## 4 · Two computers — proved on a disposable database

`backend/tests/edr/test_file_sightings_fleet_fixture.py` builds its own database,
asserts, and drops it. **No endpoint was enrolled and nothing was written to the
preview dataset.** Two endpoints in `fx-owner` share one digest with *tied*
earliest timestamps; a third endpoint holds the same digest in `fx-outsider`.

- both computers appear as lanes within one customer (`endpoint_count == 2`);
- the tie keeps **both** as first observers, rather than picking one and
  presenting it as where the file came from;
- the third endpoint is absent from the owner's read, and the owner's two are
  absent from the outsider's read;
- the filter still matches the whole history at `limit=1`;
- the section is now **"First observed on"**, and the page states that two
  computers reporting one digest is co-observation — **transfer is not
  observed**, so no spread claim is made.

## Regression caught by this work

The path-provenance rollup introduced a loop variable that **shadowed the
digest**, so the response came back keyed `PROCESS/PROCESS_OBSERVED` — which the
UI put in the SHA-256 field and into every device-trajectory link. Fixed, and the
fixture now asserts the answer is keyed to the digest that was asked for.

## Tests

- frontend: `28 files · 415 tests` passed (includes 3 new canvas-gap tests and
  the server-filter tests).
- backend: `tests/edr/test_file_sightings.py` + `test_file_sightings_fleet_fixture.py`
  → **17 passed**.

## Left for the separate task, as instructed

Dashboard → Forensic Snapshots and Dashboard → Live Query.
