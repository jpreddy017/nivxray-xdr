# D13 — JSON INGEST SHAPE (owner review gate)

Date: 2026-09-14 · Scope: **the acquisition path for JSON-document
telemetry** · **PREVIEW ONLY — no production deployment.**

Reproduce with:
```
cd /app/backend && python -m pytest tests/test_d13_json_ingest_shape.py -q
cd /app          && python scripts/p0_d13_json_ingest_shape_live_proof.py
```

---

## A · What was actually wrong

Narrower than it looked, and worse than it looked.

`CanonicalEnvelope.raw` is already `dict[str, Any]` — **the wire contract
always carried JSON documents**. The break was one function:
`_raw_event_for_pipeline` flattened every envelope into
`{line, message, …}` with `line = raw.get("line") or raw.get("message") or
""`. Since `supports()` on the document DSMs reads source fields at the TOP
level (`ev["provider"]`, `ev["EventID"]`, `ev["eventName"]`,
`ev["event_type"]`), a document arrived with `line=""`, no DSM claimed it,
and the envelope was settled `NOT_ATTEMPTED / no_verbatim_line`.

Worse than it looked: **`snort-eve` was in the same hole.** EVE is JSON and
its `supports()` reads `ev["event_type"] == "alert"` at the top level, so
Snort never resolved through the collector path either. Four of seven
registered DSMs were unreachable from the real acquisition path, not three.

No new endpoint, no contract change, and no parser change was required.

## B · Files changed

| File | Δ | What |
|---|---|---|
| `backend/routers/xdr_ingest.py` | +95 | `_payload_shape`, `_document_for_pipeline`, the `_nivx` reserved namespace, fail-closed collision handling, and the `no_verbatim_line` guard taught about documents |
| `backend/services/ingest_provenance.py` | +8 | `payload_shape`, `declared_payload_format`, `selected_dsm_id` on the ingest identity block |
| `backend/detection_content/xdr_pipeline.py` | +6 | records the DSM that actually claimed the event |
| `backend/detection_content/telemetry/sysmon_dsm.py` | +9 | tenant propagation — the minimal fix your acceptance required |
| `backend/tests/test_d13_json_ingest_shape.py` | **NEW**, 37 tests | |
| `scripts/p0_d13_json_ingest_shape_live_proof.py` | **NEW** | 41/41 PASS in preview over real HTTP |

No PATH/CWD, no rule declarations, no UI, no production deployment, no
response/collector/webhook security.

## C · The shape decision is structural, never a content guess

```
raw.line present                                  -> LINE
raw.message present AND raw carries nothing else
    beyond {line, message, payload_format}        -> LINE   (older collector shape)
anything else with keys                           -> DOCUMENT
empty raw                                         -> LINE   (unchanged NO_DSM answer)
```

The middle rule is the one that matters. A Windows export legitimately
carries its own `message` field; under the old rule that field would have
been read as a *delivered line* and handed to whichever line-oriented DSM
recognised the text. The rule is decided on the **key set**, which the
collector controls deliberately, not on what the text looks like.

`test_the_line_shape_is_unchanged_byte_for_byte` asserts the full expected
dict for a line envelope, field by field, so a LINE delivery cannot drift.

## D · `_nivx` — one reserved namespace, and it fails closed

A DOCUMENT event is handed to the DSM **exactly as the source emitted it**,
with all NivX transport metadata under the single key `_nivx`:
`payload_shape`, `tenant_id`, `collector_id`, `connector_id`,
`data_source_id`, `source`, `collection_method`, `parser_version`,
`collection_timestamp`, `source_timestamp`, `received_at`,
`declared_payload_format`.

`test_a_document_field_is_never_shadowed_by_transport_metadata` drives the
nastiest case — a document carrying its own `source`, `message`,
`timestamp`, `collector_id` and `collection_method` — and asserts every
source value survives while NivX's view of the same names is intact under
`_nivx`.

**Collision → fail closed.** A source document that already carries a
top-level `_nivx` raises `IngestShapeCollision`; the delivery is settled
`BLOCKED / ingest_shape` with the reason recorded, the idempotency claim is
completed, and no canonical evidence is created. Overwriting it would let
transport metadata destroy source evidence; honouring it would let source
content impersonate NivX provenance. Proven live: `['BLOCKED']
['ingest_shape']`, 0 canonical events.

## E · A tenant-boundary WEAKNESS (severity amended 2026-09-14)

> **CORRECTION — this section originally overstated the severity.** It
> said the payload-first pattern "would have been trivially reachable"
> with document-first shaping. That was wrong. On re-tracing: the
> normalizers read `parsed["raw"]`, which is the *whole* raw event NivX
> assembles — where `tenant_id` is already the authenticated one — while a
> payload's own `tenant_id` sits one level deeper at
> `raw["raw"]["tenant_id"]` and is never read. With D13's withholding in
> place this was **defence-in-depth / trust-boundary hardening, not a
> presently exploitable cross-tenant vulnerability**. No reachable
> exploit path was ever demonstrated. The hardening still proceeded (D14)
> because the invariant must live at the trust boundary rather than
> depend indefinitely on upstream shaping remaining correct, and because
> tenant material participates in deterministic identity (D10).
>
> Closed at the boundary in D14 — see
> `/app/memory/D14_TENANT_AUTHORITY_REPORT.md`.

`WindowsSecurityNormalizer`, `AWSCloudTrailNormalizer` and
`CefLeefNormalizer` all resolve the tenant as
`raw.get("tenant_id") or tenant_id` — **the raw payload first**. With
document-first shaping, any source document containing
`"tenant_id": "victim"` would have landed in the victim's tenant. The
precedence is pre-existing, but the document shape would have made it
trivially reachable.

Closed inside this gate's own boundary, without touching tenant-binding
code (Work Mode's domain): `_document_for_pipeline` withholds a
source-supplied `tenant_id` from the DSM-facing document and preserves the
claimed value under `_nivx.source_fields_withheld` with
`withheld_reason = "a source-supplied tenant_id is recorded as a claim and
never used: the authenticated tenant is the only authority on ownership"`.

No evidence is lost — it is recorded and **not believed**, the same pattern
D11 used for the collector's origin label. Proven live: a CloudTrail
document claiming tenant A, delivered on tenant B's authenticated key,
landed in **B**, with the claim preserved and marked withheld.

**Done in D14** (all five normalizers, not three — `linux-auditd` had the
same pattern and it feeds D10 identity material). Establishing the
authenticated tenant remains Work Mode's domain and was not touched.

## F · Sysmon tenant fix (minimal, as authorized)

`SysmonNormalizer.normalize()` hardcoded `tenant_id="default"` and took no
tenant argument, so every Sysmon event on any path landed in tenant
`default`. It now takes the tenant the pipeline already passes to the other
four normalizers and **raises with no fallback** when it is absent —
matching Windows and CloudTrail. Two tests:
`test_sysmon_no_longer_lands_every_event_in_the_default_tenant` and
`test_sysmon_refuses_to_normalize_without_a_tenant`. Nothing deeper was
touched; Sysmon Tenant Binding remains available as its own gate.

## G · DSM selection — unchanged, and now visible

`supports()` semantics are untouched, as authorized. What changed is that
the choice is now recorded as evidence in `provenance.ingest`:
`payload_shape` (LINE/DOCUMENT), `declared_payload_format` (the collector's
claim) and `selected_dsm_id` (what actually claimed it), side by side. A
declaration that disagrees with the selection is therefore visible in the
evidence instead of silent.

## H · Live proof — 41/41 PASS in preview over real HTTP

Five envelopes in one authenticated `POST /api/xdr/ingest/telemetry`:
three JSON documents and two verbatim lines, so no-regression is proven in
the **same delivery**.

| Source | Shape | DSM selected | Tenant | Basis | Activity time |
|---|---|---|---|---|---|
| Sysmon doc | DOCUMENT | `microsoft-sysmon` | `t-d13-proof-a` | ACTIVITY_TIME | `sysmon:EventData.UtcTime` |
| Windows doc | DOCUMENT | `windows-security-evd` | `t-d13-proof-a` | OBSERVATION_TIME | NOT_OBSERVED (by D12 design) |
| CloudTrail doc | DOCUMENT | `aws-cloudtrail` | `t-d13-proof-a` | ACTIVITY_TIME | `cloudtrail:eventTime` |
| auditd line | LINE | `linux-auditd` | `t-d13-proof-a` | ACTIVITY_TIME | audit header |
| CEF line | LINE | `cef-leef` | `t-d13-proof-a` | ACTIVITY_TIME | `devTime` |

Per document, asserted live: owned by the authenticated tenant · recorded as
DOCUMENT · the right DSM claimed it · D12 basis declared · all eight
temporal boundaries present · `nivx_received_at` is a real measurement · the
source document survived verbatim in `raw_ref` · the raw envelope row is
cited and resolvable.

Cross-tenant: the same Sysmon document delivered on tenant B's key produced
**separate** evidence (A=1, B=1) and tenant B holds **nothing** delivered by
tenant A's collector (0). Wall time for the five-envelope delivery: 205 ms.

## I · Synthetic proof — 37 tests

Shape classification for every source; document-reaches-the-right-DSM for
all four document DSMs; line-still-reaches-the-right-DSM for both line
DSMs; the byte-for-byte LINE shape; shadowing; the `message`-field trap;
collision fail-closed; tenant withholding; end-to-end through the **real**
pipeline and a **real** MongoDB (throwaway database, dropped in a `finally`)
for all six sources including D12 provenance and document preservation;
cross-tenant isolation per document DSM; and the two Sysmon tenant tests.

## J · Regression

| Suite | Result |
|---|---|
| D13 + D12 + D11 + D2/D3/D10 + D4 + D8 + phase2 normalization + telemetry adapters + round11 pipeline | **208 passed** |
| `p0_d11_ingest_provenance_live_proof.py` | still **30/30 PASS** |
| `p0_d12_cross_dsm_activity_time_live_proof.py` | still **16/16 PASS** |

Baseline comparison by reverting the patch **in place** (a `git worktree`
cannot isolate suites that `from server import app`), across 7
server-importing suites:

| | Baseline (HEAD, D13 reverted) | Patched |
|---|---|---|
| | 13 failed · 60 passed · 20 errors | 13 failed · 60 passed · 20 errors |
| `diff` of failure sets | — | **empty — identical, 33/33** |

The 13 + 20 are the documented pre-existing families: 4
`test_xdr_detection_consolidation`, 6 `ACCESS_DENIED … unauthenticated`
(Work Mode's auth track), 3 `KeyError: 'proc_root'` fixture, and 20
`test_xdr_data_sources_collectors` setup errors from the same auth track.

## K · Storage / performance impact

Per DOCUMENT event the `_nivx` block adds ~500 B to the DSM-facing event,
and it is stored once inside `raw_ref` (the parsers keep the document as
their raw reference). Line envelopes are unchanged. No index added, no query
path changed. Five-envelope authenticated delivery measured at 205 ms
end-to-end including detection and verdict.

## L · Known gaps after D13

1. **`supports()` is content matching, and registry ORDER now matters more.**
   A document whose own fields happen to look like another source's can be
   claimed by whichever DSM is registered first — e.g. a Windows document
   carrying a `message` field full of auditd text resolves to
   `windows-security-evd` only because it is registered before
   `linux-auditd`. This is the pre-existing selection contract you asked me
   to leave alone; the shape fix makes it reachable for documents too. A
   declaration-authoritative selection (with fail-closed on disagreement) is
   the real answer, and is now recordable because
   `declared_payload_format` and `selected_dsm_id` sit side by side in the
   evidence.
2. ~~The three normalizers still prefer a payload-supplied `tenant_id`.~~
   **CLOSED in D14** across all five normalizers, at the trust boundary.
3. `raw.line` in a source document would still be read as a delivered line.
   No real document format uses that key, but it is a structural ambiguity
   rather than an impossibility.
4. No real Windows host, cloud account or IDS is connected. Every payload
   here is TEST/SYNTHETIC; this proves the *path*, not the sources.
5. `snort-eve` documents now reach the DSM but Snort's canonical projection
   still has no `tenant_id` field of its own and predates the canonical
   event shape (it uses `timestamp`, not `event_time`). Its persisted row
   carries the tenant; the projection does not. Pre-existing, flagged.

## M · Verdict

**JSON Ingest Shape — PASS for preview scope.**

* Real Sysmon, Windows Security and CloudTrail documents now traverse the
  authenticated collector path and become correctly tenant-bound canonical
  evidence — proven over HTTP, not only through the registry.
* `snort-eve` was in the same hole and is fixed by the same change.
* Line sources are unchanged byte-for-byte and proven so in the same
  delivery.
* The reserved namespace cannot shadow source evidence, source content
  cannot impersonate provenance, and a collision fails closed.
* A tenant-boundary hole the document shape would have opened was found and
  closed inside this gate's boundary, with the hardening recommendation
  handed to Work Mode rather than taken silently.

**Not production acceptance.** All payloads are synthetic; no real source is
connected; nothing was deployed.

---

## STOP — awaiting owner review before Sysmon Tenant Binding / PATH/CWD.
