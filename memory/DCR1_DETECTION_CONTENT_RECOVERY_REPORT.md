# DCR-1 · DETECTION CONTENT RECOVERY

_owner decision: option (b) narrowed — an explicit product-neutral **allowlist**,
not a field-presence bypass · existing authoritative telemetry only · no new
source, no licence change, no M365 mapping, no IDS/YARA engine, no X1 live
wiring, no UI, no merge, no deployment_

---

## 1 · WHAT CHANGED

| Component | Change |
| --- | --- |
| `detection_content/dcr1_product_neutral.py` *(new)* | the allowlist contract: `PRODUCT_NEUTRAL_CATEGORIES = {dns, network}`, each with a **closed** field set, a closed set of admissible canonical event types, and a provenance/tenant requirement |
| `detection_content/ioc_watchlist.py` *(new)* | the IOC lane's **own** contract — three declared watchlist namespaces, named canonical paths, per-predicate evidence-type admissibility, explicit `ANY_OF` semantics, tenant-scoped entries |
| `detection_content/detection_estate.py` *(new)* | estate accounting: fixtures / MITRE reference / correlation mirrors / duplicate copies reported in their own buckets. **No document was moved, edited or deleted** |
| `detection_content/rule_store_binding.py` | `_FIELD_MAP` extended with the canonical fields N1/N2.1 already emit (multi-path, first genuinely-present wins); neutral binding + evaluation gates; IOC lane binding; every store match now carries a D8 citation |

No new evaluator was introduced. Sigma rules still run through
`nivxray_native_sigma`; the IOC lane runs under
`nivxray::detection_content::ioc_watchlist_contract` and is labelled as such
in the binding report and in every match.

### The allowlist is narrow on purpose

Four conditions must **all** hold before a rule authored for one product may
read another source's evidence:

1. the rule's declared `logsource.category` is on the allowlist (`dns`,
   `network` — process/execution, registry, file, proxy and IDS are not);
2. **every** field the rule inspects is owned by that category. A rule mixing
   `QueryName` with `CommandLine` is *not* eligible and stays product-gated;
3. the evidence is semantically of that category — `event_type` must be in the
   category's closed set, so a `network_connect` record carrying a
   destination-hostname value in `network.dns_query` is **not** admissible to a
   DNS predicate;
4. the evidence carries real `dsm_id` + collector/trace provenance and a tenant.

**Hashes were deliberately NOT made a neutral category.** `sha256` is canonical
and is now mapped, and that still gives no rule cross-product rights: hashes are
consumed only by product-gated rules or by the IOC contract. The test
`test_a_canonical_field_is_not_automatically_product_neutral` asserts that the
hash fields appear in **no** neutral category's field set.

---

## 2 · RECOVERED CAPABILITY — the B class, rule by rule

| B rule | before | after | authoritative source | canonical fields | positive proof | negative proof | genuinely fireable? | remaining blocker |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Suspicious DNS Query to Uncommon TLDs** (`net_dns_susp_tld`, `product: windows`, `category: dns`) | `NO_TELEMETRY` — declared product not collected | `BOUND`, `product_neutral=true`; declared product still `windows`, nothing rewritten | **Zeek `dns.log`** (N1) and Sysmon EID 22, both already ingested | `network.dns_query` ← `QueryName` | live Zeek `dns.log` query to `*.xyz` over the real ingest route → match, citation `QueryName\|endswith` → observed `dcr1-….xyz` → `xdr_canonical_evidence/<id>`, persisted in `xdr_detection_matches` as `CITED` | `.com` query → no match · `dns_query` empty → no match and no defaulted value · same value with `event_type=network_connect` → no match · provenance stripped → no match | **YES** | none |
| **`ioc_file_hash_watchlist`** | `STORE_CONTENT_INCOMPLETE` (no logsource, `\|watchlist` unsupported) | `BOUND` under the IOC contract | **CEF/LEEF DSM** (`cef-leef`, e.g. QRadar EDR `fileHash`) — 3 051 canonical `process.hashes.sha256` values already exist | `process.hashes.sha256`, `file.hashes.sha256` ← `hash.sha256\|watchlist` | live LEEF line with a listed hash → match citing `process.hashes.sha256` and the intel source | unlisted hash → no match · both hash paths absent → no match (and the file-entity hash alone is correctly still an observation) | **YES** | Sysmon does not emit canonical hashes today (`Hashes` is parsed into `additional_fields` only) — a separate mapping gate, not DCR-1 |
| **`ioc_network_watchlist`** | `STORE_CONTENT_INCOMPLETE` | `BOUND` under the IOC contract, `ANY_OF` semantics declared explicitly | **Zeek `dns.log` + `conn.log`** (N1) | `network.dns_query` ← `dst_domain`, `network.dest_ip` ← `dst_ip` | listed domain on a real Zeek DNS record → match · listed address on a real Zeek flow → match | unlisted values → no match · **a flow to the address the listed domain answered → NO match** (no resolution is reconstructed) · the address predicate is *refused* on DNS evidence (`EVIDENCE_TYPE_NOT_ADMISSIBLE`), because a resolver is not a peer · another tenant's watchlist entry → no match | **YES** | the platform intel corpus (`iocs`, 114 515 entries) is unscoped by design; tenant-scoped entries are honoured and isolated |
| **O365 Suspicious Mailbox Forwarding** (`email_o365_susp_forwarding`) | `NO_TELEMETRY` | **unchanged — still `NO_TELEMETRY`** | — | `Operation`, `Parameters` not emitted by any DSM | — | — | **NO** | owner decision: source-specific, not product-neutral. `Operation`/`Parameters` were deliberately **not** mapped to avoid making it *appear* supported by replay. Revisit after genuine M365/Entra onboarding |
| **10 × `cor_*` correlation mirrors** | counted as unbound Sigma rules | still correctly refused by the Sigma binder, and **no longer counted as authored detections** | correlation engine (`routers/xdr_correlation.py`) — they already fire there | n/a | n/a | n/a | **already firing elsewhere** | none — this was a reporting defect with zero security gap |

### Binder state, before → after

```
                             before   after
BOUND                             0       3      (+1 Sigma product-neutral, +2 IOC)
NO_TELEMETRY                     22      21      (the DNS rule left this bucket)
STORE_CONTENT_INCOMPLETE         52      50      (the two IOC rules left this bucket)
LICENSE_BLOCKED                  23      23      (untouched — no licence re-evaluation)
UNSUPPORTED_BY_EVALUATOR          1       1
```

Three rules now evaluate at runtime where none did. That is the honest size of
the recovery: **the number of detections that became genuinely fireable is 3**,
plus 13 correlation mirrors correctly reattributed to the engine that already
runs them.

---

## 3 · DETECTION ESTATE ACCOUNTING

```
store rows                  101   (98 enabled + 3 not-validated)
  authored detections        45   ← the only detection denominator
  duplicate copies            4   (Rundll32 with remote payload ×5)
  MITRE reference entries    12   (technique descriptions, no predicate)
  correlation mirrors        13   (already firing on the correlation engine)
  test fixtures              27   (proprietary demo ×11, lifecycle/gate/dry-run ×15, 1 other)
```

Every store row lands in exactly one bucket (asserted). `binding_report()` now
returns this as `detection_estate` and states that `authored_rules` counts
**store rows**, not detections. "0 of 98 fire" is retired: the estate is **45
distinct authored detections**, of which 3 fire today and most of the rest wait
on Windows telemetry, an IDS engine or a file-content scanner.

---

## 4 · PROOF

`scripts/p0_dcr1_detection_recovery_proof.py` — **PASS (38/38 checks)**, every
record delivered over the authenticated ingest route (collector + API key +
declared source), normalized by the existing DSMs, nothing hand-written into
the canonical collection:

* 7 envelopes accepted (`zeek-json` ×6, `cef-leef` ×1) → 7 canonical records;
* the windows-authored DNS rule fires on Zeek DNS evidence, and the evidence is
  **not** represented as Windows anywhere — `source_vendor=Zeek`,
  `_event_product != windows`, Zeek's own `field_provenance`
  (`zeek:dns.log query`) intact on the record;
* the detection is persisted in `xdr_detection_matches` with
  `citation_completeness=CITED`, the observed value and
  `evidence_ref=xdr_canonical_evidence/<event_id>`;
* benign / absent-field / wrong-evidence-type / missing-provenance /
  cross-tenant / stale-answer negatives all produce no match;
* replay: re-evaluating the same evidence yields the identical verdict, and a
  replayed envelope creates no duplicate citation row;
* the 4 proof watchlist entries are removed at the end — preview left as found.

`backend/tests/test_dcr1_detection_content_recovery.py` — **21 passed**
(1 skipped: the live-store assertion skips on databases whose copy of the store
is licence-blocked; it runs in the proof script). Covers the closed allowlist,
the mixed-field refusal, evidence semantics, provenance, IOC contract refusals,
tenant isolation, replay determinism and estate arithmetic.

**Regression:** `test_p0_f3_rule_store_binding` (11) green unchanged;
N1 / N2.1 / X1 suites green (149 passed with DCR-1's own suite).
A full `-k "pipeline or sigma or detection or library or citation"` sweep was
run **before and after** the change: identical failure set (60 failed / 26–27
errors, the known Work-Mode / control-plane baseline) with **zero new
failures** — `/tmp/dcr1_before.txt` vs `/tmp/dcr1_after.txt`.
`test_d12_cross_dsm_activity_time::test_every_registered_dsm_is_covered_by_this_suite`
fails identically on a clean tree (the m365 DSM is registered but not yet in
that suite) — pre-existing, untouched.

---

## 5 · INVARIANTS HELD

| Invariant | How it is enforced |
| --- | --- |
| absent field → no match | `flatten_with_paths` omits absent/empty values; neutral evaluation additionally requires every inspected field to be present; the IOC lane records `FIELD_ABSENT` |
| no defaulted or invented evidence | nothing is written into the flattened namespace that the record did not carry; citations report the canonical path the value actually came from |
| canonical field ≠ product-neutral | neutral categories own a closed field set; hash fields belong to none of them |
| wrong evidence semantics → no match | closed `event_type` sets per category, and per-predicate admissibility in the IOC contract (resolver ≠ peer) |
| missing provenance → no neutral evaluation | `provenance_state` requires `dsm_id` + collector/trace + tenant |
| tenant/source boundaries preserved | tenant-scoped watchlist entries never judge another tenant; every match carries the evidence's own tenant and the source's provenance |
| process/execution stays product-gated | `process_creation` is not on the allowlist; a DNS rule that also reads `CommandLine` is refused |
| predicate → observed value → canonical `evidence_ref` → detection | every store match now carries a D8 citation, re-checked by the **same** evaluator, persisted by the pipeline |
| N1 / N2.1 / X1 unchanged | no adapter, normalizer, entity-resolution or incident code touched |

---

## 6 · WHAT THIS DOES NOT CHANGE

No new telemetry source. No Windows onboarding. No YARA/file scanner. No IDS
engine. No licence re-evaluation (23 rules stay `LICENSE_BLOCKED`). No M365
field mapping. No lateral-movement content. No X1 live wiring. No UI. No merge.
No deployment. No store document was enabled, disabled, edited, re-licensed,
moved or deleted.

**STOP — awaiting owner review.**
