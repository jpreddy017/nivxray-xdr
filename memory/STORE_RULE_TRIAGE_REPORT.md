# STORE RULE TRIAGE — `xdr_detection_rules` (READ-ONLY AUDIT)
_no fixes · no rule enabling · no UI · no new telemetry · no pipeline wiring · no merge · no deployment_

Method: every enabled rule was re-bound through the **existing** binder
(`detection_content/rule_store_binding._Binding`) against the live store,
then classified by hand-checking its logsource, its inspected fields, the
canonical fields we actually emit today, and its licence state. The prior
classification was reproduced exactly before being re-interpreted:

```
binder states (98 enabled rules)
  STORE_CONTENT_INCOMPLETE  52   (39 no logsource · 13 no detection block)
  LICENSE_BLOCKED           23
  NO_TELEMETRY              22
  UNSUPPORTED_BY_EVALUATOR   1
  BOUND                      0
```

The prior numbers are **correct**. What they do not say is that the 98 is
not 98 rules' worth of security content — see §3.

---

## 1 · TOTALS

| Class | Count | Meaning |
| --- | --- | --- |
| **A · READY NOW** | **0** | nothing is blocked only by content/config |
| **B · SMALL GAP** | **14** | telemetry and canonical fields exist; a bounded mapping/declaration/binding fix is required |
| **C · TELEMETRY BLOCKED** | **34** | the authoritative source is missing |
| **D · PRODUCT/LICENSE BLOCKED** | **23** | licence policy forbids runtime use |
| **E · UNSAFE/INVALID** | **27** | cannot be a detection without inference or fabrication |

**A is genuinely zero.** Every rule whose fields we can produce is either
licence-blocked, a test fixture, or needs a mapping that does not yet
exist. That is a more useful answer than a hopeful one.

---

## 2 · PER-RULE CLASSIFICATION

Format: `rule / count | attack or behaviour | required source+fields | actual availability | blocker | class | smallest remediation`

### B · SMALL GAP (14)

| Rule | Behaviour | Needs | Have | Blocker | Remediation |
| --- | --- | --- | --- | --- | --- |
| Suspicious DNS Query to Uncommon TLDs | DGA / suspicious resolution | `QueryName`, windows dns | **`network.dns_query` is canonical** from Zeek (N1) *and* Sysmon EID 22 | `QueryName` is not in `_FIELD_MAP`, and the rule is gated on `logsource.product = windows` | map `QueryName → network.dns_query`; decide the product-gate question in §4 |
| O365 Suspicious Mailbox Forwarding Rule | T1114.003 mail forwarding | `Operation`, `Parameters`, office365 | **M365 Unified Audit DSM exists**; records carry Operation/Parameters | fields unmapped; product `office365` not in `_COLLECTED_PRODUCTS` | map the two fields; note live M365 is still `EXTERNAL_ACCESS_BLOCKED`, so it would be replay-proven only |
| `ioc_file_hash_watchlist` | known-bad file hash | `hash.sha256` | `process.hashes.sha256` / `file.hashes.sha256` canonical | no watchlist evaluator is bound; not Sigma content | bind the IOC lane to canonical hash fields, or express as a Sigma `field_match` |
| `ioc_network_watchlist` | known-bad IP/domain | `dst_ip`, `dst_domain` | `network.dest_ip`, `network.dns_query` canonical | same | same |
| 10 × `cor_*` correlation mirrors | multi-stage scenarios | correlation engine | **they already fire** via `routers/xdr_correlation.py` | they are mirrored into a *Sigma* store and the Sigma binder correctly refuses them | exclude `lane=correlation` from the Sigma binder's denominator — a reporting defect with **zero security gap** |

### C · TELEMETRY BLOCKED (34)

| Group | Count | Behaviour | Missing source |
| --- | --- | --- | --- |
| SigmaHQ Windows `process_creation` (encoded PowerShell, Squiblydoo regsvr32, mshta HTA, rundll32 from user-writable path, certutil URLCache, bitsadmin, WMIC process call create, schtasks persistence, msiexec remote MSI) | 9 | execution, defence evasion, persistence, ingress tool transfer | **real Sysmon / Windows process telemetry** (`ABSENT`) |
| Office spawning command shell; LOLBIN spawned by Office | 2 | initial access → execution | same |
| Registry Run Key to user-writable path | 1 | T1547.001 persistence | Windows registry telemetry |
| `Rundll32 with remote payload` **× 5 duplicates** | 5 | execution | same Windows gap; see §3 |
| Suspicious User-Agent strings | 1 | C2 / tooling | proxy/web telemetry (`ABSENT`) |
| AWS Root Console Login; Okta Admin Role Granted | 2 | cloud/identity privilege | no authoritative AWS/Okta DSM (only the legacy REPORT-ONLY adapter fabric) |
| Snort signatures (SSH scan, meterpreter, dyndns, log4j JNDI, curl UA, **Cobalt Strike beacon**) | 6 | C2, exploitation, scanning | they are **IDS signatures**, not Sigma: they must be evaluated by a real Snort/Suricata sensor, whose *alerts* we already ingest via `snort-eve` |
| Suricata signatures (SSH brute force, **Emotet C2**, ZeroLogon, malware agent, self-signed TLS, log4j, **DNS DGA**) | 7 | C2, exploitation | same |
| Multiple Failed Logins → Success (brute force) | 1 | T1110 | Windows Security 4624/4625 (`ABSENT`) *and* an aggregation the Sigma evaluator refuses — expressible on the correlation engine once the telemetry exists |

### D · LICENSE BLOCKED (23)

| Source | Licence | Count | Note |
| --- | --- | --- | --- |
| TestVendor `proprietary demo` | `PROPRIETARY-VENDOR` | 11 | **test fixtures**, not content (also E in substance) |
| YARA-Rules | `CC-BY-4.0` (5) / `GPL-2.0` (4) | 9 | includes a genuine PHP webshell rule targeting `linux` files — the **only** store rule whose product we collect, and it is blocked by licence policy, not telemetry |
| Snort | `GPL-2.0` | 2 | redistribution policy |
| `somewhere` | `SOME-PROPRIETARY` | 1 | fixture |

### E · UNSAFE / INVALID (27)

| Group | Count | Why it can never fire as authored |
| --- | --- | --- |
| MITRE ATT&CK `attack_T*` entries | 12 | **reference content, not detections** — a technique description has no predicate. They should not be counted in a detection denominator at all |
| `gate refusal candidate` / `lifecycle test` / `dry-run test` native rules (`{"selection": {"Image": "x"}}` or field `x`) | 15 | **test fixtures** written to exercise the authoring gates; matching them would be meaningless |

---

## 3 · DUPLICATES AND THE REAL SIZE OF THE ESTATE

Duplicate titles in the enabled store: `proprietary demo` ×11 ·
`Rundll32 with remote payload` ×5 · `lifecycle test` ×5 ·
`gate refusal candidate` ×5 · `dry-run test` ×5.

```
98 enabled store rules
 −27  test fixtures / MITRE reference (E)
 −11  proprietary demo fixtures (D, also fixtures)
 −13  correlation mirrors (already firing elsewhere)
 − 4  duplicate copies of one Windows rule
 ─────
 ≈43  genuinely distinct authored detections
```

Of those ~43, **13 are IDS signatures for an engine we do not run**, 9 are
YARA needing a file-content scanner (`ABSENT`) and licence review, and
most of the rest are Windows content. The honest headline is not "0 of 98
fire" — it is **"the authored estate is roughly 43 real detections, and
almost all of them are waiting on Windows telemetry we do not collect."**

Rules requiring fields **no current DSM emits**: `QueryName`(*),
`c-useragent`, `eventName` / `userIdentity.type` /
`responseElements.ConsoleLogin`, `eventType` / `target.type`,
`Operation` / `Parameters`(*), `EventID`, `hash.sha256`(*),
`dst_ip` / `dst_domain`(*). Those marked (*) have canonical equivalents
today and are the B class; the rest do not.

---

## 4 · THE DESIGN QUESTION THE TRIAGE SURFACED (owner decision)

`_COLLECTED_PRODUCTS = {"linux"}` gates a rule on its declared
`logsource.product`. That invariant exists for a good reason — *a Windows
rule must never judge Linux evidence* — but it also means a **DNS** rule
authored with `product: windows` cannot evaluate DNS evidence from Zeek,
even though `network.dns_query` is the same observed value with the same
meaning and full provenance.

Two options, and I am not choosing for you:

* **(a) Keep the product gate strictly.** The DNS rule stays C until
  Windows telemetry exists. Safest, and it leaves real capability unused.
* **(b) Gate on the evidence FIELD, not the product, for
  product-neutral categories (`dns`, `network`).** A rule may evaluate
  only if every field it inspects is genuinely present on the evidence,
  and the match cites the canonical `evidence_ref` that carried it. A
  process-creation rule stays product-gated, because a command line is
  product-specific; a DNS query is not.

Option (b) preserves `Detection → evaluated predicate → observed value →
canonical evidence_ref → cited verdict`, because the predicate still runs
against an observed value and nothing is defaulted. It is the difference
between the N1 DNS work being usable by authored content or not.

---

## 5 · RECOMMENDED SMALLEST GATE — **DCR-1**

> **Bind the canonical DNS / network / hash fields into the authored-rule
> field namespace, and exclude non-detection content from the denominator.**
> Telemetry: only what we already produce (Zeek N1, Sysmon EID 22,
> canonical file hashes). No new source, no inferred field.

Scope (smallest that yields real security value):

1. Extend `_FIELD_MAP` with the canonical fields N1/N2.1 added:
   `QueryName → network.dns_query`, plus DNS answer / destination /
   protocol / hash fields. Unmapped stays unmapped — an absent field must
   still produce no match.
2. Resolve §4 (a) or (b). DCR-1's value depends on it.
3. Bind the two IOC watchlist rules to canonical hash / address / domain
   fields.
4. Stop counting MITRE reference entries, correlation mirrors and test
   fixtures as authored detections — report them in their own buckets so
   the estate number stops misleading everyone, including us.
5. Nothing else. No licence re-evaluation, no Windows content, no IDS
   signature engine.

### Required tests before any rule is activated

| Rule | Positive | Benign negative |
| --- | --- | --- |
| Suspicious DNS Query to Uncommon TLDs | a Zeek `dns.log` query to a listed TLD → match citing the canonical DNS event | a query to a common TLD, **and** a DNS record whose `dns_query` is absent → no match, no defaulted value |
| O365 Mailbox Forwarding | an M365 audit record with the forwarding Operation → match | a benign mailbox operation; a record missing `Parameters` → no match |
| `ioc_file_hash_watchlist` | evidence whose `sha256` is on the watchlist → match | a different hash; evidence with no hash observed → no match |
| `ioc_network_watchlist` | evidence whose `dest_ip`/`dns_query` is listed → match | an unlisted address; and a **Zeek flow where only the peer matches a listed domain's stale answer** → no match (no fabricated resolution) |

Plus, for every activated rule: the invariant chain asserted end-to-end
(**predicate → observed value → canonical `evidence_ref` → cited
detection**), tenant isolation, and the N1/N2.1 regression suites green.

---

## 6 · WHAT THIS DOES NOT CHANGE

No rule was enabled, edited, re-licensed or deleted. No binder, evaluator,
field map or store document was modified. The audit was performed by
re-running the existing binder read-only against the live store.

**STOP — awaiting owner review.**
