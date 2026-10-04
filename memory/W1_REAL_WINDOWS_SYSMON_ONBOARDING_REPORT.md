# W1 · REAL WINDOWS / SYSMON SOURCE ONBOARDING

| | |
| --- | --- |
| **W1 engineering readiness** | **PASS** (replay/synthetic proven) |
| **W1 real-source acceptance** | **REAL_SOURCE_BLOCKED** |
| **W1 overall** | **NOT CLOSED** |

No Windows host is reachable from this environment and none is enrolled, so the
real-source leg cannot be attempted, let alone passed. Everything below that is
marked PASS was proven with synthetic records **in Microsoft's documented
EventData shape, delivered over the authenticated ingest route** — that proves
the parser, canonicalization, provenance, binding and the negative controls. It
is **REPLAY/SYNTHETIC PROVEN and is not a substitute for live telemetry.**

Measured, not assumed:

```
enrolled Windows collectors with a heartbeat : 0
canonical Sysmon records from a non-proof host: 0
```

---

## 1 · WHAT WAS WRONG BEFORE W1 (our defects, not the environment's)

| Sysmon field | Before | Consequence |
| --- | --- | --- |
| `Hashes` | never parsed | **no Sysmon hash could ever reach canonical evidence**, so the DCR-1 hash IOC predicate was unreachable from endpoints even with a live host |
| `ParentImage` | parsed, then dropped (only `parent_name` basename survived) | `process.parent_executable_path` existed in the Sigma field map but on no record — the 2 parent/child rules could never fire |
| `ParentCommandLine` | never parsed | parent context unavailable to any rule |
| `OriginalFileName` | never parsed, and Sigma `OriginalFileName` was mapped to `process.name` = **basename(Image)** | a renamed-binary rule judged the attacker-controlled on-disk name instead of the PE metadata — a **semantic defect**, not just a gap |
| `TargetFilename` (EID 11) | parsed into `additional_fields` only; canonical `file.*` never constructed | file evidence uncitable |
| `TargetObject` / `Details` | mapped to `registry.key` / `registry.value`, which **exist on no canonical record** (D18 names them `target_object` / `value_data`) | the Run-key persistence rule could never fire |

---

## 2 · WHAT W1 (HOST-INDEPENDENT HALF) CHANGED

`detection_content/telemetry/sysmon_dsm.py`
* parser now carries `OriginalFileName`, `ParentCommandLine`, `Hashes`
  (verbatim) alongside the existing fields;
* `_sysmon_hashes()` splits `SHA1=…,MD5=…,SHA256=…,IMPHASH=…` and **accepts a
  digest only when it is hex of the exact width its algorithm defines**. A
  malformed digest is REFUSED and the refusal is recorded in
  `field_provenance["hashes_rejected"]` — it is never stored, because a
  watchlist must not compare against something the endpoint never computed;
* hash ownership is decided by event id, never guessed: **EID 1 `Hashes` are the
  hashes of the image that executed → `process.hashes`**; a file event's hashes
  → `file.hashes`;
* `process.original_file_name`, `process.parent_executable_path`,
  `process.parent_command_line` are populated with per-field provenance
  (`sysmon:EventData.OriginalFileName`, `…ParentImage`, `…ParentCommandLine`);
* **EID 11 now produces canonical file evidence** — `file.path`, `file.name`,
  `file.action="create"` with provenance, and no hash invented for a record that
  carried none.

`detection_content/telemetry/models.py`
* `ProcessEntity`: `original_file_name`, `parent_executable_path`,
  `parent_command_line` (additive; `parent_name` unchanged);
* `FileEntity`: `field_provenance`, so file evidence is as traceable as network
  evidence.

`detection_content/rule_store_binding.py` — field map corrections only:
* `OriginalFileName → process.original_file_name` (**the conflation with
  `process.name` is removed**);
* `ParentImage → process.parent_executable_path`,
  `ParentCommandLine → process.parent_command_line` (now genuinely emitted);
* `TargetObject → registry.target_object` (fallback `registry.key_path`),
  `Details → registry.value_data` — the previous paths existed on no record.

**`_COLLECTED_PRODUCTS` is still `{"linux"}`.** Widening it is the live-source
acceptance step and was deliberately not done.

---

## 3 · THE 12 WINDOWS BEHAVIOUR RULES, INDIVIDUALLY

Estate note: the triage's "9 SigmaHQ execution rules" are the 9
`process_creation` rules below; the two Office parent/child rules and the
registry Run-key rule are reported with them because they share the same
authoritative Windows evidence path. `Rundll32 with remote payload` exists as
5 identical native copies (1 distinct detection) and is covered by the
rundll32 row.

DSM support column: **before → after** this gate.
Live-source state is identical for every row: **REAL_SOURCE_BLOCKED**.

| rule | EID | required fields | DSM support | canonical fields | binding state today | replay proof (positive / benign) | genuinely fireable? | remaining blocker |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `proc_creation_win_susp_encoded_pshell` | 1 | Image, CommandLine | ✔ → ✔ | `process.executable_path`, `process.command_line` | `NO_TELEMETRY` | MATCH / no match | **NO** | no real Windows source; product gate (correctly closed) |
| `proc_creation_win_regsvr32_squiblydoo` | 1 | Image, CommandLine | ✔ → ✔ | same | `NO_TELEMETRY` | MATCH / no match | **NO** | same |
| `proc_creation_win_mshta_remote_hta` | 1 | Image, CommandLine | ✔ → ✔ | same | `NO_TELEMETRY` | MATCH / no match | **NO** | same |
| `proc_creation_win_rundll32_user_writable` (+5 native copies) | 1 | Image, CommandLine | ✔ → ✔ | same | `NO_TELEMETRY` | MATCH / no match | **NO** | same |
| `proc_creation_win_certutil_urlcache` | 1 | Image, CommandLine | ✔ → ✔ | same | `NO_TELEMETRY` | MATCH / no match | **NO** | same |
| `proc_creation_win_bitsadmin_download` | 1 | Image, CommandLine | ✔ → ✔ | same | `NO_TELEMETRY` | MATCH / no match | **NO** | same |
| `proc_creation_win_wmic_process_call` | 1 | Image, CommandLine | ✔ → ✔ | same | `NO_TELEMETRY` | MATCH / no match | **NO** | same |
| `proc_creation_win_schtasks_persistence` | 1 | Image, CommandLine | ✔ → ✔ | same | `NO_TELEMETRY` | MATCH / no match | **NO** | same |
| `proc_creation_win_msiexec_remote` | 1 | Image, CommandLine | ✔ → ✔ | same | `NO_TELEMETRY` | MATCH / no match | **NO** | same |
| `proc_creation_win_office_spawns_shell` | 1 | Image, **ParentImage** | ✔ / **✘ → ✔** | + `process.parent_executable_path` | `NO_TELEMETRY` | MATCH / no match | **NO** | same — but the field gap that made it unfireable *even with* telemetry is closed |
| `behavior_lolbin_from_office` (native) | 1 | Image, **ParentImage** | ✔ / **✘ → ✔** | same | `NO_TELEMETRY` | MATCH / no match | **NO** | same |
| `win_persistence_registry_run_key` | 13 | **TargetObject, Details** | **✘ → ✔** (mapped to paths that existed on no record) | `registry.target_object`, `registry.value_data` | `NO_TELEMETRY` | MATCH / no match | **NO** | same |

**Nothing became genuinely fireable in W1: 0 of the 9 (0 of 12).** What changed
is that the *remaining* blocker is now exactly one thing — real Windows
telemetry — instead of three (telemetry **plus** two silent field/mapping
defects). The PROJECTION below is labelled as such and is not an acceptance.

### PROJECTION (product gate lifted IN MEMORY only, then restored)

All 12 rules bind (`BOUND`), each one matches its own behaviour on canonical
evidence produced by the real DSM, and **none** matches the benign
`explorer.exe → notepad.exe` record. This says the content and the evidence
path fit each other. It says nothing about telemetry existing.

---

## 4 · HASH ACCEPTANCE (replay proven)

* a Sysmon `Hashes=…SHA256=<digest>` on EID 1 reaches
  `process.hashes.sha256` with provenance
  `sysmon:EventData.Hashes(SHA256) — the hash of the image that was executed`;
* `ioc_file_hash_watchlist` consumes it and cites
  `process.hashes.sha256` → the exact observed digest →
  `xdr_canonical_evidence/<event_id>`;
* **missing hash → no match · wrong hash → no match · malformed digest →
  refused, absent from evidence, and reported**;
* a tenant-scoped watchlist entry does not judge another tenant; platform intel
  is cited as `tenant_scope: platform`.

---

## 5 · INVARIANTS HELD

| Invariant | Enforcement |
| --- | --- |
| `OriginalFileName ≠ process.name` | separate canonical field, separate provenance, and the Sigma map no longer points at `process.name`; asserted by a renamed-binary test that fails under the old behaviour |
| PID ≠ process identity | untouched — `ProcessGuid`/`ParentProcessGuid` remain the authoritative primitive; `attribution_state` still degrades to `PID_ONLY_NOT_AUTHORITATIVE` without a GUID |
| missing field → no match | absent fields are omitted from the Sigma namespace; absent hashes/OriginalFileName produce no match |
| missing provenance → no evidence-backed match | DCR-1's `provenance_state` unchanged and still required |
| no synthetic/default field values | nothing is defaulted; malformed hashes are refused rather than coerced |
| replay PASS ≠ live-source PASS | every result here is labelled REPLAY/SYNTHETIC; the report header states W1 is NOT CLOSED |
| parser support ≠ telemetry availability | the 12 rules remain `NO_TELEMETRY` and none fires |
| rule bindable ≠ genuinely live-fireable | the projection is separated from the binding state and explicitly labelled |

---

## 6 · PROOF & REGRESSION

* `scripts/p0_w1_sysmon_onboarding_proof.py` — **PASS, 40/40 checks**
  (15 Sysmon records accepted over the real ingest route; field preservation,
  provenance, OriginalFileName invariant, product gate intact, projection,
  hash→IOC, malformed-event rejection, wrong-evidence-type, tenant isolation,
  replay/dedupe), ending with an explicit `REAL_SOURCE_BLOCKED` banner.
* `backend/tests/test_w1_sysmon_field_preservation.py` — **18 passed**.
* DCR-1 + N1 + N2.1 + X1 + `p0_f3` + W1 together: **167 passed, 1 skipped**.
* Wider sweep (`-k "sysmon or d18 or registry or d11 or d12 or pipeline or
  sigma or detection or library or citation"`) run **before and after**:
  64 failed / 28 errors → 65 failed / 27 errors, with the **only** difference
  being `test_real_world_battery::test_decode_pipeline[apt_multi_stage_full_killchain]`,
  which passes on re-run — a flaky case in the NivXForge decoder battery (28 of
  its 40 cases fail on a clean tree). **No new failure attributable to W1.**
  `/tmp/w1_before.txt` vs `/tmp/w1_after.txt`.

---

## 7 · OWNER-SIDE ONBOARDING RUNBOOK (to close W1)

### 7.1 On the Windows host

1. Install Sysmon (Sysinternals) and a config that emits at least
   **EID 1, 3, 11, 12/13/14, 22** with hashing enabled:

   ```xml
   <Sysmon schemaversion="4.90">
     <HashAlgorithms>SHA256,MD5</HashAlgorithms>
     <EventFiltering>
       <RuleGroup groupRelation="or">
         <ProcessCreate onmatch="exclude"/>        <!-- EID 1  -->
         <NetworkConnect onmatch="exclude"/>       <!-- EID 3  -->
         <FileCreate onmatch="exclude"/>           <!-- EID 11 -->
         <RegistryEvent onmatch="exclude"/>        <!-- EID 12/13/14 -->
         <DnsQuery onmatch="exclude"/>             <!-- EID 22 -->
       </RuleGroup>
     </EventFiltering>
   </Sysmon>
   ```

   ```powershell
   Sysmon64.exe -accepteula -i sysmonconfig.xml
   # verify: Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -Max 5
   ```

2. `HashAlgorithms` MUST include SHA256, otherwise the endpoint hash IOC lane
   stays empty (the DSM will refuse to invent one).

### 7.2 Enrol a collector and mint exactly one key (NivXRay side)

```bash
# 1 · collector, authorized for this source ONLY
curl -X POST "$API/api/xdr/collectors" \
  -H "Authorization: Bearer $ADMIN_JWT" -H "X-Tenant-Id: <tenant>" \
  -H "Content-Type: application/json" \
  -d '{"name":"win-wef-01","protocol":"wef",
       "authorized_sources":["microsoft-sysmon"]}'

# 2 · ingest key — never printed into chat, a log, or the repo
curl -X POST "$API/api/xdr/api-keys" \
  -H "Authorization: Bearer $ADMIN_JWT" -H "X-Tenant-Id: <tenant>" \
  -H "Content-Type: application/json" \
  -d '{"name":"win-wef-01-key","confirm_tenant_id":"<tenant>",
       "allow_new_tenant":false,
       "scopes":["collectors.enroll","collectors.read"]}'
```

### 7.3 The event shape the existing route accepts

`POST /api/xdr/ingest/telemetry` with `X-XDR-API-Key` + `X-Tenant-Id`:

```json
{"envelopes": [{
  "tenant_id": "<tenant>",
  "collector_id": "<collector id from 7.2>",
  "source_event_id": "<host>:<EventRecordID>",
  "collection_method": "wef",
  "source": "win-wef-01",
  "declared_source": "microsoft-sysmon",
  "raw": {
    "event_id": 1,
    "provider": "Microsoft-Windows-Sysmon",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "Computer": "WS-01.corp.local",
    "UtcTime": "2026-06-01 10:00:00.123",
    "User": "CORP\\alice",
    "ProcessGuid": "{...}", "ProcessId": "4711",
    "Image": "C:\\Windows\\System32\\certutil.exe",
    "OriginalFileName": "CertUtil.exe",
    "CommandLine": "certutil -urlcache -split -f http://...",
    "ParentProcessGuid": "{...}", "ParentProcessId": "500",
    "ParentImage": "C:\\Windows\\explorer.exe",
    "ParentCommandLine": "explorer.exe",
    "Hashes": "MD5=...,SHA256=..."
  }}]}
```

`declared_source` must be `microsoft-sysmon` and must be in the collector's
`authorized_sources`, or D15 declared-source routing rejects the delivery —
content never selects the DSM. `raw` is Sysmon's EventData flattened; the
`provider` string must contain `Sysmon`. Any shipper that produces this JSON
works (WEF→subscriber script, winlogbeat with a small mapping, or a scheduled
`Get-WinEvent` forwarder).

### 7.4 Verification procedure (this is what closes W1)

1. Generate **safe, real** activity on the host, e.g.
   `certutil -urlcache -split -f http://<your-own-host>/benign.txt` and
   `powershell -enc <base64 of "Write-Host hello">`;
2. confirm the canonical record came from the real host:
   `xdr_canonical_evidence` where `host.hostname = <real host>`,
   `provenance.dsm_id = microsoft-sysmon`, `provenance.collector_id =` the
   enrolled collector, `process.process_guid` present,
   `process.hashes.sha256` present, `raw_ref.channel =
   Microsoft-Windows-Sysmon/Operational`;
3. **only then** add `"windows"` to `_COLLECTED_PRODUCTS` in
   `detection_content/rule_store_binding.py` — this is the one switch, and it
   must be flipped **because** real telemetry arrived, not to make the numbers
   look better;
4. re-run `scripts/p0_w1_sysmon_onboarding_proof.py` plus the 12-rule table and
   record, per rule, whether it fired on genuine evidence with a citation;
5. run the DCR-1 / N1 / N2.1 / X1 suites; then W1 can be marked CLOSED.

---

## 8 · WHAT THIS DOES NOT CHANGE

No fake Windows host and no manufactured live acceptance. No new detection
content. No licence changes. No M365, IDS, YARA or lateral-movement work. No X1
pipeline wiring. No UI. No merge. No deployment. `_COLLECTED_PRODUCTS`
unchanged, so no Windows rule became live.

**STOP — awaiting owner review.**
