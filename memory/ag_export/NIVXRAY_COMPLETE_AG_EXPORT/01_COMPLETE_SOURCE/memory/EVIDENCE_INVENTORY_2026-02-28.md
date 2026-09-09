# Evidence Inventory Report — 2026-02-28

_Read-only historical evidence pass. **Nothing has been written to
`REAL_WORLD_LOG.md`, `PRODUCT_CHARTER.md §4.5` scorecard, `CIO`, or any
governance document.** This report is a proposal for your review.
Only after you approve does any of this get promoted._

---

## 0 · Executive summary

- **Merged corpus size:** 1,612 rows (35 saved cases + 1,577 filtered investigations)
- **Highest-signal MITRE cluster:** `T1059.001 · PowerShell` (1,016 hits · 63% of corpus)
- **Recurring patterns strong enough to justify an ADR now:** 3 candidates
- **Data-quality caveats:** significant — see §1 before treating any count as evidence
- **Corpus is Workspace-only.** NivXForge remains dormant. No new capability implemented.

---

## 1 · Data quality — mandatory honesty pass

Per your rule *"Evidence quality outweighs evidence quantity"* — three
findings must accompany every count in this report:

**a) `rc2-orchestrator` dominates 77% of the corpus (1,243 / 1,612).**
This is the default deterministic engine and includes both real
analyst workflows AND automated regression / test replays. Without
distinguishing markers, treat the raw counts as *upper bounds*, not
absolute case volumes.

**b) `analyst_corrections` is largely test data.**
Raw count 632. After filtering rows tagged with
`test|redis|cache|inbox|safelist|overtest` and rows carrying
placeholder IOCs (`http://t`, `http://x`), **202 rows remain** — but
those 202 collapse to only **8 unique correction concepts**, of which
6 are themselves test artefacts (`verdict=correct regression test` and
similar). **Real analyst-signal concepts: ~2.**

**c) `v2_ai_jobs` collection (106 rows) is not usable as evidence in
its current shape.** Every `incident_bytes` field observed is an
integer ID (`'184'`, `'19'`, `'364'`) — a reference, not a payload.
Excluded from this pass.

**Adjusted evidence base after quality gate:**
- Workspace cases: **35** (all counted)
- Filtered investigations: **1,577 upper bound** — real analyst
  engagement likely a **subset**; needs a stronger signal filter
  (see §7 recommendation)
- Analyst corrections: **~2 unique concepts**, not 632
- AI jobs: **excluded**

---

## 2 · Recurring pattern table (real evidence)

| MITRE ID | Technique | Hits | Sources | Recurring? | Candidate ADR? |
|---|---|---:|---|---|---|
| **T1059.001** | Command and Scripting Interpreter: PowerShell | **1,016** | workspace + investigations | ✅ Yes | Already served |
| **T1105** | Ingress Tool Transfer | **622** | investigations | ✅ Yes | ⚠️ Maybe — needs IOC signal |
| **T1027.010** | Obfuscated Files or Information: Command Obfuscation | **414** | investigations | ✅ Yes | ✅ Yes |
| **T1566.001** | Phishing: Spearphishing Attachment | **366** | investigations | ✅ Yes | ⚠️ Maybe |
| **T1027.013** | Obfuscated Files: RC4 shellcode | **220** | investigations | ✅ Yes | ✅ Yes |
| **T1140** | Deobfuscate/Decode Files or Information | **145** | investigations | ✅ Yes | ✅ Yes |
| T1027 | Obfuscated Files or Information | 115 | investigations | ✅ Yes | subsumed by T1027.010 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | 102 | investigations | ✅ Yes | Already served |
| T1204.002 | User Execution: Malicious File | 85 | investigations | Moderate | — |
| T1082 | System Information Discovery | 57 | investigations | Moderate | — |
| T1033 | System Owner/User Discovery | 45 | investigations | Moderate | — |
| T1197 | BITS Jobs | 34 | investigations | Moderate | — |
| T1218.011 | System Binary Proxy Execution: Rundll32 | 30 | investigations | Moderate | — |
| T1218.005 | System Binary Proxy Execution: Mshta | 28 | investigations | Moderate | — |
| T1053.005 | Scheduled Task/Job: Scheduled Task | 16 | investigations | Low | — |

---

## 3 · Engine / capability weaknesses (from real signal)

| Weakness | Signal source | Cases | Actionable? |
|---|---|---:|---|
| RC4 shellcode decode + downstream IOC lift | T1027.013 (220) + reached_shellcode=1.0% | ~220 | ✅ decode succeeds but reached_shellcode almost never fires — likely a gating gap between the RC4 detector and the shellcode-analyzer binary IOC lift |
| Command-line obfuscation coverage | T1027.010 (414) — highest recurring obfuscation | 414 | ✅ Broad pattern; deserves capability-gap review |
| Ingress Tool Transfer without paired IOC | T1105 (622) but only 61 IPs / 712 domains + 709 URLs | 622 | ⚠️ Coverage of URL/domain vs IP is skewed — worth understanding why |
| LOLBAS `pwsh.exe` classification | Analyst corrections (only 2 unique concepts, but one is exactly this) | ~2 concepts | ✅ Small fix; deterministic rule refinement |
| Verdict-Evidence Gating (from Case 0001 in REAL_WORLD_LOG) | Charter Gap #2 (deferred) | 1 case | Not yet — needs recurrence |

---

## 4 · IOC coverage snapshot

| IOC type | Extracted count | Ratio |
|---|---:|---:|
| domains | 712 | 47% |
| urls | 709 | 47% |
| ips | 61 | 4% |
| sha256 | 35 | 2% |
| hashes (unspec) | 9 | <1% |
| md5 | 8 | <1% |
| emails | 5 | <1% |
| bitcoin_addresses | 1 | <1% |

**Observation:** URL/domain extraction is strong; IP extraction is
low (4%). Combined with T1105 recurring in 622 cases, this suggests
an **IP-extraction capability gap** worth an ADR investigation — but
the shape of the missing IPs (IPv4 in HEX? in decimal? in bytes?)
needs one real case to characterize before ADR justification.

---

## 5 · LOLBAS observed

| Binary | Cases (workspace_cases only) |
|---|---:|
| powershell.exe | 15 |
| cmd.exe | 6 |
| certutil.exe | 4 |
| curl.exe | 2 |
| change.exe · query.exe · regsvr32.exe · scrobj.dll · rundll32.exe · comsvcs.dll · te.exe · expand.exe | 1 each |

Sample too small for a LOLBAS-specific ADR. Include this table in
`REAL_WORLD_LOG.md` when Case 0002+ are logged so counts can grow.

---

## 6 · Candidate ADRs (ranked by evidence strength)

_Nothing is promoted yet. These are proposals only._

**Candidate ADR-0001 — Command-Line Obfuscation Deobfuscation Coverage**
- Supporting evidence: T1027.010 = **414** hits
- Pattern: recurring across investigations, largest single obfuscation-family bucket
- North Star linkage: Processing Layer · Semantic Engine
- Note: broadest impact, safest bet if only one ADR is drafted

**Candidate ADR-0002 — RC4 Shellcode → IOC Lift Bridge**
- Supporting evidence: T1027.013 = **220** hits · `reached_shellcode` fires in only 1.0% of corpus
- Pattern: RC4 obfuscation is recurring but rarely progresses to the shellcode-analyzer binary IOC lift — suggests a hand-off gap
- North Star linkage: Processing Layer + Intelligence Layer bridge
- Note: high-yield, well-scoped

**Candidate ADR-0003 — Ingress Tool Transfer IP Extraction**
- Supporting evidence: T1105 = **622** hits · IP IOC ratio = 4% vs URL/domain 94%
- Pattern: high recurrence of Ingress technique but IP extraction disproportionately low
- North Star linkage: Intelligence Layer · IOC Engine
- Note: worth investigating **but** may be an artefact of how IPs appear in the corpus (e.g., encoded), not a true gap. Needs one real diagnostic case before ADR.

**Not yet ADR-worthy:**
- T1140, T1566.001, T1204.002 — high counts but no clear engine weakness signal yet.
- Verdict-Evidence Gating (Gap #2) — still only 1 real case.

---

## 7 · Recommendations before promotion

1. **Do not promote the 1,577 investigation rows verbatim.** The E2b
   filter (`run_count > 1`) alone is not a strong signal of real
   analyst engagement. A stronger next-pass filter would combine:
   `starred=True OR notes != "" OR (kind='chain' AND run_count > 1)`.
   Recommend applying this narrower filter before any REAL_WORLD_LOG
   entries are written.

2. **Reject `analyst_corrections` as an evidence source** for the
   REAL_WORLD_LOG in its current shape. It's a prompt-correction /
   knowledge-base surface with heavy test-data contamination. Extract
   the ~2 unique real concepts as informational context but do not
   count them as SOC cases.

3. **Exclude `v2_ai_jobs` from this pass.** The `incident_bytes` field
   is not a payload. If AI-assisted analyses are meant to be evidence,
   the pipeline that populates `incident_bytes` needs to be inspected
   first.

4. **First ADR should be Candidate ADR-0001 (Command-Line Obfuscation
   Coverage)** if you choose to promote anything. It has the broadest
   evidence, the clearest capability boundary, and the safest ADR
   template shape.

5. **Second ADR should be Candidate ADR-0002 (RC4 → IOC bridge)** —
   more scoped, high-yield.

6. **Do not promote Candidate ADR-0003 (IP extraction) yet.** Log one
   real T1105 case first to confirm the extraction gap is real vs
   corpus-shape artefact.

---

## 8 · What was NOT done in this pass

- ❌ No writes to `REAL_WORLD_LOG.md`
- ❌ No scorecard update in `PRODUCT_CHARTER.md §4.5`
- ❌ No CIO normalization
- ❌ No ADR drafted
- ❌ No roadmap change
- ❌ No Workspace file modified
- ❌ No NivXForge feature implemented
- ✅ Read-only queries only

---

## 9 · Awaiting your decisions

**Decision R1 — Promotion scope.** Which candidates promote to real
`REAL_WORLD_LOG.md` entries (with case numbers Case 0002, 0003, …)?
- (r1a) Only the MITRE pattern table §2 rows with "Candidate ADR? = Yes" (3 entries)
- (r1b) The full §2 table (15 entries) — each row becomes a summary
  case category rather than one-per-investigation
- (r1c) Individual per-investigation entries for a small curated
  sample (e.g. one exemplar per top-8 MITRE ID)
- (r1d) None — reject the report and refine the extraction

**Decision R2 — ADR drafting.**
- (r2a) Draft ADR-0001 (Command-Line Obfuscation Coverage) now
- (r2b) Draft ADR-0002 (RC4 → IOC bridge) now
- (r2c) Draft both
- (r2d) None — keep them as candidates only until you personally review
  the underlying investigations

**Decision R3 — Filter refinement.** Approve or amend the stronger
investigation filter recommended in §7.1?

No further action taken until you decide. 🛰️
