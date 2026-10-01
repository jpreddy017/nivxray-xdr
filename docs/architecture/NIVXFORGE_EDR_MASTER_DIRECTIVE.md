# NivXForge EDR — MASTER IMPLEMENTATION DIRECTIVE

> **AUTHORITY**: Owner-frozen, 2026-06. This file supersedes any earlier
> framing of this programme, including the wording *"Complete 360-Degree
> Cisco Secure Endpoint UI/UX Clone"*, which is **retired as too narrow**.
>
> The correct framing is:
>
> **"NivXForge EDR — Complete Enterprise Endpoint Security Plane, with
> Cisco Secure Endpoint operational parity as the MINIMUM baseline."**
>
> Every agent working this repository must read this file before planning.
> It is the capability contract. It is not a suggestion and its scope may
> not be shrunk to make implementation easier.

---

## 0 · THE ONE-LINE TEST

> Can NivXForge EDR independently **protect, monitor, investigate and
> respond to** an endpoint like a serious enterprise EDR?

Until the answer is yes with evidence, the programme is not done.

---

## 1 · WHAT WE ARE NOT BUILDING

- a Cisco UI clone
- a Device Trajectory mockup
- an EDR-*looking* frontend
- a collection of disconnected pages
- a synthetic telemetry demonstration
- a thin investigation console pretending to be an EDR

## 2 · WHAT WE ARE BUILDING

```
REAL ENDPOINT → SENSOR/AGENT → TELEMETRY ACQUISITION → SECURE TRANSPORT
 → RAW TELEMETRY (immutable) → PARSER/DSM → NORMALIZER
 → CANONICAL ENDPOINT EVIDENCE → EVIDENCE STORE
 → DETECTION → BEHAVIORAL ANALYSIS
 → IUE → ICE → IKG → VEEE → ENDPOINT VERDICT
 → STORYLINE / TRAJECTORY → ANALYST INVESTIGATION
 → FORENSICS / LIVE QUERY / ANALYSIS
 → RESPONSE → VERIFICATION → ENDPOINT SECURITY STATE
 ↺ NEW ENDPOINT TELEMETRY
```

The whole thing must remain compatible with, and subordinate to, the
larger NivXRay XDR architecture.

---

## 3 · RELATIONSHIP TO NivXRay XDR (non-negotiable)

NivXForge EDR must **not** become a competing architecture inside
NivXRay. It is the **endpoint specialisation** of NivXRay.

```
                    NIVXRAY XDR
                         │
      ┌──────────────────┼──────────────────┐
   NivXForge            NDR               ITDR
      EDR                │                  │
      └──────────────────┼──────────────────┘
                  CANONICAL EVIDENCE
                         │
            ┌────────────┼────────────┐
           IUE          ICE          IKG
            └────────────┼────────────┘
                        VEEE
                         │
                      VERDICT
                         │
                   SECURITY STATE
```

- **NivXForge EDR owns**: endpoint sensor, endpoint telemetry, endpoint
  operations, endpoint control plane.
- **NivXRay owns**: the shared evidence / intelligence / reasoning
  substrate.

**DO NOT create duplicate versions of**: IUE · ICE · IKG · VEEE · Verdict
Engine · Decoder · IEDDE · UAIE · Detection · Correlation · Security State
· Evidence · Provenance · Attack Story · ATT&CK · Evidence Graph ·
Reporting · Threat Intelligence. **Reuse the authoritative engines.**

---

## 4 · THREE PLANES, EXPLICITLY SEPARATED

The backend cannot pretend to be a kernel sensor. Keep these apart:

**Plane A · Endpoint Agent**

| Windows | macOS | Linux |
|---|---|---|
| Process · File · Network · Registry · Service · Driver · Persistence · User · USB · Memory · Security Controls | Process · File · Network · Endpoint Security · Persistence · User · Device | Process · File · Network · eBPF · Persistence · User · Container |

**Plane B · EDR Cloud/Backend** — Collection · Parser · Normalizer ·
Canonical Evidence · Storage · Search · Detection · IUE · ICE · IKG ·
VEEE · Verdict · Trajectory · Storyline · Threat Intelligence · Forensics
· Live Query · Response · Verification

**Plane C · Analyst/Administrator Experience** — Dashboard · Inbox ·
Overview · Events · Analysis · Device Trajectory · Process Tree · File
Intelligence · File Repository · Fleet File Trajectory · Network · Threat
Hunting · Forensics · Live Query · Malware Analysis · Threat Intelligence
· Detection · Outbreak Control · Management · Administration

Explicit **capability contracts** at the plane boundaries so any future
agent can populate the same canonical evidence model.

---

## 5 · EVIDENCE-FIRST · NEVER OVERWRITE RAW TELEMETRY

```
RAW EVENT → PARSED EVENT → NORMALIZED EVENT
 → CANONICAL EVIDENCE → DERIVED INTELLIGENCE → VERDICT
```

Each layer is additive and versioned:

```
Raw evidence + parser version + normalizer version
            + detection version + analysis version + verdict version
```

Consequence, and the reason this matters: **historical telemetry must be
replayable** after a parser, normalizer, detection or intelligence
improvement.

**Architectural correction on record**: the earlier
`sensor → v2_shadow_observations → reasoning → UI` shape is useful for the
current system but is **not sufficient as the final EDR substrate**. The
immutable raw-event layer is mandatory.

---

## 6 · CANONICAL ENDPOINT EVIDENCE MODEL

Do **not** reproduce any vendor's proprietary internal data model. Cisco,
CrowdStrike, Microsoft, SentinelOne and Cortex are **capability
benchmarks only**. Vendor telemetry is translated INTO NivXForge canonical
evidence.

```
EndpointEvidence
├── tenant_id · device_iid · endpoint_id · hostname · platform
├── sensor_version · event_id · event_time · ingest_time
├── event_type · activity_type
├── process         { process_iid, pid, ppid, image, image_path, sha256,
│                     command_line, user, integrity, signer,
│                     start_time, exit_time }
├── parent_process  { process_iid, pid, image, sha256 }
├── file            { path, filename, sha256, md5, sha1, size, type,
│                     operation }
├── network         { direction, protocol, local_ip, local_port,
│                     remote_ip, remote_port, domain, url, connection_id }
├── registry        { hive, key, value, operation }
├── user_session · persistence · usb_device · service · scheduled_task
├── detection_refs[] · ioc_refs[] · mitre_refs[]
└── provenance · parser_state · telemetry_quality · confidence · source
```

Not every platform populates every field. **That is fine.** What is NOT
fine is ambiguity. Every field must resolve to exactly one of:

```
OBSERVED · NOT OBSERVED · NOT COLLECTED · NOT SUPPORTED
PARSER FAILED · UNKNOWN
```

---

## 7 · THE EPISTEMIC MODEL · FOUR INDEPENDENT DIMENSIONS

Never collapse these into one another.

| Dimension | States |
|---|---|
| **VERDICT** | BENIGN · AUTHORIZED · SUSPICIOUS · MALICIOUS · UNKNOWN |
| **EVIDENCE** | SUFFICIENT · PARTIAL · INSUFFICIENT · CONFLICTING · UNKNOWN |
| **TELEMETRY** | HEALTHY · DEGRADED · MISSING · PARSER_FAILED · NOT_CONFIGURED · STALE |
| **DETECTION EXECUTION** | EVALUATED · MATCHED · NO_MATCH · PARTIALLY_EVALUATED · NOT_EVALUABLE · DATA_MISSING · PARSER_FAILED |

**The six inequalities that define this product:**

```
NO_MATCH        ≠ BENIGN
NOT_EVALUABLE   ≠ NO_MATCH
DATA_MISSING    ≠ NO_ATTACK
PARSER_FAILED   ≠ NO_EVENT
UNKNOWN         ≠ MALICIOUS
AUTHORIZED      ≠ BENIGN
```

---

## 8 · HONEST-STATE REQUIREMENT

Never invent: parent processes · process trees · network connections ·
file operations · response results · endpoint state · telemetry ·
detections · verdicts.

| Situation | Required rendering |
|---|---|
| Parent process unavailable | `[ROOT / PARENT NOT OBSERVED]` — never invent `explorer.exe` |
| Response capability absent | `⊘ RESPONSE DRIVER NOT REGISTERED` — never `Isolation successful` |
| Telemetry unavailable | `◇ NO EVIDENCE` |
| Parser failed | `PARSER_FAILED` + the raw event preserved |
| Field not collectable by this source | `⊘ Not collected` **+ the reason** |

**"Why is this empty?" is a first-class UI requirement**, e.g. *"Current
telemetry source does not provide file-content hashing for this
observation."* No fake values. No placeholder dashes.

Process lineage is evidence-based:

```
PARENT OBSERVED                    → verified relationship
PARENT NOT OBSERVED                → unknown lineage → ghost root
PARENT OBSERVED BUT PARSER FAILED  → lineage incomplete
                                     + telemetry-quality warning
```

Parser failure path:

```
TELEMETRY → PARSER
  ├── SUCCESS → NORMALIZE
  └── FAILURE → PRESERVE RAW EVENT → PARSER_FAILED
                → TELEMETRY HEALTH FINDING → REPLAY AFTER PARSER FIX
```

---

## 9 · DETECTION ≠ VERDICT ≠ ENFORCEMENT

```
Telemetry → Detection Fabric → Detection Event
          → IUE/ICE/IKG/VEEE → Verdict → Policy → Enforcement
```

A detection match does **not** automatically mean malicious, and
malicious does **not** necessarily mean automatic blocking.

**Three fabrics, architecturally distinguished** — do NOT make everything
a "detection engine":

```
              NIVXFORGE EDR
                    │
   ┌────────────────┼────────────────┐
DETECTION FABRIC  REASONING FABRIC  CONTROL FABRIC
 Behavioral         IUE               Policy
 Heuristic          ICE               Prevention
 IOC / TI           IKG               Enforcement
 Hash               VEEE              Response
 Signature/YARA     Verdict           Playbooks
 Custom             Storyline         Verification
 Network / DFC
 Exploit
 Persistence
 Script
 Memory / Injection
 Sequence
 Correlation
   └────────────────┼────────────────┘
              CANONICAL EVIDENCE
                    │
              SECURITY STATE
```

Application Control, Firewall/DFC and Exploit Prevention belong to the
**CONTROL** fabric (policy/prevention), not the detection fabric.

**Enforcement is policy-controlled**, and Audit Mode is still a real
detection:

```
Detection Match → Policy Evaluation
   ├── AUDIT   → Alert
   ├── PROTECT → Alert + Action
   └── PREVENT → Alert + Action
```

### 9.1 · The Detection Fabric is a fabric, not one engine

Detection is **multi-layer**. These are **capabilities**, not necessarily
separate services or microservices, and they share the common NivXRay
execution/evidence substrate where appropriate.

```
NivXForge Detection Fabric
├── Behavioral Detection Engine
├── Heuristic Detection Engine
├── IOC / TI Detection Engine
├── Signature Detection Engine
│   ├── OpenIOC
│   ├── ClamAV
│   └── other supported signature formats
├── Hash Detection Engine
├── File Property Detection
├── PE / Artifact Detection
├── Application Control Engine       ← CONTROL fabric semantics
├── Network Detection Engine
├── Firewall / DFC Engine            ← CONTROL fabric semantics
├── Exploit Prevention Engine        ← CONTROL fabric semantics
├── Persistence Detection
├── Script Detection
├── Memory / Injection Detection
├── Sequence Detection
├── Correlation Detection
├── Custom Detection Engine
└── NivXRay Detection Content Fabric
```

### 9.2 · Three things that must NEVER be collapsed into one field

| Layer | Question it answers | Values |
|---|---|---|
| **Detection** | What matched? | behavioral · heuristic · IOC · YARA/signature · custom · application control · network · firewall · sequence · correlation |
| **Conviction / Verdict** | What does the evidence establish? | BENIGN · AUTHORIZED · SUSPICIOUS · MALICIOUS · UNKNOWN |
| **Enforcement** | What should the endpoint do? | AUDIT · ALERT · BLOCK · TERMINATE · QUARANTINE · ISOLATE |

Worked example — a match that must NOT block:

```
Behavioral rule matched → Detection = MATCHED
 → Evidence = PARTIAL → Verdict = SUSPICIOUS
 → Policy = AUDIT → Alert generated → NO endpoint blocking
```

Worked example — a match that must block:

```
Malicious hash matched → Detection = MATCHED
 → Evidence = SUFFICIENT → Verdict = MALICIOUS
 → Policy = PROTECT → Process terminated → File quarantined
 → Verification telemetry
```

### 9.3 · The event model — NOT `detected = true/false`

Every detection outcome must carry these as **separate fields**:

```
detection_state       (EVALUATED · MATCHED · NO_MATCH · PARTIALLY_EVALUATED
                       · NOT_EVALUABLE · DATA_MISSING · PARSER_FAILED)
policy_mode           (AUDIT · PROTECT · PREVENT)
enforcement_action    (none · alert · block · terminate · quarantine · isolate)
enforcement_result    (not attempted · dispatched · acked · executed
                       · failed · verified · unverified)
```

**AUDIT mode is NOT "no detection."** `Rule matched + Policy = AUDIT`
means Detection: MATCHED · Alert: YES · Telemetry: YES · Prevention: NO.

### 9.4 · Policy sits BETWEEN detection and enforcement

Policy evaluation must consider: rule · detection type · endpoint ·
endpoint group · OS · user · file/application · disposition · confidence ·
evidence sufficiency · current Security State · policy mode ·
exception/allowlist.

### 9.5 · Detection lifecycle, made explicit

```
CONTENT → VALIDATION → REGISTRATION → ENGINE BINDING → DEPLOYMENT
 → TELEMETRY EVALUATION → MATCH / NO_MATCH / NOT_EVALUABLE
 → DETECTION EVENT → POLICY → ALERT / PREVENTION
 → IUE / ICE / IKG / VEEE → VERDICT → INVESTIGATION → RESPONSE
 → VERIFICATION
```

This preserves the existing Engine Registry distinction:

```
ENGINE ≠ CAPABILITY ≠ EXECUTION PATH

ENGINE → CAPABILITIES → SUPPORTED CONTENT → EXECUTION PATH
       → VALIDATION → READY
```

> **A rule firing is an observation/detection. It is NOT automatically the
> final verdict.** The existing NivXRay IUE/ICE/IKG/VEEE/Verdict machinery
> remains responsible for the deeper evidence-based determination.

### 9.6 · Playbook Engine — a first-class EDR capability

Playbooks are an **EDR automation/orchestration layer**, not merely a
SOAR/XDR feature.

```
Detection Event → Policy Evaluation → PLAYBOOK ENGINE
   ├── TRIAGE & ENRICHMENT   reputation (hash/IP/domain TI), process tree,
   │                         PID/PPID, command line, user context,
   │                         sockets/network, endpoint state, sandbox
   ├── DECISION & ESCALATION conditions, severity, confidence, enterprise
   │                         baseline, allow/exception context, evidence
   │                         sufficiency, escalation, FP handling
   ├── ENDPOINT RESPONSE     isolate, terminate process/process tree,
   │                         quarantine, remove persistence, scan,
   │                         block hash/application/IP, restore/remediate
   └── EXTERNAL / FLEET      identity containment, firewall blocking,
                             DNS/SWG blocking, fleet-wide hash enforcement,
                             ticketing/audit
   → VERIFICATION → NEW TELEMETRY ↺
```

**External/fleet actions are documented in the EDR architecture but
implemented as integration-capable actions — never assumed to be
available inside the endpoint itself.**

The governing rule is:

```
Detection → Playbook → Action → Verification
```

and **never**:

```
Detection → blindly execute action
```

Policy mode (Audit vs Protect/Prevent) remains **distinct from** the
playbook itself.

---

## 10 · RESPONSE MUST CLOSE THE LOOP

Every action, without exception:

```
REQUEST → AUTHORIZATION → POLICY → APPROVAL → DISPATCH
 → ENDPOINT ACK → EXECUTION → TELEMETRY → VERIFICATION
 → SECURITY STATE ↺ NEW TELEMETRY
```

Every action records: **requested_by · approved_by · policy · playbook ·
target · action · timestamp · status · result · evidence · verification**.

**Never report success without endpoint evidence.** If the endpoint cannot
perform the action, the honest output is `⊘ RESPONSE DRIVER NOT
REGISTERED`.

Actions in scope: Isolation · Release Isolation · Kill Process ·
Quarantine · Delete · Restore · Scan · File Fetch · Remediation ·
Application Control · Network Block.

---

## 11 · CISCO SECURE ENDPOINT BASELINE — PRESERVE ALL OF IT

Surfaces: Dashboard · Inbox · Overview · Events · Analysis · Device
Trajectory · Process Tree · File Intelligence · File Repository · Fleet
File Trajectory · Computer Management · Outbreak Control · Policies ·
Groups · Connector Diagnostics · Endpoint Health · Response.

Trajectory interaction model (**do not break existing D3 mathematical
behaviour**): 30-day macro navigator · 24-hour micro scrubber ·
event-density visualisation · fit-to-observations · process swimlanes ·
continuous lifelines · orthogonal parent-child links · honest ghost roots
· IOC bands · contributing-node highlighting · activity inspector ·
millisecond timestamps · SHA-256 pivots.

**The 43-item filter taxonomy is the MINIMUM.** Categories: Activity ·
System · Disposition · Flags · File Types. **Do not remove any item.**
NivXForge extends it with: Process · File · Network · DNS · Registry ·
Service · Scheduled Task · Persistence · Identity · USB · Driver · Module
· Memory · Container · Browser · Cloud · Sensor · Response · Detection ·
MITRE. **43 filters = baseline, not ceiling.**

### SHA-256 as the universal EDR pivot

Cisco baseline: Copy · Search · Disposition · Filename · Threat
Intelligence · Detection Count · Malware Family · File Fetch · File
Repository · File Analysis · File Trajectory · Simple Detection · Block
Application · Allow Application.

NivXRay extension: Static Analysis · Decoder · YARA · Malware Family ·
ATT&CK · Threat Intelligence · Sandbox · Endpoint prevalence · First seen
· Last seen · Fleet propagation · Related processes · Related users ·
Related incidents · Response history.

### Fleet File Trajectory

```
        SHA-256
   ┌───────┼───────┐
 Host A  Host B  Host C
 09:10   09:18   09:42
   └───────┼───────┘
     PROPAGATION MAP
   ┌───────┼───────┐
 Patient  Lateral  Last
  Zero    spread   seen
```

first seen · last seen · observation count · entry point / patient zero ·
matching computers · OS · group · Device Trajectory link · isolation
state.

### File Repository is a state machine, not storage

```
FILE REPOSITORY: Available · Requested · Processing · Failed · Rejected
        → FILE OBJECT { Hash, Metadata, Provenance }
          → Static Analysis · Decoder · YARA · Sandbox · Threat Intel
            · Detection · Fleet Trajectory · Response
```

### Computer Management is a real control plane

Filters: Installed · Not Seen · AV Update · Connector Update · Fault ·
High Risk. Actions: Isolation · Scan · Diagnose · Move Group · Remote
Uninstall — each through the §10 loop. **Not buttons that call a fake
API.**

### Outbreak Control (extended)

Hash Block/Allow · Certificate Block/Allow · Application Block/Allow · IP
Block/Allow · Domain Block · URL Block · YARA · Behavioral Rule · Exploit
Rule · Device Isolation · Fleet Remediation.

```
Policy → Scope → Approval → Deployment
      → Endpoint acknowledgement → Enforcement telemetry → Verification
```

---

## 12 · MALWARE ANALYSIS — ARTIFACT-FIRST, REUSE THE ENGINES

```
Artifact → Artifact Router → Static Analysis
 → Decoder / Embedded Artifact Extraction → YARA / intelligence
 → Runtime Required? → Sandbox → Dynamic Evidence → Merge → Verdict
```

Do not duplicate the decoder or the semantic engines.

---

## 13 · VERTICAL IMPLEMENTATION — THE ONLY ALLOWED SHAPE

**WRONG**: build UI → mock API → synthetic data → next page.

**REQUIRED** — every slice:

```
CAPABILITY CONTRACT → TELEMETRY CONTRACT → AGENT/FIXTURE
 → INGESTION → PARSER → NORMALIZER → CANONICAL EVIDENCE
 → BACKEND → DETECTION/INTELLIGENCE → API → UI
 → RESPONSE (if applicable) → VERIFICATION → E2E TEST
```

Do **not** build disconnected UI pages.

---

## 14 · FEATURE STATE — NEVER HIDE INCOMPLETE STATE

Every capability carries an explicit implementation truth:

```
NOT IMPLEMENTED · CONTRACT DEFINED · BACKEND IMPLEMENTED
UI IMPLEMENTED · SYNTHETIC VALIDATED · GOLDEN-CORPUS VALIDATED
REAL ENDPOINT VALIDATED · END-TO-END VALIDATED · OPERATIONAL
PRODUCTION READY
```

Plus a gap classification: `UI ONLY` · `BACKEND ONLY` · `SCAFFOLD` ·
`TELEMETRY MISSING` · `CONTROL/DRIVER MISSING`.

---

## 15 · IMPLEMENTATION WAVES

**Wave 0 — Architecture & contracts.** Build nothing superficial.
Establish: Endpoint Identity · Telemetry Schema · Process Identity · File
Identity · Network Identity · Event Identity · Evidence Identity ·
Response Command · Response Result · Telemetry Health · Capability
Registry · Sensor Capability Registry.

**Wave 1 — Process EDR** (must work E2E): Process Start · PID · PPID ·
Image · Hash · Command Line · User · Signer · Start/Exit · Parent/Child ·
Process Tree · Device Trajectory · Detection · Verdict · Investigation.

**Wave 2 — File EDR**: Create · Modify · Move · Copy · Execute · Delete ·
Hash · Path · Type · File Repository · Fetch · Static Analysis · File
Trajectory · Fleet File Trajectory · Blocklist · Allowlist.

**Wave 3 — Network EDR**: Connection · DNS · IP · Port · Protocol ·
Direction · Domain · URL · Process↔Network · IOC · Network Detection ·
Trajectory · Block/Allow.

**Wave 4 — Persistence/System**: Registry · Services · Scheduled Tasks ·
Startup · Launch Agents · Drivers · Cron · System Extensions ·
Persistence detection.

**Wave 5 — Identity/User**: User · Session · Logon · Privilege · Token ·
Remote Session · Process↔User · User↔Endpoint.

**Wave 6 — Endpoint response**: Isolation · Kill · Quarantine · Delete ·
Restore · Scan · Fetch · Remediation · Application Control · Network
Block — each through the §10 loop.

**Wave 7 — Forensics**: Forensic Snapshot · Live Query · process/file
inventory · network connections · services · scheduled tasks · startup ·
users · PowerShell · browser artifacts · USB · memory metadata.

**Wave 8 — Malware analysis**: per §12.

**Wave 9 — Advanced detection**: IOC · Sigma · YARA · Behavioral ·
Sequence · Correlation · Anomaly · ATT&CK · Custom Detection · Detection
Testing · Detection Lifecycle.

**Wave 10 — Fleet operations**: Fleet File Trajectory · Fleet Process
Search · Global IOC Search · Prevalence · Patient Zero · Lateral
Propagation · Fleet Response · Outbreak Control.

### Dependency order (unless repository evidence proves better)

1. Endpoint contracts · 2. Process telemetry · 3. Process Tree ·
4. Device Trajectory · 5. File telemetry · 6. File Repository ·
7. File Trajectory · 8. Fleet File Trajectory · 9. Network telemetry ·
10. Network investigation · 11. Persistence/system telemetry ·
12. Identity/user telemetry · 13. Endpoint health · 14. Forensic Snapshot
· 15. Live Query · 16. Malware Analysis integration · 17. Response
framework · 18. Outbreak Control · 19. Detection engineering ·
20. Fleet operations · 21. Final EDR validation

---

## 16 · TESTING — EVERY SLICE, THIRTEEN CASES

benign · suspicious · malicious · ambiguous · false positive · missing
telemetry · partial telemetry · parser failure · unknown parent ·
conflicting evidence · late telemetry · response failure · response
verification failure.

**No feature is operational until its E2E path is proven.**

---

## 17 · ABSOLUTE RULE

**DO NOT**: fake telemetry · invent process trees · invent network
connections · invent response results · hide missing drivers · replace
backend functionality with mocks · declare UI completion as EDR
completion · delete existing NivXRay engines · duplicate existing
intelligence engines · reduce the supplied Cisco baseline · skip
capabilities because they are difficult.

Build the complete architecture incrementally through fully validated
vertical slices.

> **The target is a real NivXForge EDR, not an EDR simulation.**

---

## 18 · THE GOVERNING PRINCIPLE

> **Full architecture now. Full capability inventory now. Full contracts
> now. Incremental implementation. No fake completion.**

The engineering risk of the full target is real. The answer is **not** to
shrink the target.

```
FULL TARGET → COMPLETE ARCHITECTURE → COMPLETE CAPABILITY MAP
 → CANONICAL CONTRACTS → VERTICAL E2E SLICES
 → Process · File · Network → SYSTEM/IDENTITY
 → FORENSICS/LIVE QUERY → MALWARE ANALYSIS
 → RESPONSE → VERIFICATION → REAL ENDPOINT TEST → OPERATIONAL
```

The operational spine to preserve and then expand: Dashboard / Inbox /
Management converge into **Device Trajectory**, then **SHA-256** pivots
into **Fleet File Trajectory** or **Endpoint Response**, and finally into
the **Central File Repository**.
