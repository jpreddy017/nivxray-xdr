# CISCO XDR AUDIT DELTA — from `XDR.pptx` (76 slides)

**DELTA ONLY.** The MASTER audit was not restarted and no matrix was
duplicated. `MASTER_OWNERSHIP_AUDIT.md`, `MASTER_PARITY_MATRIX.md` and
`MASTER_GATE.md` remain the baseline. Everything the baseline already
covers and evidences is **OMITTED** below, per your rule 10.

Source: the uploaded Cisco XDR deck, read slide-by-slide from the
extracted `ppt/slides/*.xml` text (no Cisco code, implementation or asset
was copied — only observable behaviour and terminology were read).

---

## 1 · ALREADY COVERED → OMITTED

| Your delta section | Where the baseline already covers it | Verdict |
|---|---|---|
| **1 · Cisco ownership delta** | Matrix 2 §2.1/§2.2 assign every engine and UI surface to XDR / EDR / SHARED, and §2.2 already flags the three cases where an **EDR** capability is displayed in XDR *without* ownership transferring (`edr-enrollment`, `edr-response`, `edr-capability-truth`, plus Fleet File Trajectory) | **OMITTED** — the "displaying EDR data in XDR does not transfer ownership" rule is already applied |
| **3 · Detection ownership** | The deck's chain `endpoint telemetry → EDR detection → XDR ingest → analytics/correlation → prioritisation → incident` matches Matrix 2 exactly: `detection_content` is graded `SHARED — XDR authors, EDR consumes`, `edr_plane/canonical_bridge` is the ingest bridge, and no second detection engine exists | **OMITTED** — one detection fabric, already proven |
| **4 · Response ownership** | Findings **F-3** and **F-5** already split XDR (recommendation/orchestration/approval/playbooks/automation/audit) from EDR (execution/isolation/quarantine/termination/verification), and the worklist already forbids claiming success from an orchestration record | **OMITTED** |
| **5 · Endpoint / Orbital-like** | Matrix 2 §2.2 + Matrix 1 §2.3 already keep Device Trajectory, process tree, endpoint detections, files, health, hunting, forensics, live query and endpoint response **EDR-owned**, and already record the `Computers` conflict | **OMITTED except D-8** below |
| **6 · Case / Casebook** | `MASTER_GATE` + Matrix 2 already establish `v2/case_engine` + `workspace_cases` (561 rows) as the **only** case engine, and M-7 already forbids a second one | **OMITTED except D-6** below |
| **7 · Integration chain** | Matrix 2 already audits vendor auth (`/api/xdr/secrets`, `xdr_vendor` connections) → collector (F-4) → parser/normaliser → canonical ingest → events → correlation → incident → investigation → orchestration (F-5) → source-product execution → verification → evidence/audit | **OMITTED except D-13** below |
| **8 · Orphan vs legacy** | Already the audit's central distinction. `apps/nivxray-xdr-collector` = **ORPHAN, running** (F-4); `apps/nivxray-xdr-response` = **ORPHAN, implemented, unwired** (F-5); `apps/nivxray-xdr/` = the **live** product build (not legacy, not orphan); `backend/nivxforge/` = `LEGACY-DUPLICATE · PARTIALLY REUSED` **with evidence** (superseded by `v2/investigation`; one production import + one registered router still depend on it → do not wire, do not delete) | **OMITTED** — none of the four was auto-labelled legacy |
| **2 · Multi-source check** | Partially covered (B-1 / `G-16`) — see **D-3**, which upgrades it | **UPGRADED, not repeated** |
| **9 · Parity delta** | Matrix 1 covers 38 XDR + 17 EDR rows and marks 11 + 12 surfaces `REFERENCE_CAPTURE_REQUIRED` | **UPGRADED by D-1, D-5, D-7, D-9, D-10, D-11, D-12** |

**The deck validates the architecture rather than challenging it.** Its
`INGEST (Parsing · Telemetry Enrichment · Maps to Schema) → DETECT
(Analytics · Cross Correlation · Alert Prioritization · Scheduled
Searches and Custom Detection) → RESPOND (Automated Workflow · Surgical
Response · Triage and Decisioning)` is the same separation the two-product
lock already encodes. **No ownership decision in the baseline is
contradicted by the deck.**

---

## 2 · NEW AUDIT GAPS

### D-1 · The priority score is **specified**, and it invalidates one of our BLOCKED reasons
The deck states the formula outright:

```
Priority Score = Detection Risk × Asset Value          (0 – 1000)
Detection Risk = MITRE TTP Financial Risk
               + Number of MITRE TTPs
               + Source Severity                        (0 – 100)
Asset Value                                             (0 – 10)
```
and, on the Devices slide, that the device inventory *"allows defining a
device's **value**, which is used when scoring XDR incidents."*

**Consequence:** `MASTER_PARITY_MATRIX` `S-7` and Matrix 3 `B-8` record
asset value as **`BLOCKED` — no source**. That is **wrong**. Cisco's asset
value is a **user-defined field on the device record**, not collected
telemetry. `S-7`'s asset-value component must be reclassified
`BLOCKED → MISSING` (implementable without any new collector). The
*other* `B-8` columns (Vulnerabilities, Security Risk Score, Managed,
multi-vendor Sources) remain genuinely `BLOCKED`.
**Gap:** we have no audit row for a user-definable device value, nor for
whether our priority band `P1…P5` can express a 0–1000 score.

### D-2 · "Attack chain" is a **distinct object between alert and incident** — we never audited whether ours is
The deck's incident-evaluation process is explicit:
`Detection logic → alerts → alerts are correlated to form **attack
chains** → attack chains **might qualify** for incident creation → asset
resolution with **Device Insights** → asset enrichment → observable
enrichment → **scoring** → **recommend actions** → incident store`.

We hold `services/attack_graph`, `services/attack_story`,
`/api/correlations` and `xdr_correlation`. **Un-audited:** whether an
authoritative *attack-chain* object is persisted between alert and
incident, whether incident creation is **gated** on chain qualification,
and which of our **three** correlation surfaces owns that gate (Matrix 2
already flags the three as an unresolved ownership question). Also
un-audited: `Recommend Actions` as a **pipeline stage** (we only audited
response as a UI/service plane) and `Device Insights` as an
**incident-evaluation input** rather than a page.

### D-3 · Per-domain telemetry coverage — the baseline audits "a second domain" generically
The deck names the domains and, critically, names **per-domain detection
producers**: `Endpoint Detections · Firewall Log Detections · NVM
Detections · Cloud Flow Detections · Network Flow Detections`, over
`Endpoint · Network · Email · Identity · Firewall · Cloud · third-party ·
threat intelligence`.

`B-1`/`G-16` treats this as one blocker. **Gap:** there is no per-domain
coverage row, so we cannot state which domain is missing versus merely
un-normalised. **This is the audit row that decides F-4's open question:**
whether the real CEF/LEEF syslog stream (35 delivered) is a genuine
**second domain** (e.g. firewall) or merely **another transport carrying
endpoint telemetry**. Per your instruction, `G-16 / FLOW-5` stays
`BLOCKED` until that per-domain determination is evidenced.

### D-4 · **Judgements** are a first-class object we do not have
Threat Intelligence is presented as `Judgements · Feeds · Indicators ·
Events` with *"create and customize your own feeds"*, and the pivot menu's
first listed action is *"**Creating a judgement**"*.

We have verdicts and dispositions, but a **judgement** — an analyst-asserted,
time-bounded disposition on an *observable*, reusable across
investigations — is a different object. **Gap:** un-audited whether
`/api/corrections/*` (analyst correction lab, already `SHARED ·
adopted-in-product`) or `/api/verdict/*` is the existing implementation to
**adopt**. Also un-audited: user-created intel **feeds**.

### D-5 · The ribbon's contents are now **specified**
*"Use the ribbon to access the **casebook, apps, settings, search
observables for enrichment, view notifications, and view incidents**."*
Our `V-5`/`N-5` rows say only "bottom-left pill with badge". **Gap:** six
concrete ribbon capabilities, one of which (**observable search for
enrichment**) is a functional surface, not chrome — and one
(**notifications**) is the `V-4` bell we already record as missing.

### D-6 · **Worklog** is Cisco's notes surface — so `M-1` may be an ORPHAN, not MISSING
The deck describes the Worklog as *"a history of the actions taken on the
incident, including the execution of automated response actions in the
response playbook"*, plus posting notes and collaboration.

Matrix 3 `M-1` records incident **notes** as `MISSING` because
`/api/incidents/:id/notes` does not exist. But `MASTER_GATE` states the
Casebook must project onto the **existing `workspace_cases`/worklog**.
**Gap:** un-audited whether that worklog store already persists analyst
notes and response-action history. If it does, `M-1` is an **ORPHAN
(adopt)**, not a build — exactly the confusion this programme exists to
prevent. Also new: the Casebook is defined as *observables + analyst
notes*, shareable, **plus a browser extension** (the extension is
genuinely `MISSING` and, in my view, out of product scope).

### D-7 · Detection tab has an **"Important only"** filter with a published definition
Filters by *type, product and severity*, plus an **Important only**
toggle, where "important" means a detection whose *target or indicator is
a first encounter*, **or** severity is high/critical, **or** it *contains
MITRE ATT&CK data*. **Gap:** no parity row exists for it, and it is a
**derivable** rule over data we already hold (first-encounter, severity,
MITRE presence) — so it is `MISSING`, not `BLOCKED`.

### D-8 · XDR needs an **entry point** into endpoint live query — ownership stays EDR
*"Pre-built queries executed from the XDR **ribbon**"* and *"Refresh from
**Orbital Live Query**"* on the XDR Devices page. Matrix 1 records live
query as EDR `NOT_IMPLEMENTED`; there is **no row** for the XDR-side entry
point. This validates your rule 5 exactly: XDR **invokes**, EDR **owns
and executes**.

### D-9 · Control Center dashboards are **shareable**
*"Multiple dashboards… single product or mixed… **shareable with other
users**… customizable timeframe."* `V-20`/`I-12`/`I-13` cover multi-tab,
customisable and time-ranged but **not sharing**.

### D-10 · Investigate: **targets vs assets** classification is absent from our audit entirely
*"Classification of **targets** versus **assets**"*, colour-coded
observable dispositions, **saved** investigations, a **dynamic timeline**
to filter events by date/time range, and built-in response via pivot
menus. `V-11`/`S-1`/`S-3`/`I-4` cover the Investigate landing page; the
**target-vs-asset** distinction is a semantic concept we have never
audited.

### D-11 · Reference **ambiguity** in the response-playbook stage labels
The deck says `Identify · Contain · Eradicate · Recover` (SANS PICERL);
the R2 capture in `Y0` says `Identification · Containment · Eradication ·
Recovery`. Observable parity is about the **rendered** label, so this
cannot be guessed → `REFERENCE_CAPTURE_REQUIRED` on the Response tab
label set.

### D-12 · Automation rules have **five named types**, one of which is Approval
`Approval Task Rule · Email Rule · Incident Rule · Schedule Rule ·
Webhook Rule`. `F-5` treats "playbooks / automation rules / approvals"
generically. New detail: **Approval is itself an automation-rule type**,
which shapes the F-5 approval lifecycle you locked. We already hold
`xdr_webhooks` (real) — a **Webhook Rule** may be partly adoptable rather
than new.

### D-13 · Integration-chain stage genuinely absent: a **non-endpoint** source product
The deck lists cross-product response actions: *isolate hosts, block IPs
on firewalls, block hostnames in DNS, quarantine messages in a mailbox*.
Our chain is complete **only** for the endpoint product. **Gap:** the
stages `source-product API → source-product execution → verification` have
**exactly one** implementation (EDR). This is the same dependency as
`B-1`, now expressed on the response side as well as the telemetry side.

---

## 3 · OWNERSHIP AMBIGUITIES (new, unresolved — no decision taken)

| # | Ambiguity | Why the deck raises it |
|---|---|---|
| A-1 | **Attack chain** — XDR-owned (cross-source correlation) or an artefact of whichever of our three correlation surfaces wins? | the deck makes it a distinct, named stage between alert and incident |
| A-2 | **Device value** — an EDR inventory attribute or an XDR scoring input? | the deck puts the field on the **XDR** Devices page but feeds it into **XDR** incident scoring; our device inventory is EDR-owned per D-4 of the product lock |
| A-3 | **Judgement** — XDR threat-intel plane, or the existing shared correction/verdict plane? | the deck lists it under Threat Intelligence *and* as a pivot-menu action |
| A-4 | **Worklog** — is it the XDR incident record's own history, or a projection of `workspace_cases`? | the deck merges notes + automated-response history into one surface |
| A-5 | **Live query entry point** — an XDR ribbon app that invokes EDR, or an EDR surface deep-linked from XDR? | the deck executes it *from the XDR ribbon* against an endpoint-owned engine |

---

## 4 · ADDITIONAL EVIDENCE REQUIRED

The deck is an **architecture and capability** reference, not a set of
pixel captures. It therefore **cannot** close any
`REFERENCE_CAPTURE_REQUIRED` row, and I have closed none.

Still required, unchanged: the 11 XDR surfaces and 12 EDR surfaces listed
in `MASTER_PARITY_MATRIX` §1.8 and §2.4. The deck **adds** these as newly
needed captures: the **ribbon expanded** (its six contents), the
**Casebook** panel, the **Detection tab** with the *Important only*
toggle, the **Threat Intelligence** page (Judgements/Feeds/Indicators/
Events), **Automate** rule types, the **Devices** device-value control,
and the **Response tab** stage labels (D-11).

---

## 5 · NEW WIRING CANDIDATES — `EXISTING A → EXISTING B`, review only

Appended to the existing worklist; **not** approved, **not** started.
Nothing here proposes rebuilding a capability.

| P | Candidate | Existing A → Existing B | Note |
|---|---|---|---|
| **P2** | **Worklog adoption instead of a notes build** (D-6) | `v2/case_engine` + `workspace_cases` worklog → XDR incident record `Notes`/`Worklog` tab | **audit first**: if the worklog already persists notes + action history, `M-1` is an adoption, not a build. Do **not** create an `/api/incidents/:id/notes` store before this is settled |
| **P2** | **Judgement plane** (D-4) | `/api/corrections/*` (already `SHARED · adopted-in-product`) or `/api/verdict/*` → the observable pivot menu's "create judgement" action | adopt the existing analyst-assertion path; do **not** author a third disposition engine |
| **P3** | **Important-only detection filter** (D-7) | existing detection derivations (severity + MITRE + first-encounter) → incident Detection tab | derivable from data we already hold; no new store |
| **P3** | **User-definable device value** (D-1) | `edr_endpoints` record → XDR incident scoring | resolves ambiguity **A-2** first; reclassifies `S-7`'s asset component `BLOCKED → MISSING` |
| **P3** | **XDR ribbon entry point into endpoint live query** (D-8) | XDR ribbon → EDR live-query capability (currently `NOT_IMPLEMENTED`) | the entry point must **not** be built before the EDR engine exists, or XDR will advertise a capability that cannot execute |
| **P3** | **Webhook automation rule** (D-12) | existing `xdr_webhooks` (real, reachable) → the F-5 automation-rule surface | sequence **after** F-5; one of five rule types may already be adoptable |
| **—** | **Attack-chain gate audit** (D-2) | `services/attack_graph` / `attack_story` / `xdr_correlation` → incident creation | **audit, not wiring** — must resolve ambiguity A-1 and the three-correlation-surface question before any Y3/Y4 work |
| **—** | **Per-domain telemetry coverage row** (D-3) | — | **audit, not wiring**. Blocks nothing, but it is the row that decides whether F-4's CEF/LEEF stream can ever satisfy `G-16` |

---

## 6 · STOP

Delta complete. **No matrix was duplicated, no finding repeated, no
ownership decision changed, nothing implemented, nothing wired, nothing
deleted, no telemetry or runtime evidence fabricated.** One baseline
**correction** is proposed and flagged rather than applied: `S-7`/`B-8`
asset value is `MISSING`, not `BLOCKED` (D-1).

`G-16 / FLOW-5` remains `BLOCKED ·
REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED`, and per your instruction will not
be re-evaluated until F-4 establishes **what domain** the real CEF/LEEF
stream actually represents.
