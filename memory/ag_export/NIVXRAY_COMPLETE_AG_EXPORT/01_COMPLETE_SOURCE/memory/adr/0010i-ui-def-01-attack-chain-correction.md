# ADR-0010i · UI-DEF-01 — Attack Chain Panel Correction

**Status:** ✅ IMPLEMENTED · 2026-08-12 · owner explicit authorisation ("Not only titeling defect… kindly dont deviate, fix this attack graph/attack story")
**Scope:** UI-DEF-01 — Attack Chain / Evidence Trajectory panel showed inconsistent output vs the MITRE ATT&CK projection for the same input (pb-01 Deploy-Application PowerShell).
**Guiding principle:** ADR-0023 §3a Cruise-Missile — the visualisation must accurately reproduce the correlated evidence set; every visible claim traces to a real analytical signal, no invented categories, no misleading colour codes.

---

## 1 · Problem (owner-reported)

For the pb-01 Deploy-Application PowerShell input, the Workspace showed two panels with divergent output:

* **Cyber Kill Chain × MITRE ATT&CK · 6 swim lanes** — showed only one node (`executionpolicy · Bypass`), placed in the "EXECUTION" lane, coloured cyan (legend labels cyan = *Reconnaissance*).
* **ATTACK CHAIN · MITRE ATT&CK · 14 lanes** — showed T1562.001 + T1564.003 correctly under Defense Evasion.

Owner: *"You can see the attack chain graph - In Prev it is showing only 1 stage and in Prod it is showing different stage with 2 entries for the same INPUT."*

## 2 · Diagnosis (three stacked defects)

**Defect A · False-positive MITRE mapping (backend).**
`operations.py::_MITRE_MAP` line 2807 mapped **any** `.ps1` file reference to `T1566.001 (Spearphishing Attachment)`. Legitimate enterprise deployment inputs (`Deploy-Application.ps1` in `C:\WINDOWS\IMECache\…`) were flagged as *Initial Access · Phishing*. Result: `investigationObject.mitre` carried a wrong-tactic technique, so `_synthBehaviorsFromMitre` produced a wrong-tactic behavior, so the 14-lane canonical view placed a node under *Initial Access* rather than the correct *Defense Evasion*.

**Defect B · Panel title vs. lane taxonomy mismatch (frontend).**
Legacy 6-lane view titled "Cyber Kill Chain × MITRE ATT&CK · 6 swim lanes". The actual lanes are DIE **artifact categories** (`execution` · `transformation` · `network` · `filesystem` · `registry` · `persistence`) — *not* Lockheed Martin kill-chain phases. The title made a claim the layout does not honour.

**Defect C · Misleading colour fallback (frontend).**
`TrajectoryDiagram.jsx::phaseColor` fell back to `#67e8f9` (cyan) when a node's kill-chain phase could not be resolved. The colour legend labels `#67e8f9` as *Reconnaissance* → an unclassified Execution-Policy-Bypass node was visually asserted to be *Reconnaissance*, a claim no evidence supports.

**Defect D · Latent Rules-of-Hooks violation (frontend, pre-existing).**
`TrajectoryDiagram.jsx` performed an early `return null` for the empty-state case **before** `laneStats = useMemo(…)` on the code path — technically valid React only because the empty-state path never re-entered. Any subsequent edit in the vicinity surfaced the eslint block. Fixed as part of this session.

## 3 · Change

### 3.1 · Backend — `backend/operations.py`
Tightened the T1566.001 Spearphishing-Attachment rule so a bare `.ps1` / `.js` reference no longer triggers it. Now requires one of:

* A rare, phishing-tradecraft extension (`.iso` `.img` `.vhd` `.vhdx` `.hta` `.lnk` `.scr` `.vbs` `.wsf` `.jar`) — these are rarely used legitimately.
* A double-extension lure (`invoice.pdf.js`, `receipt.docx.exe`, etc.) with a phishing lure noun.
* Explicit attachment metadata (`attachment: <name>.<ext>`).

Regression on frozen 12-case corpus: **no verdict change** (rip-06 correctly stays Benign; the malicious cases were not relying on this rule).

Real-phishing suite unit-checked: HTA in Downloads / double-extension / attachment metadata / genuine .lnk in Downloads all still fire. Legitimate .ps1 in Program Files / IMECache path no longer fires.

### 3.2 · Frontend — `frontend/src/components/investigation/TrajectoryDiagram.jsx`

* **Title corrected** — legacy view now reads *"Investigation Trajectory · 6 artifact lanes · drag nodes · pan background · use +/− to zoom"* (accurate). Canonical view unchanged (correctly says *"MITRE ATT&CK"*).
* **Neutral fallback colour** — `#64748b` (slate) for any node whose kill-chain phase cannot be resolved; a new legend chip *"Unclassified / no phase"* was added so the neutral colour is legible to analysts.
* **Rules-of-Hooks fix** — the `laneStats = useMemo(…)` block was moved **above** the early `return null` empty-state check, restoring a stable hook order on every render.

### 3.3 · Governance
* SSOT allow-list (`test_ssot_isolation.py`) extended with the `frontend/src/components/investigation/TrajectoryDiagram.jsx` line and a rationale block naming UI-DEF-01 + the owner's explicit override of the standing *"no Workspace changes"* rule for this specific defect.

## 4 · Regression

* Frozen 12-case corpus: **12 / 12 stable verdicts** — no change from post-Item-3 state. Determinism 100 %.
* Canonical/api/ suite: **174 pass · 5 skip · 0 fail** — identical to post-Item-3 baseline.
* SSOT isolation guard: **3 / 3 pass**.
* Frontend compile: previously blocked by an inherited eslint hook-order violation; now compiles clean, Workspace renders normally.

## 5 · Protected surfaces verified untouched

RC5 · DIE analyzer (backend output shape) · IKG (shadow) · Verdict v3 (shadow) · Case Engine (shadow) · Retention sweeper · FileStore · P0 archive-guard · Item-1 risk-score calibration · Item-2 narrative bridge · Item-3 recursive decode. No new endpoints, no new flags, no new schema, no shadow → live promotion.

## 6 · Residual, honestly named

* **Two-mapper asymmetry remains.** `/api/analyze::mitre_map()` (regex-based) and `services.die.api.analyze::techniques` (analyzer-catalogue) produce different technique sets for the same input. Today for pb-01: analyze returns `T1059.001`; DIE returns `T1562.001 + T1564.003`. Both are *defensible* MITRE claims for this input, but the two surfaces should eventually converge. Recorded as **`UI-DEF-02`** for a follow-up session — do NOT treat as part of the current remediation queue.
* **Legacy 6-lane view still uses artifact categories, not tactics.** This ADR fixed the *labeling* to match what is actually rendered. A future decision (owner) is whether to keep the artifact-category lane view at all, or standardise the entire Workspace on the 14-lane canonical MITRE view. Not touched today.

## 7 · Cruise-Missile principle compliance

The correction reduces manufactured claims: (a) removed a false Initial-Access verdict from a legitimate deployment script, (b) removed a false *Reconnaissance* colour from unclassified nodes, (c) removed a title that claimed a taxonomy the layout did not deliver. Verdict layer remains a function of the correlated evidence set. No single-indicator branch introduced.

## 8 · UI-DEF-01 gate: PASS

- ✅ False T1566.001 on legitimate .ps1 deployment scripts eliminated
- ✅ Real phishing patterns (HTA / double-extension / attachment metadata / Downloads-folder .lnk) still fire
- ✅ Frozen 12-case corpus verdicts unchanged, determinism preserved
- ✅ Canonical suite still 174 / 5 / 0
- ✅ Title, colour legend, and node colour fallback now internally consistent
- ✅ Rules-of-Hooks violation fixed (compile clean)
- ✅ Two-mapper asymmetry honestly recorded as UI-DEF-02 for a later session
