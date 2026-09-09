# ADR-005 · Pre-Phase-5 Functional Acceptance Report

- **Status**: **HALT — Phase 5 NOT authorised.** MITRE evidence = 0 on real Sample.docx after full canonical lifecycle. Root cause diagnosed. No MITRE logic modified (per directive).
- **Directive** (2026-08-10): items 1-12 of the "one more proof" gate before Phase 5 authorisation.
- **Do NOT**: enable ARTIFACT_SPLIT · enable THREAT_INTEL_ENRICH oracle · add provenance UI · start Phase 5 · touch `routers/cases.py`, Workspace, Wave 1, Engine A, Sample1.

## 1 · Sample.docx canonical lifecycle — evidence

| Metric | Value | Item |
|---|---|:-:|
| Sample.docx SHA256 | `3915b712ed7f2a591b93f42f3597b40b4c5684f7c630902061e95c3b748623a7` | — |
| Sample.docx bytes | 40 786 | — |
| Parent SSOT ref | `cssot:sha256:58627409…20633d` | — |
| Parent fingerprint | `58627409835a9aaca29eec86af8f4f5e2f589a6de3afaf60168ee3a4c820633d` | — |
| **Parent → child ssot_ref** | 19 total (16 TEXT_EXTRACT populated · 3 legacy placeholders) | ✅ 1 |
| **word/document.xml child ssot_ref** | `cssot:sha256:5970886ee5e9cf1fde0f5fcfb3cdd9056185b90384149688369dbe0ea42526ae` | ✅ 2 |
| Child provenance-complete | ✅ (SSOT provenance + all nodes + trace + reasoning) | ✅ 2 |
| **Child IOC evidence** | **73 nodes** — 52 URLs · 13 IPs · 6 SHA256 · 2 MD5 | ✅ 3 |
| **Child MITRE evidence** | **0** | ❌ 4-5 |
| Child Attack Chain stages | 0 (correctly follows MITRE = 0) | ⚠️ 6 |
| Child Attack Story | Populated header/closing · **0 chapters** (correctly follows MITRE = 0) | ⚠️ 7 |
| Child project_recommendations | items = 0 · note = `"no evidence-derived recommendations for this case (no MITRE evidence)"` · **banned tokens absent** | ✅ 8 (P4-FW3 holds) |
| Child Analyst Summary | Populated · verdict `SUSPICIOUS` conf 68 · prose derived from IOC evidence | ✅ 9 (partial — no MITRE) |
| Child Executive Summary | Populated · severity `high` · oneliner `"No MITRE technique evidence in canonical SSOT."` | ✅ 9 (partial — no MITRE) |
| Generic IMMEDIATE/THREAT HUNTING/CONTAINMENT anywhere | **absent** across all 15 projections | ✅ 10 |
| Determinism | Parent **10/10** · child (word/document.xml) **10/10** | ✅ 11 |
| P4 projection boundary | 0 mutations to authoritative fields (parent + child fingerprints unchanged after 15-projection sweep) | ✅ 12 |

## 2 · Root-cause diagnostic — why MITRE = 0

The child SSOT input_raw is the real `word/document.xml` (195 600 bytes; ~11 839 chars of visible paragraph text after tag-strip).

The **actual textual content** of Sample.docx is a **narrative incident report**:

> *"On 2026-07-29 22:02:41 UTC Cisco XDR detected the execution of a known malicious file via Secure Endpoint which warrants additional investigation on azg51-checkin-1. This investigation involved detections from the following integrations: Cisco Secure Endpoint. This is a high priority alert because the detected file is a Remote Access Trojan (RAT) and has executed on at least one device …"*

The **current canonical MITRE_MAP capability** (`_cap_mitre_map` in `backend/canonical/executor/capabilities/__init__.py`) is a **shell/command needle-match** rule:

```
T1059.001 (PowerShell)           : ["powershell", "-encodedcommand", "-e "]
T1059.003 (Windows Command Shell): ["cmd /c", "cmd.exe"]
T1218.010 (Regsvr32)             : ["regsvr32"]
T1218.011 (Rundll32)             : ["rundll32"]
T1105     (Ingress Tool Transfer): ["certutil -urlcache", "curl ", "wget "]
```

Substring count in word/document.xml (case-insensitive):

| Technique | Needle hits |
|---|---|
| T1059.001 | **0** — no `powershell` / `-encodedcommand` / `-e ` |
| T1059.003 | **0** — no `cmd /c` / `cmd.exe` |
| T1218.010 | **0** — no `regsvr32` |
| T1218.011 | **0** — no `rundll32` |
| T1105 | **0** — no `certutil -urlcache` / `curl ` / `wget ` |

**MITRE_MAP is functioning exactly as designed. Sample.docx does not carry the shell-command signatures the current needle-set was written to detect** — it carries a *narrative description* of an incident (Cisco XDR / RAT / Secure Endpoint / azg51-checkin-1) using vendor-report language.

### What Sample.docx *does* contain that a stronger MITRE mapper would use

| Term (in paragraph text) | Suggestive MITRE tactic/technique |
|---|---|
| "Remote Access Trojan (RAT)" · "execution of a known malicious file" | Initial Access / Execution |
| "Cisco XDR" · "Cisco Secure Endpoint" (vendor telemetry) | Detection surface, not attacker technique |
| "azg51-checkin-1" (hostname) | Host asset — no direct MITRE mapping |
| "high priority alert" | Severity signal, not technique |

None of these are in the current needle set. Adding them would **change MITRE logic**, which you explicitly forbade.

## 3 · Consequence for Phase 5 authorisation

The canonical pipeline **does now recursively discover** Sample.docx's hidden textual content — that's the material win of Phase 3.x, proven by the 73 child-IOC nodes.

However, per the strict directive:

> *"IOC success alone is NOT sufficient to authorize Phase 5. If MITRE evidence is still zero, STOP and report the exact reason. Do not modify MITRE logic unless separately authorized."*

**Therefore: STOP.**

If `routers/cases.py` were migrated today, a Workspace user re-investigating Sample.docx would see:
- ✅ 73 IOCs (52 URLs / 13 IPs / 8 hashes)
- ✅ Analyst summary (`SUSPICIOUS conf 68`)
- ✅ Executive summary
- ✅ P4-FW3 no-fallback (empty recommendations + honest note)
- ❌ **Zero MITRE / zero Attack Chain / zero Attack Story chapters / zero evidence-derived Recommendations**

That would ship the architectural win **while still leaving the exact Workspace defect the whole ADR-005 effort was meant to close.**

## 4 · Sample1 golden refresh

- **Deferred to Sample1-hosting pod** — this pod does not host `workspace_cases.id = 3db79c4a-088b-4df7-b65a-f68b367b7677`.
- Fingerprint preserved unchanged: `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d`.
- No modification / re-save / re-investigation of Sample1 attempted from this pod.
- Tests `test_px_9_sample1_fingerprint_unchanged` and `test_a4_2_sample1_fingerprint_unchanged` are `pytest.skip()`-guarded when the row is absent — they must be executed on the Sample1-hosting pod before Phase 5 authorisation.

## 5 · Hard-boundary compliance

| Boundary | Verified |
|---|:-:|
| `routers/cases.py` untouched | ✅ |
| Workspace UI untouched | ✅ |
| MDR pipeline untouched | ✅ |
| Engine A / canonical verdict scoring untouched | ✅ |
| Wave 1 records untouched | ✅ |
| Sample1 row untouched | ✅ |
| MITRE algorithm untouched | ✅ (`_cap_mitre_map` needle-set is byte-identical to Phase 3 exit) |
| IOC algorithm untouched | ✅ |
| Projection code untouched | ✅ |
| No ARTIFACT_SPLIT enabled | ✅ (still in plan for docs, but plug-in remains unregistered → runs as `skipped`) |
| No THREAT_INTEL_ENRICH oracle wired | ✅ (still deterministic no-op) |
| No diagnostic route added | ✅ |
| Phase 5 not started | ✅ |

## 6 · Recommended options for the owner (each requires explicit authorisation)

Presented as options only — **none started**:

- **Option A · Author narrative-friendly MITRE_MAP rules** (Phase 3.y) — extend the deterministic MITRE needle-set to include vendor-report vocabulary (`"remote access trojan"`, `"rat"`, `"malicious file executed"`, `"secure endpoint alert"`, …). Additive analyzer rule additions only; no new IOC/projection code. Would allow narrative DOCX inputs to derive MITRE evidence and thereby light up Attack Chain / Story / Recommendations.
- **Option B · Author a `VENDOR_NORMALISER` plug-in** (Phase 3.z) — parse the narrative into typed structured events (detection · asset · verdict · classifier) that MITRE_MAP can then map from. Larger; matches the plan_builder's existing `VENDOR_NORMALISER` slot.
- **Option C · Ship Phase 5 anyway** with a documented capability gap ("MITRE mapping on narrative reports is a Phase-3.y follow-up"). Not recommended — reopens the exact Workspace defect ADR-005 was meant to close.

**No option is authorised. Awaiting owner decision. Phase 5 remains NOT started.**
