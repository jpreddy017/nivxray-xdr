# NIVXFORGE EDR & SANDBOX: DESIGN DECISIONS LOG
**Document ID:** `NIVXFORGE-DESIGN-DECISIONS-2026-09-05`  
**Classification:** Operational UI/UX Decision Record  
**Status:** Approved Design Choices  

---

## 1. Design System Reuse & Extension Strategy

| Aspect | Reused Asset | Extended / Customized Feature | Deliberately Rejected Vendor Anti-Pattern | Vendor Pattern Influence |
|---|---|---|---|---|
| **Theme System** | Dark-first token system (`nx-theme.css`) | Added 4 real surface elevation layers (`--nx-surf-canvas`, `-primary`, `-inset`, `-raised`) | Rejected flat dark slabs and mud-gray backgrounds | Microsoft Defender high-density dark surfaces |
| **Color Accents** | Signal Amber (`#F59E0B`), Cyan (`#06B6D4`), Mint (`#10B981`) | Priority fill tokens are FIXED by owner mandate and already shipped: `#EF4444` P1 red, `#F97316` P2 orange, `#EAB308` P3 amber, `#3B82F6` P4 **blue**, `#94A3B8` P5 slate (`nx-theme.css:132-136`) | Rejected generic SaaS violet `#7351B7` and teal green `#1B93A4` | CrowdStrike Falcon high-contrast severity accents |
| **Typography** | `Outfit` (Display) + `IBM Plex Sans` (Body) | `JetBrains Mono` for ALL machine-emitted facts (hashes, PIDs, IPs, timestamps) | Rejected `Inter` for headings and `Space Grotesk` everywhere | SentinelOne / Splunk technical data legibility |
| **Epistemic Grammar** | `◆` `◇` `?` `○` `⊘` glyphs | Integrated epistemic states into border line styles (solid 1px observed, dashed inferred, dotted possible) | Rejected asserting unconfirmed causality with glowing arrows | Cisco XDR progressive relationship disclosure |
| **Priority vs Verdict** | `P1`–`P5` rank chips | Decoupled priority rank from verdict labels and epistemic states | Rejected reusing pale text colors as card backgrounds (no color collapse) | Trellix action-oriented priority queue |
| **Layout Density** | 3-pane investigation canvas | Left Activity Inventory + Center Timeline Canvas + Right Activity Details | Rejected center-everything disease and spacious empty padding | Cortex XDR deep causality workbench & CrowdStrike process tree |
| **Navigation Spine** | Incident-centric URL routing | Single spine: Incident $\rightarrow$ Endpoint Entity $\rightarrow$ EDR $\rightarrow$ Device Trajectory | Rejected third trajectory surface or disconnected global endpoints tab | Microsoft Defender XDR entity navigation |
| **Device Identity** | `device_iid` IRG identity | Added explicit `INFERRED IDENTITY` pill when falling back to hostname | Rejected fabricating endpoint IDs or assuming hostname equals IID | CrowdStrike Falcon immutable entity GUIDs |
| **Sandbox Architecture**| Static Analyzers & 59 Decoders | Integrated real static analyzers into Sandbox intake report | Rejected building a secondary shadow reasoning/verdict engine | ANY.RUN / WildFire / Joe Sandbox interactive analysis |
| **Zero-Device State** | Fail-closed error handling | Built first-class Zero-Device honest empty screen with exact backend reason | Rejected filling empty tables with synthetic mock endpoints | SentinelOne Singularity operations state clarity |
