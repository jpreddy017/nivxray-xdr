# X-LAB P0 MISSION · DO NOT DEVIATE

_Locked 2026-08-01 by operator. Any deviation from this document is a
breach of directive._

## Mission

Make X-Lab **investigate** incidents exactly like an experienced MDR SOC
analyst / threat hunter and produce reports equivalent to real analyst
escalations.

**X-Lab is not** a decoder. Not a report generator. Not an LLM summary tool.
X-Lab is an **Autonomous Cyber Security Threat Investigation Engine**.

## Frozen — do not touch until acceptance criteria met

New UI · dashboards · personas · explainability · learning engine · LLM
polish · correlation dashboards · Golden Corpus expansion · Phase 4 ·
cosmetic improvements.

## Investigation Modes

### Mode 1 — Encoded / Plain Command Line
Detect encoding · recursively decode → final payload · normalize · parse
· identify commands · explain what each command does · explain WHY it
exists · explain what happens next · explain attacker objective · map to
MITRE ATT&CK · extract IOCs · enrich via OSINT · detect malware family
· produce complete investigation story. NEVER just print decoded output.

### Mode 2 — Vendor Telemetry
Cisco XDR / Secure Endpoint · Defender · CrowdStrike · Sysmon · QRadar
· Splunk · Elastic · Windows / Linux / macOS events · Suricata · Zeek
· cloud logs · raw JSON / CSV / ETW / EDR / XDR / SIEM.

Pipeline: **Parse → Normalize → Aggregate → Correlate → Look for
{command_line, process_command_line, CommandLine, ScriptBlock, PowerShell,
EncodedCommand, Base64, obfuscated payloads, URLs, domains, IPs, hashes,
registry, services, scheduled tasks, LOLBins, files, network, DNS,
children, parents, users, hosts, etc.} → if command line present run the
complete recursive decoder pipeline and merge decoded evidence → continue
investigation → if no command line, continue with available telemetry.
Never stop because no command exists.**

## The investigation MUST answer

What / Why / How / When / Where / Who initiated · which hosts, users,
processes, child processes, network connections, DNS, files, registry
keys, services, scheduled tasks, LOLBins, ATT&CK techniques, tactics,
malware family, campaign, root cause, stage of attack, likely next step,
evidence supporting every conclusion, visibility gaps, unconfirmed
elements, customer action.

## Deterministic knowledge base required

Explain, not identify. For every LOLBIN (PowerShell, WMIC, PsExec, Finger,
Tar, Curl, MSHTA, BITS, Certutil, Regsvr32, Rundll32, …), every ATT&CK
technique, every malware family, every persistence / credential-theft /
defense-evasion / execution mechanism — a knowledge-base explanation.

## Report style

MUST NOT contain: "Recovered payload…" · "Layer 0/1/…" · "Decoded output"
· "Analysis complete" · "Recovered command".

Every investigation naturally contains: Detection context · Investigation
scope · Timeline reconstruction · Correlation · Threat explanation · Root
cause · Threat intelligence · Malware family · MITRE mapping · IOC
analysis · OSINT enrichment · Visibility limitations · Confidence
discussion · Customer-specific recommendations.

## Non-negotiable rules

- Every paragraph backed by concrete evidence.
- Never generate "may indicate" / "consistent with" / "the command was
  decoded" unless supported.
- Decoder internals NEVER appear in customer-facing reports.
- No templates. Every sentence traces to specific CIO facts.

## Gold-standard examples (PENDING from operator)

- Example 1 — PsExec / Bomgar investigation
- Example 2 — Chrome cache / phishing investigation
- Example 3 — Cisco Secure Access DNS investigation
- Example 4 — Defender credential enumeration investigation

Reproduce their **methodology**, not their wording.

## Acceptance criteria

1. X-Lab investigates, not summarizes.
2. Reports read like the supplied analyst examples.
3. Encoded commands recursively decoded and integrated into the
   investigation.
4. Vendor telemetry parsed → normalized → aggregated → correlated →
   enriched → investigated.
5. Report explains what/why/how/what-next/action.
6. Every analytical statement evidence-backed.
7. Decoder internals never appear in customer-facing reports.
8. No feature work is started until the above are met.
