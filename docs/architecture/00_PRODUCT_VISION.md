# 00 · Product Vision

## What NivXRay is
NivXRay is a **deterministic MDR investigation platform**. It ingests any analyst-facing artefact (Cisco XDR incident, CrowdStrike detection, Defender alert, QRadar offense, Splunk log, Sysmon XML, Windows Event, PowerShell / CMD / Bash command line, Base64 blob, STIX bundle, YARA rule, email headers, IOC list, raw JSON, unknown) and produces a fully-evidenced investigation an experienced senior MDR analyst would be comfortable sending to a customer.

## Who it is for
- **SOC analysts (L1-L3)** — need fast triage and analyst-voice narrative.
- **Incident responders / threat hunters** — need traceable evidence and MITRE mapping.
- **Leadership** — need customer-ready reports.

## What NivXRay is NOT
- ❌ Not a decoder toy.
- ❌ Not a log viewer.
- ❌ Not an LLM summariser.
- ❌ Not two competing workspaces.

## Success metrics (measure NivXRay by these — not LoC)
1. Does the engine correctly understand any supported input?
2. Does it produce the same verdict as Workspace for the same evidence?
3. Is the Executive Summary comparable to what an experienced MDR analyst would write?
4. Is every conclusion traceable to evidence?
5. Can an analyst move from raw telemetry to a customer-ready report without leaving NivXRay?

## Workspace ↔ X-Lab relationship
- **Workspace** — operational SOC dashboard.
- **X-Lab** — advanced investigation and analysis workspace.
- Peers, not competitors. Same backend, different lenses.
- New investigation intelligence is implemented ONCE in the shared backend and automatically available to both.
