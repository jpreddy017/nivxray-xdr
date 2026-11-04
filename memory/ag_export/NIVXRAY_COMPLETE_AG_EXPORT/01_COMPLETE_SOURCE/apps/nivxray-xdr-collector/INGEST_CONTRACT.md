# NivXRay XDR · Authoritative Ingest Contract

**Owner:** NivXRay backend team.
**Consumer:** NivXRay XDR Collector service (`/app/apps/nivxray-xdr-collector`).
**Status:** LOCKED for Phase B.5 → Phase C. Any breaking change requires a version bump on the collector.

---

## 1 · Purpose

This document defines the single, authoritative HTTP contract that
carries canonical envelopes from the collector plane into the existing
NivXRay evidence pipeline. It is the ONLY doorway between the two
planes.

```
CrowdStrike ─┐
Defender ────┤
SentinelOne ─┤   REST poller / webhook / syslog
Cisco SEP ───┤   ──────► Collector ─── Outbox ─── AUTHORITATIVE INGEST
Syslog ──────┤                                    (this contract)
Webhook ─────┤                                          │
REST ────────┘                                          ▼
                                          Canonical Evidence · SSOT
                                          Correlation · Verdict · IKG
```

No vendor adapter is ever allowed to write directly into SSOT / Verdict
/ IKG. Everything transits through this one endpoint so the base
NivXRay backend remains the single source of truth.

---

## 2 · Endpoint

| | |
| --- | --- |
| **Method** | `POST` |
| **Path**   | `POST {NIVX_INGEST_URL}` — e.g. `https://nivxray.example.com/api/xdr/ingest` |
| **Auth**   | `Authorization: Bearer {NIVX_INGEST_TOKEN}` |
| **Content-Type** | `application/json` |
| **Idempotency** | Deduplication is REQUIRED on `(tenant_id, connector_id, source_event_id)` when `source_event_id` is present. The same envelope MUST be accepted twice without side-effects. |
| **Max body size** | 5 MiB per POST (the collector batches ≤ 50 envelopes per call). |
| **Timeout** | ≤ 10s server-side end-to-end. |

### 2.1 Request body

```json
{
  "envelopes": [
    {
      "tenant_id":            "acme",
      "source":               "CrowdStrike Falcon",
      "source_event_id":      "det-42",
      "connector_id":         "rest-abc123",
      "collector_id":         "collector-local",
      "collection_method":    "rest-poll",
      "parser_version":       "phaseC.crowdstrike.1",
      "source_timestamp":     "2026-02-10T09:12:33Z",
      "collection_timestamp": "2026-02-10T09:12:35.482Z",
      "event_type":           "rest",
      "raw":       { "vendor_original_payload": "..." },
      "canonical": { "extracted_or_normalized_fields": "..." }
    }
  ]
}
```

Field semantics (owner-locked):

- `tenant_id` — required. Multi-tenant scope. Base backend enforces
  RBAC against it.
- `source` — human label of the origin system (`"CrowdStrike Falcon"`,
  `"Panorama syslog"`, `"Duo webhook"`).
- `source_event_id` — the vendor's own event id, if any. Nullable.
  The base backend MUST dedupe on `(tenant_id, connector_id,
  source_event_id)` when non-null.
- `connector_id`, `collector_id` — collector-scoped identifiers. Base
  keeps them as provenance so an analyst can trace an evidence row
  back to its transport instance.
- `collection_method` — one of: `rest-poll | webhook | syslog | agent`.
  Extensible in later phases.
- `parser_version` — collector-side parser version. Bumped on any
  breaking parse change.
- `source_timestamp` — vendor-emitted timestamp (RFC3339 ideally,
  free-form string otherwise; base backend is responsible for parsing).
- `collection_timestamp` — when the collector observed the event
  (always RFC3339 UTC).
- `raw` — verbatim vendor payload. NEVER mutated by the collector.
  Kept so the base backend can re-parse authoritatively.
- `canonical` — collector's best-effort extraction (parsed syslog
  fields, extracted event id, etc.). May be empty; the base backend
  MUST NOT trust it exclusively.

### 2.2 Response codes

| Code | Meaning | Collector action |
| --- | --- | --- |
| `200` / `201` / `202` | Envelopes accepted. Response body may include per-envelope status. | Mark rows `DELIVERED`. |
| `400` | Malformed body / schema violation. | Mark rows `DEAD_LETTER`. Never retry. |
| `401` / `403` | Auth failure. | Mark rows `RETRYING` (operator must fix the token). Health flips to `AUTHENTICATION_FAILED`. |
| `408` | Ingest timeout. | `RETRYING` with backoff. |
| `413` | Body too large. | `DEAD_LETTER`. The collector's batch size is too high — operator lowers it. |
| `422` | Semantic validation failure. | `DEAD_LETTER`. |
| `429` | Rate limited. | `RETRYING` with backoff. Respect `Retry-After` header if present. |
| `5xx` | Backend fault. | `RETRYING` with backoff. |
| Network timeout / transport error | | `RETRYING` with backoff. |

Response body for 2xx should look like:

```json
{
  "accepted":   50,
  "duplicates": 0,
  "rejected":   [ /* per-envelope error rows, if any */ ]
}
```

The collector does not currently act on per-envelope rejections —
they are logged and surfaced as `last_error` in `/api/xdr/outbox/health`.

---

## 3 · Preflight handshake

To let operators validate a fresh deployment without pushing real
telemetry, the collector will POST a synthetic envelope with
`event_type = "preflight"` on demand (see
`POST /api/xdr/ingest-preflight` on the collector).

The base backend MUST accept this envelope as it would any other but
MAY short-circuit it (e.g. not create SSOT rows) as long as it
returns 2xx.

Recommended base-side detection:
```python
if envelope.get("event_type") == "preflight" \
    and envelope.get("canonical", {}).get("nivxray_preflight") is True:
    return {"accepted": 1, "preflight": True}
```

---

## 4 · Guarantees the base backend MUST hold

1. **Idempotent writes** on `(tenant_id, connector_id, source_event_id)`.
2. **Retryable timing**: respond within 10 s or return 5xx.
3. **Never mutate `raw`** — it is the collector's provenance record.
4. **Preserve `parser_version` and `connector_id`** on the resulting
   canonical evidence row so an analyst can trace a verdict back to
   the transport instance.
5. **Return a non-2xx** for any envelope the base cannot accept —
   silently dropping is forbidden. The collector NEVER reports
   `DELIVERED` without a genuine 2xx.

---

## 5 · Non-goals (owner-locked)

- No push semantics from base back to collector.
- No streaming / websocket variant in Phase C. Batched POST only.
- No filtering / dedup by the collector against SSOT — dedup is on
  vendor event id, not on evidence hashes.
- No engine duplication on the collector: SSOT, Verdict, IKG, Attack
  Story, MITRE intelligence remain authoritative on the base backend.
