# NivXRay XDR — Migration Dependency Inventory

**Rule**: NivXRay XDR must eventually own its capabilities end-to-end.
If the existing NivXRay (legacy) is decommissioned, replaced or
disconnected, NivXRay XDR must continue operating independently.

Every reused capability is tagged:

- 🟡 `TEMPORARY_MIGRATION_DEPENDENCY` — allowed today, must be
  replaced by a native NivXRay XDR capability before legacy is
  decommissioned.
- 🟢 `PERMANENT_EXTERNAL_PROVIDER` — legitimate external supplier
  (a real third party, not the legacy product).

_Last reviewed: 2026-09-02 (Phase 1 completion)._

---

## 1. Cloud LLM (Claude Sonnet via Emergent Universal Key)

- **Current provider**: `backend/llm_provider.py::EmergentClaudeProvider`
- **Consumed by (today)**: `services/narration/providers.py::CloudLLMProvider`
  (Narration Gateway "cloud" slot).
- **Classification**: 🟡 **TEMPORARY_MIGRATION_DEPENDENCY**
- **Target native XDR capability**: NivXRay XDR Narration Gateway
  already provides the abstraction.  A future permanent provider
  is any customer-approved cloud LLM key (Anthropic direct,
  OpenAI direct, Azure OpenAI, on-prem Bedrock).
- **Exit strategy**: Selection is env-driven
  (`NARRATION_PROVIDER_ORDER`).  A customer running fully
  offline sets `NARRATION_PROVIDER_ORDER=offline,deterministic`
  and no Emergent key is ever loaded.  The gateway keeps
  functioning because the deterministic narrator is mandatory.

## 2. Offline LLM (Ollama / Qwen 2.5 7B "NivX Cognis")

- **Current provider**: `backend/llm_provider.py::OllamaQwenProvider`
  (env-gated on `OLLAMA_HOST` + `OLLAMA_MODEL`).
- **Classification**: 🟢 **PERMANENT_EXTERNAL_PROVIDER** (self-hosted
  by the customer; NivXRay XDR only speaks the Ollama HTTP
  protocol).
- **Exit strategy**: Interface only.  Any Ollama-compatible model
  runtime can replace it without a code change.

## 3. Deterministic narrator wrapper

- **Wraps**: `detection_content/xdr_executive_summary.py` (existing
  NivXRay composer, no LLM, byte-identical output).
- **Classification**: 🟢 **NATIVE NivXRay XDR CAPABILITY** —
  the composer is part of the platform and is co-owned by XDR.
  There is no legacy runtime dependency for it to survive.
- **Exit strategy**: N/A — this is the guaranteed floor of the
  narration chain.  It must always work.

## 4. AttackTechniqueEvidence (SSOT)

- **Current provider**: `services/attack_evidence/service.py`.
- **Classification**: 🟢 **NATIVE NivXRay XDR CAPABILITY**.
- **Exit strategy**: N/A.

## 5. Workspace cases collection (`workspace_cases`)

- **Storage**: Mongo (local `MONGO_URL`); ingestion / promotion is
  performed by NivXRay's incident pipeline.
- **Classification**: 🟡 **TEMPORARY_MIGRATION_DEPENDENCY** (data
  ownership migration in flight).
- **Target native XDR capability**: An XDR-native incident store
  (`xdr_incidents` collection is already being populated by newer
  code).
- **Exit strategy**: Continue converging reads to `xdr_incidents`;
  keep a compatibility read on `workspace_cases` behind an
  adapter until the migration completes.

## 6. Emergent LLM Universal Key envelope (`/deps.llm_json`)

- **Current provider**: `deps.llm_json` — signs and forwards the
  request via Emergent's proxy.
- **Classification**: 🟡 **TEMPORARY_MIGRATION_DEPENDENCY** —
  helpful during migration; behind the gateway abstraction, so
  swapping to a direct-key path (Anthropic / OpenAI / etc.) is a
  provider-registration change, not a UI/consumer change.
- **Exit strategy**: Replace with a customer-supplied key using
  the same provider protocol.  UI and downstream consumers do
  not need to change.

---

## Consumers verified to route through the abstraction (Phase 1.5)

- ✅ `GET /api/narration/incident/{id}/executive-summary` — Phase-1 proof.
- ✅ `GET /api/narration/incident/{id}/attack-story` — Phase-1.5.
- ✅ `GET /api/narration/incident/{id}/r46-overlay-summary` — Phase-1.5.
- ✅ `GET /api/narration/incident/{id}/report-narration` — Phase-1.5 (R48 PDF consumes this; no PDF-specific narration logic).
- ⏳ Existing per-tab renderers in the cockpit will gradually migrate to these endpoints.  The old paths remain functional to avoid regressions.

## Terminology (owner-locked, Phase 1.5)

- **Provider Priority Chain** — ordered list the gateway tries.
- **Guaranteed-baseline provider** — the deterministic narrator; not a "fallback" in a pejorative sense, but the honest floor of narration capability that survives credit exhaustion, cloud outage, offline-runtime absence, and legacy NivXRay decommissioning.

## Consumers still calling LLMs directly (Phase 1 backlog)

Grep-visible callsites of `llm_json` / `emergentintegrations`:

- `backend/routers/die.py`, `analyze.py`, `moe_panel.py`,
  `decode_guidance.py`, `learner.py`, `reasoning/*`,
  `knowledge_base/synthesizer.py`, `investigation_report.py`,
  `chain_analyzer.py`, `threat_model/analyzer.py`,
  `engine/detectors/verdict_v2.py`.

These are **NOT narration consumers** — they are structured
reasoning / decoding / verdict paths that already validate
outputs via `training.validator` + citation verification.  They
stay on `llm_provider.llm_json` directly for now.  Only
narration-shaped surfaces (analyst-facing prose that quotes
governed evidence) route through the Narration Gateway.
