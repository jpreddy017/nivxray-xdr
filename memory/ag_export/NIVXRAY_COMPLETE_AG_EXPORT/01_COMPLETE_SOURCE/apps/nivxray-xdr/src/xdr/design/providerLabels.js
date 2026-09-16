/**
 * Provider-neutral display labels for the NivXRay XDR Narration
 * Gateway.
 *
 * The Gateway's raw `generation_mode` (`llm_cloud|llm_offline|
 * deterministic`) and `provider` slug (e.g. `cloud:emergent-claude`
 * or `cognis-offline:ollama`) are implementation details.  UI
 * surfaces MUST render the neutral labels below so the app is
 * not tied to any single vendor.
 *
 * Aligns with the locked NivXRay XDR Cognis architecture:
 *   Cognis (native intelligence layer)
 *      → Model Gateway (execution abstraction)
 *           → Online LLM  | Offline LLM | Deterministic Narrator
 */

/** Map a Gateway `generation_mode` to its neutral badge label. */
export function neutralModeLabel(mode) {
  const m = String(mode || "").toLowerCase();
  if (m === "llm_cloud")     return "ONLINE_LLM";
  if (m === "llm_offline")   return "OFFLINE_LLM";
  if (m === "deterministic") return "DETERMINISTIC";
  return (mode || "").toString().toUpperCase();
}

/** Map a Gateway provider slug to a neutral human display.
 *  We keep the raw slug available via `raw` for ops tooling. */
export function neutralProviderLabel(provider) {
  const raw = String(provider || "");
  const p = raw.toLowerCase();
  // Cloud slot — the Emergent adapter is a temporary migration
  // dependency; the neutral surface always names the model
  // family, never the routing vendor.
  if (p.startsWith("cloud:emergent-claude") ||
      p.startsWith("cloud:anthropic") ||
      p.startsWith("cloud:claude")) {
    return { display: "Anthropic · Claude", raw };
  }
  if (p.startsWith("cloud:openai") || p.startsWith("cloud:gpt")) {
    return { display: "OpenAI · GPT", raw };
  }
  if (p.startsWith("cloud:gemini") || p.startsWith("cloud:google")) {
    return { display: "Google · Gemini", raw };
  }
  if (p.startsWith("cloud:")) {
    return { display: "Online LLM", raw };
  }
  // Offline slot — Cognis-hosted local runtime today.
  if (p === "cognis-offline:ollama" || p.startsWith("cognis-offline:")) {
    return { display: "Local Model Runtime", raw };
  }
  if (p.startsWith("offline:") || p === "offline-llm") {
    return { display: "Offline LLM", raw };
  }
  // Deterministic slot — the guaranteed baseline.
  if (p === "deterministic" || p === "guaranteed-baseline") {
    return { display: "NivXRay XDR Narration Engine", raw };
  }
  return { display: raw || "unknown", raw };
}

/** Convenience helper for surfaces that want both. */
export function neutralGatewayBadges(data) {
  const mode = neutralModeLabel(data?.generation_mode);
  const prov = neutralProviderLabel(data?.provider);
  return { mode, providerDisplay: prov.display, providerRaw: prov.raw };
}
