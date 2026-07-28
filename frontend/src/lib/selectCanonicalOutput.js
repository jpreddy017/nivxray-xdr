/**
 * selectCanonicalOutput — single source of truth for which decoded
 * artifact lands in the OUTPUT textarea of the analyst workspace.
 *
 * v1.5.5 · Feb-2026 · SME directive:
 *   Both `runNivxrayDecode` (DECODE button) and `autoInvestigate`
 *   (AUTO INVESTIGATE button) MUST call this function so the two
 *   flows never diverge on final-artifact selection again.
 *
 * Priority (highest → lowest):
 *   1. `/recipe/run` terminal output — the deepest linear-recipe
 *      result. For shellcode-terminating chains this is the raw
 *      shellcode with inline C2 / User-Agent / API-import strings
 *      (which `OutputView.jsx` renders as clean extracted intel in
 *      TEXT view via `detectBinaryPayload` + `formatExtractedIntel`).
 *      ALWAYS wins when it produced something different from the
 *      RTE brain-block `output`.
 *
 *   2. Semantic peel (`semantic.deobfuscation.final`) — only when the
 *      recipe did NOT peel deeper than the RTE. Handles Invoke-
 *      Obfuscation cmdlet samples where the semantic engine
 *      resolved a deeper payload than RC2 (audited sample
 *      `invoke_obfuscation_full_stack`).
 *
 *   3. Trace-tail — when `/decode/smart` returned the raw input
 *      unchanged (e.g. base64 → PE binary case where `output`
 *      byte-matches the input because the browser can't render
 *      binary), fall back to the last trace layer's
 *      `output_preview`. RC3.1.1 PROD-BUG-4 safety net.
 *
 *   4. Default — the RTE brain-block / promoted `output`.
 *
 * @param {Object} args
 * @param {Object} args.api          axios instance (must expose `.post`)
 * @param {string} args.input        the raw user input
 * @param {Object} args.smartResp    the parsed body of `/api/decode/smart`
 * @returns {Promise<{text: string, source: string}>}
 *          `source` is one of `recipe|semantic|trace-tail|smart|empty`
 *          (used for observability / debug logging).
 */
export async function selectCanonicalOutput({ api, input, smartResp }) {
  const rawOut = smartResp?.output || "";
  const recipe = smartResp?.recipe || [];
  const semFinal =
    smartResp?.semantic?.deobfuscation?.final ||
    smartResp?.semantic?.recovered_script ||
    "";

  // 1) Recipe replay — terminal artifact of the linear deterministic
  //    decoder chain. Always wins if it produced something different
  //    from the RTE brain-block output.
  if (recipe.length) {
    try {
      const rr = await api.post("/recipe/run", {
        input,
        steps: recipe.map((s) => ({ op: s.op, args: s.args || {} })),
      });
      const terminal = rr?.data?.output || "";
      if (terminal && terminal !== rawOut) {
        return { text: terminal, source: "recipe" };
      }
    } catch (_e) {
      // Recipe replay failure is non-fatal — fall through to next
      // priority tier so the analyst still sees SOMETHING.
    }
  }

  // 2) Semantic peel — only when recipe replay didn't override.
  //    Preserved from the pre-v1.5.5 Workspace Stabilization
  //    Directive for Invoke-Obfuscation samples.
  if (
    semFinal &&
    semFinal !== rawOut &&
    semFinal.length < String(input).length
  ) {
    return { text: semFinal, source: "semantic" };
  }

  // 3) Trace-tail fallback for raw-input-echo bug (RC3.1.1 PROD-BUG-4).
  const lastTraceLayer = (smartResp?.trace || []).slice(-1)[0];
  if (rawOut && rawOut === input && lastTraceLayer?.output_preview) {
    return { text: lastTraceLayer.output_preview, source: "trace-tail" };
  }

  // 4) Default — the RTE brain-block / promoted output.
  return { text: rawOut, source: "smart" };
}
