export function commandRequest(input) {
  if (!input.trim()) throw new Error("Enter a command line.");
  if (new TextEncoder().encode(input).length > 16384) throw new Error("Command exceeds 16 KiB. Submit a smaller command or payload.");
  return { input, automatic: true }; // Preserve whitespace and exact evidence.
}
export function validateCommandResult(data, original) {
  if (data?.schema_version !== "command-intelligence/1" || data.original_command !== original ||
      typeof data.decode_status !== "string" || typeof data.decode_status_reason !== "string" ||
      !data.canonical_decoded_artifact || !data.final_recoverable ||
      typeof data.final_recoverable.value !== "string" ||
      !["text", "base64"].includes(data.final_recoverable.format) ||
      !["candidates", "detected_methods", "warnings", "behaviors", "iocs", "unresolved_portions"].every(key => Array.isArray(data[key]))) {
    throw new Error("The backend did not return a compatible automatic analysis report. Verify frontend/backend release compatibility.");
  }
  if (data.candidates.some(c => !c || !Array.isArray(c.layers) || !Array.isArray(c.recipe) || !Array.isArray(c.unresolved) || typeof c.confidence !== "string" || !c.payload ||
      c.layers.some(l => !l || !l.input || typeof l.output !== "string"))) {
    throw new Error("The backend returned an incomplete decoding timeline. No result was accepted.");
  }
  return data;
}
