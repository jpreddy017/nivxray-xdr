/**
 * diff.js — Byte-level unified diff for the Workspace Input↔Output view.
 * Uses the `diff` npm package (already installed) for a battle-tested
 * character-level LCS diff. Returns segments annotated with `type`:
 *
 *   { type: "same",  value: "..." }
 *   { type: "add",   value: "..." }  // present in output, not input
 *   { type: "del",   value: "..." }  // present in input, not output
 *
 * `deltaBytes` gives the size change in bytes (positive = grew, negative = shrunk).
 */
import { diffChars } from "diff";

export function computeDiff(input, output) {
  const a = input || "";
  const b = output || "";
  const parts = diffChars(a, b);
  const segments = parts.map((p) => ({
    type: p.added ? "add" : p.removed ? "del" : "same",
    value: p.value,
  }));
  const inputBytes = new TextEncoder().encode(a).length;
  const outputBytes = new TextEncoder().encode(b).length;
  return {
    segments,
    inputBytes,
    outputBytes,
    deltaBytes: outputBytes - inputBytes,
    identical: a === b,
  };
}

/**
 * Return a printable summary like "-142B" or "+2.3KB".
 */
export function formatDelta(bytes) {
  const sign = bytes >= 0 ? "+" : "−";
  const abs = Math.abs(bytes);
  if (abs < 1024) return `${sign}${abs}B`;
  if (abs < 1024 * 1024) return `${sign}${(abs / 1024).toFixed(1)}KB`;
  return `${sign}${(abs / (1024 * 1024)).toFixed(2)}MB`;
}

/**
 * Encode any text into a hex-dump string with 16 bytes / line + ASCII gutter.
 * Used by the Hex view toggle.
 */
export function toHexDump(text) {
  const bytes = new TextEncoder().encode(text || "");
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = Array.from(chunk).map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(chunk).map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(8, "0")}  ${hex.padEnd(48)}  ${ascii}`);
  }
  return lines.join("\n") || "(empty)";
}

/**
 * Encode any text into a base64 view.
 */
export function toBase64(text) {
  try {
    const bytes = new TextEncoder().encode(text || "");
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  } catch {
    return "(unencodable)";
  }
}
