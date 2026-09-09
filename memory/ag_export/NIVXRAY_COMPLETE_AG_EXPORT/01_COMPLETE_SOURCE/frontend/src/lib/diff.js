/**
 * diff.js — Byte-level unified diff + view helpers for the Workspace.
 *
 * IMPORTANT: for binary/shellcode payloads the backend serialises bytes as
 * a Latin-1 string (each byte 0xNN → one char). We MUST NOT re-encode via
 * `TextEncoder` (which is UTF-8) or high-byte chars will double-expand
 * (0xfc → "c3 bc"). Everywhere we compute a byte view we read `charCodeAt(i)`
 * directly.
 */
import { diffChars } from "diff";

// Byte-count helper — respects the Latin-1 wire contract, not UTF-8.
function byteLen(s) {
  return (s || "").length;
}

export function computeDiff(input, output) {
  const a = input || "";
  const b = output || "";
  const parts = diffChars(a, b);
  const segments = parts.map((p) => ({
    type: p.added ? "add" : p.removed ? "del" : "same",
    value: p.value,
  }));
  const inputBytes = byteLen(a);
  const outputBytes = byteLen(b);
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
 * Canonical hex dump — 16 bytes per line + ASCII gutter. Reads each char as
 * a single byte (Latin-1 assumption). Chars > 0xff (rare for decoded output —
 * would only happen if the source was legit UTF-8 like `€`) are surrogated
 * with `? ?` so we don't silently corrupt the byte grid.
 */
export function toHexDump(text) {
  const s = text || "";
  if (!s) return "(empty)";
  const lines = [];
  for (let i = 0; i < s.length; i += 16) {
    const chunk = s.slice(i, i + 16);
    const hex = [];
    const ascii = [];
    for (let j = 0; j < chunk.length; j++) {
      const b = chunk.charCodeAt(j);
      if (b > 0xff) {
        hex.push("??");
        ascii.push("?");
      } else {
        hex.push(b.toString(16).padStart(2, "0"));
        ascii.push(b >= 0x20 && b < 0x7f ? chunk[j] : ".");
      }
    }
    lines.push(`${i.toString(16).padStart(8, "0")}  ${hex.join(" ").padEnd(48)}  ${ascii.join("")}`);
  }
  return lines.join("\n");
}

/**
 * Base64 view — encode the buffer treating each char as a single byte
 * (Latin-1). Uses `btoa` which requires each char code < 0x100 — same
 * assumption as the hex dump.
 */
export function toBase64(text) {
  const s = text || "";
  if (!s) return "";
  try {
    // btoa is Latin-1-only, exactly what we want for binary/shellcode.
    return btoa(s);
  } catch {
    // Fallback for accidental multi-byte chars: strip to lower 8 bits.
    let sanitized = "";
    for (let i = 0; i < s.length; i++) sanitized += String.fromCharCode(s.charCodeAt(i) & 0xff);
    try { return btoa(sanitized); } catch { return "(unencodable)"; }
  }
}
