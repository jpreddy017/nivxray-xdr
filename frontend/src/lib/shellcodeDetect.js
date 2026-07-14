/**
 * shellcodeDetect.js — Client-side known-prologue detection.
 * Mirrors backend `shellcode_analyzer.starts_with_known_prologue()`.
 * Used by OutputView to auto-switch to HEX view + surface a banner whenever
 * the decoded output is raw shellcode (which would look like garbage in TEXT).
 */

// (prefix bytes, arch, family) — kept in sync with backend _SHELLCODE_PROLOGUES
const PROLOGUES = [
  { bytes: [0xfc, 0xe8], arch: "x86",    family: "MSFvenom cld;call — x86 stager" },
  { bytes: [0xfc, 0x48], arch: "x86_64", family: "MSFvenom cld;dec — x64 stager" },
  { bytes: [0xeb, 0xfe], arch: "x86",    family: "infinite-loop / debug stub" },
  { bytes: [0xfd, 0x7b], arch: "arm64",  family: "ARM64 stp fp,lr prologue" },
  { bytes: [0x4d, 0x5a], arch: "pe",     family: "PE executable (MZ header)" },
  { bytes: [0x7f, 0x45, 0x4c, 0x46], arch: "elf", family: "ELF executable" },
];

export function detectShellcode(text) {
  if (!text || text.length < 4) return null;
  // Convert first 8 chars to bytes (assume latin-1 encoding for high-byte chars)
  const bytes = [];
  for (let i = 0; i < Math.min(8, text.length); i++) {
    const c = text.charCodeAt(i);
    if (c > 0xff) return null;
    bytes.push(c);
  }
  for (const p of PROLOGUES) {
    if (p.bytes.every((b, i) => bytes[i] === b)) {
      return { arch: p.arch, family: p.family };
    }
  }
  return null;
}

/**
 * Extract obvious IOC snippets from a shellcode/text buffer for the banner.
 * Just IPv4 + first embedded URL — this is UI garnish, not the full IOC pass.
 */
export function extractShellcodeIocs(text) {
  const iocs = { ip: null, url: null, userAgent: null };
  if (!text) return iocs;
  const ipMatch = text.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/);
  if (ipMatch) iocs.ip = ipMatch[0];
  const urlMatch = text.match(/https?:\/\/[^\s"'<>]{4,120}/);
  if (urlMatch) iocs.url = urlMatch[0];
  const uaMatch = text.match(/Mozilla\/[0-9.]+[^\r\n]{0,120}/);
  if (uaMatch) iocs.userAgent = uaMatch[0];
  return iocs;
}
