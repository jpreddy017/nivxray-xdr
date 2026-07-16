/**
 * Input Classifier — analyses a pasted payload and returns a
 * recommended action sequence for the analyst.
 *
 * NO NETWORK, NO SIDE EFFECTS. Pure function → safe to run on every
 * keystroke. Callers debounce as needed.
 *
 * Returns:
 *   {
 *     kind:            "encoded" | "plaintext_malicious" | "multi_line_chain"
 *                    | "unclear_cipher" | "clean_text" | "empty",
 *     confidence:      0..1,
 *     signals:         string[]              // human-readable signal names
 *     recommended:     string[]              // ordered button ids to glow
 *     guidance_steps:  { label: string, why: string }[]
 *   }
 *
 * Button ids match the `data-testid`s in WorkspacePage:
 *   - btn-smart-decode
 *   - btn-ai-decode
 *   - btn-auto-investigate
 *   - btn-chain-add-stage      (+ ADD CHAIN)
 *   - btn-chain-run            (RUN CHAIN)
 */

// ── Heuristic detectors ─────────────────────────────────────────
const B64_RE  = /(?:[A-Za-z0-9+/]{40,}={0,2})/;
const HEX_RE  = /^(?:[\s]*(?:[0-9a-fA-F]{2}[\s,-]?){20,})$/;
const URLENC_RE = /(?:%[0-9a-fA-F]{2}){4,}/;
const PS_ENC_RE = /powershell(?:\.exe)?[^\n]*?(?:-e|-en|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i;
const CERTUTIL_DECODE_RE = /certutil(?:\.exe)?[^\n]*?-decode/i;

const KNOWN_HEADS = [
  "powershell", "pwsh", "cmd", "cmd.exe",
  "certutil", "mshta", "rundll32", "regsvr32", "regsvcs", "regasm",
  "msiexec", "installutil", "bitsadmin", "wmic", "wscript", "cscript",
  "schtasks", "at.exe", "sc.exe", "netsh", "curl", "wget",
  "iwr", "iex", "invoke-expression", "invoke-webrequest",
  "start-process", "vssadmin", "wbadmin", "bcdedit",
  "esentutl", "diskshadow", "dotnet", "dnx", "dxcap",
  "reg add", "reg delete", "net user", "net group",
];

const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/i;
const DEFANGED_URL_RE = /\bhxxps?:\/\/|\[\.\]|\[dot\]/i;
const IP_RE  = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

function _looksLikeCommand(line) {
  const t = line.trim().toLowerCase();
  if (!t || t.length > 4000) return false;
  if (/^([#;>]|::|rem\s|\/\/)/.test(t)) return false;
  return KNOWN_HEADS.some((h) => t.startsWith(h));
}

// ── Main classifier ─────────────────────────────────────────────
export function classifyInput(raw) {
  const input = String(raw || "");
  const trimmed = input.trim();

  if (!trimmed) {
    return {
      kind: "empty",
      confidence: 1,
      signals: [],
      recommended: [],
      guidance_steps: [{
        label: "Paste a command line, encoded blob, or malware sample",
        why:   "The analyst tool will guide you the moment you paste.",
      }],
    };
  }

  const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const signals = [];

  // ── Multi-line chain detection ────────────────────────────────
  const cmdLines = lines.filter(_looksLikeCommand);
  const isMultiChain = (
    lines.length >= 2 &&
    (
      // blank-line delimited
      /\n\s*\n/.test(trimmed) ||
      // OR ≥ 2 lines each starting with a known shell/LOLBAS keyword
      (cmdLines.length >= 2 && cmdLines.length / lines.length >= 0.5)
    )
  );
  if (isMultiChain) signals.push(`${cmdLines.length || lines.length} command-line stages`);

  // ── Encoded detection ─────────────────────────────────────────
  const hasB64      = B64_RE.test(trimmed);
  const hasHex      = HEX_RE.test(trimmed) || /\\x[0-9a-fA-F]{2}/.test(trimmed);
  const hasUrlEnc   = URLENC_RE.test(trimmed);
  const hasPsEnc    = PS_ENC_RE.test(trimmed);
  const hasCertUtil = CERTUTIL_DECODE_RE.test(trimmed);
  if (hasPsEnc)   signals.push("powershell -enc detected");
  if (hasCertUtil) signals.push("certutil -decode detected");
  if (hasB64)     signals.push("base64 blob detected");
  if (hasHex)     signals.push("hex string detected");
  if (hasUrlEnc)  signals.push("url-encoded content detected");
  const isEncoded = hasPsEnc || hasCertUtil || hasB64 || hasHex || hasUrlEnc;

  // ── LOLBAS / malicious plaintext detection ────────────────────
  const hasLolbin = KNOWN_HEADS.some((h) => new RegExp(`\\b${h.replace(".", "\\.")}\\b`, "i").test(trimmed));
  const hasUrl    = URL_RE.test(trimmed);
  const hasDefang = DEFANGED_URL_RE.test(trimmed);
  const hasIp     = IP_RE.test(trimmed);
  if (hasLolbin) signals.push("LOLBAS binary present");
  if (hasUrl)    signals.push(hasDefang ? "defanged URL" : "URL present");
  if (hasIp)     signals.push("IP address present");
  const isMaliciousPlaintext = hasLolbin || hasDefang || (hasUrl && trimmed.length < 800);

  // ── Unclear cipher / gibberish (short, high-entropy, no signals) ─
  const noise = !isEncoded && !isMaliciousPlaintext && !isMultiChain;
  const gibberishLike = noise && trimmed.length >= 12 && !/\s/.test(trimmed.slice(0, 200));
  if (gibberishLike) signals.push("high-entropy short blob — possible cipher / obfuscation");

  // ── Decide the recommendation ─────────────────────────────────
  if (isMultiChain) {
    return {
      kind: "multi_line_chain",
      confidence: 0.9,
      signals,
      recommended: ["btn-chain-add-stage", "btn-chain-run", "btn-auto-investigate"],
      guidance_steps: [
        { label: "+ ADD CHAIN",
          why:   `Detected ${cmdLines.length || lines.length} separate command lines — each should be its own stage.` },
        { label: "RUN CHAIN",
          why:   "Decodes each stage deterministically, then aggregates IOCs / MITRE / LOLBAS / verdict into one SOC report." },
        { label: "AUTO INVESTIGATE (single-stage)",
          why:   "Optional — run the whole blob as one payload if the stages are logically one attack." },
      ],
    };
  }

  if (isEncoded && isMaliciousPlaintext) {
    return {
      kind: "encoded",
      confidence: 0.95,
      signals,
      recommended: ["btn-auto-investigate", "btn-smart-decode"],
      guidance_steps: [
        { label: "AUTO INVESTIGATE",
          why:   "Encoded payload + malicious signals — this button decodes recursively AND enriches with OSINT, MITRE, LOLBAS, and an AI verdict." },
        { label: "SMART DECODE (fallback)",
          why:   "Use only if AUTO INVESTIGATE times out — decodes without enrichment for speed." },
      ],
    };
  }

  if (isEncoded) {
    return {
      kind: "encoded",
      confidence: 0.85,
      signals,
      recommended: ["btn-smart-decode", "btn-auto-investigate"],
      guidance_steps: [
        { label: "SMART DECODE",
          why:   "Encoding detected but no obvious malicious markers — do a fast deterministic decode first to see the plaintext." },
        { label: "AUTO INVESTIGATE",
          why:   "Once decoded, re-run this to add OSINT + MITRE + AI verdict on the decoded content." },
      ],
    };
  }

  if (isMaliciousPlaintext) {
    return {
      kind: "plaintext_malicious",
      confidence: 0.9,
      signals,
      recommended: ["btn-auto-investigate"],
      guidance_steps: [
        { label: "AUTO INVESTIGATE",
          why:   "Plaintext malicious command line — go straight to the full SOC pipeline. No decode needed." },
      ],
    };
  }

  if (gibberishLike) {
    return {
      kind: "unclear_cipher",
      confidence: 0.6,
      signals,
      recommended: ["btn-ai-decode", "btn-smart-decode"],
      guidance_steps: [
        { label: "AI DECODE",
          why:   "Obfuscated / high-entropy blob with no obvious encoding — let the LLM propose a recipe with hallucination guards." },
        { label: "SMART DECODE (fallback)",
          why:   "If AI Decode is unavailable, try the deterministic candidate engine — it still handles ROT13, custom XOR, Vigenère, etc." },
      ],
    };
  }

  // Fallback — clean text, benign-looking
  return {
    kind: "clean_text",
    confidence: 0.7,
    signals,
    recommended: ["btn-auto-investigate"],
    guidance_steps: [
      { label: "AUTO INVESTIGATE",
        why:   "No encoding or LOLBAS markers found — run the full pipeline to be safe. Verdict will likely be 'Undecoded / Clean'." },
    ],
  };
}
