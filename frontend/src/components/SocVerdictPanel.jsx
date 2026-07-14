import { useMemo, useState } from "react";
import { Target, Copy, Check, ShieldAlert, Wifi } from "lucide-react";
import { detectShellcode, extractShellcodeIocs } from "@/lib/shellcodeDetect";

/**
 * SocVerdictPanel — Analyst-friendly one-line verdict card that appears above
 * the workspace whenever a decode terminates on known shellcode / PE / ELF.
 *
 * Renders:
 *   • Malware family + arch
 *   • C2 IP + hardcoded User-Agent (if present)
 *   • MITRE ATT&CK technique badges
 *   • [COPY VERDICT] → puts the full SOC-ticket-ready block on the clipboard
 *
 * No backend call — everything is derived client-side from the decoded output
 * bytes via `detectShellcode()` + `extractShellcodeIocs()`.
 */
export default function SocVerdictPanel({ output, confidence, winnerEngine }) {
  const [copied, setCopied] = useState(false);

  const shellcode = useMemo(() => detectShellcode(output || ""), [output]);
  const iocs = useMemo(() => shellcode ? extractShellcodeIocs(output || "") : null, [shellcode, output]);

  if (!shellcode) return null;

  // Derive MITRE badges from what we observe in the shellcode text
  const mitre = ["T1027", "T1059.001", "T1055"];   // obfuscation, PowerShell, in-mem inject
  if (iocs?.ip || iocs?.url) mitre.push("T1105", "T1071.001");
  if (shellcode.family.includes("MSFvenom")) mitre.push("Meterpreter-family");

  const familyPretty = shellcode.family.includes("MSFvenom")
    ? `Metasploit / Meterpreter ${shellcode.arch} stager`
    : shellcode.family;

  const socTicket = [
    `═══ NIVXRAY — SOC VERDICT ═══`,
    ``,
    `Family:     ${familyPretty}`,
    `Arch:       ${shellcode.arch}`,
    `C2 IP:      ${iocs?.ip || "(none extracted)"}`,
    `URL:        ${iocs?.url || "(none extracted)"}`,
    `User-Agent: ${iocs?.userAgent || "(none extracted)"}`,
    `MITRE:      ${mitre.join(", ")}`,
    `Confidence: ${confidence ?? "?"} / 100 · engine=${winnerEngine || "magic"}`,
    ``,
    `RECOMMENDED ACTIONS:`,
    `  1. Block C2 IP ${iocs?.ip || "(see decoded output)"} at perimeter`,
    `  2. Hunt hardcoded User-Agent string across web proxy logs (30d)`,
    `  3. Add sample MD5/SHA256 to intel feeds (MISP / OTX / VirusTotal)`,
    `  4. Investigate: has any host already contacted this C2?`,
    ``,
    `═══════════════════════════════`,
  ].join("\n");

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(socTicket);
      setCopied(true);
      setTimeout(() => setCopied(false), 2200);
    } catch {}
  };

  return (
    <section
      className="brut-border"
      style={{
        background: "linear-gradient(180deg, rgba(217,108,108,0.10) 0%, rgba(217,108,108,0.03) 100%)",
        borderColor: "var(--high)",
        padding: 0,
      }}
      data-testid="soc-verdict-panel"
    >
      <div style={{ padding: "14px 18px", display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 14, alignItems: "center" }}>
        <Target size={22} style={{ color: "var(--high)" }} />
        <div>
          <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--high)", fontWeight: 700 }}>
            🎯 SOC VERDICT — SHELLCODE DETECTED
          </div>
          <div className="mono" style={{ fontSize: 14, color: "var(--text)", fontWeight: 600, marginTop: 5 }}>
            {familyPretty}
          </div>
        </div>
        <button
          className="nvx-btn primary"
          onClick={copy}
          data-testid="soc-verdict-copy"
          title="Copy SOC-ticket-ready verdict to clipboard"
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? " COPIED" : " COPY VERDICT"}
        </button>
      </div>

      <div style={{ padding: "0 18px 14px 18px", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12 }}>
        <VerdictField icon={ShieldAlert} label="Arch" value={shellcode.arch} color="var(--warn)" />
        {iocs?.ip && (
          <VerdictField icon={Wifi} label="C2 IP · block immediately"
                        value={iocs.ip} color="var(--high)" mono
                        testId="verdict-c2-ip" />
        )}
        {iocs?.userAgent && (
          <VerdictField label="Hardcoded UA" value={iocs.userAgent.slice(0, 60) + (iocs.userAgent.length > 60 ? "…" : "")}
                        color="var(--warn)" mono testId="verdict-ua" />
        )}
        <VerdictField label="Confidence" value={`${confidence ?? "?"} / 100 · ${winnerEngine || "magic"}`}
                      color="var(--accent)" />
      </div>

      <div style={{ padding: "0 18px 14px 18px" }}>
        <div className="mono" style={{ fontSize: 10, letterSpacing: "0.14em", color: "var(--text-mute)", marginBottom: 6 }}>
          MITRE ATT&amp;CK
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {mitre.map((t) => (
            <span key={t} className="badge" style={{ borderColor: "var(--warn)", color: "var(--warn)" }} data-testid={`verdict-mitre-${t}`}>
              {t}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

function VerdictField({ icon: Icon, label, value, color, mono, testId }) {
  return (
    <div className="brut-border" style={{ padding: "8px 12px", background: "var(--surface)" }} data-testid={testId}>
      <div className="mono" style={{ fontSize: 9, letterSpacing: "0.16em", color: "var(--text-mute)", textTransform: "uppercase", marginBottom: 3 }}>
        {Icon && <Icon size={9} style={{ verticalAlign: "middle", marginRight: 4 }} />}
        {label}
      </div>
      <div className={mono ? "mono" : ""} style={{ fontSize: 12, color, fontWeight: 600, wordBreak: "break-all" }}>
        {value}
      </div>
    </div>
  );
}
