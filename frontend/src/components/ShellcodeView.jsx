import { useEffect, useState, useMemo } from "react";
import { Cpu, Binary, Loader2, ChevronDown, ChevronUp, AlertTriangle } from "lucide-react";
import api from "@/lib/api";

/**
 * ShellcodeView — the "stop-condition" panel of the recursive decode-and-route
 * pipeline. Rendered when the decoder output looks like an executable payload
 * (entropy >= 6.0 OR a known prologue/magic byte is present).
 *
 * Wires POST /api/analyze/shellcode to auto-detect arch (x86 / x86_64 / ARM /
 * Thumb / ARM64), disassemble via Capstone, and extract IOCs / API imports
 * from the binary buffer.
 */
const ARCH_CHOICES = [
  { id: "auto",   label: "AUTO" },
  { id: "x86_64", label: "x86_64" },
  { id: "x86",    label: "x86" },
  { id: "arm64",  label: "ARM64" },
  { id: "arm",    label: "ARM" },
  { id: "thumb",  label: "THUMB" },
];

export default function ShellcodeView({ output, initialArch = null }) {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [arch, setArch] = useState(initialArch || "auto");
  const [openIocs, setOpenIocs] = useState(true);

  // Pass output as-is (server auto-detects hex / base64 / utf-8).
  const runAnalysis = async (overrideArch) => {
    if (!output) return;
    setBusy(true); setErr("");
    try {
      const r = await api.post("/analyze/shellcode", {
        input: output,
        arch: (overrideArch ?? arch) === "auto" ? null : (overrideArch ?? arch),
        max_insns: 300,
      });
      setResult(r.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    } finally {
      setBusy(false);
    }
  };

  // Auto-run on mount / when output changes
  useEffect(() => {
    if (output) runAnalysis();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [output]);

  const iocCount = useMemo(() => {
    const i = result?.iocs || {};
    return (i.urls?.length || 0) + (i.ips?.length || 0) + (i.domains?.length || 0)
         + (i.regkeys?.length || 0) + (i.mutexes?.length || 0) + (i.imports?.length || 0)
         + Object.values(i.hashes || {}).reduce((a, b) => a + (b?.length || 0), 0);
  }, [result]);

  if (!output) return null;

  return (
    <div className="card" data-testid="shellcode-view" style={{
      marginTop: 12, border: "1px solid var(--high)",
      background: "linear-gradient(180deg, rgba(248,113,113,0.06), transparent 70%)",
    }}>
      <div className="card-head" style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        gap: 10, flexWrap: "wrap",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Binary size={14} color="var(--high)" />
          <span className="mono" style={{
            fontSize: 11, color: "var(--high)", letterSpacing: "0.22em",
          }}>
            ▸ SHELLCODE STOP-CONDITION
          </span>
          <span className="badge" data-testid="sc-stop-reason"
                style={{ background: "var(--high)22", color: "var(--high)", border: "1px solid var(--high)" }}>
            {result?.is_shellcode ? "BINARY" : "TEXT"}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
          {ARCH_CHOICES.map((c) => (
            <button
              key={c.id}
              data-testid={`sc-arch-${c.id}`}
              disabled={busy}
              onClick={() => { setArch(c.id); runAnalysis(c.id); }}
              className="mono"
              style={{
                fontSize: 10, letterSpacing: "0.14em", padding: "3px 8px",
                border: `1px solid ${arch === c.id ? "var(--accent)" : "var(--line)"}`,
                background: arch === c.id ? "var(--accent)22" : "transparent",
                color: arch === c.id ? "var(--accent)" : "var(--text-dim)",
                cursor: busy ? "wait" : "pointer", borderRadius: 2,
              }}
            >
              {c.label}
            </button>
          ))}
        </div>
      </div>

      {busy && (
        <div className="mono" style={{ padding: 14, fontSize: 11, color: "var(--text-dim)" }}>
          <Loader2 size={12} className="spin" /> analysing…
        </div>
      )}
      {err && (
        <div className="mono" style={{ padding: 12, fontSize: 11, color: "var(--high)" }}
             data-testid="sc-error">
          <AlertTriangle size={12} /> {err}
        </div>
      )}

      {result && !busy && (
        <div style={{ padding: 14, display: "grid", gap: 12 }}>
          <div className="mono" style={{
            fontSize: 11, color: "var(--text-dim)", display: "flex",
            flexWrap: "wrap", gap: 14,
          }} data-testid="sc-summary">
            <span>arch: <span style={{ color: "var(--accent)" }}>{result.arch}</span></span>
            <span>size: <span style={{ color: "var(--text)" }}>{result.size} B</span></span>
            <span>entropy: <span style={{ color: result.entropy >= 6 ? "var(--high)" : "var(--text)" }}>
              {result.entropy}
            </span></span>
            <span>source: {result.input_source}</span>
            {!result.capstone_available && (
              <span style={{ color: "var(--high)" }}>· capstone missing</span>
            )}
          </div>

          {/* Hex preview */}
          {result.hex_preview && (
            <div>
              <SectionHeader label="Hex preview · first 64 bytes" testid="sc-hex-preview-head" />
              <pre className="mono" data-testid="sc-hex-preview"
                   style={{
                     margin: 0, padding: 10, background: "var(--panel-2, rgba(0,0,0,0.35))",
                     border: "1px solid var(--line)", borderRadius: 2,
                     fontSize: 11, color: "var(--good)", overflow: "auto",
                     lineHeight: 1.55, wordBreak: "break-all",
                   }}>
                {result.hex_preview}
              </pre>
            </div>
          )}

          {/* Disassembly */}
          {result.disassembly?.length > 0 && (
            <div>
              <SectionHeader
                label={`Disassembly · ${result.arch} · ${result.disassembly.length} insns`}
                testid="sc-disasm-head"
              />
              <div style={{
                maxHeight: 320, overflow: "auto", border: "1px solid var(--line)",
                background: "var(--panel-2, rgba(0,0,0,0.35))", borderRadius: 2,
              }} data-testid="sc-disasm">
                <table className="mono" style={{
                  width: "100%", fontSize: 11, borderCollapse: "collapse",
                }}>
                  <tbody>
                    {result.disassembly.map((i, idx) => (
                      <tr key={idx} style={{ borderBottom: "1px solid var(--line)" }}>
                        <td style={{ padding: "3px 8px", color: "var(--text-dim)", width: 90 }}>
                          {i.addr}
                        </td>
                        <td style={{ padding: "3px 8px", color: "var(--good)", width: 180, whiteSpace: "nowrap" }}>
                          {i.hex}
                        </td>
                        <td style={{ padding: "3px 8px", color: "var(--accent)", fontWeight: 700, width: 70 }}>
                          {i.op}
                        </td>
                        <td style={{ padding: "3px 8px", color: "var(--text)" }}>
                          {i.args}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* IOCs */}
          {result.iocs && iocCount > 0 && (
            <div>
              <SectionHeader
                label={`Extracted IOCs · ${iocCount}`}
                testid="sc-iocs-head"
                collapsible
                open={openIocs}
                onToggle={() => setOpenIocs((s) => !s)}
              />
              {openIocs && (
                <div style={{ display: "grid", gap: 10 }} data-testid="sc-iocs">
                  <IocList label="URLs" items={result.iocs.urls} color="var(--accent)" testid="sc-iocs-urls" />
                  <IocList label="IPs" items={result.iocs.ips} color="var(--accent)" testid="sc-iocs-ips" />
                  <IocList label="Domains" items={result.iocs.domains} color="var(--accent)" testid="sc-iocs-domains" />
                  <IocList label="Reg keys" items={result.iocs.regkeys} color="var(--text)" testid="sc-iocs-regkeys" />
                  <IocList label="Mutexes" items={result.iocs.mutexes} color="var(--text)" testid="sc-iocs-mutexes" />
                  <IocList label="API imports" items={result.iocs.imports} color="var(--good)" testid="sc-iocs-imports" />
                  {["md5", "sha1", "sha256"].map((h) => (
                    <IocList key={h}
                             label={h.toUpperCase()}
                             items={result.iocs.hashes?.[h]}
                             color="var(--text-dim)"
                             testid={`sc-iocs-hash-${h}`}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function SectionHeader({ label, testid, collapsible, open, onToggle }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 6, marginBottom: 6,
      cursor: collapsible ? "pointer" : "default",
    }} onClick={collapsible ? onToggle : undefined} data-testid={testid}>
      <span className="mono" style={{
        fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.18em",
        textTransform: "uppercase",
      }}>
        {label}
      </span>
      {collapsible && (open ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
    </div>
  );
}


function IocList({ label, items, color, testid }) {
  if (!items || items.length === 0) return null;
  return (
    <div data-testid={testid} style={{ display: "flex", flexDirection: "column", gap: 3 }}>
      <span className="mono" style={{
        fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.15em",
      }}>
        {label} · {items.length}
      </span>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {items.map((v, i) => (
          <code key={i} className="mono" style={{
            fontSize: 11, padding: "2px 8px", color, border: `1px solid ${color}44`,
            background: `${color}0F`, borderRadius: 2, wordBreak: "break-all",
          }}>
            {v}
          </code>
        ))}
      </div>
    </div>
  );
}
