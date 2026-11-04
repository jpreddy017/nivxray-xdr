/**
 * ELF Analysis Panel — Phase 3 · Cycle C · 2026-02.
 * Consumes shape from services.artifact_intelligence.analyzers.elf.
 */
import { useState } from "react";
import { ChevronDown, ChevronRight, Cpu, Layers, ShieldAlert, PackageOpen, Hash, ScrollText } from "lucide-react";

const _sevColor = (sev) => {
  switch (sev) {
    case "critical": return { fg: "#f43f5e", bg: "rgba(244,63,94,0.10)",  br: "rgba(244,63,94,0.45)" };
    case "high":     return { fg: "#f87171", bg: "rgba(248,113,113,0.10)", br: "rgba(248,113,113,0.40)" };
    case "medium":   return { fg: "#fcd34d", bg: "rgba(252,211,77,0.08)",  br: "rgba(252,211,77,0.35)" };
    case "low":      return { fg: "#7dd3fc", bg: "rgba(125,211,252,0.08)", br: "rgba(125,211,252,0.30)" };
    default:         return { fg: "#94a3b8", bg: "rgba(148,163,184,0.06)", br: "rgba(148,163,184,0.25)" };
  }
};

function Section({ title, icon: Icon, count, testId, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div data-testid={testId}
         style={{ border: "1px solid var(--border)", borderRadius: 6, background: "rgba(2,6,23,0.35)", marginBottom: 8 }}>
      <button type="button" onClick={() => setOpen((v) => !v)} data-testid={`${testId}-toggle`}
              style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "10px 14px",
                       background: "transparent", border: "none", cursor: "pointer", color: "var(--text)", textAlign: "left" }}>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        {Icon && <Icon size={14} style={{ color: "var(--accent)" }} />}
        <span className="mono" style={{ fontSize: 11, letterSpacing: "0.14em", fontWeight: 700 }}>{title}</span>
        {count != null && <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", marginLeft: 4 }}>({count})</span>}
      </button>
      {open && <div style={{ padding: "0 14px 14px" }}>{children}</div>}
    </div>
  );
}

function CharFlag({ set, label, color }) {
  return (
    <span className="mono" style={{
      fontSize: 9, padding: "1px 5px", borderRadius: 3, letterSpacing: "0.10em", fontWeight: 700,
      background: set ? color.bg : "transparent",
      color:      set ? color.fg : "rgba(148,163,184,0.35)",
      border:     `1px solid ${set ? color.br : "rgba(148,163,184,0.15)"}`,
    }}>{label}</span>
  );
}

export default function ELFAnalysisPanel({ elf, hashes }) {
  if (!elf) return null;
  if (elf.available === false) {
    return (
      <div data-testid="elf-analysis-unavailable"
           style={{ border: "1px dashed rgba(148,163,184,0.35)", borderRadius: 6,
                    padding: "14px 18px", background: "rgba(2,6,23,0.35)", marginBottom: 12 }}>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", letterSpacing: "0.14em" }}>
          ELF ANALYSIS CAPABILITY UNAVAILABLE
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>{elf.message}</div>
      </div>
    );
  }
  if (elf.error) {
    return (
      <div data-testid="elf-analysis-error"
           style={{ border: "1px solid rgba(248,113,113,0.35)", borderRadius: 6,
                    padding: "14px 18px", background: "rgba(248,113,113,0.06)", marginBottom: 12 }}>
        <div className="mono" style={{ fontSize: 11, color: "#f87171", letterSpacing: "0.14em" }}>ELF ANALYSIS FAILED · {elf.error}</div>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>{elf.message}</div>
      </div>
    );
  }

  const { overview, sections, segments, dynamic, symbols, notes, findings } = elf;
  const highSev = _sevColor("high");
  const medSev = _sevColor("medium");
  const infoSev = _sevColor("info");

  return (
    <div data-testid="elf-analysis-panel" className="brut-border"
         style={{ padding: 16, background: "var(--surface)", borderRadius: 8, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <Cpu size={16} style={{ color: "var(--accent)" }} />
        <span className="mono" style={{ fontSize: 12, letterSpacing: "0.20em", fontWeight: 800, color: "var(--accent)" }}>
          ELF STATIC ANALYSIS
        </span>
        <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }} data-testid="elf-header-summary">
          {overview.elf_class}-bit · {overview.machine} · {overview.type} · {overview.endianness}
        </span>
      </div>

      {findings && findings.length > 0 && (
        <div data-testid="elf-findings" style={{ marginBottom: 10 }}>
          {findings.map((f, i) => {
            const c = _sevColor(f.severity);
            return (
              <div key={`${f.code}-${i}`} data-testid={`elf-finding-${f.code}`}
                   style={{ border: `1px solid ${c.br}`, background: c.bg, borderRadius: 6,
                            padding: "8px 12px", marginBottom: 6, display: "flex", gap: 10, alignItems: "flex-start" }}>
                <ShieldAlert size={13} style={{ color: c.fg, marginTop: 2 }} />
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                    <span className="mono" style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, letterSpacing: "0.14em",
                                                     background: c.bg, color: c.fg, border: `1px solid ${c.br}`, fontWeight: 700 }}>
                      {String(f.severity || "info").toUpperCase()}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: c.fg, fontWeight: 600 }}>{f.title}</span>
                  </div>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)" }}>{f.detail}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <Section title="OVERVIEW" icon={Layers} testId="elf-overview" defaultOpen>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          {[
            ["ELF Class",   `${overview.elf_class}-bit`],
            ["Endianness",  overview.endianness],
            ["Machine",     overview.machine],
            ["Type",        overview.type],
            ["Entry Point", overview.entry_point],
            ["ABI",         overview.abi],
            ["Sections",    String(overview.num_sections)],
            ["Segments",    String(overview.num_segments)],
            ["File Size",   `${overview.file_size} B`],
          ].map(([k, v]) => (
            <div key={k} className="mono" style={{ fontSize: 10.5 }}>
              <span style={{ color: "var(--text-dim)", letterSpacing: "0.10em" }}>{k}</span>
              <div style={{ color: "var(--text)", fontWeight: 700, marginTop: 1, wordBreak: "break-all" }}>{v}</div>
            </div>
          ))}
        </div>
      </Section>

      <Section title="SECTIONS" icon={Layers} testId="elf-sections" count={sections.length}>
        <div style={{ overflowX: "auto" }}>
          <table className="mono" style={{ width: "100%", fontSize: 10.5, borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ color: "var(--text-dim)", textAlign: "left", letterSpacing: "0.10em" }}>
                <th style={{ padding: "6px 8px" }}>Name</th>
                <th style={{ padding: "6px 8px" }}>Type</th>
                <th style={{ padding: "6px 8px" }}>Addr</th>
                <th style={{ padding: "6px 8px" }}>Size</th>
                <th style={{ padding: "6px 8px" }}>Entropy</th>
                <th style={{ padding: "6px 8px" }}>Flags</th>
              </tr>
            </thead>
            <tbody>
              {sections.map((s, i) => (
                <tr key={i} data-testid={`elf-section-${i}`} style={{ borderTop: "1px solid rgba(148,163,184,0.10)" }}>
                  <td style={{ padding: "6px 8px", color: "var(--text)", fontWeight: 700 }}>{s.name}</td>
                  <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{s.type}</td>
                  <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{s.addr}</td>
                  <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{s.size}</td>
                  <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{s.entropy.toFixed(2)}</td>
                  <td style={{ padding: "6px 8px", display: "flex", gap: 4 }}>
                    <CharFlag set={true}          label="A" color={infoSev} />
                    <CharFlag set={s.flags.write} label="W" color={medSev} />
                    <CharFlag set={s.flags.exec}  label="X" color={highSev} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="SEGMENTS" icon={PackageOpen} testId="elf-segments" count={segments.length}>
        {segments.map((seg, i) => (
          <div key={i} className="mono" style={{ fontSize: 10.5, padding: "4px 0", display: "flex", gap: 10, alignItems: "center" }}>
            <span style={{ color: "var(--text)", fontWeight: 700, minWidth: 140 }}>{seg.type}</span>
            <span style={{ color: "var(--text-dim)" }}>vaddr {seg.vaddr}</span>
            <span style={{ color: "var(--text-dim)" }}>filesz {seg.filesz}</span>
            <span style={{ display: "flex", gap: 4 }}>
              <CharFlag set={seg.permissions.read}  label="R" color={infoSev} />
              <CharFlag set={seg.permissions.write} label="W" color={medSev} />
              <CharFlag set={seg.permissions.exec}  label="X" color={highSev} />
            </span>
          </div>
        ))}
      </Section>

      <Section title="DYNAMIC" icon={PackageOpen} testId="elf-dynamic"
               count={(dynamic.needed?.length || 0) + (dynamic.rpath?.length || 0) + (dynamic.runpath?.length || 0)}>
        {dynamic.needed?.length > 0 && (
          <>
            <div className="mono" style={{ fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.14em", marginBottom: 3 }}>DT_NEEDED</div>
            {dynamic.needed.map((n) => (
              <div key={n} className="mono" style={{ fontSize: 10.5, color: "var(--text)", padding: "1px 0" }}>{n}</div>
            ))}
          </>
        )}
        {dynamic.rpath?.length > 0 && (
          <div style={{ marginTop: 6 }}>
            <div className="mono" style={{ fontSize: 10, color: "#f87171", letterSpacing: "0.14em" }}>DT_RPATH</div>
            {dynamic.rpath.map((n) => <div key={n} className="mono" style={{ fontSize: 10.5, color: "#f87171" }}>{n}</div>)}
          </div>
        )}
        {dynamic.runpath?.length > 0 && (
          <div style={{ marginTop: 6 }}>
            <div className="mono" style={{ fontSize: 10, color: "#fcd34d", letterSpacing: "0.14em" }}>DT_RUNPATH</div>
            {dynamic.runpath.map((n) => <div key={n} className="mono" style={{ fontSize: 10.5, color: "#fcd34d" }}>{n}</div>)}
          </div>
        )}
        {dynamic.soname && (
          <div className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 6 }}>SONAME · {dynamic.soname}</div>
        )}
      </Section>

      {symbols && symbols.length > 0 && (
        <Section title="DYNAMIC SYMBOLS" icon={ScrollText} testId="elf-symbols" count={symbols.length}>
          <div style={{ maxHeight: 240, overflowY: "auto" }}>
            {symbols.slice(0, 250).map((s, i) => (
              <div key={i} className="mono" style={{ fontSize: 10.5, padding: "1px 0", display: "flex", gap: 8 }}>
                <span style={{ color: "var(--text)", fontWeight: 700, minWidth: 220, wordBreak: "break-all" }}>{s.name}</span>
                <span style={{ color: "var(--text-dim)" }}>{s.type}</span>
                <span style={{ color: "var(--text-dim)" }}>{s.bind}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {hashes && (
        <Section title="HASHES" icon={Hash} testId="elf-hashes">
          {["md5","sha1","sha256"].map((k) => hashes[k] ? (
            <div key={k} className="mono" style={{ fontSize: 10.5, padding: "3px 0", display: "flex", gap: 8 }}>
              <span style={{ color: "var(--text-dim)", width: 60 }}>{k.toUpperCase()}</span>
              <span style={{ color: "var(--text)", wordBreak: "break-all", flex: 1 }}>{hashes[k]}</span>
            </div>
          ) : null)}
        </Section>
      )}
    </div>
  );
}
