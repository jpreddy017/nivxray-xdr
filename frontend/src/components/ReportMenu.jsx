import { useState, useRef, useEffect } from "react";
import { Download, ChevronDown, FileText, FileCode2, FileSpreadsheet, FileType2, FileText as FilePdf } from "lucide-react";

const FORMATS = [
  { id: "html", label: "HTML", icon: <FileCode2 size={12} />, hint: "styled web report" },
  { id: "pdf",  label: "PDF",  icon: <FilePdf size={12} />, hint: "printable report" },
  { id: "docx", label: "DOCX", icon: <FileType2 size={12} />, hint: "Microsoft Word" },
  { id: "csv",  label: "CSV",  icon: <FileSpreadsheet size={12} />, hint: "artifacts spreadsheet" },
  { id: "txt",  label: "TXT",  icon: <FileText size={12} />, hint: "plain text" },
];

export default function ReportMenu({ onDownload }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);
  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button className="nvx-btn" onClick={() => setOpen(!open)} data-testid="btn-download-report">
        <Download size={13} /> REPORT <ChevronDown size={11} />
      </button>
      {open && (
        <div
          data-testid="report-format-menu"
          className="brut-border"
          style={{
            position: "absolute", top: "calc(100% + 4px)", right: 0,
            background: "var(--surface)", minWidth: 220, zIndex: 30,
          }}
        >
          <div className="mono" style={{ padding: "8px 10px", fontSize: 10, color: "var(--text-mute)", letterSpacing: "0.16em", borderBottom: "1px solid var(--border)" }}>
            EXPORT FORMAT
          </div>
          {FORMATS.map((f) => (
            <button
              key={f.id}
              data-testid={`report-fmt-${f.id}`}
              onClick={() => { setOpen(false); onDownload(f.id); }}
              className="mono"
              style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                width: "100%", padding: "8px 10px", background: "transparent",
                color: "var(--text)", border: "none", borderBottom: "1px solid var(--border)",
                cursor: "pointer", fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
                textAlign: "left",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--inset)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ color: "var(--accent)" }}>{f.icon}</span>
                {f.label}
              </span>
              <span style={{ color: "var(--text-mute)", fontSize: 10 }}>{f.hint}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
