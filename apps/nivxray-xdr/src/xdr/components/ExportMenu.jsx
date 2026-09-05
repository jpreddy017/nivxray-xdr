/**
 * ExportMenu · P1.9 · client-side investigation export.
 *
 * Builds the evidence manifest from what is already on screen and hands
 * it to the browser.  No server round-trip, no persisted artifact.
 */
import React, { useState } from "react";
import { Download, Loader2 } from "lucide-react";

import {
  buildExport, toJson, toMarkdown, toCsv, download, slug, EXPORT_MODE,
} from "@/xdr/lib/investigationExport";

const FORMATS = [
  { key: "json", label: "JSON (machine-verifiable)", ext: "json", mime: "application/json" },
  { key: "md",   label: "Markdown (analyst handover)", ext: "md",  mime: "text/markdown" },
  { key: "csv",  label: "CSV (evidence ledger)",       ext: "csv", mime: "text/csv" },
];

export default function ExportMenu({ build, basename, testid = "export" }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(null);
  const [last, setLast] = useState(null);

  const run = async (fmt) => {
    setBusy(fmt.key);
    try {
      const args = build();
      const pkg = await buildExport(args);
      const text = fmt.key === "json" ? toJson(pkg)
                 : fmt.key === "md"   ? toMarkdown(pkg)
                 : toCsv(pkg);
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      download(`nivxray-${slug(basename)}-${stamp}.${fmt.ext}`, text, fmt.mime);
      setLast({ rows: pkg.payload.events.length,
                digest: pkg.integrity.payload_sha256,
                redactions: pkg.payload.secret_redactions });
    } finally {
      setBusy(null);
      setOpen(false);
    }
  };

  return (
    <div style={{ position: "relative" }}>
      <button className="btn" style={{ padding: "4px 10px", fontSize: 10.5 }}
              onClick={() => setOpen((v) => !v)}
              title={`${EXPORT_MODE} · client-side only, nothing is stored server-side`}
              data-testid={`${testid}-button`}>
        {busy ? <Loader2 size={11} className="spin" /> : <Download size={11} />} Export
      </button>

      {open && (
        <div style={{ position: "absolute", right: 0, top: "calc(100% + 4px)",
                      zIndex: 80, width: 300, background: "#11161D",
                      border: "1px solid #212B36", borderRadius: 5,
                      boxShadow: "0 12px 34px rgba(0,0,0,0.55)", padding: 8 }}
             data-testid={`${testid}-menu`}>
          <div className="mono" style={{ fontSize: 9, color: "var(--faint)",
                                         lineHeight: 1.6, marginBottom: 7 }}>
            {EXPORT_MODE}
            <br />
            Scoped to the active window, filters and search. Evidence manifest
            only — no canvas rendering, no narrative. Carries its own SHA-256.
          </div>
          {FORMATS.map((f) => (
            <button key={f.key} className="btn"
                    style={{ width: "100%", justifyContent: "flex-start",
                             padding: "4px 8px", marginBottom: 4, fontSize: 10 }}
                    disabled={busy !== null}
                    onClick={() => run(f)}
                    data-testid={`${testid}-${f.key}`}>
              {f.label}
            </button>
          ))}
          <div className="mono" style={{ fontSize: 8.8, color: "#5D6875",
                                         marginTop: 4, lineHeight: 1.6 }}>
            Forensic fields (user, host, path, command line) are PRESERVED.
            Credential material inside a command line is replaced with
            [REDACTED:SECRET]. External sanitised handover is a future capability.
          </div>
        </div>
      )}

      {last && (
        <div className="mono" style={{ position: "absolute", right: 0,
                                       top: "calc(100% + 4px)", zIndex: 79,
                                       width: 300, fontSize: 8.8,
                                       color: "var(--faint)",
                                       background: "#0B0F14",
                                       border: "1px solid #212B36",
                                       borderRadius: 4, padding: 6,
                                       display: open ? "none" : "block" }}
             data-testid={`${testid}-receipt`}>
          ◆ exported {last.rows} evidence row{last.rows === 1 ? "" : "s"}
          {last.redactions > 0 && ` · ${last.redactions} secret redaction(s)`}
          <br />
          sha256 {last.digest ? `${last.digest.slice(0, 16)}…` : "⊘ unavailable"}
        </div>
      )}
    </div>
  );
}
