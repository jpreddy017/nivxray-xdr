/**
 * ADR-0022 · Lab2Renderer for /nivxforge/investigate.
 *
 * Owns the FULL investigation experience under the feature flag:
 *   1. Input capture (textarea + focus + file upload)
 *   2. Content-aware submission (same routing as legacy: decode/smart vs v2/auto-investigate)
 *   3. Mounts Lab2Provider with the returned CIO
 *   4. Renders Lab2Shell — the permanent workspace layout contract
 *
 * §4 principle: renderers do NOT coexist. The LegacyInvestigate
 * renderer is unaware of this file, and vice versa.
 *
 * All investigation output flows through the CIO — never through
 * a bespoke pipeline JSON. Downstream lenses (Phase B) will
 * consume selectors and dock into the shell's canvas slot.
 */
import React, { useCallback, useState } from "react";
import api from "../../lib/api";
import { Lab2Provider } from "./Lab2Provider";
import Lab2Shell from "./Lab2Shell";
import Lab2ToggleButton from "./Lab2ToggleButton";
import "../design/tokens.css";

const S = {
  root: {
    minHeight: "100vh",
    background: "var(--bg-canvas)",
    color: "var(--fg-primary)",
    fontFamily: "var(--font-sans)",
  },
  bar: {
    display: "flex",
    gap: "var(--space-3)",
    padding: "var(--space-4) var(--space-6)",
    background: "var(--bg-panel)",
    borderBottom: "1px solid var(--border)",
    alignItems: "center",
  },
  input: {
    flex: 1,
    background: "var(--bg-canvas)",
    color: "var(--fg-primary)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-sm)",
    padding: "var(--space-3) var(--space-4)",
    fontFamily: "var(--font-mono)",
    fontSize: "var(--fs-body)",
    minWidth: 0,
  },
  submit: {
    padding: "var(--space-3) var(--space-5)",
    background: "var(--fg-accent)",
    color: "var(--fg-inverse)",
    border: "none",
    borderRadius: "var(--radius-sm)",
    fontFamily: "var(--font-mono)",
    fontWeight: "var(--fw-bold)",
    letterSpacing: "0.14em",
    textTransform: "uppercase",
    fontSize: "var(--fs-caption)",
    cursor: "pointer",
  },
  err: {
    padding: "var(--space-4) var(--space-6)",
    color: "var(--verdict-critical)",
    fontFamily: "var(--font-mono)",
    fontSize: "var(--fs-body)",
    background: "var(--bg-panel)",
    borderBottom: "1px solid var(--border)",
  },
  loading: {
    padding: "var(--space-3) var(--space-6)",
    color: "var(--fg-quiet)",
    fontFamily: "var(--font-mono)",
    fontSize: "var(--fs-caption)",
    letterSpacing: "0.12em",
    background: "var(--bg-panel)",
    borderBottom: "1px solid var(--border)",
  },
};

// Copied verbatim from legacy renderer (ADR-0014 · Phase 1 content-based
// routing). We do NOT reimplement or diverge — one pipeline, two
// renderers.
function detectPipeline(text) {
  const raw = (text || "").trim();
  if (!raw) return "decode";
  const looksLikeJson = /^[\[{]/.test(raw) && /[\]}]$/.test(raw);
  if (looksLikeJson) {
    const vendorSignals = /"(connector_guid|computer|detection|falcon|CrowdStrike|Defender|SecurityAlert|QRadar|SentinelOne|threat_name|SHA256|sha256|ExecutedMalware|amp\.cisco\.com|xdr\.us\.security\.cisco\.com|Sysmon)"/i;
    if (vendorSignals.test(raw)) return "auto";
    if (/"(incident|alert|host|user|process|command_line|src_ip|dst_ip|hash)"/i.test(raw)) return "auto";
  }
  const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const incidentSignals = /\b(incident|alert|detection|malware|SIEM|SOC|IOC|SHA256|MD5|host\s*=|user\s*=|process\s*=|src_ip|dst_ip|ExecutedMalware|Quarantine|Cisco Secure|CrowdStrike|Falcon|Defender|QRadar|Splunk|SentinelOne|Sysmon)\b/i;
  if (incidentSignals.test(raw)) return "auto";
  if (lines.length >= 3) return "auto";
  return "decode";
}

export default function Lab2InvestigateRenderer() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [cio, setCio] = useState(null);

  const run = useCallback(async () => {
    if (!input.trim() || loading) return;
    setLoading(true);
    setErr("");
    setCio(null);
    const pipeline = detectPipeline(input);
    try {
      const r =
        pipeline === "auto"
          ? await api.post("/v2/auto-investigate", { incident_text: input, focus: null })
          : await api.post("/decode/smart", { input });
      setCio(r.data?.cio || null);
    } catch (e) {
      setErr(e?.friendlyMessage || e?.response?.data?.detail || String(e?.message || e));
    } finally {
      setLoading(false);
    }
  }, [input, loading]);

  return (
    <div className="lab2" style={S.root} data-testid="lab2-renderer">
      <div style={S.bar} data-testid="lab2-input-bar">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              run();
            }
          }}
          placeholder="Paste command line, script, or incident excerpt · press Enter to investigate"
          style={S.input}
          data-testid="lab2-input"
        />
        <button
          type="button"
          onClick={run}
          disabled={loading || !input.trim()}
          style={{ ...S.submit, opacity: loading || !input.trim() ? 0.5 : 1 }}
          data-testid="lab2-submit"
        >
          {loading ? "Investigating…" : "Investigate"}
        </button>
      </div>

      {loading ? (
        <div style={S.loading} data-testid="lab2-loading">
          RUNNING · Investigation Engine
        </div>
      ) : null}
      {err ? (
        <div style={S.err} data-testid="lab2-error">
          {err}
        </div>
      ) : null}

      <Lab2Provider initialCIO={cio}>
        <Lab2Shell
          caseLabel={cio?.cio_id || "no active case"}
          headerRight={
            <>
              <Lab2ToggleButton />
              <button type="button" style={{ padding: "6px 10px", borderRadius: 4, background: "transparent", border: "1px solid var(--border)", color: "var(--fg-quiet)", fontSize: 11, fontFamily: "var(--font-mono)", letterSpacing: "0.12em", cursor: "pointer" }} data-testid="lab2-palette-trigger">⌘K</button>
            </>
          }
        />
      </Lab2Provider>
    </div>
  );
}
