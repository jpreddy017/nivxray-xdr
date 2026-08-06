/**
 * InvestigationSessionGateway · Rule R22 (2026-03-02)
 * ───────────────────────────────────────────────────
 * Compact card the Workspace shows after AUTO INVESTIGATE completes
 * on an acquired document.  Replaces the heavy inline artifacts
 * table with:
 *
 *   • A one-glance readiness summary
 *     (✓ HTML Acquired · ✓ N Commands Investigated · ✓ N URLs …)
 *   • A gateway button → /workspace/session/:id
 *   • A "Resume Investigation" affordance (the Workspace itself)
 *
 * On click, mints a durable Session server-side (POST
 * /api/session/from-investigation) and navigates.  Falls back to a
 * client-cached session envelope so the deep-dive still opens even
 * when Mongo is unavailable.
 */
import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "@/lib/api";

const CACHE_KEY = (id) => `nivxray:session:${id}`;
const MIRROR    = "nivxray:last_investigation";

export default function InvestigationSessionGateway({ investigation, input }) {
  const navigate = useNavigate();
  const [minting, setMinting] = useState(false);
  const [session, setSession] = useState(null);
  const [error,   setError]   = useState(null);

  const summary = useMemo(() => _localSummary(investigation), [investigation]);

  async function openSession() {
    setMinting(true);
    setError(null);
    try {
      const { data } = await api.post("/session/from-investigation", {
        input, investigation,
      });
      const s = data?.session;
      if (s?.session_id) {
        try {
          sessionStorage.setItem(CACHE_KEY(s.session_id), JSON.stringify(s));
          sessionStorage.setItem(MIRROR, JSON.stringify(investigation));
        } catch { /* noop */ }
        setSession(s);
        navigate(`/workspace/session/${s.session_id}`);
        return;
      }
      throw new Error("No session returned.");
    } catch (e) {
      // Client-side fallback: build a minimal session envelope from the
      // investigation object so the analyst still gets to the deep-dive.
      const fallbackId = `ses_local_${Date.now().toString(36)}`;
      try {
        const local = {
          session_id: fallbackId,
          schema: "session-v1",
          summary,
          document_profile:  investigation.document_profile,
          acquired_document: investigation.acquired_document,
          incident:          investigation.incident,
          investigation_inputs: [],  // resolved on the session page from mirror
          raw_investigation: investigation,
        };
        sessionStorage.setItem(CACHE_KEY(fallbackId), JSON.stringify(local));
        sessionStorage.setItem(MIRROR, JSON.stringify(investigation));
      } catch { /* noop */ }
      setError(e?.response?.data?.detail || "Persist failed — opened locally.");
      navigate(`/workspace/session/${fallbackId}`);
    } finally {
      setMinting(false);
    }
  }

  if (!investigation) return null;

  return (
    <section style={sx.wrap} data-testid="investigation-session-gateway">
      <div style={sx.head}>
        <div style={sx.eyebrow}>▸ INVESTIGATION COMPLETE</div>
        <div style={sx.title}>{summary.title}</div>
        {summary.vendor && (
          <div style={sx.subtitle}>{summary.vendor}</div>
        )}
      </div>

      <ul style={sx.checkList}>
        {summary.checks.map((c, i) => (
          <li key={i} style={sx.check} data-testid={`gateway-check-${i}`}>
            <span style={sx.ok}>✓</span>
            <span style={sx.checkLabel}>{c.label}</span>
            {c.detail && <span style={sx.checkDetail}>· {c.detail}</span>}
          </li>
        ))}
        {!summary.checks.length && (
          <li style={sx.dim}>No readiness signals extracted.</li>
        )}
      </ul>

      <div style={sx.actions}>
        <button
          type="button"
          onClick={openSession}
          disabled={minting}
          data-testid="btn-open-investigation-session"
          style={{ ...sx.primary, opacity: minting ? 0.6 : 1 }}>
          {minting ? "Opening …" : "Open Investigation Session →"}
        </button>
        <span style={sx.resumeHint} data-testid="gateway-resume-hint">
          You are here.  Scroll to resume this Workspace.
        </span>
      </div>
      {error && <div style={sx.err} data-testid="gateway-error">{error}</div>}
    </section>
  );
}


// ── Deterministic summary card ────────────────────────────────────
function _localSummary(inv) {
  const prof  = inv?.document_profile || {};
  const acq   = inv?.acquired_document || {};
  const ext   = inv?.report_extraction || {};
  const inc   = inv?.incident?.summary || {};
  const commands       = ext.commands || [];
  const investigations = ext.command_investigations || [];
  const investigated   = investigations.filter(i => i && !i.error && i.language).length;

  const counts = {
    urls:     (ext.body_artifacts || []).filter(a => a.type === "url").length,
    hashes:   (ext.body_artifacts || []).filter(a => a.type === "hash").length,
    ips:      (ext.body_artifacts || []).filter(a => a.type === "ip").length,
    domains:  (ext.body_artifacts || []).filter(a => a.type === "domain").length,
    paths:    (ext.body_artifacts || []).filter(a => a.type === "file_path").length,
    cves:     (ext.body_artifacts || []).filter(a => a.type === "cve").length,
  };

  const checks = [];
  if (acq?.ok) {
    checks.push({
      label:  "HTML Acquired",
      detail: prof.vendor || acq.sitename || "",
    });
  }
  if (commands.length) {
    checks.push({
      label:  `${commands.length} Command${commands.length === 1 ? "" : "s"} Investigated`,
      detail: `${investigated}/${commands.length} full DIE`,
    });
  }
  for (const [k, label] of [
    ["urls",    "URLs"],
    ["hashes",  "Hashes"],
    ["ips",     "IPs"],
    ["domains", "Domains"],
    ["paths",   "File Paths"],
    ["cves",    "CVEs"],
  ]) {
    if (counts[k]) checks.push({ label: `${counts[k]} ${label} Correlated` });
  }

  return {
    title:    prof.title || acq.title || "Investigation",
    vendor:   prof.vendor || acq.sitename || "",
    actor:    inc.actor,
    severity: inc.severity,
    checks,
    counts,
  };
}


// ── Styles ────────────────────────────────────────────────────────
const sx = {
  wrap: {
    margin: "12px 12px 10px",
    padding: "14px 18px",
    border: "1px solid rgba(126, 230, 168, 0.28)",
    borderRadius: 4,
    background: "linear-gradient(180deg, rgba(0, 40, 22, 0.55), rgba(0, 30, 15, 0.35))",
    color: "#c5f5d6",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
  },
  head:     { marginBottom: 10 },
  eyebrow:  { fontSize: 10, letterSpacing: 2, color: "#7ee6a8" },
  title:    { fontSize: 16, color: "#e6ffe9", marginTop: 4 },
  subtitle: { fontSize: 11, color: "#96c9aa", marginTop: 2 },
  checkList: {
    listStyle: "none", padding: 0, margin: "10px 0",
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    gap: 4, fontSize: 12,
  },
  check:       { display: "flex", gap: 6, alignItems: "baseline",
                  color: "#e6ffe9" },
  ok:          { color: "#3ddc84" },
  checkLabel:  { color: "#e6ffe9" },
  checkDetail: { color: "#7ee6a8", opacity: 0.75 },
  actions: {
    marginTop: 10,
    display: "flex", alignItems: "center", justifyContent: "space-between",
    gap: 12, flexWrap: "wrap",
  },
  primary: {
    background: "#0d3d24", color: "#7ee6a8",
    border: "1px solid #7ee6a8",
    padding: "8px 16px", borderRadius: 3,
    fontFamily: "inherit", fontSize: 12, letterSpacing: 1.2,
    cursor: "pointer", textTransform: "uppercase",
  },
  resumeHint: { fontSize: 10, color: "#96c9aa", letterSpacing: 1 },
  err: { marginTop: 8, fontSize: 11, color: "#ff9a9a" },
  dim: { color: "#96c9aa", fontSize: 11 },
};
