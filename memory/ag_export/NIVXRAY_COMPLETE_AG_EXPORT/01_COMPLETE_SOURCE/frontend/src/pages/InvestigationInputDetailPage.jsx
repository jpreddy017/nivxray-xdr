/**
 * InvestigationInputDetailPage · Rule R22 (2026-03-02)
 * ────────────────────────────────────────────────────
 * Deep-dive page for a single Investigation Input (one extracted
 * artifact that was promoted to a full child investigation).
 *
 * Route: /workspace/session/:sessionId/input/:inputId
 * Source: GET /api/session/:sessionId/input/:inputId
 *
 * RULE: this page renders the SAME shape the atomic-paste
 * investigation produces.  No bespoke UI.  For commands, that means
 * language + decoded output + MITRE techniques + LOLBAS + IOCs +
 * risk + evidence, all derived deterministically by the same DIE
 * pipeline the Workspace runs for a manual paste.
 */
import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import api from "@/lib/api";

export default function InvestigationInputDetailPage() {
  const { sessionId, inputId } = useParams();
  const [state, setState] = useState({ loading: true, input: null, error: null });

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { data } = await api.get(`/session/${sessionId}/input/${inputId}`);
        if (!alive) return;
        setState({ loading: false, input: data?.input, error: null });
      } catch (e) {
        // fallback: pull from sessionStorage-cached session
        try {
          const raw = sessionStorage.getItem(`nivxray:session:${sessionId}`);
          if (raw) {
            const s = JSON.parse(raw);
            const found = (s.investigation_inputs || []).find(i => i.id === inputId);
            if (found && alive) {
              setState({ loading: false, input: found, error: null });
              return;
            }
          }
        } catch { /* noop */ }
        if (alive) {
          setState({ loading: false, input: null,
                      error: e?.response?.data?.detail || "Investigation Input not found." });
        }
      }
    })();
    return () => { alive = false; };
  }, [sessionId, inputId]);

  if (state.loading) return <Shell><p style={sx.dim}>Loading …</p></Shell>;
  if (!state.input)  return <Shell><p style={sx.dim}>{state.error || "Not found."}</p></Shell>;

  const inp = state.input;
  const inv = inp.investigation || {};

  return (
    <Shell sessionId={sessionId} inputId={inputId}>
      <Header input={inp} />
      <Section title="Original">
        <pre style={sx.code} data-testid="input-original">{inp.value || "—"}</pre>
      </Section>

      {inv.stage?.decoded && inv.stage.decoded !== inp.value && (
        <Section title="Decoded">
          <pre style={sx.code} data-testid="input-decoded">
            {inv.stage.decoded}
          </pre>
        </Section>
      )}

      <Section title="Classification">
        <KV rows={[
          ["Language",   inv.language   || inp.type_label || "—"],
          ["Section",    inp.section    || "—"],
          ["Source",     inp.source     || "—"],
          ["Purpose",    inp.purpose    || inv.stage?.purpose || "—"],
          ["Status",     inp.status     || "—"],
        ]} />
      </Section>

      <Section title={`MITRE ATT&CK (${(inv.techniques || []).length})`}>
        {inv.techniques?.length ? (
          <ul style={sx.list}>
            {inv.techniques.map((t, i) => (
              <li key={i} style={sx.listItem}
                  data-testid={`input-mitre-${i}`}>
                <strong style={sx.tid}>{t.id}</strong>
                <span>{t.name}</span>
              </li>
            ))}
          </ul>
        ) : <p style={sx.dim}>None mapped.</p>}
      </Section>

      <Section title={`LOLBAS (${(inv.lolbins || []).length})`}>
        {inv.lolbins?.length ? (
          <ul style={sx.list}>
            {inv.lolbins.map((lb, i) => (
              <li key={i} style={sx.listItem}
                  data-testid={`input-lolbas-${i}`}>
                <strong>{lb.binary || lb.name}</strong>
                {lb.description && <span style={sx.dim}>· {lb.description}</span>}
              </li>
            ))}
          </ul>
        ) : <p style={sx.dim}>None matched.</p>}
      </Section>

      <Section title={`IOCs (${(inv.iocs || []).length})`}>
        {inv.iocs?.length ? (
          <ul style={sx.list}>
            {inv.iocs.map((ioc, i) => (
              <li key={i} style={sx.listItem}
                  data-testid={`input-ioc-${i}`}>
                <span style={sx.tid}>{ioc.kind || ioc.type}</span>
                <span style={sx.wrap}>{ioc.value || ioc.indicator}</span>
              </li>
            ))}
          </ul>
        ) : <p style={sx.dim}>None extracted.</p>}
      </Section>

      {inv.stage?.families?.length > 0 && (
        <Section title="Behavior Families">
          <ul style={sx.list}>
            {inv.stage.families.map((f, i) => (
              <li key={i} style={sx.listItem}>
                <strong>{f.name || f.id}</strong>
                {f.confidence != null && (
                  <span style={sx.dim}>· {Math.round(f.confidence * 100)}%</span>
                )}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {inp.detail && (
        <Section title="Detail">
          <pre style={sx.code} data-testid="input-detail">
            {JSON.stringify(inp.detail, null, 2)}
          </pre>
        </Section>
      )}
    </Shell>
  );
}

// ── Sub-components ────────────────────────────────────────────────
function Shell({ sessionId, inputId, children }) {
  return (
    <div style={sx.page} data-testid="input-detail-page">
      <div style={sx.breadcrumb}>
        <Link to="/" style={sx.link}>Workspace</Link>
        <span style={sx.sep}>›</span>
        {sessionId
          ? <Link to={`/workspace/session/${sessionId}`} style={sx.link}>Investigation Session</Link>
          : <span>Investigation Session</span>}
        <span style={sx.sep}>›</span>
        <span style={sx.active}>Investigation Input</span>
        {inputId && <span style={sx.crumbId}>· {inputId}</span>}
      </div>
      {children}
    </div>
  );
}

function Header({ input }) {
  return (
    <header style={sx.header}>
      <div style={sx.eyebrow}>▸ INVESTIGATION INPUT #{input.index}</div>
      <div style={sx.title}>{input.type_label}</div>
      <div style={sx.meta}>
        {input.section && <span>{input.section}</span>}
        {input.source  && <span>· {input.source}</span>}
        <StatusPill status={input.status} />
      </div>
    </header>
  );
}

function StatusPill({ status }) {
  const color = status === "investigated" ? "#3ddc84"
              : status === "correlated"   ? "#7ee6a8"
              :                              "#96c9aa";
  return (
    <span style={{ ...sx.pill, color, borderColor: color }}
           data-testid={`status-${status}`}>
      {status?.toUpperCase()}
    </span>
  );
}

function Section({ title, children }) {
  return (
    <section style={sx.section}
             data-testid={`section-${title.split(" ")[0].toLowerCase()}`}>
      <h3 style={sx.h3}>{title}</h3>
      {children}
    </section>
  );
}

function KV({ rows }) {
  return (
    <div style={sx.kvBlock}>
      {rows.map(([k, v]) => (
        <div key={k} style={sx.kvRow}>
          <span style={sx.kvKey}>{k}</span>
          <span style={sx.kvVal}>{v || "—"}</span>
        </div>
      ))}
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────
const sx = {
  page: {
    background: "#001a0d", minHeight: "100vh",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    color: "#c5f5d6", padding: "18px 24px 60px",
  },
  breadcrumb: { fontSize: 11, color: "#7ee6a8", letterSpacing: 1.4,
                 marginBottom: 12, display: "flex", gap: 8, alignItems: "center" },
  link: { color: "#7ee6a8", textDecoration: "none" },
  sep:  { color: "#4a8b63" },
  active: { color: "#e6ffe9" },
  crumbId: { color: "#4a8b63" },
  header: {
    padding: "8px 0 16px",
    borderBottom: "1px solid rgba(126, 230, 168, 0.2)",
    marginBottom: 18,
  },
  eyebrow: { fontSize: 10, letterSpacing: 2, color: "#7ee6a8" },
  title:   { fontSize: 22, color: "#e6ffe9", marginTop: 4 },
  meta:    { fontSize: 12, color: "#96c9aa", marginTop: 6,
             display: "flex", gap: 8, alignItems: "center" },
  pill: {
    fontSize: 10, letterSpacing: 1, border: "1px solid",
    padding: "1px 6px", borderRadius: 2,
  },
  section: {
    marginBottom: 14,
    padding: "12px 16px",
    border: "1px solid rgba(126, 230, 168, 0.18)",
    background: "rgba(0, 30, 15, 0.4)", borderRadius: 4,
  },
  h3: { fontSize: 12, color: "#e6ffe9", letterSpacing: 1.4,
        margin: "0 0 10px", textTransform: "uppercase" },
  code: { background: "rgba(0, 40, 22, 0.4)",
          padding: "8px 12px", borderRadius: 3,
          fontSize: 12, color: "#c5f5d6",
          overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" },
  kvBlock: { display: "grid", gridTemplateColumns: "150px 1fr",
              gap: "6px 12px", fontSize: 12 },
  kvKey: { color: "#7ee6a8", letterSpacing: 1 },
  kvVal: { color: "#e6ffe9", wordBreak: "break-all" },
  kvRow: { display: "contents" },
  list: { listStyle: "none", padding: 0, margin: 0,
           display: "flex", flexDirection: "column", gap: 4 },
  listItem: {
    padding: "5px 8px",
    border: "1px solid rgba(126, 230, 168, 0.14)",
    borderRadius: 3, background: "rgba(0, 40, 22, 0.24)",
    fontSize: 12, color: "#e6ffe9",
    display: "flex", gap: 8, alignItems: "baseline",
  },
  tid: { color: "#7ee6a8", letterSpacing: 1 },
  wrap: { wordBreak: "break-all" },
  dim: { color: "#96c9aa", fontSize: 11 },
};
