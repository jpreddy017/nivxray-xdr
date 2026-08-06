/**
 * AcquisitionPlanPanel · IVE projection (Rule R16)
 * ─────────────────────────────────────────────────
 * Slice 1.6 · Frozen 2026-03-01
 *
 * Pure projection of SSOT.acquisition_plan.  No fetching, no
 * computation.  Renders the concrete IDA pipeline the platform will
 * execute for an acquirable URL — turning the old "atomic-ioc-
 * passthrough" surface into a real Investigator Plan.
 *
 * Every step carries a status ∈ {done, running, pending, skipped}.
 *   ✓ done      → engine executed, result is in the SSOT
 *   ● running   → executing right now (future slices)
 *   ○ pending   → queued for a future IDA slice
 *   – skipped   → not applicable to this input class
 *
 * Consumer is expected to pass `investigation` (the SSOT object)
 * and hide this component when `acquisition_plan` is empty.
 */
import React from "react";

const STATUS_META = {
  done:    { glyph: "✓", cls: "acq-done",    label: "DONE" },
  running: { glyph: "●", cls: "acq-running", label: "RUNNING" },
  pending: { glyph: "○", cls: "acq-pending", label: "QUEUED" },
  skipped: { glyph: "–", cls: "acq-skipped", label: "SKIPPED" },
};

export default function AcquisitionPlanPanel({ investigation }) {
  const plan   = investigation?.acquisition_plan || [];
  const ida    = investigation?.ida || {};
  const intent = ida?.url_intent;
  const acq    = investigation?.acquired_document || {};
  const prof   = investigation?.document_profile || {};
  const ext    = investigation?.report_extraction || {};
  const totals = ext?.totals || {};

  if (!plan.length) return null;

  const doneCount    = plan.filter(s => s.status === "done").length;
  const pendingCount = plan.filter(s => s.status === "pending").length;
  const acquired     = acq?.ok === true;

  return (
    <section
      className="acq-panel"
      data-testid="acquisition-plan-panel"
      style={{
        border: "1px solid rgba(0, 255, 128, 0.28)",
        borderRadius: 6,
        background: "rgba(0, 22, 12, 0.55)",
        padding: "14px 16px",
        margin: "0 12px 8px",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        color: "#c5f5d6",
      }}
    >
      <header style={{ display: "flex", alignItems: "baseline",
                       justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
        <div>
          <div style={{ fontSize: 11, letterSpacing: 1.6,
                        color: "#7ee6a8", opacity: 0.9 }}>
            ▸ IDA · ACQUISITION PLAN
          </div>
          <div style={{ fontSize: 15, fontWeight: 600, marginTop: 2,
                        color: "#e6ffe9" }} data-testid="acquisition-plan-title">
            {intent?.vendor
              ? <>Threat Intelligence Report — <span style={{ color: "#7ee6a8" }}>{intent.vendor}</span></>
              : <>{prettyIntent(intent?.intent) || "Acquirable URL"}</>}
          </div>
          {intent?.host && (
            <div style={{ fontSize: 12, color: "#96c9aa", marginTop: 3 }}>
              {intent.scheme}://{intent.host}
            </div>
          )}
        </div>
        <div style={{ textAlign: "right", fontSize: 11,
                      color: "#7ee6a8", opacity: 0.85 }}>
          <div data-testid="acq-progress">
            {doneCount}/{plan.length} <span style={{ opacity: 0.6 }}>steps complete</span>
          </div>
          {pendingCount > 0 && (
            <div style={{ marginTop: 2, opacity: 0.75 }}>
              {pendingCount} queued for future IDA slice
            </div>
          )}
        </div>
      </header>

      {acquired && (
        <div
          data-testid="acquired-document-summary"
          style={{
            marginBottom: 12,
            padding: "12px 14px",
            border: "1px solid rgba(126, 230, 168, 0.28)",
            borderRadius: 4,
            background: "rgba(0, 40, 22, 0.35)",
          }}
        >
          <div style={{ fontSize: 11, color: "#7ee6a8", letterSpacing: 1.4,
                        marginBottom: 6 }}>
            ▸ RESOURCE SUCCESSFULLY ACQUIRED
          </div>
          <div style={{ fontSize: 14, color: "#e6ffe9", fontWeight: 600 }}
               data-testid="acquired-title">
            {acq.title || "(untitled)"}
          </div>
          <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
                        gap: 10, marginTop: 10, fontSize: 12,
                        color: "#c5f5d6" }}>
            <Stat label="Vendor"     value={prof?.vendor || acq.sitename || "—"} />
            <Stat label="Author"     value={acq.author || "—"} />
            <Stat label="Published"  value={acq.published_date || "—"} />
            <Stat label="Bytes"      value={(acq.fetched_bytes || 0).toLocaleString()} />
            <Stat label="Article"    value={`${(acq.article_chars || 0).toLocaleString()} chars`} />
            <Stat label="Links"      value={acq.outbound_links?.length ?? 0} />
            <Stat label="Fetched in" value={`${acq.duration_ms || 0} ms`} />
            <Stat label="HTTP"       value={acq.status_code || "—"} />
          </div>

          <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
                        gap: 10, marginTop: 14, fontSize: 12 }}
               data-testid="extraction-totals">
            <ExtStat label="Commands"        value={totals.commands ?? 0} />
            <ExtStat label="MITRE ATT&CK"    value={totals.mitre ?? 0} />
            <ExtStat label="IOCs"            value={totals.artifacts ?? 0} />
            <ExtStat label="Threat Actors"   value={totals.actors ?? 0} />
            <ExtStat label="Malware"         value={totals.malware ?? 0} />
            <ExtStat label="CVEs"            value={totals.cves ?? 0} />
            <ExtStat label="Timeline Events" value={totals.timeline ?? 0} />
            <ExtStat label="YARA / Sigma"    value={(totals.yara ?? 0) + (totals.sigma ?? 0)} />
          </div>

          {prof?.capabilities?.length > 0 && (
            <div style={{ marginTop: 12, fontSize: 11, color: "#96c9aa" }}>
              <span style={{ color: "#7ee6a8", letterSpacing: 1.2, marginRight: 8 }}>
                CAPABILITIES
              </span>
              {prof.capabilities.map(c => (
                <span key={c} style={{
                  display: "inline-block",
                  marginRight: 6, marginBottom: 4,
                  padding: "2px 8px",
                  border: "1px solid rgba(126, 230, 168, 0.32)",
                  borderRadius: 3, fontSize: 10,
                  color: "#c5f5d6", background: "rgba(0, 60, 30, 0.4)",
                }}>{c.replace(/_/g, " ")}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {acq?.ok === false && acq?.error_code && (
        <div
          data-testid="acquired-document-error"
          style={{
            marginBottom: 12, padding: "10px 12px",
            border: "1px solid rgba(255, 120, 120, 0.45)",
            borderRadius: 4, background: "rgba(50, 10, 10, 0.4)",
            color: "#ffb0b0", fontSize: 12,
          }}
        >
          <div style={{ letterSpacing: 1.4, marginBottom: 4, fontSize: 10 }}>
            ⚠ ACQUISITION FAILED · {acq.error_code}
          </div>
          <div style={{ opacity: 0.9 }}>{acq.error_detail}</div>
        </div>
      )}

      <ol style={{ listStyle: "none", padding: 0, margin: 0 }}
          data-testid="acquisition-plan-steps">
        {plan.map((step, i) => {
          const meta = STATUS_META[step.status] || STATUS_META.pending;
          return (
            <li
              key={step.id}
              data-testid={`acq-step-${step.id}`}
              data-status={step.status}
              style={{
                display: "grid",
                gridTemplateColumns: "22px 1fr auto",
                gap: 10,
                alignItems: "start",
                padding: "6px 4px",
                borderBottom: i === plan.length - 1 ? "none"
                                                    : "1px dashed rgba(126, 230, 168, 0.14)",
                opacity: step.status === "pending" ? 0.68 : 1,
              }}
            >
              <span style={{ color: statusColor(step.status),
                             fontWeight: 700, textAlign: "center" }}>
                {meta.glyph}
              </span>
              <div>
                <div style={{ fontSize: 13, color: "#e6ffe9" }}>
                  <span style={{ color: "#7ee6a8", marginRight: 8,
                                  fontSize: 10, letterSpacing: 0.8 }}>
                    {step.id.toUpperCase()}
                  </span>
                  {step.title}
                </div>
                <div style={{ fontSize: 11, color: "#96c9aa",
                              marginTop: 2, opacity: 0.88 }}>
                  {step.engine} — {step.detail}
                </div>
              </div>
              <span style={{ fontSize: 10, letterSpacing: 1.2,
                             color: statusColor(step.status),
                             padding: "2px 8px",
                             border: `1px solid ${statusColor(step.status)}`,
                             borderRadius: 3, opacity: 0.85 }}>
                {meta.label}
              </span>
            </li>
          );
        })}
      </ol>

      {ida?.reasoning?.length > 0 && (
        <details style={{ marginTop: 10 }} data-testid="acq-reasoning">
          <summary style={{ cursor: "pointer", fontSize: 11,
                            color: "#7ee6a8", letterSpacing: 1 }}>
            ▸ WHY THIS PLAN
          </summary>
          <ul style={{ margin: "6px 0 0 22px", padding: 0,
                        fontSize: 12, color: "#c5f5d6", lineHeight: 1.6 }}>
            {ida.reasoning.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </details>
      )}
    </section>
  );
}

function statusColor(status) {
  switch (status) {
    case "done":    return "#3ddc84";
    case "running": return "#ffd66b";
    case "skipped": return "#8ba598";
    default:        return "#7ee6a8";
  }
}

function prettyIntent(intent) {
  return {
    threat_report:  "Threat Intelligence Report",
    code_snippet:   "Code Snippet / Paste",
    repository:     "Source Repository",
    file_resource:  "Direct File Resource",
    ioc_portal:     "IOC / Reputation Portal",
    atomic_ioc:     "Atomic URL IOC",
  }[intent] || null;
}

function Stat({ label, value }) {
  return (
    <div>
      <div style={{ fontSize: 10, letterSpacing: 1, color: "#7ee6a8",
                    opacity: 0.85, textTransform: "uppercase" }}>{label}</div>
      <div style={{ fontSize: 13, color: "#e6ffe9", marginTop: 2 }}>{value}</div>
    </div>
  );
}

function ExtStat({ label, value }) {
  const active = Number(value) > 0;
  return (
    <div style={{
      padding: "6px 10px",
      border: `1px solid ${active ? "rgba(126, 230, 168, 0.42)" : "rgba(126, 230, 168, 0.14)"}`,
      borderRadius: 3,
      background: active ? "rgba(0, 60, 30, 0.35)" : "rgba(0, 30, 15, 0.2)",
      opacity: active ? 1 : 0.55,
    }}>
      <div style={{ fontSize: 20, fontWeight: 700, color: active ? "#3ddc84" : "#8ba598",
                    lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 10, letterSpacing: 1, color: "#96c9aa",
                    marginTop: 4, textTransform: "uppercase" }}>{label}</div>
    </div>
  );
}

function ExtractedList({ label, items, testid }) {
  if (!items?.length) return null;
  return (
    <div style={{ marginTop: 12, fontSize: 11, color: "#96c9aa" }}
         data-testid={testid}>
      <span style={{ color: "#7ee6a8", letterSpacing: 1.2, marginRight: 8 }}>
        {label.toUpperCase()} ({items.length})
      </span>
      {items.map((n, i) => (
        <span key={`${n}-${i}`} style={{
          display: "inline-block",
          marginRight: 6, marginBottom: 4,
          padding: "2px 8px",
          border: "1px solid rgba(255, 200, 140, 0.32)",
          borderRadius: 3, fontSize: 11,
          color: "#ffe0b3", background: "rgba(60, 40, 10, 0.4)",
        }}>{n}</span>
      ))}
    </div>
  );
}

