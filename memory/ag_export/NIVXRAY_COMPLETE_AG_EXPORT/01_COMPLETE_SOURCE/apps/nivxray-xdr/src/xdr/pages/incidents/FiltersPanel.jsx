/**
 * FiltersPanel · a lightweight side sheet opened by the toolbar
 * "Filters" button.  Lets analysts compose multi-facet filters
 * (priority · severity · verdict · confidence · customer ·
 *  detection source · MITRE technique) that URL-persist.
 */
import React, { useState, useEffect, useRef } from "react";
import { X, Filter as FilterIcon } from "lucide-react";

const PRIORITIES = ["P1", "P2", "P3", "P4", "P5"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const VERDICTS   = ["malicious", "suspicious", "benign", "unknown"];
const CONFS      = ["high", "medium", "low"];

function useOutsideClose(ref, onClose) {
  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) onClose(); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [ref, onClose]);
}

export default function FiltersPanel({ open, onClose, filters, onApply }) {
  const [local, setLocal] = useState(filters);
  const ref = useRef(null);
  useOutsideClose(ref, onClose);

  useEffect(() => { setLocal(filters); }, [filters, open]);

  if (!open) return null;

  const set = (k, v) => setLocal(prev => ({ ...prev, [k]: v }));
  const clearAll = () => setLocal({
    priority: null, severity: null, verdict: null, confidence: null,
    customer: null, detection_source: null, technique: null,
  });
  const apply = () => { onApply(local); onClose(); };

  const Section = ({ title, children }) => (
    <div style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: 0.5,
                    textTransform: "uppercase", color: "var(--ql-muted)",
                    marginBottom: 6 }}>{title}</div>
      {children}
    </div>
  );

  const Pill = ({ active, onClick, children, testId }) => (
    <button
      type="button"
      onClick={onClick}
      data-testid={testId}
      style={{
        padding: "4px 10px", borderRadius: 4,
        border: `1px solid ${active ? "var(--ql-purple)" : "var(--ql-border-hi)"}`,
        background: active ? "var(--ql-purple-dim)" : "var(--ql-surface-2)",
        color: active ? "var(--ql-purple)" : "var(--ql-text-dim)",
        fontFamily: "var(--qs-mono)", fontSize: 10.5, fontWeight: 700,
        cursor: "pointer", marginRight: 4, marginBottom: 4,
      }}
    >
      {children}
    </button>
  );

  return (
    <>
      <div className="ql-drawer-scrim" onClick={onClose} />
      <aside
        ref={ref}
        style={{
          position: "fixed", top: 0, right: 0, bottom: 0,
          width: "min(420px, 92vw)",
          background: "var(--ql-surface)",
          color: "var(--ql-text)",
          borderLeft: "1px solid var(--ql-border)",
          boxShadow: "-12px 0 32px rgba(15,20,30,0.10)",
          zIndex: 90,
          display: "flex", flexDirection: "column",
          fontFamily: "var(--qs-sans)",
        }}
        data-testid="ql-filters-panel"
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                      padding: "12px 16px",
                      borderBottom: "1px solid var(--ql-border)",
                      background: "var(--ql-surface-2)" }}>
          <FilterIcon size={14} color="var(--ql-purple)" />
          <span style={{ fontWeight: 700, fontSize: 14 }}>Filters</span>
          <button
            type="button"
            onClick={clearAll}
            style={{ marginLeft: "auto", background: "transparent",
                     border: "none", color: "var(--ql-purple)",
                     cursor: "pointer", fontSize: 11.5, fontWeight: 600 }}
            data-testid="ql-filters-clear"
          >
            Clear all
          </button>
          <button
            type="button"
            onClick={onClose}
            style={{ background: "transparent", border: "1px solid var(--ql-border)",
                     borderRadius: 4, padding: 3, cursor: "pointer",
                     color: "var(--ql-text-dim)" }}
            data-testid="ql-filters-close"
          >
            <X size={13} />
          </button>
        </div>

        <div style={{ padding: 16, flex: 1, overflowY: "auto" }}>
          <Section title="Priority">
            {PRIORITIES.map(p =>
              <Pill key={p} active={local.priority === p}
                    onClick={() => set("priority", local.priority === p ? null : p)}
                    testId={`ql-filter-priority-${p}`}>
                {p}
              </Pill>)}
          </Section>

          <Section title="Severity">
            {SEVERITIES.map(s =>
              <Pill key={s} active={local.severity === s}
                    onClick={() => set("severity", local.severity === s ? null : s)}
                    testId={`ql-filter-severity-${s}`}>
                {s.toUpperCase()}
              </Pill>)}
          </Section>

          <Section title="Verdict">
            {VERDICTS.map(v =>
              <Pill key={v} active={local.verdict === v}
                    onClick={() => set("verdict", local.verdict === v ? null : v)}
                    testId={`ql-filter-verdict-${v}`}>
                {v.toUpperCase()}
              </Pill>)}
          </Section>

          <Section title="Confidence">
            {CONFS.map(c =>
              <Pill key={c} active={local.confidence === c}
                    onClick={() => set("confidence", local.confidence === c ? null : c)}
                    testId={`ql-filter-confidence-${c}`}>
                {c.toUpperCase()}
              </Pill>)}
          </Section>

          <Section title="Customer / tenant">
            <input
              type="text"
              value={local.customer || ""}
              onChange={e => set("customer", e.target.value || null)}
              placeholder="Exact tenant id…"
              data-testid="ql-filter-customer"
              style={inputStyle}
            />
          </Section>

          <Section title="Detection source">
            <input
              type="text"
              value={local.detection_source || ""}
              onChange={e => set("detection_source", e.target.value || null)}
              placeholder="e.g. IUE, UAIE, VEEE…"
              data-testid="ql-filter-detection-source"
              style={inputStyle}
            />
          </Section>

          <Section title="MITRE technique">
            <input
              type="text"
              value={local.technique || ""}
              onChange={e => set("technique", e.target.value?.toUpperCase() || null)}
              placeholder="T1059, T1027…"
              data-testid="ql-filter-technique"
              style={inputStyle}
            />
          </Section>
        </div>

        <div style={{ padding: "12px 16px",
                      borderTop: "1px solid var(--ql-border)",
                      display: "flex", gap: 8, justifyContent: "flex-end",
                      background: "var(--ql-surface-2)" }}>
          <button
            type="button"
            className="ql-btn"
            onClick={onClose}
            data-testid="ql-filters-cancel"
          >Cancel</button>
          <button
            type="button"
            className="ql-btn primary"
            onClick={apply}
            data-testid="ql-filters-apply"
          >Apply filters</button>
        </div>
      </aside>
    </>
  );
}

const inputStyle = {
  width: "100%",
  padding: "6px 9px",
  border: "1px solid var(--ql-border)",
  borderRadius: 4,
  background: "var(--ql-surface-2)",
  color: "var(--ql-text)",
  fontFamily: "var(--qs-mono)",
  fontSize: 12,
  outline: "none",
};
