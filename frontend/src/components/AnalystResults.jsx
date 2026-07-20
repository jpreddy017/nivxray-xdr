/* AnalystResults · P0.2 UX refactor
 * ---------------------------------
 * Consolidates the post-decode analyst brief into 7 CANONICAL panels
 * rendered in this order (locked by product):
 *
 *   1. Analysis Verdict   → verdict · confidence · risk score · reason
 *   2. Recovered Payload  → decoded plaintext + final-layer badge + copy
 *   3. Chain Recipe       → Layer 1 → Layer 2 → … (from decodeTrace)
 *   4. MITRE              → ATT&CK techniques (from analysis.mitre)
 *   5. IOCs               → hashes / files / registry / all-non-network
 *   6. Network            → urls / domains / ips (also from analysis.iocs)
 *   7. Behavior           → LOLBAS + tradecraft + kill-chain
 *
 * Each panel: sticky header, collapse toggle, copy-to-clipboard where
 * meaningful, `data-testid` per panel and per interactive element.
 *
 * The panel is UI-only. All API contracts are preserved — this
 * component consumes the SAME props the previous panels did.
 */
import { useState, useMemo } from "react";
import {
  Copy, ChevronDown, ChevronRight, Check,
  Shield, Target, Globe, ListTree, Activity,
} from "lucide-react";
import RecoveredPayloadCard from "./RecoveredPayloadCard";

/* ------------------------------------------------------------------ *
 * Shared collapsible Panel primitive
 * ------------------------------------------------------------------ */
function Panel({
  title, icon = null, badge = null, actions = null,
  testid, children, defaultOpen = true, sticky = true,
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <section
      className="brut-border"
      data-testid={`${testid}-panel`}
      style={{
        margin: "0 16px 12px",
        background: "var(--surface, #0b0f14)",
        borderColor: "var(--border, #1e293b)",
      }}
    >
      <header
        data-testid={`${testid}-panel-header`}
        style={{
          position: sticky ? "sticky" : "static",
          top: sticky ? 0 : "auto",
          zIndex: 2,
          background: "var(--surface, #0b0f14)",
          borderBottom: "1px solid var(--border, #1e293b)",
          padding: "10px 14px",
          display: "flex",
          alignItems: "center",
          gap: 10,
          fontFamily: "JetBrains Mono, monospace",
        }}
      >
        <button
          className="nvx-btn sm ghost"
          data-testid={`${testid}-toggle`}
          aria-label={open ? `Collapse ${title}` : `Expand ${title}`}
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
          style={{ padding: "2px 4px" }}
        >
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </button>
        {icon}
        <span
          style={{
            fontSize: 11, letterSpacing: "0.18em", fontWeight: 700,
            color: "var(--accent, #7ee3c9)",
          }}
        >
          {title}
        </span>
        {badge}
        <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>{actions}</span>
      </header>
      {open && <div style={{ padding: "12px 14px" }}>{children}</div>}
    </section>
  );
}

/* ------------------------------------------------------------------ *
 * Small helpers
 * ------------------------------------------------------------------ */
function CopyBtn({ text, testid, label = "COPY", disabled = false }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="nvx-btn sm"
      data-testid={testid}
      disabled={disabled || !text}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text || "");
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch (_e) {
          /* clipboard blocked */
        }
      }}
    >
      {done ? <Check size={11} /> : <Copy size={11} />}
      &nbsp;{done ? "COPIED" : label}
    </button>
  );
}

function EmptyState({ text = "No data yet.", testid }) {
  return (
    <div
      data-testid={testid}
      style={{
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 11, color: "var(--text-mute, #64748b)",
        padding: "6px 4px",
      }}
    >
      {text}
    </div>
  );
}

const chip = (color, extra = {}) => ({
  display: "inline-block",
  padding: "2px 8px",
  fontSize: 10,
  fontFamily: "JetBrains Mono, monospace",
  letterSpacing: "0.06em",
  border: `1px solid ${color}`,
  color,
  background: `${color}14`,
  borderRadius: 3,
  ...extra,
});

/* ------------------------------------------------------------------ *
 * 1. Analysis Verdict
 * ------------------------------------------------------------------ */
function VerdictPanel({ verdictCard }) {
  const vc = verdictCard || {
    label: "Awaiting analysis",
    confidence: 0,
    risk_score: 0,
    reason: "Run AUTO INVESTIGATE or DECODE to generate a verdict.",
    indicators: [],
    recommended_action: null,
  };
  const label = vc.label || vc.verdict || "Unknown";
  const conf = Number.isFinite(vc.confidence) ? vc.confidence : 0;
  const risk = Number.isFinite(vc.risk_score) ? vc.risk_score : conf;

  const color =
    label === "Malicious" ? "#ef4444"
    : label === "Suspicious" ? "#f59e0b"
    : label === "Corrupted" ? "#a855f7"
    : label === "Benign" ? "#22c55e"
    : label === "Inconclusive" ? "#94a3b8"
    : "#7ee3c9";

  const copyBody = useMemo(() => {
    const lines = [
      `Verdict:     ${label}`,
      `Confidence:  ${conf}%`,
      `Risk score:  ${risk}/100`,
      `Reason:      ${vc.reason || "—"}`,
    ];
    if (vc.recommended_action) lines.push(`Action:      ${vc.recommended_action}`);
    if (Array.isArray(vc.indicators) && vc.indicators.length) {
      lines.push("Indicators:");
      vc.indicators.forEach((i) => lines.push(`  · ${i.label || i}`));
    }
    return lines.join("\n");
  }, [label, conf, risk, vc]);

  return (
    <Panel
      title="① ANALYSIS VERDICT"
      icon={<Shield size={13} color={color} />}
      badge={
        <span style={chip(color)} data-testid="verdict-label-chip">
          {label.toUpperCase()}
        </span>
      }
      actions={<CopyBtn text={copyBody} testid="verdict-copy" />}
      testid="verdict"
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
          gap: 12,
          fontFamily: "JetBrains Mono, monospace",
        }}
      >
        <div>
          <div style={{ fontSize: 9, color: "var(--text-mute)", letterSpacing: "0.18em" }}>
            VERDICT
          </div>
          <div
            data-testid="verdict-value"
            style={{ fontSize: 20, fontWeight: 700, color, marginTop: 4 }}
          >
            {label}
          </div>
        </div>
        <div>
          <div style={{ fontSize: 9, color: "var(--text-mute)", letterSpacing: "0.18em" }}>
            CONFIDENCE
          </div>
          <div
            data-testid="verdict-confidence"
            style={{ fontSize: 20, fontWeight: 700, color: "var(--text)", marginTop: 4 }}
          >
            {conf}%
          </div>
        </div>
        <div>
          <div style={{ fontSize: 9, color: "var(--text-mute)", letterSpacing: "0.18em" }}>
            RISK SCORE
          </div>
          <div
            data-testid="verdict-risk-score"
            style={{ fontSize: 20, fontWeight: 700, color: "var(--text)", marginTop: 4 }}
          >
            {risk}/100
          </div>
        </div>
      </div>
      {vc.reason && (
        <div
          data-testid="verdict-reason"
          style={{
            marginTop: 12, padding: "8px 10px",
            background: "var(--surface-2, #0a0e13)",
            border: "1px solid var(--border, #1e293b)",
            fontFamily: "JetBrains Mono, monospace", fontSize: 11,
            color: "var(--text-dim, #cbd5e1)", lineHeight: 1.5,
          }}
        >
          {vc.reason}
        </div>
      )}
      {vc.recommended_action && (
        <div
          data-testid="verdict-action"
          style={{
            marginTop: 8, fontSize: 10,
            fontFamily: "JetBrains Mono, monospace",
            color: "var(--warn, #f59e0b)", letterSpacing: "0.06em",
          }}
        >
          ▸ ACTION: {vc.recommended_action}
        </div>
      )}
      {Array.isArray(vc.indicators) && vc.indicators.length > 0 && (
        <ul
          data-testid="verdict-indicators"
          style={{
            marginTop: 10, paddingLeft: 18, fontSize: 11,
            fontFamily: "JetBrains Mono, monospace", color: "var(--text-dim)",
          }}
        >
          {vc.indicators.slice(0, 8).map((i, idx) => (
            <li key={idx} style={{ marginBottom: 3 }}>
              <span
                style={{
                  color:
                    i.kind === "positive" ? "#ef4444"
                    : i.kind === "negative" ? "#f59e0b"
                    : "var(--text-mute)",
                  marginRight: 6,
                }}
              >
                {i.kind === "positive" ? "▲" : i.kind === "negative" ? "▼" : "◆"}
              </span>
              {i.label || String(i)}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ *
 * 3. Chain Recipe
 * ------------------------------------------------------------------ */
function ChainRecipePanel({ decodeTrace = [] }) {
  const steps = Array.isArray(decodeTrace) ? decodeTrace : [];
  const copyBody = useMemo(
    () =>
      steps
        .map((t, i) => `L${i + 1}  ${t.op}${t.reason ? "  — " + t.reason : ""}`)
        .join("\n"),
    [steps],
  );

  return (
    <Panel
      title="③ CHAIN RECIPE"
      icon={<ListTree size={13} color="var(--accent)" />}
      badge={
        steps.length > 0 && (
          <span style={chip("#7ee3c9")} data-testid="chain-recipe-count">
            {steps.length} LAYER{steps.length === 1 ? "" : "S"}
          </span>
        )
      }
      actions={<CopyBtn text={copyBody} testid="chain-recipe-copy" disabled={!steps.length} />}
      testid="chain-recipe"
    >
      {steps.length === 0 ? (
        <EmptyState text="No chain recipe yet — no decoder layers ran." testid="chain-recipe-empty" />
      ) : (
        <ol
          data-testid="chain-recipe-list"
          style={{
            listStyle: "none", padding: 0, margin: 0,
            fontFamily: "JetBrains Mono, monospace", fontSize: 11,
            display: "flex", flexDirection: "column", gap: 6,
          }}
        >
          {steps.map((t, i) => (
            <li
              key={i}
              data-testid={`chain-recipe-step-${i}`}
              style={{
                display: "flex", gap: 10, alignItems: "flex-start",
                padding: "6px 8px",
                background: "var(--surface-2, #0a0e13)",
                border: "1px solid var(--border, #1e293b)",
                borderLeft: `3px solid ${t.error ? "#ef4444" : "var(--accent, #7ee3c9)"}`,
              }}
            >
              <span
                style={{
                  color: "var(--text-mute, #64748b)", minWidth: 32,
                  letterSpacing: "0.1em",
                }}
              >
                L{i + 1}
              </span>
              <span
                style={{
                  color: t.error ? "#ef4444" : "var(--warn, #f59e0b)",
                  minWidth: 160, letterSpacing: "0.06em",
                }}
              >
                {String(t.op || "").toUpperCase()}
              </span>
              <span style={{ color: "var(--text-dim)", flex: 1 }}>
                {t.error ? `error: ${t.error}` : (t.reason || "")}
                {t.output_length != null && (
                  <span style={{ color: "var(--text-mute)", marginLeft: 8 }}>
                    · {t.output_length} B
                  </span>
                )}
              </span>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ *
 * 4. MITRE
 * ------------------------------------------------------------------ */
function MitrePanel({ mitre = [] }) {
  const items = Array.isArray(mitre) ? mitre : [];
  const copyBody = useMemo(
    () => items.map((m) => `${m.id || ""}  ${m.technique || m.name || ""}`).join("\n"),
    [items],
  );

  return (
    <Panel
      title="④ MITRE ATT&CK"
      icon={<Target size={13} color="#f59e0b" />}
      badge={
        items.length > 0 && (
          <span style={chip("#f59e0b")} data-testid="mitre-count">
            {items.length} TECHNIQUE{items.length === 1 ? "" : "S"}
          </span>
        )
      }
      actions={<CopyBtn text={copyBody} testid="mitre-copy" disabled={!items.length} />}
      testid="mitre"
    >
      {items.length === 0 ? (
        <EmptyState text="No MITRE techniques detected." testid="mitre-empty" />
      ) : (
        <ul
          data-testid="mitre-list"
          style={{
            listStyle: "none", padding: 0, margin: 0,
            display: "flex", flexWrap: "wrap", gap: 6,
          }}
        >
          {items.map((m, i) => (
            <li
              key={i}
              data-testid={`mitre-item-${i}`}
              title={m.evidence || m.technique || m.name || ""}
              style={{
                fontFamily: "JetBrains Mono, monospace", fontSize: 11,
                padding: "4px 10px",
                background: "rgba(245,158,11,0.06)",
                border: "1px solid #f59e0b",
                color: "#fef3c7",
              }}
            >
              <strong style={{ color: "#fbbf24" }}>{m.id || "?"}</strong>
              {(m.technique || m.name) && (
                <span style={{ marginLeft: 6, color: "var(--text-dim)" }}>
                  {m.technique || m.name}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ *
 * 5. IOCs (non-network — files/hashes/registry/emails/misc)
 * 6. Network (urls/domains/ips)
 *   split from the same `iocs` object so the analyst sees network-vs-
 *   host-level indicators separately.
 * ------------------------------------------------------------------ */
const NETWORK_KEYS = ["urls", "domains", "hosts", "ips"];

function IocPanel({ iocs = {} }) {
  const io = iocs && typeof iocs === "object" ? iocs : {};
  const nonNet = Object.entries(io).filter(
    ([k, v]) => !NETWORK_KEYS.includes(k) && Array.isArray(v) && v.length > 0,
  );
  const total = nonNet.reduce((acc, [, v]) => acc + v.length, 0);
  const copyBody = useMemo(
    () =>
      nonNet
        .map(([k, v]) => `# ${k}\n${v.join("\n")}`)
        .join("\n\n"),
    [nonNet],
  );

  return (
    <Panel
      title="⑤ IOCs"
      icon={<Shield size={13} color="#38bdf8" />}
      badge={
        total > 0 && (
          <span style={chip("#38bdf8")} data-testid="ioc-count">
            {total} INDICATOR{total === 1 ? "" : "S"}
          </span>
        )
      }
      actions={<CopyBtn text={copyBody} testid="ioc-copy" disabled={!total} />}
      testid="iocs"
    >
      {nonNet.length === 0 ? (
        <EmptyState text="No file / hash / registry / email IOCs surfaced." testid="ioc-empty" />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {nonNet.map(([kind, values]) => (
            <div key={kind} data-testid={`ioc-group-${kind}`}>
              <div
                style={{
                  fontFamily: "JetBrains Mono, monospace", fontSize: 9,
                  color: "var(--text-mute)", letterSpacing: "0.18em",
                  marginBottom: 4,
                }}
              >
                {kind.toUpperCase()} · {values.length}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {values.slice(0, 40).map((v, i) => (
                  <code
                    key={i}
                    data-testid={`ioc-${kind}-${i}`}
                    style={{
                      fontSize: 10, padding: "2px 6px",
                      background: "var(--surface-2, #0a0e13)",
                      border: "1px solid var(--border, #1e293b)",
                      color: "var(--text-dim)",
                      wordBreak: "break-all",
                    }}
                  >
                    {String(v)}
                  </code>
                ))}
                {values.length > 40 && (
                  <span
                    style={{
                      fontSize: 10, color: "var(--text-mute)",
                      fontFamily: "JetBrains Mono, monospace",
                    }}
                  >
                    + {values.length - 40} more
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function NetworkPanel({ iocs = {} }) {
  const io = iocs && typeof iocs === "object" ? iocs : {};
  const groups = NETWORK_KEYS
    .map((k) => [k, Array.isArray(io[k]) ? io[k] : []])
    .filter(([, v]) => v.length > 0);
  const total = groups.reduce((acc, [, v]) => acc + v.length, 0);
  const copyBody = useMemo(
    () => groups.map(([k, v]) => `# ${k}\n${v.join("\n")}`).join("\n\n"),
    [groups],
  );

  return (
    <Panel
      title="⑥ NETWORK"
      icon={<Globe size={13} color="#22d3ee" />}
      badge={
        total > 0 && (
          <span style={chip("#22d3ee")} data-testid="network-count">
            {total} ENDPOINT{total === 1 ? "" : "S"}
          </span>
        )
      }
      actions={<CopyBtn text={copyBody} testid="network-copy" disabled={!total} />}
      testid="network"
    >
      {groups.length === 0 ? (
        <EmptyState text="No network endpoints (URL / domain / IP) surfaced." testid="network-empty" />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {groups.map(([kind, values]) => (
            <div key={kind} data-testid={`network-group-${kind}`}>
              <div
                style={{
                  fontFamily: "JetBrains Mono, monospace", fontSize: 9,
                  color: "var(--text-mute)", letterSpacing: "0.18em",
                  marginBottom: 4,
                }}
              >
                {kind.toUpperCase()} · {values.length}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                {values.slice(0, 30).map((v, i) => (
                  <code
                    key={i}
                    data-testid={`network-${kind}-${i}`}
                    style={{
                      fontSize: 11, padding: "3px 8px",
                      background: "var(--surface-2, #0a0e13)",
                      border: "1px solid var(--border, #1e293b)",
                      borderLeft: "3px solid #22d3ee",
                      color: "var(--text-dim)",
                      wordBreak: "break-all",
                      fontFamily: "JetBrains Mono, monospace",
                    }}
                  >
                    {String(v)}
                  </code>
                ))}
                {values.length > 30 && (
                  <span
                    style={{
                      fontSize: 10, color: "var(--text-mute)",
                      fontFamily: "JetBrains Mono, monospace",
                    }}
                  >
                    + {values.length - 30} more
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ *
 * 7. Behavior — LOLBAS + tradecraft + kill chain
 * ------------------------------------------------------------------ */
function BehaviorPanel({ lolbas = [], tradecraft = [], killChain = [] }) {
  const lb = Array.isArray(lolbas) ? lolbas : [];
  const tc = Array.isArray(tradecraft) ? tradecraft : [];
  const kc = Array.isArray(killChain) ? killChain : [];
  const total = lb.length + tc.length + kc.length;

  const copyBody = useMemo(() => {
    const parts = [];
    if (lb.length)
      parts.push(
        "# LOLBAS\n" +
          lb.map((h) => `${h.binary || h.name || ""}  ${h.description || ""}`).join("\n"),
      );
    if (tc.length)
      parts.push(
        "# Tradecraft\n" +
          tc.map((t) => `${t.flag || t.name || ""}  ${t.evidence || ""}`).join("\n"),
      );
    if (kc.length) parts.push("# Kill chain\n" + kc.join("\n"));
    return parts.join("\n\n");
  }, [lb, tc, kc]);

  return (
    <Panel
      title="⑦ BEHAVIOR"
      icon={<Activity size={13} color="#c084fc" />}
      badge={
        total > 0 && (
          <span style={chip("#c084fc")} data-testid="behavior-count">
            {total} SIGNAL{total === 1 ? "" : "S"}
          </span>
        )
      }
      actions={<CopyBtn text={copyBody} testid="behavior-copy" disabled={!total} />}
      testid="behavior"
    >
      {total === 0 ? (
        <EmptyState
          text="No behavioural signals (LOLBAS / tradecraft) detected."
          testid="behavior-empty"
        />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {lb.length > 0 && (
            <div data-testid="behavior-lolbas">
              <div
                style={{
                  fontFamily: "JetBrains Mono, monospace", fontSize: 9,
                  color: "var(--text-mute)", letterSpacing: "0.18em",
                  marginBottom: 4,
                }}
              >
                LOLBAS · {lb.length}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                {lb.map((h, i) => (
                  <span
                    key={i}
                    data-testid={`behavior-lolbas-item-${i}`}
                    style={{
                      fontFamily: "JetBrains Mono, monospace", fontSize: 11,
                      padding: "3px 8px",
                      background: "rgba(192,132,252,0.08)",
                      border: "1px solid #c084fc", color: "#e9d5ff",
                    }}
                    title={h.description || h.evidence || h.name}
                  >
                    {h.binary || h.name || String(h)}
                  </span>
                ))}
              </div>
            </div>
          )}
          {tc.length > 0 && (
            <div data-testid="behavior-tradecraft">
              <div
                style={{
                  fontFamily: "JetBrains Mono, monospace", fontSize: 9,
                  color: "var(--text-mute)", letterSpacing: "0.18em",
                  marginBottom: 4,
                }}
              >
                TRADECRAFT · {tc.length}
              </div>
              <ul
                style={{
                  listStyle: "none", padding: 0, margin: 0,
                  fontFamily: "JetBrains Mono, monospace", fontSize: 11,
                }}
              >
                {tc.map((t, i) => (
                  <li
                    key={i}
                    data-testid={`behavior-tradecraft-item-${i}`}
                    style={{ padding: "3px 0", color: "var(--text-dim)" }}
                  >
                    <span style={{ color: "#c084fc", marginRight: 6 }}>▸</span>
                    <strong>{t.flag || t.name || "flag"}</strong>
                    {t.evidence && <span> — {t.evidence}</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {kc.length > 0 && (
            <div data-testid="behavior-killchain">
              <div
                style={{
                  fontFamily: "JetBrains Mono, monospace", fontSize: 9,
                  color: "var(--text-mute)", letterSpacing: "0.18em",
                  marginBottom: 4,
                }}
              >
                KILL CHAIN · {kc.length}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                {kc.map((k, i) => (
                  <span
                    key={i}
                    data-testid={`behavior-killchain-item-${i}`}
                    style={chip("#c084fc")}
                  >
                    {String(k).toUpperCase()}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ *
 * Public container — renders all 7 panels in the locked order.
 * Renders nothing (returns null) if there is no analysis / output yet
 * AND no verdict card — prevents empty scaffolding above the input.
 * ------------------------------------------------------------------ */
export default function AnalystResults({
  verdictCard = null,
  output = "",
  decodeTrace = [],
  decodeConfidence = null,
  analysis = null,
}) {
  const hasContent =
    !!verdictCard ||
    !!(output && String(output).trim()) ||
    (Array.isArray(decodeTrace) && decodeTrace.length > 0) ||
    !!analysis;
  if (!hasContent) return null;

  const trace = Array.isArray(decodeTrace) ? decodeTrace : [];
  const finalLayer =
    trace.length > 0 ? (trace[trace.length - 1]?.op || null) : null;
  const iocs = analysis?.iocs || {};
  const mitre = analysis?.mitre || [];
  const lolbas = analysis?.lolbas || analysis?.lolbins || [];
  const tradecraft = analysis?.tradecraft || [];
  const killChain = analysis?.kill_chain_phases || [];

  return (
    <div data-testid="analyst-results" style={{ marginTop: 4 }}>
      {/* 1. Analysis Verdict — pinned via CSS-sticky header inside Panel */}
      <VerdictPanel verdictCard={verdictCard} />

      {/* 2. Recovered Payload */}
      <RecoveredPayloadCard
        output={output}
        finalLayer={finalLayer}
        layerCount={trace.length}
        confidence={decodeConfidence}
        testid="recovered-payload"
      />

      {/* 3. Chain Recipe */}
      <ChainRecipePanel decodeTrace={trace} />

      {/* 4. MITRE */}
      <MitrePanel mitre={mitre} />

      {/* 5. IOCs */}
      <IocPanel iocs={iocs} />

      {/* 6. Network */}
      <NetworkPanel iocs={iocs} />

      {/* 7. Behavior */}
      <BehaviorPanel lolbas={lolbas} tradecraft={tradecraft} killChain={killChain} />
    </div>
  );
}
