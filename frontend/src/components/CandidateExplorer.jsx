import { useState, useEffect } from "react";
import { ChevronDown, ChevronRight, X, AlertCircle, CheckCircle2, MinusCircle, Edit3 } from "lucide-react";
import api from "@/lib/api";
import CorrectionModal from "@/components/CorrectionModal";

/**
 * CandidateExplorer — Feb-2026 SOC panel that renders EVERY encoding candidate
 * with its confidence, evidence, and structured "why-not" breakdown.
 *
 * Fetches: POST /api/decode/candidates {input, top_n}
 * Renders:
 *   • Winner card (top) — confidence, hex, IOCs, LOLBins, MITRE
 *   • Ranked runners-up — collapsible; hover/click shows rejection reasons
 *   • Verdict banner — decoded / possible / unknown-or-identifier
 *
 * Props:
 *   input:     string    the raw payload to analyse
 *   onSelect?: function  optional callback(op) when analyst clicks a candidate
 *   testidPrefix?: string
 */
const SEVERITY_STYLE = {
  high: { color: "#f87171", bg: "rgba(248, 113, 113, 0.10)", Icon: AlertCircle },
  medium: { color: "#f59e0b", bg: "rgba(245, 158, 11, 0.10)", Icon: MinusCircle },
  low: { color: "#94a3b8", bg: "rgba(148, 163, 184, 0.08)", Icon: CheckCircle2 },
};

const BAND_STYLE = {
  decoded: { color: "#7ee3c9", bg: "rgba(126, 227, 201, 0.10)", label: "DECODED" },
  possible: { color: "#f59e0b", bg: "rgba(245, 158, 11, 0.10)", label: "POSSIBLE" },
  "unknown-or-identifier": { color: "#94a3b8", bg: "rgba(148, 163, 184, 0.10)", label: "UNKNOWN" },
};

function ConfidenceBar({ value }) {
  const pct = Math.round((value || 0) * 100);
  const color =
    value >= 0.65 ? "#7ee3c9" : value >= 0.30 ? "#f59e0b" : "#f87171";
  return (
    <div style={{ width: 120, height: 6, background: "rgba(148,163,184,0.15)", borderRadius: 3 }}>
      <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 3 }} />
    </div>
  );
}

function RejectionReason({ reason }) {
  const style = SEVERITY_STYLE[reason.severity] || SEVERITY_STYLE.low;
  const { Icon } = style;
  return (
    <div
      style={{
        display: "flex", gap: 8, alignItems: "flex-start",
        padding: "6px 10px", borderRadius: 4, background: style.bg,
        fontSize: 11, marginBottom: 4,
      }}
      data-testid="rejection-reason"
    >
      <Icon size={13} color={style.color} style={{ flexShrink: 0, marginTop: 2 }} />
      <div style={{ flex: 1 }}>
        <div style={{ color: style.color, fontFamily: "monospace", fontWeight: 600 }}>
          {reason.code}
        </div>
        <div style={{ color: "#c9d1d9", opacity: 0.85 }}>
          {reason.description}
        </div>
        {reason.detail && (
          <div style={{ color: "#94a3b8", fontFamily: "monospace", fontSize: 10, marginTop: 2 }}>
            {reason.detail}
          </div>
        )}
      </div>
    </div>
  );
}

function CandidateRow({ candidate, isWinner, expanded, onToggle, onSelect }) {
  const conf = candidate.confidence || 0;
  return (
    <div
      style={{
        border: `1px solid ${isWinner ? "rgba(126,227,201,0.4)" : "rgba(148,163,184,0.15)"}`,
        borderRadius: 6,
        padding: "10px 12px",
        marginBottom: 8,
        background: isWinner ? "rgba(126,227,201,0.05)" : "rgba(15,23,42,0.4)",
      }}
      data-testid={`candidate-row-${candidate.op}`}
    >
      <div
        style={{ display: "flex", alignItems: "center", gap: 12, cursor: "pointer" }}
        onClick={onToggle}
      >
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <span
          style={{
            fontFamily: "monospace",
            fontWeight: 600,
            color: isWinner ? "#7ee3c9" : "#c9d1d9",
            minWidth: 180,
          }}
        >
          {isWinner && "★ "}
          {candidate.op}
        </span>
        <ConfidenceBar value={conf} />
        <span style={{ fontFamily: "monospace", fontSize: 12, color: "#94a3b8", minWidth: 44 }}>
          {conf.toFixed(2)}
        </span>
        {candidate.decoded_preview && (
          <span
            style={{
              flex: 1,
              fontFamily: "monospace",
              fontSize: 11,
              color: "#94a3b8",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              maxWidth: 300,
            }}
          >
            → {candidate.decoded_preview}
          </span>
        )}
        {candidate.vs_winner && (
          <span
            style={{
              fontFamily: "monospace",
              fontSize: 10,
              color: "#f59e0b",
              opacity: 0.7,
            }}
          >
            gap {candidate.vs_winner.confidence_gap >= 0 ? "+" : ""}
            {candidate.vs_winner.confidence_gap.toFixed(2)}
          </span>
        )}
      </div>

      {expanded && (
        <div style={{ marginTop: 10, paddingLeft: 26 }}>
          {/* Evidence block */}
          <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 8 }}>
            <span style={{ color: "#7ee3c9", fontWeight: 600 }}>Evidence: </span>
            {Object.entries(candidate.evidence || {}).map(([k, v], i, arr) => (
              <span key={k} style={{ fontFamily: "monospace" }}>
                {k}={typeof v === "object" ? JSON.stringify(v) : String(v)}
                {i < arr.length - 1 && " · "}
              </span>
            ))}
          </div>
          {/* Structured why-not */}
          {candidate.rejection_reasons && candidate.rejection_reasons.length > 0 && (
            <div>
              <div style={{ fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 6 }}>
                Why not selected:
              </div>
              {candidate.rejection_reasons.map((rr, i) => (
                <RejectionReason key={i} reason={rr} />
              ))}
            </div>
          )}
          {/* Rationale text (backwards compat) */}
          {candidate.rationale && (
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 6, fontStyle: "italic" }}>
              {candidate.rationale}
            </div>
          )}
          {onSelect && !isWinner && (
            <button
              onClick={() => onSelect(candidate.op)}
              className="nvx-btn sm ghost"
              style={{ marginTop: 8 }}
              data-testid={`try-candidate-${candidate.op}`}
            >
              Try this candidate →
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function EnrichmentBlock({ label, items, renderItem, testid }) {
  if (!items || items.length === 0) return null;
  return (
    <div style={{ marginBottom: 10 }} data-testid={testid}>
      <div style={{ fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 4 }}>
        {label} ({items.length})
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {items.map((item, i) => (
          <span
            key={i}
            style={{
              fontSize: 11,
              fontFamily: "monospace",
              padding: "2px 8px",
              background: "rgba(148,163,184,0.10)",
              borderRadius: 3,
              color: "#c9d1d9",
            }}
          >
            {renderItem(item)}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function CandidateExplorer({ input, onSelect, testidPrefix = "candidate-explorer" }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState({});
  const [correctionOpen, setCorrectionOpen] = useState(false);

  useEffect(() => {
    if (!input || input.trim().length === 0) {
      setData(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .post("/decode/candidates", { input, top_n: 8 })
      .then((r) => {
        if (cancelled) return;
        setData(r.data);
        // Auto-expand the winner
        if (r.data?.verdict?.op) {
          setExpanded({ [r.data.verdict.op]: true });
        }
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e.response?.data?.detail || e.message || "Failed to load candidates");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [input]);

  if (!input) return null;
  if (loading) {
    return (
      <div className="nvx-card" style={{ padding: 16 }} data-testid={`${testidPrefix}-loading`}>
        <div style={{ fontSize: 12, color: "#94a3b8" }}>Scoring encoding candidates…</div>
      </div>
    );
  }
  if (error) {
    return (
      <div className="nvx-card" style={{ padding: 16 }} data-testid={`${testidPrefix}-error`}>
        <div style={{ fontSize: 12, color: "#f87171" }}>Error: {error}</div>
      </div>
    );
  }
  if (!data) return null;

  const verdict = data.verdict || {};
  const isUnknown = verdict.verdict === "unknown-or-identifier";
  const bandStyle = BAND_STYLE[verdict.verdict] || BAND_STYLE["unknown-or-identifier"];
  const iocs = data.iocs || {};
  const flatIocs = [
    ...(iocs.urls || []).map((u) => ({ kind: "url", value: u })),
    ...(iocs.ips || []).map((u) => ({ kind: "ip", value: u })),
    ...(iocs.domains || []).map((u) => ({ kind: "domain", value: u })),
    ...(iocs.md5 || []).map((u) => ({ kind: "md5", value: u })),
    ...(iocs.sha1 || []).map((u) => ({ kind: "sha1", value: u })),
    ...(iocs.sha256 || []).map((u) => ({ kind: "sha256", value: u })),
  ];

  return (
    <div className="nvx-card" data-testid={testidPrefix} style={{ marginBottom: 12 }}>
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <span className="dot" />
          CANDIDATE EXPLORER
        </div>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
          <button
            className="nvx-btn sm ghost"
            onClick={() => setCorrectionOpen(true)}
            data-testid={`${testidPrefix}-correct-btn`}
            style={{ fontSize: 10 }}
          >
            <Edit3 size={11} /> CORRECT THIS
          </button>
          <span
            style={{
              padding: "4px 10px",
              borderRadius: 3,
              background: bandStyle.bg,
              color: bandStyle.color,
              fontFamily: "monospace",
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: 1,
            }}
            data-testid={`${testidPrefix}-verdict-badge`}
          >
            {bandStyle.label}
          </span>
        </div>
      </div>
      <div className="nvx-card-body">
        {/* Verdict summary line */}
        {!isUnknown && verdict.op && (
          <div
            style={{
              padding: "8px 12px",
              background: "rgba(126,227,201,0.06)",
              borderRadius: 4,
              marginBottom: 12,
              fontSize: 12,
              color: "#c9d1d9",
            }}
            data-testid={`${testidPrefix}-summary`}
          >
            Selected <b style={{ color: "#7ee3c9" }}>{verdict.op}</b> at{" "}
            <b>{(verdict.confidence * 100).toFixed(0)}%</b> confidence.{" "}
            {data.explanation && (
              <span style={{ color: "#94a3b8" }}>{data.explanation.slice(0, 200)}…</span>
            )}
          </div>
        )}
        {isUnknown && verdict.hypotheses && (
          <div
            style={{
              padding: "8px 12px",
              background: bandStyle.bg,
              borderRadius: 4,
              marginBottom: 12,
              fontSize: 12,
              color: "#c9d1d9",
            }}
            data-testid={`${testidPrefix}-unknown-summary`}
          >
            No encoding candidate reached the minimum-acceptance threshold. Likely alternatives:
            <ul style={{ margin: "6px 0 0 20px", padding: 0 }}>
              {verdict.hypotheses.map((h, i) => (
                <li key={i} style={{ fontSize: 11, color: "#94a3b8" }}>
                  {h}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Enrichment on winner */}
        {!isUnknown && (
          <div style={{ marginBottom: 12 }}>
            {data.hex_representation && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 4 }}>
                  Hex representation
                </div>
                <div
                  style={{
                    fontFamily: "monospace",
                    fontSize: 11,
                    padding: "6px 10px",
                    background: "rgba(15,23,42,0.5)",
                    borderRadius: 3,
                    color: "#c9d1d9",
                    overflow: "auto",
                    maxHeight: 60,
                  }}
                  data-testid={`${testidPrefix}-hex`}
                >
                  {data.hex_representation}
                </div>
              </div>
            )}
            <EnrichmentBlock
              label="IOCs"
              items={flatIocs}
              renderItem={(i) => `${i.kind}: ${i.value}`}
              testid={`${testidPrefix}-iocs`}
            />
            <EnrichmentBlock
              label="LOLBins"
              items={data.lolbins || []}
              renderItem={(l) => l.binary || "?"}
              testid={`${testidPrefix}-lolbins`}
            />
            <EnrichmentBlock
              label="MITRE ATT&CK"
              items={data.mitre_techniques || []}
              renderItem={(t) => `${t.id} — ${t.name || t.tactic || ""}`}
              testid={`${testidPrefix}-mitre`}
            />
            {data.signature && (
              <div style={{ fontSize: 11, color: "#f59e0b", marginBottom: 8 }}>
                <b>Signature:</b> {data.signature}
              </div>
            )}
          </div>
        )}

        {/* Ranked candidates */}
        <div style={{ fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 6, letterSpacing: 0.5 }}>
          RANKED CANDIDATES ({data.candidates?.length || 0})
        </div>
        {(data.candidates || []).map((c) => (
          <CandidateRow
            key={c.op}
            candidate={c}
            isWinner={!isUnknown && verdict.op === c.op}
            expanded={!!expanded[c.op]}
            onToggle={() => setExpanded((s) => ({ ...s, [c.op]: !s[c.op] }))}
            onSelect={onSelect}
          />
        ))}
      </div>
      <CorrectionModal
        open={correctionOpen}
        onClose={() => setCorrectionOpen(false)}
        input={input}
        engineOutput={data.best?.decoded_preview || (verdict.op ? verdict.op : "")}
        engineChain={verdict.op ? [{ op: verdict.op }] : []}
        engineConfidence={verdict.confidence ?? null}
      />
    </div>
  );
}
