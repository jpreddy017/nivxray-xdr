/**
 * ResponseStrategiesBody · Round 20 · Knowledge-transparency surface
 * ──────────────────────────────────────────────────────────────────
 *
 * Renders the 14-family × 5-objective response-strategy knowledge
 * matrix served by
 *     GET /api/admin/content-supply-chain/response-strategies
 *
 * This is NOT another recommendation engine.  It's a transparency
 * surface so analysts can browse WHAT NivXRay knows before an
 * incident lands: which strategies fire for which family, which
 * evidence dimensions each strategy consumes, which candidate
 * actions it composes, and whether exclusions are permitted.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Layers, ShieldCheck, Lock, Unlock, Loader2, Radar } from "lucide-react";
import api from "@/lib/api";


const OBJECTIVE_COLOR = {
  "Cleanup":               "#38bdf8",
  "Containment":           "#f87171",
  "Credential Protection": "#a78bfa",
  "Eradication":           "#f59e0b",
  "Investigation":         "var(--mint)",
  "Prevention":            "var(--faint)",
  "Recovery Verification": "var(--mint)",
};


export default function ResponseStrategiesBody() {
  const [data,    setData]    = useState(null);
  const [error,   setError]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [q,       setQ]       = useState("");
  const [openId,  setOpenId]  = useState(null);

  useEffect(() => {
    (async () => {
      setLoading(true); setError(null);
      try {
        const r = await api.get(
          "/admin/content-supply-chain/response-strategies");
        setData(r.data);
      } catch (e) {
        setError(e?.response?.data?.detail || e?.message || "failed");
      } finally { setLoading(false); }
    })();
  }, []);

  const rows = useMemo(() => {
    const items = data?.strategies || [];
    if (!q.trim()) return items;
    const t = q.toLowerCase();
    return items.filter((s) =>
      s.id.toLowerCase().includes(t)
      || s.family.toLowerCase().includes(t)
      || s.objective.toLowerCase().includes(t)
      || (s.description || "").toLowerCase().includes(t)
      || (s.candidate_action_ids || []).some((a) =>
              a.toLowerCase().includes(t)));
  }, [data, q]);

  const byObjective = useMemo(() => {
    const out = {};
    rows.forEach((s) => (out[s.objective] ||= []).push(s));
    return out;
  }, [rows]);

  if (loading) {
    return <div className="rl-loading"
                        data-testid="response-strategies-loading">
      <Loader2 size={12} className="rl-spin" style={{ marginRight: 6 }} />
      Loading response strategy knowledge…
    </div>;
  }
  if (error) {
    return <div className="rl-error"
                        data-testid="response-strategies-error">{String(error)}</div>;
  }

  const s = data.summary || {};
  return (
    <div data-testid="response-strategies-body" style={{ padding: "0 4px" }}>
      <Header summary={s} rowCount={rows.length}
                    onSearch={setQ} q={q} />

      {Object.entries(byObjective).map(([obj, list]) => (
        <ObjectiveGroup key={obj} objective={obj} list={list}
                                    openId={openId} setOpenId={setOpenId} />
      ))}

      <Contract />
    </div>
  );
}


function Header({ summary, rowCount, onSearch, q }) {
  return (
    <div style={{ padding: "10px 12px", marginBottom: 12,
                        border: "1px solid var(--border)", borderRadius: 4,
                        background: "var(--panel2)" }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center",
                          flexWrap: "wrap" }}>
        <Layers size={13} style={{ color: "#a78bfa" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
          Response Strategy Knowledge
        </b>
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                            color: "var(--faint)" }}>
          role={summary.role} · not_an_engine={String(summary.not_an_engine)}
        </span>
        <span style={{ flex: 1 }} />
        <input data-testid="response-strategies-search"
                    value={q} onChange={(e) => onSearch(e.target.value)}
                    placeholder="filter · family / action / description"
                    style={{ padding: "3px 8px",
                                    fontFamily: "var(--mono)", fontSize: 11,
                                    background: "var(--panel)",
                                    color: "var(--text)",
                                    border: "1px solid var(--border)",
                                    borderRadius: 2, width: 240 }} />
      </div>
      <div style={{ marginTop: 6, display: "flex", gap: 16,
                          fontFamily: "var(--mono)", fontSize: 10,
                          color: "var(--text-dim)", flexWrap: "wrap" }}>
        <span>Total: <b>{summary.total}</b></span>
        <span>Families: <b>{(summary.families || []).length}</b></span>
        <span>Objectives: <b>{(summary.objectives || []).length}</b></span>
        <span>Filtered: <b>{rowCount}</b></span>
      </div>
    </div>
  );
}


function ObjectiveGroup({ objective, list, openId, setOpenId }) {
  const color = OBJECTIVE_COLOR[objective] || "var(--faint)";
  return (
    <div style={{ marginBottom: 14 }}
              data-testid={`response-strategies-objective-${objective}`}>
      <div style={{ display: "flex", gap: 8, alignItems: "center",
                          padding: "6px 8px", marginBottom: 6,
                          border: `1px solid ${color}`,
                          borderRadius: 3,
                          background: `${color}12` }}>
        <ShieldCheck size={12} style={{ color }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 11,
                          color, letterSpacing: 0.5 }}>
          {objective.toUpperCase()}
        </b>
        <span style={{ flex: 1 }} />
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                              color: "var(--faint)" }}>
          {list.length} strateg{list.length === 1 ? "y" : "ies"}
        </span>
      </div>
      {list.map((s) => (
        <StrategyRow key={s.id} s={s} color={color}
                              open={openId === s.id}
                              onToggle={() => setOpenId(openId === s.id
                                                                        ? null : s.id)} />
      ))}
    </div>
  );
}


function StrategyRow({ s, color, open, onToggle }) {
  return (
    <div data-testid={`strategy-${s.id}`}
              style={{ marginBottom: 6, padding: 10,
                              border: "1px solid var(--border)",
                              borderRadius: 3, background: "var(--panel2)" }}>
      <div onClick={onToggle}
                style={{ cursor: "pointer", display: "flex", gap: 8,
                                alignItems: "center", flexWrap: "wrap" }}>
        <b style={{ fontFamily: "var(--mono)", fontSize: 11,
                          color }}>{s.id}</b>
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                            color: "var(--text-dim)" }}>
          family <b>{s.family}</b>
        </span>
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                            padding: "1px 6px", borderRadius: 2,
                            border: `1px solid ${color}`, color }}>
          {s.objective}
        </span>
        {s.allow_exclusions
          ? <span title="exclusions permitted"
                        style={pill("#a78bfa")}
                        data-testid={`strategy-${s.id}-exclusions-on`}>
              <Unlock size={9} style={{ marginRight: 3 }} />
              EXCLUSIONS OK
            </span>
          : <span title="exclusions forbidden" style={pill("var(--faint)")}
                        data-testid={`strategy-${s.id}-exclusions-off`}>
              <Lock size={9} style={{ marginRight: 3 }} />
              EXCLUSIONS BLOCKED
            </span>}
        <span style={{ flex: 1 }} />
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                            color: "var(--faint)" }}>
          {s.candidate_action_ids?.length || 0} candidates
        </span>
      </div>
      <div style={{ marginTop: 4, fontSize: 11.5, color: "var(--text-dim)",
                          fontStyle: "italic", lineHeight: 1.5 }}>
        {s.description}
      </div>
      {open && (
        <div style={{ marginTop: 10 }}>
          <Row k="Required evidence dimensions"
                    values={s.required_evidence_dims} color="#38bdf8" />
          <Row k="Candidate action IDs"
                    values={s.candidate_action_ids} color="var(--cyan)" />
          {s.framework_hint && (
            <div style={{ marginTop: 6,
                                  fontFamily: "var(--mono)", fontSize: 10,
                                  color: "var(--faint)" }}>
              <Radar size={9} style={{ marginRight: 4 }} />
              Framework hint: {JSON.stringify(s.framework_hint)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function Row({ k, values, color }) {
  return (
    <div style={{ marginTop: 6 }}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 10,
                          color: "var(--faint)", marginBottom: 3 }}>{k}</div>
      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
        {(values || []).map((v) => (
          <span key={v} style={{ ...pill(color), fontSize: 10 }}>{v}</span>
        ))}
      </div>
    </div>
  );
}


function Contract() {
  return (
    <div style={{ marginTop: 20, padding: 10,
                        border: "1px dashed var(--border)",
                        borderRadius: 3, background: "var(--panel2)",
                        fontFamily: "var(--mono)", fontSize: 10,
                        color: "var(--faint)", lineHeight: 1.55 }}>
      <b style={{ color: "var(--text-dim)" }}>
        ARCHITECTURAL CONTRACT ·
      </b>{" "}
      Threat family determines the response STRATEGY. Evidence
      determines which INDIVIDUAL ACTIONS are applicable. NivXRay
      never emits a recommendation solely because a malware/threat-
      family name matches — recommendations are synthesized from
      current incident evidence.
    </div>
  );
}


const pill = (color) => ({
  padding: "1px 6px", border: `1px solid ${color}`, color,
  borderRadius: 2, fontFamily: "var(--mono)",
  fontSize: 9, fontWeight: 700,
  display: "inline-flex", alignItems: "center",
});
