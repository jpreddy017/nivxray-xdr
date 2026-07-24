/**
 * InvestigationWorkspace — the NivXRay Enterprise Attack Investigation
 * Platform shell. Reads the Investigation Knowledge Graph (IKG) once
 * from `GET /api/v2/cases/{id}/investigation` and hands it down to every
 * tab as the single source of truth.
 *
 * Route     : /v2/case/:caseId?tab=<view>&profile=<id>
 * Legacy    : /v2/trajectory/:caseId  is preserved unchanged. It also
 *             redirects here (see App.js) so existing links keep working
 *             but land inside the unified workspace.
 *
 * Phase 1 · scope (this file):
 *   ✓ Persistent header (case · severity · device score · incident score
 *     · confidence · verdict band · profile chip · IKG stats)
 *   ✓ URL-driven tab router (?tab=<view>)
 *   ✓ Tab strip · 10 views defined; Phase 1 activates Trajectory
 *     (embeds existing DeviceTrajectoryV2 canvas — zero refactor).
 *   ✓ Global collapsible Explainability panel (bottom rail on every tab)
 *   ✓ Placeholder tabs for Phase 2-5 features
 *
 * Nothing existing is removed. `/v2/trajectory/:caseId`, `/v2/irg`,
 * `/v2/compare`, `/`, `/analyst`, and every other route stay live.
 */
import { lazy, Suspense, useEffect, useMemo, useState, useCallback } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import { T } from "../theme";
import { isObservable } from "../flags";
import api from "@/lib/api";

const DeviceTrajectoryV2 = lazy(() => import("./DeviceTrajectoryV2"));

// ═══════════════════════════════════════════════════════════════════
// Tab manifest — the ONE place a new view is registered.
// A tab is either { key, label, testid, render } or an unfinished
// placeholder { key, label, testid, comingSoon: "phase-N …" }.
// ═══════════════════════════════════════════════════════════════════
const BAND_TONES = {
  benign:        "#4ADE80",
  informational: "#7DB1D6",
  low:           "#D4C069",
  suspicious:    "#F5A34C",
  malicious:     "#F87171",
  critical:      "#FCA5A5",
};

// ═══════════════════════════════════════════════════════════════════
// Persistent header
// ═══════════════════════════════════════════════════════════════════
function HeaderKV({ label, value, tone }) {
  return (
    <div className="flex flex-col" data-testid={`header-kv-${label.toLowerCase().replace(/\s+/g, "-")}`}>
      <span className="text-[9px] tracking-[1.4px] font-bold"
            style={{ color: T.inkMute }}>{label}</span>
      <span className="text-[13px] font-mono font-bold"
            style={{ color: tone || T.ink }}>{value}</span>
    </div>
  );
}

function PersistentHeader({ inv, loading, profile, onProfile, profiles }) {
  const h = inv?.header || {};
  const band = h.verdict_band || "benign";
  const tone = BAND_TONES[band] || BAND_TONES.benign;
  return (
    <div data-testid="investigation-header"
         className="flex items-center gap-6 px-4 py-2.5 flex-wrap"
         style={{ background: T.paper, borderBottom: `1px solid ${T.line}` }}>
      <div className="flex flex-col min-w-0">
        <span className="text-[9px] tracking-[1.4px] font-bold"
              style={{ color: T.inkMute }}>CASE</span>
        <span className="text-[13px] font-mono truncate max-w-[420px]"
              style={{ color: T.ink }} title={inv?.case_id}>
          {inv?.case_id || "—"}
        </span>
      </div>

      <div className="h-8 w-px" style={{ background: T.line }} />

      <HeaderKV label="Severity"       value={band.toUpperCase()} tone={tone} />
      <HeaderKV label="Device Risk"    value={h.device_score ?? "—"} tone={tone} />
      <HeaderKV label="Incident Risk"  value={h.incident_score ?? "—"} tone={tone} />
      <HeaderKV label="Confidence"     value={h.confidence != null ? `${h.confidence}%` : "—"} />
      <HeaderKV label="Verdict"        value={loading ? "…" : (band.toUpperCase())} tone={tone} />

      <div className="h-8 w-px" style={{ background: T.line }} />

      <HeaderKV label="Events"    value={h.event_count ?? "—"} />
      <HeaderKV label="Processes" value={h.process_count ?? "—"} />
      <HeaderKV label="Chains"    value={h.chain_count ?? "—"} />

      <div className="ml-auto flex items-center gap-3">
        {profiles?.length > 0 && (
          <label className="flex items-center gap-2" data-testid="workspace-profile-selector">
            <span className="text-[9px] tracking-[1.4px] font-bold"
                  style={{ color: T.inkMute }}>PROFILE</span>
            <select value={profile}
                    onChange={(e) => onProfile(e.target.value)}
                    data-testid="workspace-profile-select"
                    className="text-[11px] font-mono px-2 py-1 rounded"
                    style={{ background: T.paper2, border: `1px solid ${T.line}`,
                             color: T.ink }}>
              {profiles.map(p => (
                <option key={p.id} value={p.id}>
                  {p.label}{p.is_default ? " · default" : ""}
                </option>
              ))}
            </select>
          </label>
        )}
        <span className="text-[9px] font-mono px-2 py-1 rounded"
              style={{ background: T.paper2, color: T.inkMute,
                       border: `1px solid ${T.line}` }}
              title="Investigation engine version">
          engine v{inv?.engine_version?.verdict || "3.1b"}
        </span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Tab strip
// ═══════════════════════════════════════════════════════════════════
function TabStrip({ tabs, activeKey, onTab }) {
  return (
    <div data-testid="investigation-tabs"
         className="flex items-center gap-1 px-3 py-1.5 overflow-x-auto"
         style={{ background: T.paper, borderBottom: `1px solid ${T.line}` }}>
      {tabs.map(t => {
        const active = t.key === activeKey;
        return (
          <button key={t.key}
                  data-testid={`tab-${t.key}`}
                  onClick={() => onTab(t.key)}
                  disabled={t.comingSoon}
                  className="px-3 py-1.5 rounded text-[11px] tracking-[0.6px] font-semibold whitespace-nowrap transition-colors"
                  style={{
                    background: active ? T.paper2 : "transparent",
                    color:      active ? T.ink : (t.comingSoon ? T.inkFaint : T.inkDim),
                    border: `1px solid ${active ? T.emerald : "transparent"}`,
                    cursor: t.comingSoon ? "not-allowed" : "pointer",
                    opacity: t.comingSoon ? 0.5 : 1,
                  }}
                  title={t.comingSoon ? `Coming in ${t.comingSoon}` : t.label}>
            {t.label}
            {t.comingSoon && <span className="ml-1 text-[9px]" style={{ color: T.inkFaint }}>·soon</span>}
          </button>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Placeholder view (Phase 2-5 features)
// ═══════════════════════════════════════════════════════════════════
function PlaceholderView({ tab }) {
  return (
    <div data-testid={`placeholder-${tab.key}`}
         className="flex flex-col items-center justify-center p-12 gap-3"
         style={{ minHeight: 400 }}>
      <div className="text-[10px] tracking-[2px] font-bold"
           style={{ color: T.inkMute }}>{tab.comingSoon}</div>
      <div className="text-[22px] font-bold" style={{ color: T.ink }}>
        {tab.label}
      </div>
      <div className="text-[12px] max-w-md text-center" style={{ color: T.inkDim }}>
        {tab.description}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Global collapsible Explainability panel
// Renders on every tab. Content is a Phase-1 minimal — full deterministic
// reasoning engine ships in Phase 4.
// ═══════════════════════════════════════════════════════════════════
function ExplainabilityPanel({ inv, activeTab }) {
  const [open, setOpen] = useState(false);
  const h = inv?.header || {};
  const dv = inv?.verdicts?.device;

  const reasons = useMemo(() => {
    if (!dv) return [];
    const out = [];
    // 1 · Top 3 evidence signals (deterministic sort by effective_weight).
    const evi = [...(dv.evidence_breakdown || [])]
      .sort((a, b) => (b.effective_weight || 0) - (a.effective_weight || 0))
      .slice(0, 3);
    evi.forEach(e => out.push({
      kind: "evidence", weight: e.effective_weight,
      text: `${e.signal.replaceAll("_", " ").toLowerCase()} detected · +${e.effective_weight}`,
      detail: e.reason,
    }));
    // 2 · Correlation bonuses.
    (dv.correlation_bonuses || []).forEach(b => out.push({
      kind: "bonus", weight: b.weight,
      text: `${b.signal.replaceAll("_", " ").toLowerCase()} · +${b.weight}`,
      detail: b.reason,
    }));
    // 3 · Progressions.
    (dv.progressions || []).forEach(p => out.push({
      kind: "progression", weight: p.effective_weight || p.weight,
      text: `${p.label} · +${p.effective_weight || p.weight}`,
      detail: p.reason,
    }));
    // 4 · Tactic coverage summary line.
    const nTactics = Object.keys(dv.tactic_coverage || {}).length;
    if (nTactics > 0) {
      out.push({
        kind: "coverage",
        text: `${nTactics} MITRE tactic${nTactics > 1 ? "s" : ""} covered`,
        detail: Object.keys(dv.tactic_coverage).join(", "),
      });
    }
    return out;
  }, [dv]);

  const band = h.verdict_band || "benign";
  const tone = BAND_TONES[band] || BAND_TONES.benign;

  return (
    <div data-testid="explainability-panel"
         className="border-t"
         style={{ borderColor: T.line, background: T.paper }}>
      <button data-testid="explainability-toggle"
              onClick={() => setOpen(o => !o)}
              className="w-full flex items-center gap-3 px-4 py-2 hover:bg-white/5 transition-colors">
        <span className="text-[10px]" style={{ color: T.inkFaint }}>
          {open ? "▾" : "▸"}
        </span>
        <span className="text-[10px] tracking-[1.5px] font-bold"
              style={{ color: T.inkMute }}>EXPLAIN</span>
        <span className="text-[12px]" style={{ color: T.ink }}>
          Why is this <span style={{ color: tone }}>{band}</span>?
        </span>
        <span className="ml-auto text-[9px] font-mono" style={{ color: T.inkFaint }}>
          {activeTab} view · deterministic · no LLM
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-1 border-t space-y-1"
             style={{ borderColor: T.line, maxHeight: 260, overflowY: "auto" }}>
          {reasons.length === 0 ? (
            <div className="text-[11px]" style={{ color: T.inkFaint }}
                 data-testid="explainability-empty">
              No evidence fired. Classification remains {band.toUpperCase()}.
            </div>
          ) : (
            reasons.map((r, i) => (
              <div key={i}
                   data-testid={`explainability-reason-${i}`}
                   className="flex items-baseline gap-3 text-[11px]"
                   style={{ color: T.inkDim }}>
                <span className="font-mono font-bold"
                      style={{ color: r.kind === "bonus" ? "#7DB1D6"
                                    : r.kind === "progression" ? "#FCA5A5"
                                    : r.kind === "coverage" ? "#4ADE80" : "#F5A34C",
                               minWidth: 90 }}>
                  {r.kind}
                </span>
                <span style={{ color: T.ink }}>{r.text}</span>
                {r.detail && (
                  <span className="text-[10px] flex-1 truncate"
                        style={{ color: T.inkFaint }} title={r.detail}>
                    · {r.detail}
                  </span>
                )}
              </div>
            ))
          )}
          <div className="pt-2 text-[9px] font-mono"
               style={{ color: T.inkFaint, borderTop: `1px solid ${T.line}` }}>
            Reasoned from the Investigation Knowledge Graph · {inv?.ikg?.stats?.nodes || 0} nodes · {inv?.ikg?.stats?.edges || 0} edges
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Main workspace
// ═══════════════════════════════════════════════════════════════════
export default function InvestigationWorkspace() {
  const { caseId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeKey = searchParams.get("tab") || "trajectory";
  const profile   = searchParams.get("profile") || "soc_balanced";

  const [inv, setInv] = useState(null);
  const [err, setErr] = useState(null);
  const [loading, setLoading] = useState(false);
  const [profiles, setProfiles] = useState([]);

  const enabled = isObservable("VERDICT_ENGINE_V3");

  // Load profiles once.
  useEffect(() => {
    if (!enabled) return;
    api.get("/v2/verdict/profiles")
       .then(r => setProfiles(r.data?.profiles || []))
       .catch(() => {});
  }, [enabled]);

  // Load the Investigation on caseId or profile change.
  useEffect(() => {
    if (!enabled || !caseId) return;
    let cancelled = false;
    setLoading(true);
    api.get(`/v2/cases/${encodeURIComponent(caseId)}/investigation?limit=500&profile=${profile}`)
      .then(r => { if (!cancelled) setInv(r.data); })
      .catch(e => { if (!cancelled) setErr(e?.response?.data?.detail || e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [caseId, profile, enabled]);

  const setTab = useCallback((key) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", key);
    setSearchParams(next, { replace: false });
  }, [searchParams, setSearchParams]);

  const setProfile = useCallback((next) => {
    const p = new URLSearchParams(searchParams);
    p.set("profile", next);
    setSearchParams(p, { replace: true });
  }, [searchParams, setSearchParams]);

  // ─── Tab manifest ─────────────────────────────────────────────
  const TABS = useMemo(() => ([
    { key: "summary",     label: "Summary",           testid: "tab-summary",
      comingSoon: "phase 4",
      description: "Executive view · severity, device risk, incident risk, confidence, timeline, recommendations." },
    { key: "trajectory",  label: "Device Trajectory", testid: "tab-trajectory",
      render: () => (
        <div style={{ minHeight: "70vh" }}
             data-testid="workspace-trajectory-embed">
          <DeviceTrajectoryV2 />
        </div>
      ),
    },
    { key: "process",     label: "Process Tree",      testid: "tab-process",
      comingSoon: "phase 3",
      description: "Parent-child ancestry projection of the IKG — the primary DFIR view." },
    { key: "story",       label: "Attack Story",      testid: "tab-story",
      comingSoon: "phase 2",
      description: "Deterministic incident narrative · every sentence linked to IKG evidence." },
    { key: "graph",       label: "Evidence Graph",    testid: "tab-graph",
      comingSoon: "phase 3",
      description: "Cause-and-effect visualisation of the IKG · not chronological — relational." },
    { key: "verdict",     label: "Verdict",           testid: "tab-verdict",
      comingSoon: "phase 4",
      description: "Event → Process → Chain → Device → Incident with escalation ladder, evidence breakdown, confidence." },
    { key: "attack",      label: "ATT&CK",            testid: "tab-attack",
      comingSoon: "phase 2",
      description: "Tactic coverage wheel, technique list, kill chain, Navigator export, STIX." },
    { key: "ti",          label: "Threat Intelligence", testid: "tab-ti",
      comingSoon: "phase 5",
      description: "Enrichment only. Never influences the deterministic verdict." },
    { key: "reports",     label: "Reports",           testid: "tab-reports",
      comingSoon: "phase 5",
      description: "One-click export · Exec Summary → Attack Story → Evidence Graph → ATT&CK → IOCs → Timeline → Verdict → Recommendations → Appendix." },
  ]), []);

  const active = TABS.find(t => t.key === activeKey) || TABS[1];

  if (!enabled) {
    return (
      <div data-testid="workspace-disabled"
           className="p-8 text-[12px]" style={{ color: T.inkFaint }}>
        Investigation Workspace requires VERDICT_ENGINE_V3 to be observable.
      </div>
    );
  }

  return (
    <div data-testid="investigation-workspace"
         className="flex flex-col"
         style={{ background: T.bg, color: T.ink, minHeight: "100vh" }}>
      <PersistentHeader inv={inv} loading={loading}
                        profile={profile} onProfile={setProfile}
                        profiles={profiles} />
      <TabStrip tabs={TABS} activeKey={active.key} onTab={setTab} />

      <div className="flex-1 min-w-0">
        {err && (
          <div className="p-6 text-[12px]" style={{ color: "#F87171" }}
               data-testid="workspace-error">
            Failed to load investigation: {err}
          </div>
        )}
        <Suspense fallback={
          <div className="p-6 text-[11px] font-mono" style={{ color: T.inkFaint }}>
            loading tab…
          </div>
        }>
          {active.render ? active.render() : <PlaceholderView tab={active} />}
        </Suspense>
      </div>

      <ExplainabilityPanel inv={inv} activeTab={active.label} />

      <div className="px-4 py-1.5 text-[9px] font-mono flex items-center gap-3"
           style={{ background: T.paper, borderTop: `1px solid ${T.line}`,
                    color: T.inkFaint }}
           data-testid="workspace-footer">
        <span>NivXRay · Enterprise Attack Investigation Platform</span>
        <span>·</span>
        <span>IKG {inv?.engine_version?.ikg || "1.0"}</span>
        <span>·</span>
        <span>profile {inv?.profile || profile}</span>
        <span className="ml-auto">
          <Link to={`/v2/trajectory/${caseId}`}
                data-testid="link-legacy-trajectory"
                className="hover:underline"
                style={{ color: T.inkMute }}>
            open legacy trajectory view →
          </Link>
        </span>
      </div>
    </div>
  );
}
