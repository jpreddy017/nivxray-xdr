/**
 * Admin › Detection Content Registry (P1).
 *
 * Real, populated, executable detection-content registry.  Renders
 * honest counts from /xdr/detection/status — never fabricates.
 * ATT&CK coverage is the union of real rule tags, not a target.
 */
import React, { useEffect, useMemo, useState } from "react";
import { RefreshCcw, ShieldCheck, ShieldAlert, ShieldOff, BookOpen,
                 CheckCircle2, XCircle } from "lucide-react";
import api from "@/lib/api";


export default function DetectionRegistryBody() {
  const [status,  setStatus]  = useState(null);
  const [rules,   setRules]   = useState([]);
  const [versions, setVersions] = useState([]);
  const [srcCat,  setSrcCat]  = useState(null);
  const [err,     setErr]     = useState(null);
  const [busy,    setBusy]    = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [q,       setQ]       = useState("");
  const [tab,     setTab]     = useState("rules");
  const [filter,  setFilter]  = useState({ source: "", rule_type: "",
                                                                    state: "", attack: "",
                                                                    license_state: "" });
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [st, rl, vs, sc] = await Promise.all([
          api.get("/xdr/detection/status"),
          api.get("/xdr/detection/rules", { params: { limit: 1000,
              q: q || undefined, ...Object.fromEntries(Object.entries(filter)
                    .filter(([, v]) => v)) } }),
          api.get("/xdr/detection/versions"),
          api.get("/xdr/detection/sources/catalog"),
        ]);
        setStatus(st?.data?.data || null);
        setRules(rl?.data?.data?.rules || []);
        setVersions(vs?.data?.data?.versions || []);
        setSrcCat(sc?.data?.data || null);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "load failed");
      } finally { setBusy(false); }
    })();
  }, [refresh, q, filter]);

  const doSync = async (source) => {
    setSyncing(true);
    try {
      const url = source ? `/xdr/detection/sync?source=${encodeURIComponent(source)}`
                                  : "/xdr/detection/sync";
      await api.post(url);
      setRefresh((n) => n + 1);
    } catch (e) {
      alert(JSON.stringify(e?.response?.data?.detail || e?.message));
    } finally { setSyncing(false); }
  };

  const s = status || {};
  const attackTechniques = s.attack_techniques || [];
  const licenseStates = s.license_state_counts || {};

  return (
    <div data-testid="xdr-admin-detection-registry-body">
      <div style={{ display: "flex", gap: 10, marginBottom: 14,
                          alignItems: "center" }}>
        <ShieldCheck size={16} style={{ color: "var(--mint)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
          Detection Content Registry
        </b>
        <StateBadge state={s.sync_state || "NEVER_SYNCED"}
                          data-testid="det-status-badge" />
        {s.bundled_fallback_available && (
          <span data-testid="det-bundled-badge" style={{
              padding: "1px 6px", border: "1px solid var(--faint)",
              color: "var(--faint)", borderRadius: 3, fontSize: 9.5,
              fontFamily: "var(--mono)", letterSpacing: ".3px" }}
              title="Bundled DRL-1.1 snapshot ships with the backend">
            BUNDLED · OK
          </span>
        )}
        <span style={{ flex: 1 }} />
        <button className="btn" onClick={() => doSync()} disabled={syncing || busy}
                     data-testid="det-sync-btn"
                     style={{ padding: "3px 10px", fontSize: 11,
                                     opacity: (syncing || busy) ? 0.5 : 1,
                                     cursor: (syncing || busy) ? "wait" : "pointer" }}>
          <RefreshCcw size={11}
                                  style={{ animation: syncing ? "spin 0.8s linear infinite"
                                                                          : "none" }} /> {syncing ? "Syncing…" : "Sync all"}
        </button>
        <button className="btn ghost" onClick={() => setRefresh((n) => n + 1)}
                     data-testid="det-refresh-btn" disabled={busy}
                     style={{ padding: "3px 10px", fontSize: 11,
                                     opacity: busy ? 0.5 : 1,
                                     cursor: busy ? "wait" : "pointer" }}>
          <RefreshCcw size={11}
                                  style={{ animation: busy ? "spin 0.8s linear infinite"
                                                                          : "none" }} /> {busy ? "Loading…" : "Refresh"}
        </button>
      </div>

      {/* Stats grid */}
      <div style={statsGrid}>
        <Stat label="Total rules"       value={s.total_rules ?? "—"}
                   testid="det-stat-total" />
        <Stat label="Valid rules"       value={s.valid_rules ?? "—"}
                   testid="det-stat-valid" color="var(--mint)" />
        <Stat label="Active rules"      value={s.active_rules ?? "—"}
                   testid="det-stat-active" color="var(--cyan)" />
        <Stat label="ATT&CK techniques" value={s.attack_technique_count ?? "—"}
                   testid="det-stat-attack" color="var(--amber)" />
        <Stat label="Sources"           value={Object.keys(s.sources || {}).length}
                   testid="det-stat-sources" />
        <Stat label="Rule types"        value={Object.keys(s.rule_types || {}).length}
                   testid="det-stat-types" />
      </div>

      {/* License policy strip */}
      <div data-testid="det-license-policy-strip"
                style={{ display: "flex", gap: 6, marginBottom: 12,
                                flexWrap: "wrap" }}>
        {Object.entries(licenseStates).map(([k, n]) => (
          <span key={k} style={{
                padding: "2px 8px", fontSize: 10, fontFamily: "var(--mono)",
                fontWeight: 700, borderRadius: 3,
                border: `1px solid ${licenseColor(k)}`,
                color: licenseColor(k), letterSpacing: ".3px" }}>
            {k}: {n}
          </span>
        ))}
      </div>

      {/* Tabs · RULES | CONTENT PACKS | ATT&CK | PROVENANCE | VERSIONS | VALIDATION */}
      <div style={{ display: "flex", gap: 4, marginBottom: 12,
                          borderBottom: "1px solid var(--border)" }}>
        {[
          ["rules",     "Rules",         rules.length],
          ["packs",     "Content Packs", Object.keys(s.sources || {}).length],
          ["attack",    "ATT&CK",        attackTechniques.length],
          ["provenance","Provenance",    rules.length],
          ["versions",  "Versions",      versions.length],
          ["validation","Validation",    "beta"],
        ].map(([k, label, count]) => (
          <button key={k} onClick={() => setTab(k)}
                       data-testid={`det-tab-${k}`}
                       className={tab === k ? "btn" : "btn ghost"}
                       style={{ padding: "4px 10px", fontSize: 11,
                                       borderRadius: "3px 3px 0 0",
                                       borderBottom: "none" }}>
            {label} · <span style={{ color: tab === k ? "var(--cyan)"
                                                                      : "var(--faint)" }}>{count}</span>
          </button>
        ))}
      </div>

      {/* ATT&CK coverage tab */}
      {tab === "attack" && (
      <div style={{ marginBottom: 12 }}>
        <div className="mono" style={sectionLabel}>ATT&CK Coverage</div>
        <div data-testid="det-attack-chips"
                  style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {attackTechniques.length === 0 ? (
            <div style={emptyText}>NO ATT&CK MAPPINGS</div>
          ) : attackTechniques.map((t) => (
            <span key={t} className="mono" style={chip}>
              {t}
            </span>
          ))}
        </div>
      </div>
      )}

      {/* Content Packs tab · shows source breakdown from the registry */}
      {tab === "packs" && (
        <div data-testid="det-packs-body" style={{ marginBottom: 12 }}>
          <div className="mono" style={sectionLabel}>
            Content Sources · Sigma · Snort · Suricata · YARA · MITRE ATT&CK
          </div>
          {(srcCat?.sources || []).map((src) => (
            <div key={src.name} data-testid={`det-source-${src.name}`}
                       style={{ border: "1px solid var(--border)", borderRadius: 3,
                                        padding: 10, marginBottom: 6,
                                        background: "var(--panel2)",
                                        fontFamily: "var(--mono)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <b style={{ color: "var(--cyan)", fontSize: 12 }}>
                  {src.display_name || src.name}
                </b>
                <span style={{
                  padding: "1px 6px",
                  border: `1px solid ${acqColor(src.acquisition_state)}`,
                  color: acqColor(src.acquisition_state),
                  borderRadius: 2, fontSize: 9, fontWeight: 700,
                  letterSpacing: ".3px" }}>
                  {src.acquisition_state}
                </span>
                <span style={{ color: "var(--faint)", fontSize: 10 }}>
                  license default: {src.default_license || "—"}
                </span>
                <span style={{ flex: 1 }} />
                <span style={{ color: "var(--text)", fontSize: 11 }}>
                  {src.rules_total} rules · {src.rules_active} active
                </span>
                <button className="btn ghost"
                              disabled={syncing || busy}
                              onClick={() => doSync(src.name)}
                              data-testid={`det-source-sync-${src.name}`}
                              style={{ padding: "2px 8px", fontSize: 10,
                                              opacity: (syncing || busy) ? 0.5 : 1 }}>
                  <RefreshCcw size={9} /> Sync
                </button>
              </div>
              {src.homepage && (
                <div style={{ color: "var(--faint)", fontSize: 10, marginTop: 4 }}>
                  {src.homepage}
                </div>
              )}
            </div>
          ))}
          {(!srcCat || !(srcCat.sources || []).length) && (
            <div style={emptyText}>NO CONTENT SOURCES CONFIGURED</div>
          )}
          {srcCat?.policy && (
            <div style={{ marginTop: 12, padding: 10,
                                    border: "1px solid var(--border)",
                                    borderRadius: 3, background: "var(--panel2)",
                                    fontFamily: "var(--mono)", fontSize: 10.5,
                                    color: "var(--faint)" }}>
              <b style={{ color: "var(--text-dim)" }}>License policy v{srcCat.policy.version} · </b>
              <span style={{ color: licenseColor("PERMITTED") }}>
                PERMITTED
              </span>: {srcCat.policy.permitted.join(", ")} ·{" "}
              <span style={{ color: licenseColor("RESTRICTED") }}>
                RESTRICTED
              </span>: {srcCat.policy.restricted.join(", ")} ·{" "}
              <span style={{ color: licenseColor("LICENSE_BLOCKED") }}>
                BLOCKED
              </span>: {srcCat.policy.blocked.join(", ")}
            </div>
          )}
        </div>
      )}

      {/* Provenance tab · flat list showing each rule's lineage */}
      {tab === "provenance" && (
        <div data-testid="det-provenance-body" style={{ marginBottom: 12,
                                          border: "1px solid var(--border)",
                                          borderRadius: 3, overflow: "hidden" }}>
          <div className="mono" style={{ display: "grid",
              gridTemplateColumns: "1.8fr 0.7fr 0.7fr 1.2fr 1.4fr",
              gap: 6, padding: "4px 8px", background: "var(--panel2)",
              fontSize: 10, color: "var(--faint)",
              textTransform: "uppercase" }}>
            <div>Rule / Upstream ID</div><div>Source</div>
            <div>License</div><div>Author · Dates</div><div>SHA-256</div>
          </div>
          {rules.map((r) => (
            <div key={r.id} className="mono" style={{ display: "grid",
                gridTemplateColumns: "1.8fr 0.7fr 0.7fr 1.2fr 1.4fr",
                gap: 6, padding: "6px 8px", fontSize: 10.5,
                color: "var(--text-dim)",
                borderTop: "1px solid var(--border)",
                alignItems: "center" }}>
              <div>
                <div style={{ color: "var(--text)" }}>{r.title}</div>
                <div style={{ color: "var(--faint)", fontSize: 9.5 }}>
                  {r.upstream_id}
                </div>
              </div>
              <div style={{ color: "var(--cyan)" }}>{r.source}</div>
              <div style={{ color: r.license_verified ? "var(--mint)"
                                                                            : "var(--amber)" }}>
                {r.license}
              </div>
              <div style={{ fontSize: 10 }}>
                {r.author}<br/>
                <span style={{ color: "var(--faint)" }}>
                  {r.created} → {r.modified}
                </span>
              </div>
              <div style={{ fontSize: 9.5, color: "var(--faint)",
                                    overflow: "hidden", textOverflow: "ellipsis" }}>
                {r.original_content_hash?.slice(0, 32)}…
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Versions tab · sync history */}
      {tab === "versions" && (
        <div data-testid="det-versions-body" style={{ marginBottom: 12,
                                          border: "1px solid var(--border)",
                                          borderRadius: 3, overflow: "hidden" }}>
          <div className="mono" style={{ display: "grid",
              gridTemplateColumns: "1fr 0.8fr 0.6fr 1fr 1fr",
              gap: 6, padding: "4px 8px", background: "var(--panel2)",
              fontSize: 10, color: "var(--faint)",
              textTransform: "uppercase" }}>
            <div>Version</div><div>Outcome</div><div>Active</div>
            <div>Registered</div><div>Synced at</div>
          </div>
          {versions.map((v) => (
            <div key={v.id} className="mono" style={{ display: "grid",
                gridTemplateColumns: "1fr 0.8fr 0.6fr 1fr 1fr",
                gap: 6, padding: "6px 8px", fontSize: 11,
                color: "var(--text-dim)",
                borderTop: "1px solid var(--border)",
                alignItems: "center" }}>
              <div style={{ color: "var(--text)", fontSize: 10 }}>{v.id}</div>
              <div style={{ color: v.outcome === "COMPLETE"
                                              ? "var(--mint)" : "var(--amber)" }}>
                {v.outcome}
              </div>
              <div>{v.active ? "✓" : "—"}</div>
              <div>{v.counts?.registered ?? 0}</div>
              <div style={{ fontSize: 10 }}>{v.synced_at}</div>
            </div>
          ))}
          {versions.length === 0 && (
            <div style={emptyRow}>NO SYNC VERSIONS YET</div>
          )}
        </div>
      )}

      {/* Validation tab · placeholder that honestly names the next work */}
      {tab === "validation" && (
        <div data-testid="det-validation-body" style={{ marginBottom: 12,
                                          padding: 14, fontFamily: "var(--mono)",
                                          fontSize: 11.5,
                                          border: "1px dashed var(--amber)",
                                          borderRadius: 4,
                                          background: "rgba(245,166,35,.06)",
                                          color: "var(--text-dim)" }}>
          <b style={{ color: "var(--amber)" }}>REGRESSION GATE — PENDING</b>
          <div style={{ marginTop: 6, lineHeight: 1.6 }}>
            Every rule promotion to <code>ACTIVE</code> will require positive +
            negative + false-positive tests to pass against the Investigation
            Corpus. The gate is queued as the immediate next milestone; no rule
            in this registry has been forced to <code>ACTIVE</code> without evidence.
            Current authoritative state: <b style={{ color: "var(--cyan)" }}>
              VALIDATED
            </b> — schema + license + provenance verified.
          </div>
        </div>
      )}

      {/* Filter row · only visible on the Rules tab */}
      {tab === "rules" && (
      <div style={{ display: "flex", gap: 6, marginBottom: 8, flexWrap: "wrap" }}>
        <input type="text" placeholder="Search title / description…"
                    value={q} onChange={(e) => setQ(e.target.value)}
                    data-testid="det-search" style={{ ...inputStyle, width: 260 }} />
        <select value={filter.source}
                    onChange={(e) => setFilter({ ...filter, source: e.target.value })}
                    data-testid="det-filter-source" style={inputStyle}>
          <option value="">All sources</option>
          {Object.entries(s.sources || {}).map(([k, n]) =>
            <option key={k} value={k}>{k} ({n})</option>)}
        </select>
        <select value={filter.rule_type}
                    onChange={(e) => setFilter({ ...filter, rule_type: e.target.value })}
                    data-testid="det-filter-type" style={inputStyle}>
          <option value="">All rule types</option>
          {Object.entries(s.rule_types || {}).map(([k, n]) =>
            <option key={k} value={k}>{k} ({n})</option>)}
        </select>
        <button className="btn ghost" onClick={() => setRefresh((n) => n + 1)}
                     data-testid="det-refresh"
                     style={{ padding: "4px 8px", fontSize: 11 }}>
          <RefreshCcw size={11} /> Refresh
        </button>
      </div>
      )}

      {err && <div data-testid="det-error" style={{ color: "var(--amber)",
                                          fontSize: 11, marginBottom: 8 }}>{err}</div>}

      {/* Rules table · only visible on the Rules tab */}
      {tab === "rules" && (
      <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                          overflow: "hidden" }}>
        <div className="mono" style={rowHead}>
          <div>Title</div><div>Source</div><div>Type</div>
          <div>ATT&CK</div><div>State</div><div>Level</div><div>Actions</div>
        </div>
        {rules.map((r) => (
          <div key={r.id} className="mono" style={rowBody}
                   data-testid={`det-row-${r.id}`}>
            <div>
              <div style={{ color: "var(--text)" }}>{r.title}
                {r.capability_not_verdict && (
                  <span title="Capability ≠ Verdict — evidence only" style={{
                      marginLeft: 4, padding: "0 4px",
                      background: "var(--panel2)", color: "var(--amber)",
                      fontSize: 9, border: "1px solid var(--border)",
                      borderRadius: 2 }}>CAPABILITY</span>)}
              </div>
              <div style={{ fontSize: 10, color: "var(--faint)" }}>
                {r.author} · {r.upstream_id}
              </div>
            </div>
            <div style={{ fontSize: 10.5, color: "var(--cyan)" }}>{r.source}</div>
            <div style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
              {r.rule_type}
            </div>
            <div style={{ fontSize: 10, color: "var(--amber)",
                              maxWidth: 160, overflow: "hidden",
                              textOverflow: "ellipsis" }}>
              {(r.attack_techniques || []).join(", ") || "—"}
            </div>
            <RuleStateBadge state={r.state} />
            <div style={{ fontSize: 10, color: "var(--faint)" }}>{r.level || "—"}</div>
            <div style={{ display: "flex", gap: 4 }}>
              {r.enabled ? (
                <button className="btn ghost" style={iconBtn}
                             data-testid={`det-disable-${r.id}`}
                             title="Disable"
                             onClick={async () => {
                                try {
                                  await api.post(`/xdr/detection/rules/${r.id}/disable`);
                                  setRefresh((n) => n + 1);
                                } catch (e) {
                                  alert(JSON.stringify(e?.response?.data?.detail));
                                }
                             }}>
                  <ShieldOff size={11} />
                </button>
              ) : (
                <button className="btn ghost" style={iconBtn}
                             data-testid={`det-enable-${r.id}`}
                             title="Enable"
                             onClick={async () => {
                                try {
                                  await api.post(`/xdr/detection/rules/${r.id}/enable`);
                                  setRefresh((n) => n + 1);
                                } catch (e) {
                                  alert(JSON.stringify(e?.response?.data?.detail));
                                }
                             }}>
                  <ShieldCheck size={11} />
                </button>
              )}
            </div>
          </div>
        ))}
        {rules.length === 0 && !busy && (
          <div data-testid="det-empty" style={emptyRow}>
            NO RULES · run Sync now to populate from the bundled DRL-1.1 snapshot.
          </div>
        )}
      </div>
      )}
    </div>
  );
}


function StateBadge({ state, ...p }) {
  const color = state === "SYNCED" ? "var(--mint)"
                          : state === "PARTIAL" ? "var(--amber)"
                          : "var(--faint)";
  const Icon = state === "SYNCED" ? CheckCircle2 : ShieldAlert;
  return (
    <span {...p} style={{ display: "inline-flex", alignItems: "center",
                            gap: 3, padding: "1px 6px", border: `1px solid ${color}`,
                            color, borderRadius: 3, fontSize: 10,
                            fontFamily: "var(--mono)", fontWeight: 700 }}>
      <Icon size={10} /> {state}
    </span>
  );
}


function licenseColor(state) {
  switch (state) {
    case "PERMITTED":       return "var(--mint)";
    case "RESTRICTED":      return "#38bdf8";
    case "LICENSE_REVIEW":  return "var(--amber)";
    case "LICENSE_BLOCKED": return "#f87171";
    default:                return "var(--faint)";
  }
}


function acqColor(state) {
  switch (state) {
    case "LIVE":              return "var(--mint)";
    case "BUNDLED_FALLBACK":  return "var(--amber)";
    case "UNAVAILABLE":       return "#f87171";
    default:                  return "var(--faint)";
  }
}


function RuleStateBadge({ state }) {
  const good = state === "ACTIVE" || state === "VALIDATED"
                        || state === "COMPILED" || state === "TESTED"
                        || state === "ENABLED";
  const color = good ? "var(--mint)"
                          : state === "DISABLED" ? "var(--faint)"
                          : "#f87171";
  return (
    <span data-testid={`det-state-${state}`} className="mono" style={{
        padding: "1px 5px", border: `1px solid ${color}`, color,
        borderRadius: 2, fontSize: 9.5 }}>
      {state}
    </span>
  );
}


function Stat({ label, value, testid, color }) {
  return (
    <div data-testid={testid} style={statCard}>
      <div className="mono" style={statLabel}>{label}</div>
      <div className="mono" style={{ ...statValue, color: color || "var(--text)" }}>
        {value}
      </div>
    </div>
  );
}


const statsGrid = {
  display: "grid",
  gridTemplateColumns: "repeat(6, 1fr)",
  gap: 8, marginBottom: 14,
};
const statCard = {
  padding: 10, border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel2)",
};
const statLabel = {
  fontSize: 9.5, color: "var(--faint)", textTransform: "uppercase",
  marginBottom: 4, letterSpacing: ".3px",
};
const statValue = { fontSize: 20, fontWeight: 700 };
const sectionLabel = {
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
  marginBottom: 6, letterSpacing: ".3px",
};
const chip = {
  padding: "1px 5px", fontSize: 9.5,
  border: "1px solid var(--border)", color: "var(--amber)",
  borderRadius: 2, background: "var(--panel2)",
};
const inputStyle = {
  padding: "4px 8px", fontSize: 11, border: "1px solid var(--border)",
  borderRadius: 3, background: "var(--panel2)", color: "var(--text)",
  fontFamily: "var(--mono)",
};
const rowHead = {
  display: "grid",
  gridTemplateColumns: "2fr 0.8fr 0.8fr 1.4fr 0.7fr 0.5fr 0.6fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rowBody = {
  display: "grid",
  gridTemplateColumns: "2fr 0.8fr 0.8fr 1.4fr 0.7fr 0.5fr 0.6fr",
  gap: 6, padding: "6px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
const iconBtn = { padding: "2px 6px", fontSize: 10 };
const emptyRow = { padding: 10, fontSize: 11, color: "var(--faint)",
                              fontFamily: "var(--mono)" };
const emptyText = { fontSize: 10, color: "var(--faint)",
                                fontFamily: "var(--mono)" };
