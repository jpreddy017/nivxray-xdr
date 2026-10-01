import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import Header from "@/components/Header";
import PageHeader from "@/components/PageHeader";
import api from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Check, X, KeyRound, ExternalLink, Save, TestTube2, Users, BarChart3, RefreshCw, Database, Sparkles, Upload, ShieldCheck, Gauge, Battery } from "lucide-react";
import { Link } from "react-router-dom";
import TrainingNotesCard from "@/components/TrainingNotesCard";
import ConfusionMatrixCard from "@/components/ConfusionMatrixCard";
import TaxiiAdminPanel from "@/components/TaxiiAdminPanel";
import RegressionDashboard from "@/components/RegressionDashboard";
import EnrichmentAdminPanel from "@/components/EnrichmentAdminPanel";
import ThreatIntelAdminPanel from "@/components/ThreatIntelAdminPanel";
import DocsFeedbackPanel from "@/components/DocsFeedbackPanel";

export default function AdminPage() {
  const { user } = useAuth();
  const [services, setServices] = useState([]);
  const [keys, setKeys] = useState({});
  const [testing, setTesting] = useState({});
  const [testResults, setTestResults] = useState({});
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");
  const [lolbasStatus, setLolbasStatus] = useState(null);
  const [lolbasSyncing, setLolbasSyncing] = useState(false);

  useEffect(() => {
    if (!user || user.role !== "admin") return;
    api.get("/admin/osint/services").then((r) => {
      setServices(r.data);
      const k = {};
      r.data.forEach((s) => { k[s.id] = s.configured ? "" : ""; });
      setKeys(k);
    }).catch(() => {});
    api.get("/admin/stats").then((r) => setStats(r.data)).catch(() => {});
    api.get("/admin/users").then((r) => setUsers(r.data)).catch(() => {});
    api.get("/admin/lolbas/status").then((r) => setLolbasStatus(r.data)).catch(() => {});
  }, [user]);

  const syncLolbas = async () => {
    setLolbasSyncing(true);
    try {
      const r = await api.post("/admin/lolbas/sync");
      setLolbasStatus((s) => ({ ...(s || {}), ...r.data,
        active_count: r.data.count || s?.active_count,
        source_count: r.data.source_count ?? s?.source_count,
      }));
      const fresh = await api.get("/admin/lolbas/status");
      setLolbasStatus(fresh.data);
    } catch (e) {
      setLolbasStatus((s) => ({ ...(s || {}), last_error: e?.response?.data?.detail || e.message }));
    } finally {
      setLolbasSyncing(false);
    }
  };

  if (!user) return <Navigate to="/login" replace />;
  if (user.role !== "admin") {
    return (
      <div className="App"><Header />
        <div className="mono" style={{ padding: 40, color: "var(--high)" }}>ACCESS DENIED — admin only</div>
      </div>
    );
  }

  const save = async () => {
    setSaving(true);
    setSaveMsg("");
    try {
      // only send non-empty keys (empty means "keep existing")
      const payload = {};
      Object.entries(keys).forEach(([k, v]) => { if (v && v.trim()) payload[k] = v.trim(); });
      const r = await api.put("/admin/osint/settings", { keys: payload });
      setSaveMsg(`Saved · ${r.data.configured_services.length} services active`);
      // refresh masked list
      const s = await api.get("/admin/osint/services");
      setServices(s.data);
      // clear inputs
      const cleared = {}; Object.keys(keys).forEach((k) => (cleared[k] = ""));
      setKeys(cleared);
    } catch (e) {
      setSaveMsg("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setSaving(false);
    }
  };

  const test = async (svcId) => {
    setTesting((t) => ({ ...t, [svcId]: true }));
    try {
      const r = await api.post(`/admin/osint/test/${svcId}`);
      setTestResults((tr) => ({ ...tr, [svcId]: r.data }));
    } catch (e) {
      setTestResults((tr) => ({ ...tr, [svcId]: { ok: false, error: e?.response?.data?.detail || e.message } }));
    } finally {
      setTesting((t) => ({ ...t, [svcId]: false }));
    }
  };

  const remove = async (svcId) => {
    if (!window.confirm(`Remove API key for ${svcId}?`)) return;
    await api.put("/admin/osint/settings", { keys: { [svcId]: "" } });
    const s = await api.get("/admin/osint/services");
    setServices(s.data);
  };

  return (
    <div className="App">
      <Header />

      <div style={{ padding: 24, display: "grid", gap: 24, maxWidth: 1400, margin: "0 auto" }}>
        <PageHeader
          testId="admin-hero"
          eyebrow="Control Plane · Platform Configuration"
          title="Admin · Settings"
          subtitle="Configure OSINT integrations, review analytics, manage users, and administer the deterministic-first analysis stack. All changes are audited."
          icon={KeyRound}
          tone="amber"
        />

        {/* Stats */}
        {stats && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }} className="stagger">
            <StatCard label="OPERATIONS" value={stats.total_operations} icon={<BarChart3 size={14} />} />
            <StatCard label="USERS" value={stats.total_users} icon={<Users size={14} />} />
            <StatCard label="SHARED RECIPES" value={stats.total_shares} icon={<ExternalLink size={14} />} />
            <StatCard label="OSINT ACTIVE" value={stats.configured_osint_services} icon={<KeyRound size={14} />} />
          </div>
        )}

        {/* Sample Library quick-link */}
        <section className="brut-border" style={{ background: "var(--surface)" }} data-testid="sample-library-link-card">
          <div style={{ padding: "14px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>▸ SAMPLE LIBRARY</div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 6, lineHeight: 1.5 }}>
                Real-world encoded/obfuscated payloads with expected decoded outputs. Continuous regression
                testing + nightly benchmark keeps decoder coverage growing without breaking existing samples.
              </div>
            </div>
            <Link to="/admin/samples" className="nvx-btn primary" data-testid="admin-open-sample-library">
              <Sparkles size={13} /> OPEN LIBRARY
            </Link>
          </div>
        </section>

        {/* Model Studio quick-link */}
        <section className="brut-border" style={{ background: "var(--surface)" }} data-testid="model-studio-link-card">
          <div style={{ padding: "14px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>▸ MODEL STUDIO</div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 6, lineHeight: 1.5 }}>
                Teach NivXRay new tricks: custom detection rules, decode recipes, AI personas, and LLM provider switching.
                All changes go live immediately on the next investigation.
              </div>
            </div>
            <Link to="/admin/models" className="nvx-btn primary" data-testid="admin-open-model-studio">
              <Sparkles size={13} /> OPEN STUDIO
            </Link>
          </div>
        </section>

        {/* Investigation Ingestion Engine (Phase 4.1) — quick-link */}
        <section className="brut-border" style={{ background: "var(--surface)" }} data-testid="ingest-link-card">
          <div style={{ padding: "14px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>▸ INVESTIGATION INGESTION</div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 6, lineHeight: 1.5 }}>
                Drop Sysmon XML, Windows Security XML, JSON/NDJSON, CSV, or ZIP bundles. Format &amp; source
                are auto-detected, events normalize into the Canonical Event Schema, and a full Investigation
                Workspace is generated deterministically. Also hosts the 34-dataset Golden Corpus seed
                buttons for one-click benchmark cases.
              </div>
            </div>
            <Link to="/v2/ingest" className="nvx-btn primary" data-testid="admin-open-ingest">
              <Upload size={13} /> OPEN INGEST
            </Link>
          </div>
        </section>

        {/* Validation Pack (Phase 4.2) — quick-link */}
        <section className="brut-border" style={{ background: "var(--surface)" }} data-testid="validation-link-card">
          <div style={{ padding: "14px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>▸ VALIDATION PACK</div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 6, lineHeight: 1.5 }}>
                Runs every Golden Corpus dataset through the full ingestion → correlation → IKG → story →
                verdict pipeline and scores 11 dimensions (verdict · MITRE · story · processes · IOCs · …).
                This is the release gate — accuracy regressions fail the build.
              </div>
            </div>
            <Link to="/v2/validation" className="nvx-btn primary" data-testid="admin-open-validation">
              <ShieldCheck size={13} /> OPEN VALIDATION
            </Link>
          </div>
        </section>

        {/* Benchmark — quick-link */}
        <section className="brut-border" style={{ background: "var(--surface)" }} data-testid="benchmark-link-card">
          <div style={{ padding: "14px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>▸ BENCHMARK</div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 6, lineHeight: 1.5 }}>
                Performance benchmarking suite — measures decoder throughput, verdict engine latency,
                and end-to-end investigation build times across the corpus.
              </div>
            </div>
            <Link to="/benchmark" className="nvx-btn primary" data-testid="admin-open-benchmark">
              <Gauge size={13} /> OPEN BENCHMARK
            </Link>
          </div>
        </section>

        {/* Battery — quick-link */}
        <section className="brut-border" style={{ background: "var(--surface)" }} data-testid="battery-link-card">
          <div style={{ padding: "14px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>▸ BATTERY</div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 6, lineHeight: 1.5 }}>
                Adversarial regression battery — replays every historical failure to guarantee no
                previously-fixed detection has regressed.
              </div>
            </div>
            <Link to="/battery" className="nvx-btn primary" data-testid="admin-open-battery">
              <Battery size={13} /> OPEN BATTERY
            </Link>
          </div>
        </section>

        {/* Global AI Training Notes — always-on directives, feedback-weighted */}
        <TrainingNotesCard />

        {/* Corpus Confusion Matrix — decoder health at a glance */}
        <ConfusionMatrixCard />

        {/* Regression Dashboard — auto-benchmark + gate status (Feb-2026 #4) */}
        <RegressionDashboard />

        {/* Threat Intelligence + Fine-tuning dataset (Feb-2026 #6 + #8) */}
        <ThreatIntelAdminPanel />

        {/* Enrichment providers — VT / OTX / AbuseIPDB API keys (Feb-2026 #6) */}
        <EnrichmentAdminPanel />

        {/* TAXII 2.1 Push — publish IOCs as STIX 2.1 to your TAXII server */}
        <TaxiiAdminPanel />

        {/* LOLBAS Catalog */}
        <section className="brut-border" style={{ background: "var(--surface)" }} data-testid="lolbas-catalog-card">
          <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>▸ LOLBAS CATALOG</div>
            <button className="nvx-btn primary sm" onClick={syncLolbas} disabled={lolbasSyncing} data-testid="btn-lolbas-sync">
              <RefreshCw size={12} /> {lolbasSyncing ? "SYNCING…" : "SYNC NOW"}
            </button>
          </div>
          <div style={{ padding: 16, display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
            <StatCard label="ACTIVE ENTRIES" value={lolbasStatus?.active_count ?? "—"} icon={<Database size={14} />} />
            <StatCard label="FROM SOURCE" value={lolbasStatus?.source_count ?? "—"} icon={<Database size={14} />} />
            <StatCard label="CURATED (ARGV)" value={lolbasStatus?.defaults_count ?? "—"} icon={<Database size={14} />} />
            <div className="brut-border" style={{ padding: 12, background: "var(--inset)" }}>
              <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", letterSpacing: "0.14em" }}>LAST SYNCED</div>
              <div className="mono" style={{ fontSize: 11, color: lolbasStatus?.last_error ? "var(--high)" : "var(--accent)", marginTop: 4, wordBreak: "break-all" }}>
                {lolbasStatus?.last_error
                  ? `ERROR · ${lolbasStatus.last_error}`
                  : (lolbasStatus?.last_updated ? new Date(lolbasStatus.last_updated).toLocaleString() : "never")}
              </div>
              <a className="mono" href={lolbasStatus?.source_url || "https://lolbas-project.github.io/"} target="_blank" rel="noreferrer"
                 style={{ fontSize: 10, color: "var(--text-mute)", textDecoration: "none", marginTop: 6, display: "inline-block" }}>
                {lolbasStatus?.source_url || "lolbas-project.github.io"} ↗
              </a>
            </div>
          </div>
          <div style={{ padding: "0 16px 14px", fontSize: 11, color: "var(--text-mute)", fontFamily: "JetBrains Mono", lineHeight: 1.6 }}>
            Auto-refreshes every 7 days on backend startup. Curated argv-pattern rules always take precedence over
            remote entries for high-fidelity matching (e.g. certutil, mshta, powershell). Network failures preserve
            the last successful cache.
          </div>
        </section>

        {/* OSINT services */}
        <section className="brut-border" style={{ background: "var(--surface)" }}>
          <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>▸ OSINT INTEGRATIONS</div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              {saveMsg && <span className="mono" style={{ fontSize: 11, color: saveMsg.startsWith("ERROR") ? "var(--high)" : "var(--accent)" }}>{saveMsg}</span>}
              <button className="nvx-btn primary sm" onClick={save} disabled={saving} data-testid="btn-save-keys">
                <Save size={12} /> {saving ? "SAVING…" : "SAVE"}
              </button>
            </div>
          </div>
          <div style={{ padding: 16 }}>
            <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginBottom: 14, lineHeight: 1.6 }}>
              Paste API keys below. Leave a field blank to keep the existing key.
              Use the trash icon to remove a saved key entirely.
              Keys are stored server-side in MongoDB and never exposed back to the client.
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <Th>SERVICE</Th>
                  <Th>SUPPORTS</Th>
                  <Th>CURRENT KEY</Th>
                  <Th>NEW KEY</Th>
                  <Th>ACTIONS</Th>
                </tr>
              </thead>
              <tbody>
                {services.map((s) => {
                  const tr = testResults[s.id];
                  return (
                    <tr key={s.id} style={{ borderBottom: "1px solid var(--border)" }} data-testid={`osint-row-${s.id}`}>
                      <Td>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          {s.configured ? <Check size={13} color="var(--accent)" /> : <X size={13} color="var(--text-mute)" />}
                          <span className="mono" style={{ color: s.configured ? "var(--text)" : "var(--text-dim)" }}>{s.label}</span>
                          <a href={s.docs} target="_blank" rel="noreferrer" style={{ color: "var(--text-mute)" }} title="Docs">
                            <ExternalLink size={11} />
                          </a>
                        </div>
                      </Td>
                      <Td>
                        <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                          {s.supports.map((t) => (
                            <span key={t} className="badge neutral">{t}</span>
                          ))}
                        </div>
                      </Td>
                      <Td>
                        <span className="mono" style={{ fontSize: 11, color: s.configured ? "var(--accent)" : "var(--text-mute)" }}>
                          {s.configured ? s.masked_key : "— not configured —"}
                        </span>
                      </Td>
                      <Td>
                        <input
                          className="nvx-input"
                          type="password"
                          placeholder="paste key"
                          value={keys[s.id] || ""}
                          onChange={(e) => setKeys({ ...keys, [s.id]: e.target.value })}
                          data-testid={`osint-input-${s.id}`}
                          style={{ minWidth: 180 }}
                        />
                      </Td>
                      <Td>
                        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                          <button
                            className="nvx-btn sm"
                            onClick={() => test(s.id)}
                            disabled={!s.configured || testing[s.id]}
                            data-testid={`osint-test-${s.id}`}
                            title="Test key against the service"
                          >
                            <TestTube2 size={11} /> {testing[s.id] ? "…" : "TEST"}
                          </button>
                          {s.configured && (
                            <button className="nvx-btn sm ghost warn" onClick={() => remove(s.id)} title="Remove key">
                              REMOVE
                            </button>
                          )}
                          {tr && (
                            <span className="mono" style={{ fontSize: 10, color: tr.ok ? "var(--accent)" : "var(--high)" }}>
                              {tr.ok ? `OK (${tr.status_code})` : `FAIL${tr.status_code ? ` (${tr.status_code})` : ""}`}
                            </span>
                          )}
                        </div>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* Docs Explain feedback (👍/👎 signal from the docs assistant) */}
        <DocsFeedbackPanel />

        {/* Users */}
        <section className="brut-border" style={{ background: "var(--surface)" }}>
          <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>▸ USERS</div>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)" }}>
                <Th>EMAIL</Th><Th>ROLE</Th><Th>CREATED</Th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.email} style={{ borderBottom: "1px solid var(--border)" }} data-testid={`user-row-${u.email}`}>
                  <Td>{u.email}</Td>
                  <Td><span className="badge">{u.role}</span></Td>
                  <Td>{u.created_at?.slice(0, 19).replace("T", " ")}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}

function StatCard({ label, value, icon }) {
  return (
    <div className="brut-border" style={{ padding: 14, background: "var(--surface)" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span className="mono" style={{ fontSize: 10, letterSpacing: "0.2em", color: "var(--warn)" }}>{label}</span>
        <span style={{ color: "var(--accent)" }}>{icon}</span>
      </div>
      <div style={{ fontFamily: "Chivo", fontWeight: 900, fontSize: 32, color: "var(--text)", marginTop: 6 }}>{value}</div>
    </div>
  );
}

function Th({ children }) {
  return <th className="mono" style={{ textAlign: "left", padding: "8px 12px", fontSize: 10, letterSpacing: "0.16em", color: "var(--text-mute)", fontWeight: 700 }}>{children}</th>;
}

function Td({ children }) {
  return <td className="mono" style={{ padding: "10px 12px", fontSize: 11, color: "var(--text)", verticalAlign: "middle" }}>{children}</td>;
}
