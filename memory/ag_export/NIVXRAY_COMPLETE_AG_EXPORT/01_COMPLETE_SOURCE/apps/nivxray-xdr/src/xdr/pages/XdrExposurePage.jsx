/**
 * XdrExposurePage — CVE / Vulnerability Intelligence & Exposure pillar.
 *
 * Reads `/api/xdr/cve/*` — the authoritative CVE pillar.  Renders:
 *   • Pillar status  (total CVEs · KEV · CVSS · asset / software counts)
 *   • Exposure state machine (6 states) with current per-state counts
 *   • CVE catalog with KEV / EPSS / CVSS filters
 *   • Asset + software minimal inventory management
 *   • Recompute exposures
 *
 * CRITICAL SEMANTIC: CVE ≠ vulnerable ≠ exploitable ≠ exploited
 * ≠ compromised.  The UI never claims a higher state without
 * explicit evidence bucket present in the exposure record.
 */
import React, { useEffect, useMemo, useState } from "react";
import { ShieldAlert, RefreshCcw, Search, Server, Package,
                Zap, AlertTriangle, CheckCircle2 } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";


const EXPOSURE_STATES = [
  "CVE_PRESENT",
  "AFFECTED_SOFTWARE",
  "VULNERABLE_ASSET",
  "EXPLOITABLE",
  "EXPLOITATION_OBSERVED",
  "COMPROMISE_EVIDENCE",
];
const STATE_COLOR = {
  CVE_PRESENT:           "var(--faint)",
  AFFECTED_SOFTWARE:     "#38bdf8",
  VULNERABLE_ASSET:      "var(--amber)",
  EXPLOITABLE:           "#f97316",
  EXPLOITATION_OBSERVED: "#f87171",
  COMPROMISE_EVIDENCE:   "#ef4444",
};


export default function XdrExposurePage() {
  const [status,    setStatus]    = useState(null);
  const [cves,      setCves]      = useState([]);
  const [assets,    setAssets]    = useState([]);
  const [software,  setSoftware]  = useState([]);
  const [exposures, setExposures] = useState([]);
  const [busy,      setBusy]      = useState(false);
  const [computing, setComputing] = useState(false);
  const [err,       setErr]       = useState(null);
  const [tab,       setTab]       = useState("catalog");
  const [q,         setQ]         = useState("");
  const [kev,       setKev]       = useState(false);
  const [severity,  setSeverity]  = useState("");
  const [refresh,   setRefresh]   = useState(0);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [s, c, a, sw, e] = await Promise.all([
          api.get("/xdr/cve/status"),
          api.get("/xdr/cve/list", { params: { limit: 500,
              q: q || undefined,
              kev: kev ? true : undefined,
              severity: severity || undefined } }),
          api.get("/xdr/cve/assets"),
          api.get("/xdr/cve/software"),
          api.get("/xdr/cve/exposures", { params: { limit: 500 } }),
        ]);
        if (cancelled) return;
        setStatus(s?.data?.data || null);
        setCves(c?.data?.data?.cves || []);
        setAssets(a?.data?.data?.assets || []);
        setSoftware(sw?.data?.data?.software || []);
        setExposures(e?.data?.data?.exposures || []);
      } catch (x) {
        setErr(x?.response?.data?.detail || x?.message || "load failed");
      } finally { if (!cancelled) setBusy(false); }
    })();
    return () => { cancelled = true; };
  }, [refresh, q, kev, severity]);

  const computeExposures = async () => {
    setComputing(true);
    try {
      await api.post("/xdr/cve/exposures/compute");
      setRefresh((n) => n + 1);
    } catch (x) {
      setErr(x?.response?.data?.detail || x?.message);
    } finally { setComputing(false); }
  };

  const exposureCounts = useMemo(() => {
    const c = Object.fromEntries(EXPOSURE_STATES.map((s) => [s, 0]));
    exposures.forEach((e) => { c[e.state] = (c[e.state] || 0) + 1; });
    return c;
  }, [exposures]);

  const [assetForm, setAssetForm]   = useState({ name: "", kind: "endpoint" });
  const [swForm, setSwForm]         = useState({ asset_id: "", vendor: "",
                                                                        product: "", version: "",
                                                                        patched: false });

  const createAsset = async () => {
    if (!assetForm.name) return;
    try {
      await api.post("/xdr/cve/assets", assetForm);
      setAssetForm({ name: "", kind: "endpoint" });
      setRefresh((n) => n + 1);
    } catch (x) { setErr(x?.response?.data?.detail || x?.message); }
  };
  const createSoftware = async () => {
    if (!swForm.asset_id || !swForm.vendor || !swForm.product) return;
    try {
      await api.post("/xdr/cve/software", swForm);
      setSwForm({ asset_id: "", vendor: "", product: "", version: "",
                            patched: false });
      setRefresh((n) => n + 1);
    } catch (x) { setErr(x?.response?.data?.detail || x?.message); }
  };

  const s = status || {};

  return (
    <XdrShell>
      <div data-testid="xdr-exposure-page">
        <div style={{ display: "flex", alignItems: "center", gap: 10,
                                marginBottom: 6 }}>
          <ShieldAlert size={16} style={{ color: "var(--cyan)" }} />
          <h1 className="page-h1" style={{ margin: 0 }}>Vulnerability Exposure</h1>
          <span style={{ padding: "1px 6px", border: "1px solid var(--cyan)",
                                  color: "var(--cyan)", borderRadius: 2, fontSize: 9.5,
                                  fontFamily: "var(--mono)", fontWeight: 700 }}>
            NVD · CISA KEV · EPSS · CVSS · CPE
          </span>
          <span style={{ flex: 1 }} />
          <button className="btn" onClick={computeExposures}
                        disabled={computing || busy}
                        data-testid="xdr-cve-compute-btn"
                        style={{ padding: "3px 10px", fontSize: 11,
                                        opacity: (computing || busy) ? 0.5 : 1 }}>
            <Zap size={11} /> {computing ? "Computing…" : "Recompute exposures"}
          </button>
          <button className="btn ghost" onClick={() => setRefresh((n) => n + 1)}
                        disabled={busy} data-testid="xdr-cve-refresh"
                        style={{ padding: "3px 10px", fontSize: 11,
                                        opacity: busy ? 0.5 : 1 }}>
            <RefreshCcw size={11}
                                    style={{ animation: busy ? "spin 0.8s linear infinite"
                                                                            : "none" }} /> {busy ? "Loading…" : "Refresh"}
          </button>
        </div>
        <div className="page-sub" style={{ marginBottom: 12 }}>
          CVE ≠ vulnerable asset ≠ exploitable ≠ exploited ≠ compromised.
          Each state requires its own evidence.  NivXRay never infers
          upward without explicit evidence buckets.
        </div>

        {/* Pillar stats */}
        <div style={statsGrid}>
          <Stat label="CVEs"          value={s.total_cves ?? "—"}
                    testid="cve-stat-total" />
          <Stat label="KEV listed"    value={s.kev_listed ?? "—"}
                    testid="cve-stat-kev" color="#f97316" />
          <Stat label="CVSS Critical" value={s.cvss_critical ?? "—"}
                    testid="cve-stat-critical" color="#ef4444" />
          <Stat label="CVSS High"     value={s.cvss_high ?? "—"}
                    testid="cve-stat-high" color="var(--amber)" />
          <Stat label="Assets"        value={s.assets_registered ?? "—"}
                    testid="cve-stat-assets" color="var(--cyan)" />
          <Stat label="Software rows" value={s.software_rows ?? "—"}
                    testid="cve-stat-software" />
          <Stat label="Exposures"     value={s.exposures_computed ?? "—"}
                    testid="cve-stat-exposures" color="var(--mint)" />
        </div>

        {/* State machine strip */}
        <div style={{ padding: 10, background: "var(--panel2)",
                                border: "1px solid var(--border)", borderRadius: 3,
                                marginBottom: 14 }}
                  data-testid="xdr-exposure-state-strip">
          <div style={{ fontFamily: "var(--mono)", fontSize: 10,
                                  fontWeight: 700, color: "var(--faint)",
                                  textTransform: "uppercase", marginBottom: 8 }}>
            Exposure State Machine (evidence-gated · never inferred)
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6,
                                  flexWrap: "wrap" }}>
            {EXPOSURE_STATES.map((state, i) => (
              <React.Fragment key={state}>
                <div style={{ padding: "5px 10px", borderRadius: 3,
                                        border: `1px solid ${STATE_COLOR[state]}`,
                                        color: STATE_COLOR[state],
                                        fontFamily: "var(--mono)", fontSize: 10,
                                        fontWeight: 700, letterSpacing: ".3px" }}
                            data-testid={`xdr-exposure-state-${state}`}>
                  {state.replace(/_/g, " ")} · {exposureCounts[state]}
                </div>
                {i < EXPOSURE_STATES.length - 1 && (
                  <span style={{ color: "var(--faint)" }}>→</span>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {err && <div style={errBox} data-testid="xdr-cve-error">{err}</div>}

        {/* Tabs */}
        <div style={{ display: "flex", gap: 4, marginBottom: 8 }}>
          <TabBtn active={tab === "catalog"} onClick={() => setTab("catalog")}
                        testid="cve-tab-catalog">CVE Catalog · {cves.length}</TabBtn>
          <TabBtn active={tab === "exposures"} onClick={() => setTab("exposures")}
                        testid="cve-tab-exposures">Exposures · {exposures.length}</TabBtn>
          <TabBtn active={tab === "assets"} onClick={() => setTab("assets")}
                        testid="cve-tab-assets">Assets · {assets.length}</TabBtn>
          <TabBtn active={tab === "software"} onClick={() => setTab("software")}
                        testid="cve-tab-software">Software · {software.length}</TabBtn>
        </div>

        {tab === "catalog" && (
          <>
            <div style={{ display: "flex", gap: 6, marginBottom: 8,
                                    alignItems: "center" }}>
              <Search size={12} style={{ color: "var(--faint)" }} />
              <input value={q} onChange={(e) => setQ(e.target.value)}
                           placeholder="CVE-ID / description…"
                           data-testid="cve-search"
                           style={inputStyle} />
              <label style={filterLabel}>
                <input type="checkbox" checked={kev}
                            onChange={(e) => setKev(e.target.checked)}
                            data-testid="cve-filter-kev" /> KEV only
              </label>
              <select value={severity}
                             onChange={(e) => setSeverity(e.target.value)}
                             data-testid="cve-filter-severity"
                             style={selectStyle}>
                <option value="">Any severity</option>
                <option>CRITICAL</option>
                <option>HIGH</option>
                <option>MEDIUM</option>
                <option>LOW</option>
              </select>
            </div>
            <CveTable cves={cves} />
          </>
        )}

        {tab === "exposures" && <ExposureTable rows={exposures} />}

        {tab === "assets" && (
          <AssetPanel assets={assets} form={assetForm}
                                  onChange={setAssetForm} onCreate={createAsset} />
        )}

        {tab === "software" && (
          <SoftwarePanel software={software} assets={assets}
                                          form={swForm} onChange={setSwForm}
                                          onCreate={createSoftware} />
        )}
      </div>
    </XdrShell>
  );
}


function CveTable({ cves }) {
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                            overflow: "hidden" }}>
      <div style={rowHeadCve}>
        <div>CVE ID</div><div>Severity</div><div>KEV</div><div>EPSS</div>
        <div>ATT&CK</div><div>Description</div>
      </div>
      {cves.map((c) => (
        <div key={c.cve_id} style={rowBodyCve}
                   data-testid={`cve-row-${c.cve_id}`}>
          <div style={{ color: "var(--cyan)" }}>{c.cve_id}</div>
          <div style={{ color: STATE_COLOR[
              c.cvss_v3?.severity === "CRITICAL" ? "COMPROMISE_EVIDENCE"
                  : c.cvss_v3?.severity === "HIGH" ? "EXPLOITABLE"
                  : "AFFECTED_SOFTWARE"] }}>
            {c.cvss_v3?.severity || "—"} · {c.cvss_v3?.baseScore ?? "—"}
          </div>
          <div style={{ color: c.kev?.listed ? "#f97316" : "var(--faint)" }}>
            {c.kev?.listed ? "LISTED" : "no"}
          </div>
          <div>{c.epss?.score
              ? (c.epss.score * 100).toFixed(1) + "%"
              : "—"}</div>
          <div style={{ color: "var(--amber)", fontSize: 10 }}>
            {(c.attack_techniques || []).slice(0, 3).join(", ") || "—"}
          </div>
          <div style={{ color: "var(--text-dim)", fontSize: 10 }}>
            {(c.description || "").slice(0, 90)}…
          </div>
        </div>
      ))}
      {cves.length === 0 && <div style={emptyRow}>NO CVEs — sync the pillar</div>}
    </div>
  );
}


function ExposureTable({ rows }) {
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                            overflow: "hidden" }}>
      <div style={rowHeadExp}>
        <div>Asset</div><div>CVE</div><div>State</div>
        <div>Evidence</div><div>KEV</div><div>EPSS</div>
      </div>
      {rows.map((e) => (
        <div key={e.id} style={rowBodyExp}
                   data-testid={`exposure-row-${e.id}`}>
          <div style={{ color: "var(--cyan)" }}>{e.asset_name}</div>
          <div>{e.cve_id}</div>
          <div>
            <span style={{ padding: "1px 6px",
                                    border: `1px solid ${STATE_COLOR[e.state]}`,
                                    color: STATE_COLOR[e.state], borderRadius: 2,
                                    fontSize: 9.5, fontWeight: 700,
                                    fontFamily: "var(--mono)" }}>
              {e.state}
            </span>
          </div>
          <div style={{ color: "var(--faint)", fontSize: 10 }}>
            {Object.keys(e.evidence || {}).join(" + ") || "—"}
          </div>
          <div style={{ color: e.kev?.listed ? "#f97316" : "var(--faint)" }}>
            {e.kev?.listed ? "yes" : "no"}
          </div>
          <div>{e.epss?.score
              ? (e.epss.score * 100).toFixed(1) + "%"
              : "—"}</div>
        </div>
      ))}
      {rows.length === 0 && <div style={emptyRow}>NO EXPOSURES — register assets + software then Recompute</div>}
    </div>
  );
}


function AssetPanel({ assets, form, onChange, onCreate }) {
  return (
    <div>
      <div style={inlineForm}>
        <Server size={12} />
        <input placeholder="Asset name"
                     value={form.name}
                     onChange={(e) => onChange({ ...form, name: e.target.value })}
                     data-testid="cve-asset-name" style={inputStyleSm} />
        <select value={form.kind}
                     onChange={(e) => onChange({ ...form, kind: e.target.value })}
                     data-testid="cve-asset-kind" style={selectStyle}>
          <option>endpoint</option><option>server</option>
          <option>appliance</option><option>cloud</option>
        </select>
        <button className="btn" onClick={onCreate}
                      data-testid="cve-asset-create"
                      style={{ padding: "3px 10px", fontSize: 11 }}>Register asset</button>
      </div>
      <div style={{ marginTop: 10, border: "1px solid var(--border)",
                            borderRadius: 3, overflow: "hidden" }}>
        <div style={rowHeadSm}>
          <div>Name</div><div>Kind</div><div>OS</div><div>Reachable</div><div>ID</div>
        </div>
        {assets.map((a) => (
          <div key={a.id} style={rowBodySm}
                     data-testid={`cve-asset-${a.id}`}>
            <div style={{ color: "var(--cyan)" }}>{a.name}</div>
            <div>{a.kind}</div>
            <div>{a.os || "—"}</div>
            <div>{a.network_reachable ? "yes" : "no"}</div>
            <div style={{ color: "var(--faint)", fontSize: 10 }}>{a.id}</div>
          </div>
        ))}
        {assets.length === 0 && <div style={emptyRow}>NO ASSETS — register one to compute exposures</div>}
      </div>
    </div>
  );
}


function SoftwarePanel({ software, assets, form, onChange, onCreate }) {
  return (
    <div>
      <div style={inlineForm}>
        <Package size={12} />
        <select value={form.asset_id}
                     onChange={(e) => onChange({ ...form, asset_id: e.target.value })}
                     data-testid="cve-sw-asset" style={selectStyle}>
          <option value="">— pick asset —</option>
          {assets.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </select>
        <input placeholder="vendor"
                     value={form.vendor}
                     onChange={(e) => onChange({ ...form, vendor: e.target.value })}
                     data-testid="cve-sw-vendor" style={inputStyleSm} />
        <input placeholder="product"
                     value={form.product}
                     onChange={(e) => onChange({ ...form, product: e.target.value })}
                     data-testid="cve-sw-product" style={inputStyleSm} />
        <input placeholder="version"
                     value={form.version}
                     onChange={(e) => onChange({ ...form, version: e.target.value })}
                     data-testid="cve-sw-version" style={inputStyleSm} />
        <label style={filterLabel}>
          <input type="checkbox" checked={form.patched}
                      onChange={(e) => onChange({ ...form, patched: e.target.checked })}
                      data-testid="cve-sw-patched" /> patched
        </label>
        <button className="btn" onClick={onCreate}
                      data-testid="cve-sw-create"
                      style={{ padding: "3px 10px", fontSize: 11 }}>Add software</button>
      </div>
      <div style={{ marginTop: 10, border: "1px solid var(--border)",
                            borderRadius: 3, overflow: "hidden" }}>
        <div style={rowHeadSm}>
          <div>Vendor</div><div>Product</div><div>Version</div><div>Patched</div><div>Asset</div>
        </div>
        {software.map((s) => (
          <div key={s.id} style={rowBodySm}
                     data-testid={`cve-sw-${s.id}`}>
            <div>{s.vendor}</div><div>{s.product}</div>
            <div>{s.version || "—"}</div>
            <div style={{ color: s.patched ? "var(--mint)" : "var(--amber)" }}>
              {s.patched ? <CheckCircle2 size={11} /> : <AlertTriangle size={11} />}
              {" "}{s.patched ? "yes" : "no"}
            </div>
            <div style={{ color: "var(--faint)", fontSize: 10 }}>{s.asset_id}</div>
          </div>
        ))}
        {software.length === 0 && <div style={emptyRow}>NO SOFTWARE — add rows to correlate with CVEs</div>}
      </div>
    </div>
  );
}


function TabBtn({ active, onClick, testid, children }) {
  return (
    <button data-testid={testid} onClick={onClick}
                 className={active ? "btn" : "btn ghost"}
                 style={{ padding: "3px 10px", fontSize: 11 }}>{children}</button>
  );
}


function Stat({ label, value, testid, color }) {
  return (
    <div data-testid={testid} style={statCard}>
      <div style={statLabel}>{label}</div>
      <div style={{ ...statValue, color: color || "var(--text)" }}>{value}</div>
    </div>
  );
}


const statsGrid = { display: "grid",
                                    gridTemplateColumns: "repeat(7, 1fr)",
                                    gap: 6, marginBottom: 14 };
const statCard = { padding: 8, border: "1px solid var(--border)",
                                   borderRadius: 3, background: "var(--panel2)" };
const statLabel = { fontSize: 9, fontFamily: "var(--mono)",
                                     color: "var(--faint)", textTransform: "uppercase",
                                     letterSpacing: ".3px", fontWeight: 700,
                                     marginBottom: 4 };
const statValue = { fontSize: 18, fontWeight: 700, fontFamily: "var(--mono)" };
const inputStyle = { flex: 1, padding: "4px 8px",
                                     background: "var(--panel2)",
                                     border: "1px solid var(--border)",
                                     color: "var(--text)", fontSize: 11,
                                     borderRadius: 3, fontFamily: "var(--mono)" };
const inputStyleSm = { ...inputStyle, flex: "0 0 auto", width: 130 };
const selectStyle = { padding: "4px 6px", background: "var(--panel2)",
                                     border: "1px solid var(--border)",
                                     color: "var(--text)", fontSize: 11,
                                     borderRadius: 3, fontFamily: "var(--mono)" };
const filterLabel = { display: "inline-flex", alignItems: "center",
                                     gap: 4, fontSize: 11, fontFamily: "var(--mono)",
                                     color: "var(--text-dim)" };
const rowHeadCve = { display: "grid",
                                    gridTemplateColumns: "1.2fr 1fr 0.6fr 0.6fr 1.4fr 3fr",
                                    gap: 6, padding: "5px 10px",
                                    background: "var(--panel2)", fontSize: 10,
                                    color: "var(--faint)", textTransform: "uppercase",
                                    fontFamily: "var(--mono)", fontWeight: 700 };
const rowBodyCve = { display: "grid",
                                    gridTemplateColumns: "1.2fr 1fr 0.6fr 0.6fr 1.4fr 3fr",
                                    gap: 6, padding: "6px 10px", fontSize: 11,
                                    color: "var(--text-dim)",
                                    borderTop: "1px solid var(--border)",
                                    fontFamily: "var(--mono)" };
const rowHeadExp = { display: "grid",
                                    gridTemplateColumns: "1.4fr 1fr 1.4fr 1.6fr 0.6fr 0.6fr",
                                    gap: 6, padding: "5px 10px",
                                    background: "var(--panel2)", fontSize: 10,
                                    color: "var(--faint)", textTransform: "uppercase",
                                    fontFamily: "var(--mono)", fontWeight: 700 };
const rowBodyExp = { display: "grid",
                                    gridTemplateColumns: "1.4fr 1fr 1.4fr 1.6fr 0.6fr 0.6fr",
                                    gap: 6, padding: "6px 10px", fontSize: 11,
                                    color: "var(--text-dim)",
                                    borderTop: "1px solid var(--border)",
                                    fontFamily: "var(--mono)" };
const rowHeadSm = { display: "grid",
                                  gridTemplateColumns: "1.2fr 1.2fr 1fr 0.8fr 2fr",
                                  gap: 6, padding: "5px 10px",
                                  background: "var(--panel2)", fontSize: 10,
                                  color: "var(--faint)", textTransform: "uppercase",
                                  fontFamily: "var(--mono)", fontWeight: 700 };
const rowBodySm = { display: "grid",
                                  gridTemplateColumns: "1.2fr 1.2fr 1fr 0.8fr 2fr",
                                  gap: 6, padding: "6px 10px", fontSize: 11,
                                  color: "var(--text-dim)",
                                  borderTop: "1px solid var(--border)",
                                  fontFamily: "var(--mono)" };
const emptyRow = { padding: 12, fontSize: 11, color: "var(--faint)",
                                  fontFamily: "var(--mono)" };
const errBox = { padding: "6px 10px", border: "1px solid var(--amber)",
                             color: "var(--amber)", fontSize: 11,
                             fontFamily: "var(--mono)", borderRadius: 3,
                             marginBottom: 8 };
const inlineForm = { display: "flex", alignItems: "center", gap: 6,
                                       padding: 10, background: "var(--panel2)",
                                       border: "1px solid var(--border)",
                                       borderRadius: 3 };
