/**
 * XdrIocIntelPage · `/xdr/intelligence/iocs`
 *
 * Wires the EXISTING NivXRay IOC enrichment fabric into NivXRay XDR:
 *   /api/ioc/health      → per-provider live/absent state and the env var
 *                          that governs it
 *   /api/ioc/enrich/one  → on-demand enrichment {kind, value, use_cache}
 *   /api/threat-intel/lookup/{value} → stored-indicator lookup
 *
 * This is also the destination of the incident record's IOC evidence pointer
 * (`deep_link` /xdr/intelligence/iocs?incident_id=…&tenant=…), so the
 * incident reference is displayed rather than silently dropped.
 *
 * PROVENANCE RULE: enrichment output is rendered as the provider returned it.
 * No verdict is synthesised here, and a response with no provider attribution
 * is labelled PROVENANCE MISSING rather than shown as a finding.
 */
import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Globe, RefreshCcw, Zap } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";

const KINDS = ["ip", "domain", "url", "sha256", "md5", "sha1"];

function guessKind(v) {
  const s = String(v || "").trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "ip";
  if (/^https?:\/\//i.test(s)) return "url";
  if (/^[a-f0-9]{64}$/i.test(s)) return "sha256";
  if (/^[a-f0-9]{40}$/i.test(s)) return "sha1";
  if (/^[a-f0-9]{32}$/i.test(s)) return "md5";
  if (/\./.test(s)) return "domain";
  return "ip";
}

export default function XdrIocIntelPage() {
  const [params] = useSearchParams();
  const incidentId = params.get("incident_id");

  const [health, setHealth] = useState(null);
  const [err, setErr]       = useState(null);
  const [tick, setTick]     = useState(0);

  const [value, setValue]   = useState(params.get("q") || "");
  const [kind, setKind]     = useState(guessKind(params.get("q") || ""));
  const [result, setResult] = useState(null);
  const [running, setRun]   = useState(false);
  const [runErr, setRunErr] = useState(null);

  useEffect(() => {
    let dead = false;
    (async () => {
      setErr(null);
      try {
        const r = await api.get("/ioc/health");
        if (!dead) setHealth(r?.data || null);
      } catch (x) {
        if (!dead) setErr(x?.response?.data?.detail || x?.message || "load failed");
      }
    })();
    return () => { dead = true; };
  }, [tick]);

  const enrich = async (e) => {
    e?.preventDefault?.();
    if (!value.trim()) return;
    setRun(true); setRunErr(null); setResult(null);
    try {
      const r = await api.post("/ioc/enrich/one",
        { kind, value: value.trim(), use_cache: true });
      setResult(r?.data || null);
    } catch (x) {
      setRunErr(x?.response?.data?.detail || x?.message || "enrichment failed");
    } finally { setRun(false); }
  };

  const providers = health?.providers || [];
  const live = providers.filter((p) => p.state === "live");

  return (
    <XdrShell>
      <div data-testid="xdr-ioc-intel-page">
        <div style={head}>
          <Globe size={16} />
          <h1 className="page-h1" style={{ margin: 0 }}>IOC Intelligence</h1>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" data-testid="xdr-ioc-refresh"
                  onClick={() => setTick((n) => n + 1)}
                  style={{ padding: "6px 12px", fontSize: 12 }}>
            <RefreshCcw size={12} /> Refresh
          </button>
        </div>
        <div style={sub}>
          On-demand observable enrichment through the NivXRay enrichment
          fabric. Provider state below is read from the service, including the
          environment variable that governs each provider.
        </div>

        {incidentId && (
          <div style={ctxBox} data-testid="xdr-ioc-incident-context">
            Arrived from incident <b>{incidentId}</b>. Per-incident indicator
            correlation is not wired yet — this surface enriches an observable
            you supply.
          </div>
        )}

        {err && <div style={errBox} data-testid="xdr-ioc-error">{err}</div>}

        <div style={grid3}>
          <Stat label="Providers live"
                value={providers.length ? `${live.length} of ${providers.length}` : "—"}
                testid="xdr-ioc-stat-live" />
          <Stat label="Cache" value={health?.cache?.state || health?.cache || "—"}
                testid="xdr-ioc-stat-cache" />
          <Stat label="Service" value={health?.state || (providers.length ? "reachable" : "—")}
                testid="xdr-ioc-stat-state" />
        </div>

        <div style={{ ...panel, marginTop: 10 }}>
          <div style={panelH}>Providers</div>
          <div style={{ ...row, ...rowH, gridTemplateColumns: cols }}>
            <div>Provider</div><div>State</div><div>Credential</div><div>Detail</div>
          </div>
          {providers.map((p) => (
            <div key={p.provider} style={{ ...row, gridTemplateColumns: cols }}
                 data-testid={`xdr-ioc-provider-${p.provider}`}
                 data-state={p.state}>
              <div>{p.provider}</div>
              <div className="mono" style={{ fontSize: 10,
                                              color: p.state === "live"
                                                ? "var(--nx-ok, #2f9e44)"
                                                : "var(--faint)" }}>
                {String(p.state || "").toUpperCase()}
              </div>
              <div className="mono" style={{ fontSize: 10 }}>{p.env || "—"}</div>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
                {p.detail || "—"}
              </div>
            </div>
          ))}
          {providers.length === 0 && (
            <div style={empty} data-testid="xdr-ioc-providers-empty">
              /api/ioc/health returned no providers
            </div>
          )}
        </div>

        <form style={{ ...panel, marginTop: 10 }} onSubmit={enrich}>
          <div style={panelH}>Enrich an observable</div>
          <div style={{ display: "flex", gap: 6, padding: "8px 10px" }}>
            <select value={kind} onChange={(e) => setKind(e.target.value)}
                    data-testid="xdr-ioc-kind"
                    style={{ ...input, flex: "0 0 120px" }}>
              {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
            <input value={value}
                   onChange={(e) => {
                     setValue(e.target.value);
                     setKind(guessKind(e.target.value));
                   }}
                   placeholder="8.8.8.8 · evil.example.com · sha256…"
                   data-testid="xdr-ioc-value" style={input} />
            <button type="submit" className="btn primary" disabled={running}
                    data-testid="xdr-ioc-enrich"
                    style={{ fontSize: 11, opacity: running ? 0.5 : 1 }}>
              <Zap size={12} /> {running ? "Enriching…" : "Enrich"}
            </button>
          </div>
          {runErr && (
            <div style={{ ...errBox, margin: "0 10px 10px" }}
                 data-testid="xdr-ioc-enrich-error">{runErr}</div>
          )}
          {result && (
            <div style={{ padding: "0 10px 10px" }} data-testid="xdr-ioc-result">
              <div className="mono" style={{ fontSize: 10, marginBottom: 6,
                                              color: "var(--faint)" }}>
                {hasProvenance(result)
                  ? "Provider response · rendered verbatim"
                  : "PROVENANCE MISSING — no provider attribution in this "
                    + "response, so it is shown as raw output, not a verdict"}
              </div>
              <pre style={pre}>{JSON.stringify(result, null, 2)}</pre>
            </div>
          )}
        </form>
      </div>
    </XdrShell>
  );
}

function hasProvenance(r) {
  if (!r || typeof r !== "object") return false;
  return ["providers", "provider", "sources", "source", "results"]
    .some((k) => r[k] !== undefined && r[k] !== null);
}

function Stat({ label, value, testid }) {
  return (
    <div data-testid={testid} style={statCard}>
      <div style={statLabel}>{label}</div>
      <div style={statValue}>{String(value)}</div>
    </div>
  );
}

const head = { display: "flex", alignItems: "center", gap: 10, marginBottom: 6 };
const sub = { color: "var(--text-dim)", fontSize: 12, marginBottom: 12,
              maxWidth: 760, lineHeight: 1.6 };
const grid3 = { display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 };
const panel = { border: "1px solid var(--border)", borderRadius: 3,
                overflow: "hidden" };
const panelH = { padding: "7px 10px", fontSize: 10, fontWeight: 800,
                 letterSpacing: ".4px", textTransform: "uppercase",
                 color: "var(--faint)", borderBottom: "1px solid var(--border)" };
const cols = "1fr .6fr 1fr 2fr";
const row = { display: "grid", gap: 8, padding: "6px 10px", fontSize: 11.5,
              borderBottom: "1px solid var(--border)", alignItems: "center" };
const rowH = { fontSize: 9.5, fontWeight: 800, letterSpacing: ".4px",
               textTransform: "uppercase", color: "var(--faint)" };
const empty = { padding: "10px", fontSize: 11, color: "var(--faint)",
                fontFamily: "var(--mono)" };
const input = { flex: 1, padding: "5px 8px", fontSize: 12 };
const pre = { background: "var(--panel2, rgba(0,0,0,.04))", padding: 10,
              borderRadius: 3, overflow: "auto", fontSize: 11,
              whiteSpace: "pre-wrap", maxHeight: "46vh" };
const statCard = { border: "1px solid var(--border)", borderRadius: 3,
                   padding: "10px 12px" };
const statLabel = { fontSize: 9.5, fontWeight: 800, letterSpacing: ".4px",
                    textTransform: "uppercase", color: "var(--faint)" };
const statValue = { fontSize: 22, fontWeight: 700, marginTop: 4 };
const ctxBox = { border: "1px solid var(--border)", borderRadius: 3,
                 padding: "8px 10px", fontSize: 11.5, marginBottom: 10,
                 lineHeight: 1.6 };
const errBox = { border: "1px solid var(--nx-danger, #d64545)", borderRadius: 3,
                 padding: "8px 10px", fontSize: 11, marginBottom: 10,
                 fontFamily: "var(--mono)" };
