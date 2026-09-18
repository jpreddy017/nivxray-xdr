/**
 * XdrIocIntelPage · `/xdr/intelligence/iocs`  (B4 · nx modernization)
 *
 * Wires the EXISTING NivXRay IOC enrichment fabric into NivXRay XDR:
 *   /api/ioc/health      → per-provider live/absent state and the env var
 *                          that governs it
 *   /api/ioc/enrich/one  → on-demand enrichment {kind, value, use_cache}
 *
 * This is also the destination of the incident record's IOC evidence pointer
 * (`deep_link` /xdr/intelligence/iocs?incident_id=…&tenant=…), so the
 * incident reference is displayed rather than silently dropped.
 *
 * PROVENANCE RULE: enrichment output is rendered as the provider returned it.
 * No verdict is synthesised here, and a response with no provider attribution
 * is labelled PROVENANCE MISSING rather than shown as a finding.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Globe, RefreshCcw, Zap } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvValue, NxInvMetrics,
  ABSENCE,
} from "@/xdr/nx";
import "@/xdr/nx/nx-inv.css";
import "@/xdr/nx/nx-workspace.css";

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

function hasProvenance(r) {
  if (!r || typeof r !== "object") return false;
  return ["providers", "provider", "sources", "source", "results"]
    .some((k) => r[k] !== undefined && r[k] !== null);
}

/** Per-provider rows out of whatever shape the fabric returned — never
 *  invented, never merged into a single verdict. */
function providerRows(result) {
  if (!result || typeof result !== "object") return [];
  const out = [];
  const push = (name, payload) => out.push({ provider: name, payload });
  if (Array.isArray(result.providers)) {
    result.providers.forEach((p, i) => push(p.provider || p.name || `#${i}`, p));
  } else if (result.providers && typeof result.providers === "object") {
    Object.entries(result.providers).forEach(([k, v]) => push(k, v));
  } else if (result.results && typeof result.results === "object") {
    Object.entries(result.results).forEach(([k, v]) => push(k, v));
  } else if (result.provider) {
    push(result.provider, result);
  }
  return out;
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
  const [sel, setSel]       = useState(null);
  const [paneTab, setPaneTab] = useState("details");

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
    setRun(true); setRunErr(null); setResult(null); setSel(null);
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
  const answered = useMemo(() => providerRows(result), [result]);
  const selected = useMemo(() => answered.find(
    (a) => a.provider === sel) || null, [answered, sel]);

  return (
    <XdrShell>
      <div className="inv" data-testid="xdr-ioc-intel-page"
           style={{ padding: "12px 16px 24px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10,
                      marginBottom: 10, flexWrap: "wrap" }}>
          <Globe size={16} style={{ alignSelf: "center" }} />
          <h1 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}>
            IOC Intelligence
          </h1>
          <span style={{ fontSize: 11, color: "var(--nx-muted, var(--muted))",
                         maxWidth: 700, lineHeight: 1.6 }}>
            On-demand observable enrichment through the NivXRay enrichment
            fabric. Provider state is read from the service, including the
            environment variable that governs each provider.
          </span>
          <button className="inv-chip" style={{ marginLeft: "auto" }}
                  data-testid="xdr-ioc-refresh"
                  onClick={() => setTick((n) => n + 1)}>
            <RefreshCcw size={11} /> Refresh
          </button>
        </div>

        {incidentId && (
          <NxInvEmpty testid="xdr-ioc-incident-context"
            title={`Arrived from incident ${incidentId}`}
            body="Per-incident indicator correlation is not wired yet — this surface enriches an observable you supply." />
        )}

        {err && (
          <NxInvEmpty testid="xdr-ioc-error"
            title={`${ABSENCE.ERROR} — the enrichment fabric could not be read`}
            body={typeof err === "object" ? JSON.stringify(err) : String(err)} />
        )}

        <NxInvSection title="Enrichment fabric"
                      subtitle="capability is read from the service, never assumed"
                      testid="xdr-ioc-summary">
          <NxInvMetrics testid="xdr-ioc-stat" items={[
            { key: "live", label: "Providers live",
              value: providers.length
                ? `${live.length} of ${providers.length}` : null,
              absent: ABSENCE.NOT_AVAILABLE },
            { key: "cache", label: "Cache",
              value: health?.cache?.state || (typeof health?.cache === "string"
                ? health.cache : null),
              absent: ABSENCE.NOT_RECORDED },
            { key: "state", label: "Service",
              value: health?.state || (providers.length ? "reachable" : null),
              absent: ABSENCE.NOT_AVAILABLE },
          ]} />
        </NxInvSection>

        <NxInvSection title="Providers"
                      subtitle="state · governing credential · the reason the service gave"
                      testid="xdr-ioc-providers-sec">
          <NxInvTable testid="xdr-ioc-providers-table" rows={providers}
                      rowKey={(p) => p.provider}
                      columns={[
                        { key: "provider", label: "Provider", width: 200,
                          render: (p) => <span
                            data-testid={`xdr-ioc-provider-${p.provider}`}
                            data-state={p.state}>{p.provider}</span> },
                        { key: "state", label: "State", width: 120,
                          render: (p) => <span className="mono"
                            style={{ color: p.state === "live"
                              ? "var(--nx-ok, #2f9e44)"
                              : "var(--nx-faint, var(--faint))" }}>
                            {String(p.state || "").toUpperCase()
                              || ABSENCE.NOT_RECORDED}</span> },
                        { key: "env", label: "Governing credential", width: 230,
                          render: (p) => <NxInvValue value={p.env} mono
                            absent="NO CREDENTIAL DECLARED" /> },
                        { key: "detail", label: "Detail",
                          render: (p) => <NxInvValue value={p.detail}
                            absent={ABSENCE.NOT_RECORDED} /> },
                      ]}
                      empty={<NxInvEmpty testid="xdr-ioc-providers-empty"
                        title={ABSENCE.NO_DATA}
                        body="/api/ioc/health returned no provider. No provider is invented to fill this table." />} />
        </NxInvSection>

        <NxInvSection title="Enrich an observable"
                      subtitle="the fabric answers per provider; nothing is merged into a verdict here"
                      testid="xdr-ioc-enrich-sec">
          <form onSubmit={enrich} className="inv-filters"
                data-testid="xdr-ioc-form">
            <select value={kind} onChange={(e) => setKind(e.target.value)}
                    data-testid="xdr-ioc-kind"
                    style={{ fontSize: 10.6, padding: "3px 6px",
                             borderRadius: 3, background: "transparent",
                             color: "var(--nx-text, var(--text))",
                             border: "1px solid var(--nx-bd-quiet, var(--border))" }}>
              {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
            <span className="inv-cov__k" style={{ display: "inline-flex",
                    alignItems: "center", gap: 5 }}>
              <input value={value}
                     onChange={(e) => { setValue(e.target.value);
                                        setKind(guessKind(e.target.value)); }}
                     placeholder="8.8.8.8 · evil.example.com · sha256…"
                     data-testid="xdr-ioc-value"
                     style={{ fontSize: 11, background: "transparent",
                              border: "none", outline: "none", width: 330,
                              color: "var(--nx-text, var(--text))",
                              textTransform: "none", letterSpacing: 0 }} />
            </span>
            <button type="submit" className="inv-chip" disabled={running}
                    data-testid="xdr-ioc-enrich">
              <Zap size={11} /> {running ? "Enriching…" : "Enrich"}
            </button>
          </form>

          {runErr && (
            <NxInvEmpty testid="xdr-ioc-enrich-error"
              title={`${ABSENCE.ERROR} — enrichment did not complete`}
              body={typeof runErr === "object"
                ? JSON.stringify(runErr) : String(runErr)} />
          )}

          {result && (
            <div data-testid="xdr-ioc-result">
              <div className="inv-sec__s" style={{ padding: "6px 12px" }}
                   data-provenance={hasProvenance(result) ? "present" : "missing"}>
                {hasProvenance(result)
                  ? "Provider responses, rendered as the provider returned them."
                  : "PROVENANCE MISSING — no provider attribution in this response, so it is shown as raw output, not a verdict."}
              </div>

              <div className="inv-split" data-testid="xdr-ioc-wk"
                   data-pane={selected ? "open" : "closed"}>
                <div className="inv-split__t">
                  <NxInvTable testid="xdr-ioc-answers-table" rows={answered}
                              rowKey={(a) => a.provider}
                              onRowClick={(a) => { setSel(a.provider);
                                                   setPaneTab("details"); }}
                              columns={[
                                { key: "provider", label: "Provider", width: 200,
                                  render: (a) => <b data-testid={
                                    `xdr-ioc-answer-${a.provider}`}>
                                    {a.provider}</b> },
                                { key: "verdict", label: "Provider verdict",
                                  width: 170,
                                  render: (a) => <NxInvValue
                                    value={a.payload?.verdict
                                      || a.payload?.disposition
                                      || a.payload?.classification}
                                    mono absent={ABSENCE.NOT_EVALUATED} /> },
                                { key: "score", label: "Score", width: 100,
                                  num: true,
                                  render: (a) => <NxInvValue
                                    value={a.payload?.score
                                      ?? a.payload?.confidence}
                                    mono absent="—" /> },
                                { key: "state", label: "Answer state", width: 150,
                                  render: (a) => <NxInvValue
                                    value={a.payload?.state
                                      || a.payload?.status
                                      || (a.payload?.error ? "ERROR" : null)}
                                    mono absent={ABSENCE.NOT_RECORDED} /> },
                                { key: "note", label: "What the provider said",
                                  render: (a) => <NxInvValue
                                    value={a.payload?.error
                                      || a.payload?.message
                                      || a.payload?.summary}
                                    absent={ABSENCE.NOT_RECORDED} /> },
                              ]}
                              empty={<NxInvEmpty testid="xdr-ioc-answers-empty"
                                title="NO PER-PROVIDER ATTRIBUTION"
                                body="The fabric answered without a per-provider structure. The verbatim response is available under Technical details below — it is not reshaped into providers that did not answer." />} />
                </div>

                {selected && (
                  <div className="inv-split__p" data-testid="xdr-ioc-pane">
                    <div className="inv-pane__h">
                      <span style={{ minWidth: 0 }}>
                        <div className="inv-pane__k">PROVIDER</div>
                        <div className="inv-pane__t"
                             data-testid="xdr-ioc-pane-title">
                          {selected.provider}
                        </div>
                      </span>
                      <button className="inv-chip" style={{ marginLeft: "auto" }}
                              onClick={() => setSel(null)}
                              data-testid="xdr-ioc-pane-close">Close</button>
                    </div>
                    <div className="inv-pane__tabs" role="tablist">
                      {[["details", "Details"], ["raw", "Raw response"]]
                        .map(([k, label]) => (
                        <button key={k} className="inv-pane__tab" role="tab"
                                aria-selected={paneTab === k}
                                onClick={() => setPaneTab(k)}
                                data-testid={`xdr-ioc-pane-tab-${k}`}>
                          {label}
                        </button>
                      ))}
                    </div>
                    <div className="inv-pane__b">
                      {paneTab === "details" ? (
                        <dl className="inv-kv">
                          <dt>Observable</dt>
                          <dd className="mono">{kind} · {value}</dd>
                          <dt>Provider verdict</dt>
                          <dd className="mono"><NxInvValue
                            value={selected.payload?.verdict
                              || selected.payload?.disposition}
                            absent={ABSENCE.NOT_EVALUATED} /></dd>
                          <dt>Score / confidence</dt>
                          <dd className="mono"><NxInvValue
                            value={selected.payload?.score
                              ?? selected.payload?.confidence}
                            absent={ABSENCE.NOT_EVALUATED} /></dd>
                          <dt>Answer state</dt>
                          <dd className="mono"><NxInvValue
                            value={selected.payload?.state
                              || selected.payload?.status}
                            absent={ABSENCE.NOT_RECORDED} /></dd>
                          <dt>Error</dt>
                          <dd className="mono"><NxInvValue
                            value={selected.payload?.error}
                            absent="NO ERROR REPORTED" /></dd>
                        </dl>
                      ) : (
                        <pre style={{ margin: 0, fontSize: 10.4,
                                      whiteSpace: "pre-wrap",
                                      wordBreak: "break-all" }}>
                          {JSON.stringify(selected.payload, null, 1)}
                        </pre>
                      )}
                    </div>
                  </div>
                )}
              </div>

              <NxInvTech label="Technical details · verbatim fabric response"
                         testid="xdr-ioc-raw">
                <pre>{JSON.stringify(result, null, 2)}</pre>
              </NxInvTech>
            </div>
          )}
        </NxInvSection>
      </div>
    </XdrShell>
  );
}
