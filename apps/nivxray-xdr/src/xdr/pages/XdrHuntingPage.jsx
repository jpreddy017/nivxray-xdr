/**
 * `/xdr/hunting` — Threat Hunting workbench.
 *
 * Hunting is analyst-initiated interrogation of the authoritative stores:
 * one question — "what does this platform know about this observable?" —
 * answered by `GET /api/xdr/search`, which reads canonical records only
 * and builds no index of its own.
 *
 * This is the SINGLE hunting surface. `/xdr/search` is kept as a
 * permanent compatibility redirect into it (with `?q=` preserved) so no
 * deep link breaks and the rail carries no duplicate destination.
 *
 * What this platform cannot hunt is STATED: there is no saved-hunt,
 * scheduled-hunt or hunt-query-language model in this build, so those
 * read NOT AVAILABLE with the reason instead of rendering empty widgets.
 */
import React, { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Loader2, Search, Radar } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";
import "@/xdr/nx/nx-cc.css";

const TYPE_TONE = {
  INCIDENT: "var(--nx-critical, #E5484D)", DETECTION: "var(--nx-high, #F5A524)",
  ENDPOINT: "var(--nx-cyan, #22B8CF)", EVIDENCE: "var(--nx-benign, #3DD68C)",
  PROCESS: "var(--nx-purple, #7c3aed)", FILE: "var(--nx-muted)",
  NETWORK: "var(--nx-muted)",
};

const UNSUPPORTED = [
  { k: "Saved hunts", state: "NOT AVAILABLE",
    why: "no saved-hunt persistence model exists in this backend; a saved "
       + "hunt that silently forgets itself would be worse than none" },
  { k: "Scheduled hunts", state: "NOT AVAILABLE",
    why: "no scheduler owns hunt execution; automation lives in Automate ▸ "
       + "Automation Rules and acts on detections, not hunts" },
  { k: "Hunt query language", state: "UNSUPPORTED",
    why: "search accepts an observable (hostname · SHA-256 · IP · rule id · "
       + "incident · process), not a query grammar" },
];

export default function XdrHuntingPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const q = params.get("q") || "";
  const [term, setTerm] = useState(q);
  const [data, setData] = useState(null);
  const [caps, setCaps] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const run = useCallback((value) => {
    if (!value.trim()) { setData(null); return; }
    setBusy(true); setErr(null);
    api.get("/xdr/search", { params: { q: value.trim() } })
      .then(({ data: d }) => setData(d))
      .catch((e) => setErr(e?.response?.data?.detail || e?.message || String(e)))
      .finally(() => setBusy(false));
  }, []);

  useEffect(() => { setTerm(q); run(q); }, [q, run]);
  useEffect(() => {
    api.get("/xdr/search/capabilities").then(({ data: d }) => setCaps(d))
      .catch((e) => setCaps({ error: e?.message }));
  }, []);

  return (
    <XdrShell>
      <div className="cc" data-testid="xdr-hunting-page"
           style={{ padding: "12px 16px 24px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12,
                      flexWrap: "wrap" }}>
          <h1 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}
              data-testid="xdr-hunting-title">
            Hunting
          </h1>
          <span style={{ fontSize: 11, color: "var(--nx-muted, var(--muted))",
                         maxWidth: 720, lineHeight: 1.6 }}>
            Interrogate the authoritative NivXRay stores directly. Every result
            traces to a canonical record; nothing is inferred and nothing is
            indexed twice.
          </span>
          <button className="cx-pill" style={{ marginLeft: "auto" }}
                  data-testid="xdr-hunting-activities"
                  onClick={() => navigate("/xdr/activities")}>
            <Radar size={11} /> Environment activity
          </button>
        </div>

        <form onSubmit={(e) => { e.preventDefault();
                                 setParams(term.trim() ? { q: term.trim() } : {}); }}
              style={{ display: "flex", gap: 8, maxWidth: 820 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1,
                        border: "1px solid var(--nx-bd-quiet, var(--border))",
                        borderRadius: 5, padding: "8px 10px",
                        background: "var(--nx-surf, var(--panel))" }}>
            <Search size={13} style={{ opacity: .7 }} />
            <input value={term} onChange={(e) => setTerm(e.target.value)}
                   data-testid="xdr-hunting-input"
                   placeholder="Hostname · endpoint id · SHA-256 · IP · rule id · incident · process · evidence id"
                   style={{ flex: 1, background: "transparent", border: "none",
                            outline: "none", fontSize: 12,
                            color: "var(--nx-text, var(--text))" }} />
          </div>
          <button type="submit" className="cx-pill"
                  data-testid="xdr-hunting-submit"
                  style={{ padding: "0 18px" }}>
            Hunt
          </button>
        </form>

        {busy && (
          <div className="cc-empty" data-testid="xdr-hunting-busy">
            <Loader2 size={13} className="spin"
                     style={{ verticalAlign: "middle", marginRight: 6 }} />
            Reading the authoritative stores…
          </div>
        )}
        {err && (
          <div className="cc-cond" data-testid="xdr-hunting-error"
               style={{ color: "var(--nx-critical, #E5484D)" }}>
            {typeof err === "object" ? JSON.stringify(err) : String(err)}
          </div>
        )}

        {!q && !busy && (
          <div className="cc-card" data-testid="xdr-hunting-idle">
            <div className="cc-card__h">
              <span className="cc-card__t">What you can hunt</span>
              <span className="cc-card__s">
                the stores this hunt reads, named at the source
              </span>
            </div>
            <div className="cc-card__b">
              {!caps ? <div className="cc-empty">Reading capability contract…</div>
                : caps.error ? (
                  <div className="cc-empty">
                    <b>NOT EVALUATED</b> — {String(caps.error)}
                  </div>
                ) : (
                  <table className="cc-tb" data-testid="xdr-hunting-surfaces">
                    <thead><tr><th>Entity</th><th>Authoritative source</th></tr></thead>
                    <tbody>
                      {(caps.searchable || []).map((s) => (
                        <tr key={s.entity_type}
                            data-testid={`xdr-hunting-surface-${s.entity_type}`}>
                          <td><b>{s.entity_type}</b></td>
                          <td className="mono">{s.source}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
            </div>
          </div>
        )}

        {data && (
          <div data-testid="xdr-hunting-results"
               data-state={data.state} data-total={data.total ?? 0}>
            <div className="cc-cond">
              <span className="cc-cond__i">
                <span className="cc-cond__k">Term</span>
                <span className="cc-cond__v"
                      data-testid="xdr-hunting-classification">
                  {data.term_classification}
                </span>
              </span>
              <span className="cc-cond__i">
                <span className="cc-cond__k">Results</span>
                <span className="cc-cond__v">
                  {data.total ?? 0} across {data.groups?.length || 0} entity type(s)
                </span>
              </span>
              {data.searched && (
                <span className="cc-cond__i">
                  <span className="cc-cond__k">Endpoints searched</span>
                  <span className="cc-cond__v">
                    {data.searched.authorised_endpoints}
                  </span>
                </span>
              )}
            </div>

            {data.state === "NO_MATCH" && (
              <div className="cc-card"><div className="cc-empty"
                   data-testid="xdr-hunting-no-match">
                <b>NO MATCHING RECORD</b> — {data.message}
              </div></div>
            )}
            {data.state === "NOT_AUTHORIZED" && (
              <div className="cc-card"><div className="cc-empty"
                   data-testid="xdr-hunting-unauthorized">
                <b>NOT AUTHORIZED</b> — your principal resolves to no customer
                scope, so no record may be hunted.
              </div></div>
            )}

            {(data.groups || []).map((g) => (
              <div className="cc-card" key={g.entity_type}
                   data-testid={`xdr-hunting-group-${g.entity_type}`}>
                <div className="cc-card__h">
                  <span className="cc-card__t"
                        style={{ color: TYPE_TONE[g.entity_type] }}>
                    {g.entity_type}
                  </span>
                  <span className="cc-card__s">{g.count} result(s)</span>
                </div>
                <div className="cc-card__b">
                  <table className="cc-tb">
                    <tbody>
                      {g.results.map((r) => (
                        <tr key={`${r.entity_type}-${r.id}`}>
                          <td style={{ width: "34%" }}>
                            <Link to={r.href}
                                  data-testid={`xdr-hunting-result-${r.id}`}
                                  style={{ color: "inherit",
                                           textDecoration: "none",
                                           fontWeight: 600 }}>
                              {r.label}
                            </Link>
                          </td>
                          <td className="mono">
                            {r.detail || <span className="cc-tb__na">
                              NOTHING FURTHER RECORDED</span>}
                          </td>
                          <td className="mono" style={{ width: 160 }}>
                            {r.tenant_id || <span className="cc-tb__na">
                              TENANT NOT ATTRIBUTED</span>}
                          </td>
                          <td className="mono" style={{ width: 110 }}
                              data-product={r.source_product || ""}>
                            {r.source_product === "NIVXFORGE_EDR"
                              ? "NivXRay EDR" : "NivXRay XDR"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="cc-grid">
          <div className="cc-card" data-testid="xdr-hunting-unsupported">
            <div className="cc-card__h">
              <span className="cc-card__t">What this platform cannot hunt yet</span>
              <span className="cc-card__s">stated, not hidden</span>
            </div>
            <div className="cc-card__b">
              <table className="cc-tb">
                <tbody>
                  {UNSUPPORTED.map((u) => (
                    <tr key={u.k} style={{ cursor: "default" }}
                        data-testid={`xdr-hunting-unsupported-${
                          u.k.toLowerCase().replace(/\W+/g, "-")}`}>
                      <td style={{ width: 170 }}><b>{u.k}</b></td>
                      <td className="mono cc-tb__na" style={{ width: 130 }}>
                        {u.state}
                      </td>
                      <td>{u.why}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="cc-card" data-testid="xdr-hunting-not-searchable">
            <div className="cc-card__h">
              <span className="cc-card__t">Entities with no index</span>
            </div>
            <div className="cc-card__b">
              {!caps?.not_searchable?.length ? (
                <div className="cc-empty">
                  Every entity this platform stores is searchable.
                </div>
              ) : (
                <table className="cc-tb">
                  <tbody>
                    {caps.not_searchable.map((n) => (
                      <tr key={n.entity_type} style={{ cursor: "default" }}>
                        <td style={{ width: 150 }}><b>{n.entity_type}</b></td>
                        <td className="mono cc-tb__na">{n.state}</td>
                        <td>{n.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </XdrShell>
  );
}
