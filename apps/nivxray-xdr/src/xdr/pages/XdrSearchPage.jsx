/**
 * X2 · Unified NivXRay XDR global search.
 *
 * One question — "what does this platform know about this string?" —
 * answered from `GET /api/xdr/search`, which reads the authoritative
 * stores only. Every result is typed, and selecting it opens the
 * authoritative context (incident · endpoint trajectory · exact
 * observation · process tree · file trajectory).
 *
 * Nothing is fabricated: an entity type this platform holds no index
 * for is stated as NOT_SEARCHABLE_NO_INDEX, and a term with no match
 * says so in the analyst's own vocabulary.
 */
import React, { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Loader2, Search } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";

const TYPE_TONE = {
  INCIDENT: "var(--red, #E5484D)", DETECTION: "var(--amber, #F5A524)",
  ENDPOINT: "var(--cyan, #22B8CF)", EVIDENCE: "var(--mint, #3DD68C)",
  PROCESS: "var(--violet, #7c3aed)", FILE: "var(--muted)",
  NETWORK: "var(--muted)",
};

export default function XdrSearchPage() {
  const [params, setParams] = useSearchParams();
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
      .catch((e) => setErr(e?.message || String(e)))
      .finally(() => setBusy(false));
  }, []);

  useEffect(() => { setTerm(q); run(q); }, [q, run]);
  useEffect(() => {
    api.get("/xdr/search/capabilities").then(({ data: d }) => setCaps(d))
      .catch(() => {});
  }, []);

  return (
    <XdrShell>
      <div style={{ padding: "14px 18px 26px" }} data-testid="xdr-search-page">
        <h1 style={{ fontSize: 20, fontWeight: 700, margin: "0 0 3px" }}>
          Global search
        </h1>
        <p style={{ fontSize: 11.5, color: "var(--muted)", margin: "0 0 14px",
                    maxWidth: 780, lineHeight: 1.6 }}>
          Searches the authoritative NivXRay stores — incidents, the
          tenant-authorised endpoint inventory, detection derivations and
          canonical evidence. It builds no index of its own and returns no
          result it cannot trace to a record.
        </p>

        <form onSubmit={(e) => { e.preventDefault();
                                 setParams({ q: term.trim() }); }}
              style={{ display: "flex", gap: 8, marginBottom: 16,
                       maxWidth: 720 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8,
                        flex: 1, border: "1px solid var(--border)",
                        borderRadius: 4, padding: "8px 10px",
                        background: "var(--panel)" }}>
            <Search size={13} style={{ opacity: .7 }} />
            <input value={term} onChange={(e) => setTerm(e.target.value)}
                   data-testid="xdr-search-input"
                   placeholder="Incident · hostname · endpoint id · SHA-256 · IP · rule id · evidence id · process"
                   style={{ flex: 1, background: "transparent",
                            border: "none", outline: "none", fontSize: 12,
                            color: "var(--text)" }} />
          </div>
          <button type="submit" className="btn" data-testid="xdr-search-submit"
                  style={{ fontSize: 11.5, padding: "0 16px" }}>
            Search
          </button>
        </form>

        {busy && (
          <div data-testid="xdr-search-busy"
               style={{ fontSize: 11.5, color: "var(--muted)" }}>
            <Loader2 size={13} className="spin"
                     style={{ verticalAlign: "middle", marginRight: 6 }} />
            Reading the authoritative stores…
          </div>
        )}
        {err && (
          <div className="x-empty" data-testid="xdr-search-error"
               style={{ color: "#ff9494" }}>{String(err)}</div>
        )}

        {data && (
          <div data-testid="xdr-search-results"
               data-state={data.state} data-total={data.total ?? 0}>
            <div style={{ fontSize: 10.6, color: "var(--muted)",
                          marginBottom: 10 }}>
              <span className="mono" data-testid="xdr-search-classification">
                {data.term_classification}
              </span>
              {" · "}{data.total ?? 0} result(s) across{" "}
              {data.groups?.length || 0} entity type(s)
              {data.searched && (
                <> · searched {data.searched.authorised_endpoints}{" "}
                  authorised endpoint(s)</>
              )}
            </div>

            {data.state === "NO_MATCH" && (
              <div className="x-empty" data-testid="xdr-search-no-match">
                <b>NO MATCHING RECORD</b> — {data.message}
              </div>
            )}
            {data.state === "NOT_AUTHORIZED" && (
              <div className="x-empty" data-testid="xdr-search-unauthorized">
                <b>NOT AUTHORIZED</b> — your principal resolves to no
                customer scope, so no record may be searched.
              </div>
            )}

            {(data.groups || []).map((g) => (
              <section key={g.entity_type} style={{ marginBottom: 18 }}
                       data-testid={`xdr-search-group-${g.entity_type}`}>
                <div style={{ display: "flex", alignItems: "center", gap: 8,
                              marginBottom: 6 }}>
                  <span style={{ fontSize: 9.6, fontWeight: 800,
                                 letterSpacing: .8, padding: "2px 7px",
                                 borderRadius: 2, color: "#fff",
                                 background: TYPE_TONE[g.entity_type]
                                   || "var(--muted)" }}>
                    {g.entity_type}
                  </span>
                  <span className="mono" style={{ fontSize: 10,
                                                  color: "var(--faint)" }}>
                    {g.count}
                  </span>
                </div>
                <div className="panel" style={{ overflow: "hidden" }}>
                  {g.results.map((r) => (
                    <Link key={`${r.entity_type}-${r.id}`} to={r.href}
                          data-testid={`xdr-search-result-${r.id}`}
                          style={{ display: "flex", gap: 10,
                                   alignItems: "baseline",
                                   padding: "8px 12px",
                                   textDecoration: "none",
                                   color: "var(--text)",
                                   borderBottom: "1px solid var(--border)" }}>
                      <span style={{ fontSize: 11.6, fontWeight: 600,
                                     minWidth: 220, maxWidth: 320,
                                     overflow: "hidden",
                                     textOverflow: "ellipsis",
                                     whiteSpace: "nowrap" }}>
                        {r.label}
                      </span>
                      <span className="mono" style={{ flex: 1, fontSize: 10,
                              color: "var(--muted)", overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap" }}>
                        {r.detail || "◇ nothing further reported"}
                      </span>
                      <span className="mono" style={{ fontSize: 9.4,
                              color: "var(--faint)", flex: "0 0 auto" }}>
                        {r.tenant_id || "◇ tenant not attributed"}
                      </span>
                      {/* Y2 · M-5 · which PRODUCT owns this record. */}
                      <span data-testid={`xdr-search-product-${r.id}`}
                            data-product={r.source_product || ""}
                            style={{ fontSize: 8.8, fontWeight: 800,
                                     letterSpacing: .6, flex: "0 0 auto",
                                     padding: "2px 6px", borderRadius: 2,
                                     border: "1px solid var(--border)",
                                     color: r.source_product
                                       === "NIVXFORGE_EDR"
                                       ? "var(--cyan, #22B8CF)"
                                       : "var(--muted)" }}>
                        {r.source_product === "NIVXFORGE_EDR"
                          ? "NivXForge EDR" : "NivXRay XDR"}
                      </span>
                      <span style={{ fontSize: 9.2, flex: "0 0 auto",
                                     color: "var(--muted)" }}>
                        {r.source_product === "NIVXFORGE_EDR"
                          ? "Open in EDR →" : "Open →"}
                      </span>
                    </Link>
                  ))}
                </div>
              </section>
            ))}

            {caps?.not_searchable?.length > 0 && (
              <details data-testid="xdr-search-not-searchable"
                       style={{ marginTop: 6 }}>
                <summary style={{ fontSize: 10.6, color: "var(--muted)",
                                  cursor: "pointer" }}>
                  What this search cannot answer ·{" "}
                  {caps.not_searchable.length} entity type(s)
                </summary>
                <div className="panel" style={{ marginTop: 6 }}>
                  {caps.not_searchable.map((n) => (
                    <div key={n.entity_type}
                         data-testid={`xdr-not-searchable-${n.entity_type}`}
                         style={{ display: "flex", gap: 10,
                                  padding: "6px 12px", fontSize: 10.6,
                                  borderBottom: "1px solid var(--border)" }}>
                      <span style={{ minWidth: 150, fontWeight: 600 }}>
                        {n.entity_type}
                      </span>
                      <span className="mono" style={{ color: "var(--amber)" }}>
                        {n.state}
                      </span>
                      <span style={{ color: "var(--muted)" }}>{n.reason}</span>
                    </div>
                  ))}
                </div>
              </details>
            )}
          </div>
        )}
      </div>
    </XdrShell>
  );
}
