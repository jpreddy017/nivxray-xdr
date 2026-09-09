/**
 * Admin › Investigation Corpus — 8-category scenario coverage.
 *
 * Reads exclusively from src/xdr/corpus/scenarioRegistry.js.  Every
 * scenario is real JSON that ships in-tree at
 * docs/corpus/scenarios/<category>/<id>.json.  Each row proves the
 * eight required categories exist so tuning + regression have real
 * data to run against; when a category is empty the panel honestly
 * surfaces "CORPUS INCOMPLETE — category empty" rather than hiding it.
 */
import React, { useMemo, useState } from "react";
import { FolderTree, Search, CheckCircle2, AlertTriangle } from "lucide-react";

import {
  CORPUS_CATEGORIES, listScenarios, categoryCounts,
  corpusCoverage, validateScenario,
} from "@/xdr/corpus/scenarioRegistry";


function CategoryCard({ category, count }) {
  const empty = count === 0;
  return (
    <div className="panel"
            data-testid={`xdr-corpus-cat-${category.key}`}
            style={{ padding: 10, display: "flex",
                        flexDirection: "column", gap: 4 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <b className="mono" style={{ fontSize: 11, color: "var(--text)" }}>
          {category.label}
        </b>
        <span style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 10,
                                                        color: empty ? "var(--amber)" : "var(--mint)",
                                                        padding: "1px 6px", borderRadius: 3,
                                                        border: `1px solid ${empty ? "var(--amber)" : "var(--mint)"}` }}>
          {empty ? "EMPTY" : `${count} scenario${count === 1 ? "" : "s"}`}
        </span>
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
        {category.purpose}
      </div>
    </div>
  );
}


function ScenarioRow({ s, valid }) {
  return (
    <div data-testid={`xdr-corpus-scenario-${s.id}`}
            style={{ padding: "5px 0", fontSize: 11,
                        color: "var(--text-dim)",
                        borderBottom: "1px solid var(--border)",
                        display: "flex", alignItems: "center", gap: 8 }}>
      {valid.valid
        ? <CheckCircle2 size={11} style={{ color: "var(--mint)" }} />
        : <AlertTriangle size={11} style={{ color: "var(--amber)" }} />}
      <span className="mono" style={{ color: "var(--cyan)" }}>{s.id}</span>
      <span style={{ flex: 1 }}>{s.title}</span>
      <span className="mono" style={{ fontSize: 9.5,
                                                      color: "var(--faint)" }}>
        {s.category}
      </span>
      {!valid.valid && (
        <span className="mono" style={{ fontSize: 9.5,
                                                        color: "var(--amber)" }}>
          missing: {valid.missing.slice(0, 3).join(", ")}
          {valid.missing.length > 3 ? "…" : ""}
        </span>
      )}
    </div>
  );
}


export default function CorpusBody() {
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("all");

  const coverage = useMemo(() => corpusCoverage(), []);
  const counts   = useMemo(() => categoryCounts(),   []);
  const all      = useMemo(() => listScenarios(),    []);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return all.filter((s) => {
      if (cat !== "all" && s.category !== cat) return false;
      if (!needle) return true;
      const hay = `${s.id} ${s.title} ${s.description || ""}`.toLowerCase();
      return hay.includes(needle);
    });
  }, [all, q, cat]);

  return (
    <div data-testid="xdr-corpus-body">
      {/* Header strip */}
      <div style={{ display: "flex", alignItems: "center", gap: 12,
                       marginBottom: 10, flexWrap: "wrap" }}>
        <div className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
          {coverage.total} scenario{coverage.total === 1 ? "" : "s"} ·
          {" "}
          {coverage.complete_coverage
            ? <span style={{ color: "var(--mint)" }}>
                8/8 categories covered
              </span>
            : <span style={{ color: "var(--amber)" }}
                        data-testid="xdr-corpus-incomplete">
                CORPUS INCOMPLETE — {coverage.categories_empty.length}
                {" "}categor{coverage.categories_empty.length === 1 ? "y" : "ies"} empty:{" "}
                {coverage.categories_empty.join(", ")}
              </span>}
        </div>
        <span style={{ flex: 1 }} />
        <div style={{ position: "relative" }}>
          <Search size={11} style={{ position: "absolute", left: 6,
                                                        top: 6, color: "var(--faint)" }} />
          <input
            data-testid="xdr-corpus-search"
            placeholder="Search scenarios…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ padding: "4px 8px 4px 22px", fontSize: 11,
                        width: 260, border: "1px solid var(--border)",
                        borderRadius: 4, background: "var(--panel2)",
                        color: "var(--text)", fontFamily: "var(--mono)" }} />
        </div>
        <select value={cat} onChange={(e) => setCat(e.target.value)}
                  data-testid="xdr-corpus-cat-filter"
                  style={{ padding: "4px 6px", fontSize: 11,
                              border: "1px solid var(--border)", borderRadius: 4,
                              background: "var(--panel2)",
                              color: "var(--text)" }}>
          <option value="all">All categories</option>
          {CORPUS_CATEGORIES.map((c) => (
            <option key={c.key} value={c.key}>{c.label}</option>
          ))}
        </select>
      </div>

      {/* Category grid */}
      <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
                        gap: 8, marginBottom: 12 }}>
        {CORPUS_CATEGORIES.map((c) => (
          <CategoryCard key={c.key} category={c} count={counts[c.key] || 0} />
        ))}
      </div>

      {/* Scenario list */}
      <div className="section-title" style={{ marginBottom: 6 }}>
        Scenarios ({filtered.length})
      </div>
      {filtered.length === 0 && (
        <div style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                          fontFamily: "var(--mono)" }}>
          NO MATCHING SCENARIOS
        </div>
      )}
      <div>
        {filtered.map((s) => (
          <ScenarioRow key={s.id} s={s} valid={validateScenario(s)} />
        ))}
      </div>

      <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--faint)",
                       fontFamily: "var(--mono)" }}>
        source: <span style={{ color: "var(--cyan)" }}>
          docs/corpus/scenarios/**/*.json
        </span>{" "}· read-only projection ·
        every scenario exercises evidence → correlation → verdict →
        severity → recommendation → playbook → report.
      </div>
    </div>
  );
}
