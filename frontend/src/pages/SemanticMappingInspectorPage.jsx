/**
 * Semantic Mapping Inspector — Stage 3 engineering surface.
 *
 * Route: /lab/semantic-mapping-inspector
 *
 * Purpose: expose Stage 2b (Schema Understanding) + Stage 3 (Semantic
 * Field Mapping) exactly as the pipeline sees them. Not the analyst
 * incident UI — this is for engineering + validation.
 *
 * Renders every FieldMapping with its confidence provenance ledger
 * so analysts and engineers can see WHY each mapping was made.
 */
import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";

const API_BASE = `${process.env.REACT_APP_BACKEND_URL}/api`;

const SAMPLE = JSON.stringify(
  {
    "@timestamp": "2026-02-01T00:00:00Z",
    "host.name": "web-01",
    "user.name": "alice",
    "source.ip": "10.0.0.1",
    "source.port": 5555,
    "destination.ip": "203.0.113.44",
    "destination.port": 443,
    "process.name": "curl",
    "event.category": "network",
    "event.action": "connection",
    "file.hash.sha256":
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  },
  null,
  2
);

function ConfidenceBar({ value }) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  const tone =
    value >= 0.85 ? "#22c55e" : value >= 0.6 ? "#eab308" : "#ef4444";
  return (
    <div
      data-testid="confidence-bar"
      style={{
        height: 6,
        background: "#1f2937",
        borderRadius: 3,
        overflow: "hidden",
        width: 120,
      }}
    >
      <div
        style={{
          width: `${pct}%`,
          height: "100%",
          background: tone,
          transition: "width 240ms ease",
        }}
      />
    </div>
  );
}

function ProvenanceLedger({ contributions }) {
  const items = contributions || [];
  const total = items.reduce((s, c) => s + (c.delta || 0), 0);
  return (
    <div
      data-testid="confidence-provenance"
      style={{
        borderLeft: "2px solid #334155",
        paddingLeft: 12,
        marginTop: 8,
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 12,
        color: "#cbd5e1",
      }}
    >
      {items.map((c, i) => {
        const sign = c.delta >= 0 ? "+" : "";
        const tone =
          c.signal.startsWith("clamp_") ? "#64748b"
            : c.delta >= 0 ? "#86efac"
            : "#fca5a5";
        return (
          <div
            key={i}
            data-testid={`provenance-row-${i}`}
            style={{
              display: "flex",
              justifyContent: "space-between",
              gap: 12,
              padding: "2px 0",
            }}
          >
            <span>
              <span style={{ color: tone }}>
                {c.delta >= 0 ? "✓" : "↓"}
              </span>{" "}
              <span style={{ color: "#e2e8f0" }}>{c.signal}</span>
              {c.detail && (
                <span style={{ color: "#64748b", marginLeft: 6 }}>
                  · {c.detail}
                </span>
              )}
            </span>
            <span style={{ color: tone, minWidth: 60, textAlign: "right" }}>
              {sign}
              {c.delta.toFixed(2)}
            </span>
          </div>
        );
      })}
      <div
        style={{
          marginTop: 4,
          paddingTop: 4,
          borderTop: "1px dashed #334155",
          display: "flex",
          justifyContent: "space-between",
          color: "#f8fafc",
          fontWeight: 600,
        }}
      >
        <span>total</span>
        <span data-testid="provenance-total">{total.toFixed(2)}</span>
      </div>
    </div>
  );
}

function MappingCard({ mapping }) {
  const [open, setOpen] = useState(false);
  const pct = Math.round(mapping.confidence * 100);
  return (
    <div
      data-testid={`mapping-${mapping.surface_field}`}
      style={{
        border: "1px solid #1f2937",
        borderRadius: 8,
        padding: 12,
        marginBottom: 8,
        background: "#0b1220",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          cursor: "pointer",
        }}
        onClick={() => setOpen((v) => !v)}
        data-testid={`mapping-toggle-${mapping.surface_field}`}
      >
        <code style={{ color: "#93c5fd", fontSize: 13 }}>
          {mapping.surface_field}
        </code>
        <span style={{ color: "#64748b" }}>→</span>
        <Badge variant="outline" data-testid={`mapping-concept-${mapping.surface_field}`}>
          {mapping.concept}
        </Badge>
        <div style={{ flex: 1 }} />
        <span style={{ color: "#f1f5f9", fontVariantNumeric: "tabular-nums" }}>
          {pct}%
        </span>
        <ConfidenceBar value={mapping.confidence} />
        <span style={{ color: "#64748b", fontSize: 11 }}>
          {open ? "hide" : "why?"}
        </span>
      </div>
      {open && <ProvenanceLedger contributions={mapping.confidence_provenance} />}
      {open && mapping.rejected_alternatives && mapping.rejected_alternatives.length > 0 && (
        <div style={{ marginTop: 8, fontSize: 12, color: "#94a3b8" }}>
          <div style={{ color: "#64748b", marginBottom: 2 }}>
            rejected alternatives:
          </div>
          {mapping.rejected_alternatives.map((r, i) => (
            <div key={i} data-testid={`rejected-${i}`}>
              · {r.concept} ({r.confidence.toFixed(2)}) — {r.reason}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function SemanticMappingInspectorPage() {
  const [raw, setRaw] = useState(SAMPLE);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [registry, setRegistry] = useState(null);

  useEffect(() => {
    axios
      .get(`${API_BASE}/v2/semantic/registry`)
      .then((r) => setRegistry(r.data))
      .catch(() => {});
  }, []);

  const runPreview = async () => {
    setLoading(true);
    try {
      const r = await axios.post(`${API_BASE}/v2/semantic/preview`, {
        raw,
      });
      setResult(r.data);
    } catch (e) {
      toast.error("preview failed", { description: e?.message });
    } finally {
      setLoading(false);
    }
  };

  const sm = result?.semantic_mapping;
  const fp = result?.schema_fingerprint;
  const mappings = useMemo(() =>
    (sm?.mappings || []).slice().sort((a, b) => b.confidence - a.confidence),
    [sm]);

  return (
    <div
      data-testid="semantic-mapping-inspector-page"
      style={{
        minHeight: "100vh",
        background: "#020617",
        color: "#e2e8f0",
        padding: 24,
      }}
    >
      <div style={{ maxWidth: 1240, margin: "0 auto" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 16, marginBottom: 8 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>
            Semantic Mapping Inspector
          </h1>
          <span style={{ color: "#64748b", fontSize: 12, fontFamily: "JetBrains Mono, monospace" }}>
            Stage 2b · Schema Understanding &nbsp;→&nbsp; Stage 3 · Semantic Field Mapping
          </span>
        </div>
        <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 20 }}>
          Engineering / validation surface. Paste raw telemetry and see how the
          pipeline resolves fields to canonical concepts — with an itemised
          confidence provenance ledger for every mapping.
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
          <Card style={{ background: "#0b1220", borderColor: "#1f2937" }}>
            <CardHeader>
              <CardTitle style={{ color: "#f1f5f9", fontSize: 15 }}>
                Raw telemetry
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Textarea
                data-testid="raw-input"
                value={raw}
                onChange={(e) => setRaw(e.target.value)}
                rows={16}
                style={{
                  background: "#020617",
                  color: "#e2e8f0",
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 12,
                }}
              />
              <div style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "center" }}>
                <Button
                  onClick={runPreview}
                  disabled={loading}
                  data-testid="run-preview-btn"
                >
                  {loading ? "running …" : "Run semantic preview"}
                </Button>
                {registry && (
                  <span style={{ color: "#64748b", fontSize: 11, fontFamily: "JetBrains Mono, monospace" }}>
                    {registry.registry_version} · ambiguity Δ ≤ {registry.ambiguity_threshold_default}
                  </span>
                )}
              </div>
            </CardContent>
          </Card>

          <Card style={{ background: "#0b1220", borderColor: "#1f2937" }}>
            <CardHeader>
              <CardTitle style={{ color: "#f1f5f9", fontSize: 15 }}>
                Schema fingerprint
              </CardTitle>
            </CardHeader>
            <CardContent>
              {!fp && (
                <div style={{ color: "#64748b", fontSize: 12 }}>
                  Run a preview to see schema detection results.
                </div>
              )}
              {fp && (
                <div style={{ fontSize: 13, fontFamily: "JetBrains Mono, monospace" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <Badge data-testid="schema-family">{fp.schema_family}</Badge>
                    {fp.schema_version && (
                      <span style={{ color: "#94a3b8" }}>{fp.schema_version}</span>
                    )}
                    <span style={{ color: "#64748b" }}>
                      confidence {Math.round(fp.schema_confidence * 100)}%
                    </span>
                  </div>
                  {fp.reasons && fp.reasons.length > 0 && (
                    <ul style={{ marginTop: 8, paddingLeft: 16, color: "#cbd5e1" }}>
                      {fp.reasons.map((r, i) => (
                        <li key={i} data-testid={`schema-reason-${i}`}>
                          {r}
                        </li>
                      ))}
                    </ul>
                  )}
                  <div style={{ marginTop: 10, color: "#64748b", fontSize: 12 }}>
                    candidate fields: {fp.candidate_fields.length} · key style: {fp.parser_features?.key_style}
                    {fp.parser_features?.has_dotted_keys && " · dotted"}
                    {fp.parser_features?.has_nested_objects && " · nested"}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {sm && (
          <div style={{ marginTop: 24 }}>
            <div style={{ display: "flex", gap: 16, alignItems: "baseline", marginBottom: 12 }}>
              <h2 style={{ margin: 0, fontSize: 16, color: "#f1f5f9" }}>
                Field mappings
              </h2>
              <span style={{ color: "#64748b", fontSize: 12 }}>
                {sm.mappings.length} mapped · {sm.ambiguous_fields.length} ambiguous · {sm.unmapped_fields.length} unmapped · aggregate confidence {Math.round((sm.semantic_confidence || 0) * 100)}%
              </span>
            </div>

            <div data-testid="mappings-list">
              {mappings.map((m) => (
                <MappingCard key={m.surface_field} mapping={m} />
              ))}
              {mappings.length === 0 && (
                <div style={{ color: "#64748b", fontSize: 13 }}>
                  No mappings resolved. Every candidate field is either
                  ambiguous or unmapped — see below.
                </div>
              )}
            </div>

            {sm.ambiguous_fields.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <h3 style={{ fontSize: 14, color: "#facc15", margin: "0 0 8px" }}>
                  Ambiguous fields ({sm.ambiguous_fields.length})
                </h3>
                {sm.ambiguous_fields.map((a) => (
                  <div
                    key={a.surface_field}
                    data-testid={`ambiguous-${a.surface_field}`}
                    style={{
                      background: "#1a1408",
                      border: "1px solid #52410a",
                      borderRadius: 6,
                      padding: 8,
                      marginBottom: 6,
                      fontSize: 13,
                      fontFamily: "JetBrains Mono, monospace",
                    }}
                  >
                    <code style={{ color: "#fcd34d" }}>{a.surface_field}</code>{" "}
                    <span style={{ color: "#94a3b8" }}>
                      {a.candidates.map((c) => `${c[0]}(${c[1].toFixed(2)})`).join(" ↔ ")}
                      {" · Δ="}{a.delta.toFixed(2)}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {sm.unmapped_fields.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <h3 style={{ fontSize: 14, color: "#94a3b8", margin: "0 0 8px" }}>
                  Unmapped ({sm.unmapped_fields.length})
                </h3>
                <div
                  data-testid="unmapped-list"
                  style={{
                    display: "flex",
                    flexWrap: "wrap",
                    gap: 6,
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 12,
                  }}
                >
                  {sm.unmapped_fields.map((f) => (
                    <span
                      key={f}
                      data-testid={`unmapped-${f}`}
                      style={{
                        padding: "2px 8px",
                        background: "#0f172a",
                        border: "1px solid #1f2937",
                        borderRadius: 4,
                        color: "#cbd5e1",
                      }}
                    >
                      {f}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
