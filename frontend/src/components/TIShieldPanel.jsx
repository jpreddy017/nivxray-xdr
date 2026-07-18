/**
 * TIShieldPanel  (v1.5.5 · 360° Per-Layer Intelligence)
 * ─────────────────────────────────────────────────────
 * Renders every decode layer (L0 raw → L1..LN intermediates → L-final)
 * with the FULL intelligence stack applied to each:
 *   · IOCs · LOLBins · MITRE · YARA · Local TI · Live OSINT (9 providers)
 *   · Family hint · Severity score/band
 *
 * Props:
 *   layers — array from `/api/decode/smart` → `ti_shield`
 */
export default function TIShieldPanel({ layers }) {
  if (!Array.isArray(layers) || layers.length === 0) return null;

  return (
    <div
      className="nvx-card"
      data-testid="ti-shield-panel"
      style={{ marginTop: 10, marginBottom: 10 }}
    >
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <span className="dot" style={{ background: "#8b5cf6" }} />
          TI SHIELD · 360° PER-LAYER INTELLIGENCE
          <span className="count">{layers.length} layers correlated</span>
        </div>
      </div>
      <div className="nvx-card-body" style={{ display: "grid", gap: 10 }}>
        {layers.map((L, i) => {
          const sev = L.severity || {};
          const bandColor = {
            critical: "#dc2626", high: "#ea580c", medium: "#eab308",
            low: "#84cc16", none: "#64748b",
          }[sev.band || "none"] || "#64748b";
          const iocCount = (L.iocs
            ? Object.values(L.iocs).reduce((s, v) => s + (Array.isArray(v) ? v.length : 0), 0)
            : 0);
          return (
            <div
              key={i}
              data-testid={`ti-shield-layer-${L.layer}`}
              style={{
                border: `1px solid ${bandColor}`,
                borderRadius: 8,
                padding: 12,
                background: "#0f172a",
                boxShadow: sev.band === "critical" ? "0 0 0 1px #dc2626" : "none",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between",
                            alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 6 }}>
                <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: 1.5, color: "#a7f3d0" }}>
                  {L.label}
                </div>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  {L.family_hint && (
                    <span style={{
                      background: "#4c1d95", color: "#e9d5ff",
                      padding: "2px 8px", borderRadius: 999, fontSize: 10,
                      letterSpacing: 0.6, fontWeight: 600,
                    }}>
                      family · {L.family_hint}
                    </span>
                  )}
                  <span style={{
                    background: bandColor, color: "#fff",
                    padding: "2px 8px", borderRadius: 4, fontSize: 10,
                    letterSpacing: 1, fontWeight: 700,
                  }}>
                    {(sev.band || "none").toUpperCase()} · {sev.score || 0}/100
                  </span>
                </div>
              </div>

              <div style={{ display: "grid",
                            gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
                            gap: 6, marginBottom: 8 }}>
                <MetricChip label="IOCS"    n={iocCount}                      color="#0ea5e9" />
                <MetricChip label="LOLBAS"  n={(L.lolbas || []).length}       color="#f59e0b" />
                <MetricChip label="MITRE"   n={(L.mitre || []).length}        color="#8b5cf6" />
                <MetricChip label="YARA"    n={(L.yara || []).length}         color="#22c55e" />
                <MetricChip label="TI HITS" n={(L.ti_hits || []).length}      color="#ef4444" />
                <MetricChip label="LIVE"    n={_liveHitCount(L.live_osint)}   color="#f97316" />
              </div>

              {L.preview && (
                <div style={{
                  fontFamily: "JetBrains Mono, monospace", fontSize: 10,
                  background: "#020617", color: "#a7f3d0", padding: 8,
                  borderRadius: 4, marginBottom: 6, maxHeight: 60,
                  overflow: "hidden", textOverflow: "ellipsis",
                  whiteSpace: "pre-wrap", wordBreak: "break-all",
                }}>
                  {L.preview}
                </div>
              )}

              {_liveHitCount(L.live_osint) > 0 && (
                <details style={{ marginTop: 4 }}>
                  <summary style={{ fontSize: 10, color: "#f97316", cursor: "pointer",
                                    letterSpacing: 1 }}>
                    ▸ Live OSINT hits ({_liveHitCount(L.live_osint)})
                  </summary>
                  <div style={{ marginTop: 6, display: "flex", flexDirection: "column", gap: 4 }}>
                    {_flattenLive(L.live_osint).map((row, j) => (
                      <div key={j} style={{
                        fontSize: 10, background: "#1e293b", padding: 6,
                        borderRadius: 3, fontFamily: "JetBrains Mono",
                      }}>
                        <b style={{ color: "#a7f3d0" }}>{row.value}</b> ·{" "}
                        <span style={{ color: "#94a3b8" }}>{row.summary}</span>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
          );
        })}
      </div>
      <div style={{ padding: "6px 16px 12px", fontSize: 10, color: "#64748b" }}>
        Every layer is scanned through <b>IOC · LOLBAS · MITRE · YARA · Local TI</b> +
        live enrichment against <b>VirusTotal · AbuseIPDB · OTX · URLScan · Shodan ·
        GreyNoise · Hybrid Analysis · IPinfo · abuse.ch</b>. Nothing gets past a layer
        without a 360° verdict.
      </div>
    </div>
  );
}

function MetricChip({ label, n, color }) {
  const active = (n || 0) > 0;
  return (
    <div
      style={{
        background: active ? color : "#1e293b",
        color: active ? "#fff" : "#64748b",
        border: `1px solid ${active ? color : "#334155"}`,
        padding: "4px 8px", borderRadius: 4, textAlign: "center",
        fontSize: 10, letterSpacing: 0.8, fontWeight: 600,
      }}
    >
      {label} · {n || 0}
    </div>
  );
}

function _liveHitCount(live) {
  if (!live || typeof live !== "object") return 0;
  let n = 0;
  ["ips", "domains", "urls", "hashes"].forEach((k) => {
    for (const row of live[k] || []) {
      if (!row) continue;
      const vt = row.virustotal || {};
      const ab = row.abuseipdb || {};
      const otx = row.otx || {};
      if ((vt.malicious || 0) + (vt.suspicious || 0) > 0) { n++; continue; }
      if ((ab.abuse_confidence_score || 0) > 25)          { n++; continue; }
      if ((otx.pulse_count || (otx.pulses || []).length) > 0) { n++; continue; }
    }
  });
  return n;
}

function _flattenLive(live) {
  if (!live) return [];
  const out = [];
  ["ips", "domains", "urls", "hashes"].forEach((k) => {
    for (const row of live[k] || []) {
      if (!row) continue;
      const badges = [];
      const vt = row.virustotal || {};
      const ab = row.abuseipdb || {};
      const otx = row.otx || {};
      if ((vt.malicious || 0) + (vt.suspicious || 0) > 0) badges.push(`VT:${vt.malicious + (vt.suspicious || 0)}`);
      if ((ab.abuse_confidence_score || 0) > 0) badges.push(`AbuseIPDB:${ab.abuse_confidence_score}%`);
      const pc = otx.pulse_count || (otx.pulses || []).length;
      if (pc) badges.push(`OTX:${pc}`);
      if (badges.length) out.push({ value: row.value, summary: badges.join(" · ") });
    }
  });
  return out;
}
