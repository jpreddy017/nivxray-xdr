import { useState, useMemo } from "react";
import { Copy, X } from "lucide-react";
import FlowGraph from "@/components/FlowGraph";

function severityBadgeClass(sev) {
  return { high: "high", medium: "medium", low: "low", safe: "safe", critical: "high" }[sev] || "neutral";
}

function EmptyState({ label }) {
  return (
    <div
      className="mono"
      style={{ color: "var(--text-mute)", fontSize: 11, padding: "20px 4px", textAlign: "center" }}
    >
      {label}
    </div>
  );
}

export default function ThreatAnalysis({ analysis, loading, selectedTactic = null, onClearTactic = null }) {
  const tabs = ["MITRE", "LOLBAS", "RULES", "IOCs", "TI-HITS", "OSINT", "AI", "FLOW", "CHAIN"];
  const [tab, setTab] = useState("MITRE");

  // Build a technique-id → tactic map from the merged MITRE list.
  // Used to filter LOLBAS entries (whose only tactic linkage is via technique IDs).
  const techniqueToTactic = useMemo(() => {
    const m = {};
    (analysis?.mitre || []).forEach((x) => { if (x.id && x.tactic) m[x.id] = x.tactic; });
    return m;
  }, [analysis?.mitre]);

  return (
    <aside
      className="brut-border threat-panel"
      style={{
        borderRight: "none", borderTop: "none", borderBottom: "none",
        background: "var(--surface)", display: "flex", flexDirection: "column", overflow: "hidden",
      }}
      data-testid="threat-analysis-panel"
    >
      <div
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "12px 14px", borderBottom: "1px solid var(--border)",
        }}
      >
        <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>
          ▸ THREAT ANALYSIS
        </div>
        {analysis?.risk && (
          <span className={`badge ${analysis.risk.level}`} data-testid="risk-badge">
            {analysis.risk.verdict} · {analysis.risk.score}/100
          </span>
        )}
      </div>

      {selectedTactic && (
        <div
          data-testid="ta-tactic-filter-bar"
          style={{
            padding: "8px 14px", background: "rgba(226,126,93,0.08)",
            borderBottom: "1px solid var(--warn)",
            display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap",
          }}
        >
          <span className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.18em" }}>
            FILTER ▸
          </span>
          <span className="badge warn">{selectedTactic}</span>
          <span className="mono" style={{ fontSize: 10, color: "var(--text-mute)", flex: 1 }}>
            MITRE + LOLBAS filtered · IOCs / OSINT / AI unfiltered
          </span>
          <button className="nvx-btn sm ghost" onClick={onClearTactic} data-testid="btn-clear-tactic-filter-panel">
            <X size={11} /> CLEAR
          </button>
        </div>
      )}

      <div style={{ display: "flex", borderBottom: "1px solid var(--border)", background: "var(--inset)", flexWrap: "wrap" }}>
        {tabs.map((t) => (
          <button
            key={t}
            className={`nvx-tab ${tab === t ? "active" : ""}`}
            onClick={() => setTab(t)}
            data-testid={`tab-${t.toLowerCase().replace(/[^a-z0-9]/g, "-")}`}
          >
            {t}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: 14 }} data-testid={`tab-content-${tab.toLowerCase().replace(/[^a-z0-9]/g, "-")}`}>
        {loading && (
          <div className="mono" style={{ color: "var(--text-dim)", fontSize: 12 }}>
            Running analysis<span className="blink">_</span>
          </div>
        )}
        {!loading && !analysis && (
          <EmptyState label="No analysis yet — run a recipe or press AUTO-INVESTIGATE." />
        )}

        {analysis && tab === "MITRE" && <MitreTab items={analysis.mitre} selectedTactic={selectedTactic} />}
        {analysis && tab === "LOLBAS" && <LolbasTab items={analysis.lolbas} selectedTactic={selectedTactic} techniqueToTactic={techniqueToTactic} />}
        {analysis && tab === "RULES" && <RulesTab items={analysis.yara} />}
        {analysis && tab === "IOCs" && <IocTab iocs={analysis.iocs} />}
        {analysis && tab === "TI-HITS" && <TiHitsTab hits={analysis.ti_hits} />}
        {analysis && tab === "OSINT" && <OsintTab osint={analysis.osint} />}
        {analysis && tab === "AI" && <AiTab desc={analysis.description} verdict={analysis.ai_verdict} />}
        {analysis && tab === "FLOW" && <FlowTab description={analysis.description} />}
        {analysis && tab === "CHAIN" && <ChainTab chain={analysis.chain || []} />}
      </div>
    </aside>
  );
}

function MitreTab({ items = [], selectedTactic = null }) {
  const filtered = selectedTactic ? items.filter((m) => (m.tactic || "Unknown") === selectedTactic) : items;
  if (!items.length) return <EmptyState label="No MITRE ATT&CK techniques matched" />;
  if (!filtered.length) return <EmptyState label={`No MITRE techniques for tactic "${selectedTactic}"`} />;
  const byTactic = filtered.reduce((acc, m) => {
    (acc[m.tactic || "Unknown"] ||= []).push(m);
    return acc;
  }, {});
  return (
    <div className="stagger">
      {Object.entries(byTactic).map(([tactic, list]) => (
        <div key={tactic} style={{ marginBottom: 14 }}>
          <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.18em", marginBottom: 6 }}>
            {tactic.toUpperCase()}
          </div>
          {list.map((m) => (
            <div key={m.id} className="brut-border" style={{ padding: "8px 10px", marginBottom: 6, background: "var(--inset)" }} data-testid={`mitre-${m.id}`}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                <span className="mono" style={{ fontSize: 11, color: "var(--accent)" }}>{m.id}</span>
                <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  {m.source === "ai" && <span className="badge warn" title="Derived by AI from decoded behavior">AI</span>}
                  <a className="mono" style={{ fontSize: 10, color: "var(--text-mute)", textDecoration: "none" }}
                     href={`https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`} target="_blank" rel="noreferrer">
                    attack.mitre.org ↗
                  </a>
                </span>
              </div>
              <div className="mono" style={{ fontSize: 12, color: "var(--text)", marginTop: 4 }}>{m.technique}</div>
              {m.evidence && (
                <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 4, borderLeft: "2px solid var(--warn)", paddingLeft: 6, background: "rgba(226,126,93,0.05)" }}>
                  <span style={{ color: "var(--warn)" }}>evidence:</span> {m.evidence}
                </div>
              )}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function LolbasTab({ items = [], selectedTactic = null, techniqueToTactic = {} }) {
  const filtered = selectedTactic
    ? items.filter((l) => (l.mitre || []).some((tid) => techniqueToTactic[tid] === selectedTactic))
    : items;
  if (!items.length) return <EmptyState label="No LOLBAS-listed binaries detected" />;
  if (!filtered.length) return <EmptyState label={`No LOLBAS matches for tactic "${selectedTactic}"`} />;
  return (
    <div className="stagger">
      <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.18em", marginBottom: 8 }}>
        {filtered.length} MATCH{filtered.length > 1 ? "ES" : ""} · LIVING OFF THE LAND BINARIES
      </div>
      {filtered.map((l, i) => (
        <div key={i} className="brut-border" style={{ padding: 10, marginBottom: 8, background: "var(--inset)" }} data-testid={`lolbas-${l.binary}`}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
            <span className="mono" style={{ fontSize: 12, color: "var(--warn)", fontWeight: 700 }}>{l.binary}</span>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              {l.custom && (
                <span className="badge warn" data-testid={`lolbas-custom-${l.model_id || i}`} title={l.model_name ? `Custom rule: ${l.model_name}` : "Custom rule"}>
                  ✦ CUSTOM
                </span>
              )}
              {l.url && (
                <a href={l.url} target="_blank" rel="noreferrer" className="mono" style={{ fontSize: 10, color: "var(--text-mute)", textDecoration: "none" }}>
                  lolbas-project ↗
                </a>
              )}
            </div>
          </div>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 6 }}>
            {l.purposes.map((p) => <span key={p} className="badge">{p}</span>)}
            {l.mitre.map((t) => <span key={t} className="badge warn">{t}</span>)}
          </div>
          <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>{l.description}</div>
          <pre className="mono" style={{
            margin: "6px 0 0 0", fontSize: 10, color: "var(--text-mute)",
            background: "transparent", whiteSpace: "pre-wrap", wordBreak: "break-all",
          }}>{l.snippet}</pre>
        </div>
      ))}
    </div>
  );
}

function FlowTab({ description }) {
  const chain = description?.attack_chain || [];
  const fallbackGraph = description?.flow_graph;

  if (!chain.length && (!fallbackGraph || !fallbackGraph.nodes?.length)) {
    return <EmptyState label="No attack chain — run AUTO INVESTIGATE / AI DESCRIBE to generate the sequence" />;
  }

  // If AI returned attack_chain: render the rich vertical flowchart.
  if (chain.length) return <AttackChain chain={chain} />;

  // Fallback: render the older node-graph
  return (
    <div>
      <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.18em", marginBottom: 8 }}>
        BEHAVIOR FLOW · {fallbackGraph.nodes.length} STEPS
      </div>
      <FlowGraph nodes={fallbackGraph.nodes} edges={fallbackGraph.edges || []} />
    </div>
  );
}

function AttackChain({ chain }) {
  const KIND_COLOR = {
    ingestion: "#7fb9ff", deobfuscation: "#c0ca33", context: "#8b949e",
    filesystem: "#E27E5D", network: "#7fb9ff", crypto: "#c0ca33",
    execution: "#d96c6c", persistence: "#e27e5d", discovery: "#8b949e",
    c2: "#d96c6c", impact: "#d96c6c",
  };
  return (
    <div className="stagger" data-testid="attack-chain">
      <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.18em", marginBottom: 14 }}>
        DYNAMIC ATTACK CHAIN · {chain.length} STAGES
      </div>
      <div style={{ position: "relative", paddingLeft: 4 }}>
        {/* vertical connector rail */}
        <div
          aria-hidden
          style={{
            position: "absolute", left: 18, top: 12, bottom: 12, width: 2,
            background: "repeating-linear-gradient(180deg,var(--border) 0 6px,transparent 6px 12px)",
          }}
        />
        {chain.map((c, i) => {
          const color = KIND_COLOR[c.kind] || "var(--accent)";
          const isLast = i === chain.length - 1;
          return (
            <div
              key={i}
              data-testid={`attack-step-${i + 1}`}
              style={{ position: "relative", paddingLeft: 46, marginBottom: isLast ? 0 : 18 }}
            >
              {/* number node on the rail */}
              <span
                className="mono"
                style={{
                  position: "absolute", left: 0, top: 4,
                  width: 38, height: 38,
                  display: "inline-flex", alignItems: "center", justifyContent: "center",
                  border: `2px solid ${color}`, color, fontSize: 13, fontWeight: 700,
                  background: "var(--bg)",
                  boxShadow: `0 0 0 4px var(--bg), 0 0 12px ${color}55`,
                  zIndex: 2,
                }}
              >
                {String(c.step ?? i + 1).padStart(2, "0")}
              </span>

              {/* horizontal tick from node to card */}
              <span
                aria-hidden
                style={{
                  position: "absolute", left: 38, top: 22, height: 2, width: 8,
                  background: color,
                }}
              />

              {/* card */}
              <div
                className="brut-border fade-in"
                style={{
                  background: "var(--inset)",
                  borderLeft: `4px solid ${color}`,
                  padding: "12px 14px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
                  <span
                    className="mono"
                    style={{
                      fontSize: 12, fontWeight: 700, letterSpacing: "0.14em",
                      color: "var(--text)", textTransform: "uppercase",
                    }}
                  >
                    {c.title}
                  </span>
                  <span
                    className="badge"
                    style={{
                      marginLeft: "auto", color, borderColor: color, background: "transparent",
                    }}
                  >
                    {c.kind || "step"}
                  </span>
                </div>
                <p className="mono" style={{ fontSize: 12, color: "var(--text-dim)", margin: 0, lineHeight: 1.65 }}>
                  {c.summary}
                </p>
                {c.technical_detail && (
                  <div
                    className="mono"
                    style={{
                      marginTop: 10, padding: "8px 10px", fontSize: 11,
                      color: "var(--warn)", background: "rgba(226,126,93,0.06)",
                      borderLeft: "2px solid var(--warn)", wordBreak: "break-all",
                    }}
                  >
                    <span style={{ color: "var(--text-mute)", letterSpacing: "0.12em", fontSize: 10 }}>ARTIFACT</span>
                    <div style={{ marginTop: 3 }}>{c.technical_detail}</div>
                  </div>
                )}
              </div>

              {/* down arrow between steps */}
              {!isLast && (
                <div
                  aria-hidden
                  style={{
                    position: "absolute", left: 12, bottom: -18, width: 14, height: 18,
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}
                >
                  <span style={{
                    borderLeft: "5px solid transparent",
                    borderRight: "5px solid transparent",
                    borderTop: `7px solid ${color}`,
                    width: 0, height: 0,
                  }} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function RulesTab({ items = [] }) {
  if (!items.length) return <EmptyState label="No YARA-lite rules triggered" />;
  return (
    <div className="stagger">
      {items.map((y, i) => (
        <div key={i} className="brut-border" style={{ padding: "10px 12px", marginBottom: 8, background: "var(--inset)" }} data-testid={`rule-${y.rule}`}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
            <span className="mono" style={{ fontSize: 12, color: "var(--text)" }}>{y.rule}</span>
            <span className={`badge ${severityBadgeClass(y.severity)}`}>{y.severity}</span>
          </div>
          <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 4 }}>{y.description}</div>
          <pre className="mono" style={{ margin: 0, fontSize: 10, color: "var(--text-mute)", background: "transparent", whiteSpace: "pre-wrap" }}>
            {`match: ${y.match}`}
          </pre>
        </div>
      ))}
    </div>
  );
}

function IocTab({ iocs = {} }) {
  const labels = {
    urls: "URLs", ips: "IPs", domains: "Domains", emails: "Emails",
    md5: "MD5", sha1: "SHA1", sha256: "SHA256", bitcoin_addresses: "BTC Addresses",
  };
  const has = Object.values(iocs).some((v) => (v || []).length);
  if (!has) return <EmptyState label="No IOCs extracted" />;
  return (
    <div className="stagger">
      {Object.entries(labels).map(([k, label]) => {
        const arr = iocs[k] || [];
        if (!arr.length) return null;
        return (
          <div key={k} style={{ marginBottom: 10 }}>
            <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.18em", marginBottom: 4 }}>
              {label} · {arr.length}
            </div>
            {arr.map((v) => (
              <div key={v} data-testid={`ioc-${k}-${v}`} className="mono brut-border"
                style={{
                  fontSize: 11, padding: "6px 8px", background: "var(--inset)",
                  color: "var(--text)", marginBottom: 4, wordBreak: "break-all",
                  display: "flex", alignItems: "center", justifyContent: "space-between", gap: 6,
                }}>
                <span>{v}</span>
                <button className="nvx-btn sm ghost" title="Copy" onClick={() => navigator.clipboard.writeText(v)}>
                  <Copy size={11} />
                </button>
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}

function TiHitsTab({ hits = [] }) {
  if (!hits.length) return <EmptyState label="No matches in local Threat-Intel DB — sync feeds via Threat Intel tab" />;
  return (
    <div className="stagger">
      <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.18em", marginBottom: 8 }}>
        {hits.length} HITS ACROSS CURATED FEEDS
      </div>
      {hits.map((h, i) => (
        <div key={i} className="brut-border" style={{ padding: 10, marginBottom: 8, background: "var(--inset)" }} data-testid={`ti-hit-${i}`}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
            <span className="mono" style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.18em" }}>{h.kind}</span>
            <span className={`badge ${severityBadgeClass(h.severity === "critical" ? "high" : h.severity)}`}>{h.severity}</span>
          </div>
          <div className="mono" style={{ fontSize: 11, color: "var(--text)", wordBreak: "break-all", marginTop: 4 }}>{h.value}</div>
          <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 3 }}>
            source: <span style={{ color: "var(--text-dim)" }}>{h.source}</span>
            {h.tags?.length ? <> · tags: {h.tags.slice(0, 3).join(", ")}</> : null}
          </div>
        </div>
      ))}
    </div>
  );
}

function OsintTab({ osint }) {
  if (!osint) return <EmptyState label="OSINT enrichment disabled or unavailable" />;
  if (osint.error) return <div className="mono" style={{ color: "var(--high)", fontSize: 11 }}>Error: {osint.error}</div>;
  const empty = ["ips", "domains", "urls", "hashes"].every((k) => (osint[k] || []).length === 0);
  if (empty) return <EmptyState label="No IOCs to enrich" />;

  return (
    <div>
      {osint.sources_used?.length > 0 && (
        <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginBottom: 10, letterSpacing: "0.08em" }}>
          SOURCES: {osint.sources_used.join(" · ")}
        </div>
      )}
      {(osint.ips || []).map((ip, i) => (
        <div key={i} className="brut-border stagger" style={{ padding: 10, marginBottom: 8, background: "var(--inset)" }} data-testid={`osint-ip-${ip.value}`}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div className="mono" style={{ color: "var(--accent)", fontSize: 12 }}>{ip.value}</div>
            {ip.is_private && <span className="badge safe">PRIVATE</span>}
          </div>
          {ip.geo && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
              {[ip.geo.country, ip.geo.city, ip.geo.isp].filter(Boolean).join(" · ")}
              {ip.geo.hosting && <span className="badge warn" style={{ marginLeft: 8 }}>HOSTING</span>}
              {ip.geo.proxy && <span className="badge high" style={{ marginLeft: 4 }}>PROXY</span>}
            </div>
          )}
          {ip.reverse_dns && <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)" }}>rDNS: {ip.reverse_dns}</div>}
          {ip.virustotal && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
              VT: <span style={{ color: "var(--high)" }}>{ip.virustotal.malicious} malicious</span>
              {" "}· {ip.virustotal.suspicious} suspicious · rep {ip.virustotal.reputation}
            </div>
          )}
          {ip.abuseipdb && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
              AbuseIPDB: <span style={{ color: ip.abuseipdb.abuse_confidence_score > 50 ? "var(--high)" : "var(--text)" }}>
                {ip.abuseipdb.abuse_confidence_score}%</span> confidence · {ip.abuseipdb.total_reports} reports
            </div>
          )}
          {ip.shodan && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
              Shodan: {ip.shodan.ports?.slice(0, 8).join(", ")} · {ip.shodan.org}
            </div>
          )}
          {ip.greynoise && ip.greynoise.classification && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
              GreyNoise: {ip.greynoise.classification}{ip.greynoise.name ? ` · ${ip.greynoise.name}` : ""}
            </div>
          )}
          {ip.otx && ip.otx.pulse_count > 0 && (
            <div className="mono" style={{ fontSize: 11, color: "var(--warn)", marginTop: 2 }}>
              OTX: {ip.otx.pulse_count} pulses
            </div>
          )}
        </div>
      ))}
      {(osint.domains || []).map((d, i) => (
        <div key={i} className="brut-border stagger" style={{ padding: 10, marginBottom: 8, background: "var(--inset)" }} data-testid={`osint-domain-${d.value}`}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div className="mono" style={{ color: "var(--accent)", fontSize: 12, wordBreak: "break-all" }}>{d.value}</div>
            {d.classification?.is_high_risk_tld && <span className="badge warn">HIGH-RISK TLD</span>}
            {d.classification?.is_onion && <span className="badge high">TOR</span>}
          </div>
          {d.resolved_ips?.length > 0 && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
              Resolves: {d.resolved_ips.join(", ")}
            </div>
          )}
          {d.virustotal && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
              VT: <span style={{ color: "var(--high)" }}>{d.virustotal.malicious} malicious</span>
              {" "}· {d.virustotal.suspicious} suspicious
            </div>
          )}
        </div>
      ))}
      {(osint.urls || []).map((u, i) => (
        <div key={i} className="brut-border stagger" style={{ padding: 10, marginBottom: 8, background: "var(--inset)" }} data-testid={`osint-url-${i}`}>
          <div className="mono" style={{ color: "var(--accent)", fontSize: 11, wordBreak: "break-all" }}>{u.value}</div>
          <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 4 }}>
            {u.scheme}://{u.host} {u.is_onion && <span className="badge high" style={{ marginLeft: 4 }}>TOR</span>}
          </div>
          {u.virustotal && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
              VT: <span style={{ color: "var(--high)" }}>{u.virustotal.malicious} malicious</span>
            </div>
          )}
        </div>
      ))}
      {(osint.hashes || []).map((h, i) => (
        <div key={i} className="brut-border stagger" style={{ padding: 10, marginBottom: 8, background: "var(--inset)" }} data-testid={`osint-hash-${h.value}`}>
          <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.16em" }}>{h.algorithm.toUpperCase()}</div>
          <div className="mono" style={{ fontSize: 11, color: "var(--text)", wordBreak: "break-all", marginTop: 3 }}>{h.value}</div>
          {h.virustotal && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
              VT: <span style={{ color: "var(--high)" }}>{h.virustotal.malicious} malicious</span>
              {h.virustotal.threat_label ? ` · ${h.virustotal.threat_label}` : ""}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function AiTab({ desc, verdict }) {
  if (!desc && !verdict) return <EmptyState label="Press AUTO-INVESTIGATE or DESCRIBE for AI analysis" />;
  const fam = desc?.malware_family;
  return (
    <div className="stagger">
      {fam && fam.name && (
        <div className="brut-border" style={{ padding: 12, marginBottom: 12, background: "var(--inset)", borderLeft: "3px solid var(--warn)" }} data-testid="malware-family">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
            <span className="mono" style={{ fontSize: 10, letterSpacing: "0.2em", color: "var(--warn)" }}>MALWARE FAMILY</span>
            <span className={`badge ${fam.confidence === "high" ? "high" : fam.confidence === "medium" ? "medium" : "low"}`}>
              {fam.confidence || "?"} confidence
            </span>
          </div>
          <div style={{ fontFamily: "Chivo", fontWeight: 900, fontSize: 22, color: "var(--text)", marginTop: 8, letterSpacing: "-0.01em" }}>
            {fam.name}
          </div>
          {fam.rationale && (
            <p className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6, lineHeight: 1.6 }}>{fam.rationale}</p>
          )}
        </div>
      )}
      {verdict && !verdict.error && (
        <div className="brut-border" style={{ padding: 12, marginBottom: 12, background: "var(--inset)" }} data-testid="ai-verdict">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span className="mono" style={{ fontSize: 10, letterSpacing: "0.2em", color: "var(--warn)" }}>AI VERDICT</span>
            <span className={`badge ${verdict.verdict === "Malicious" ? "high" : verdict.verdict === "Suspicious" ? "medium" : "safe"}`}>
              {verdict.verdict} · {verdict.confidence}%
            </span>
          </div>
          <p className="mono" style={{ fontSize: 12, color: "var(--text)", marginTop: 8, lineHeight: 1.6 }}>{verdict.summary}</p>
        </div>
      )}
      {desc && !desc.error && (
        <div data-testid="ai-description">
          <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.2em", marginBottom: 6 }}>EXECUTIVE SUMMARY</div>
          <div className="brut-border" style={{ padding: 12, marginBottom: 12, background: "var(--inset)" }}>
            <p className="mono" style={{ fontSize: 12, color: "var(--text)", margin: 0, lineHeight: 1.6 }}>{desc.summary}</p>
          </div>
          {desc.behavior?.length > 0 && (
            <>
              <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.2em", marginBottom: 6 }}>BEHAVIOR</div>
              <ul className="mono" style={{ fontSize: 12, color: "var(--text-dim)", paddingLeft: 18, margin: "0 0 12px 0" }}>
                {desc.behavior.map((b, i) => <li key={i} style={{ marginBottom: 4 }}>{b}</li>)}
              </ul>
            </>
          )}
          {desc.ioc_narrative && (
            <>
              <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.2em", marginBottom: 6 }}>IOC NARRATIVE</div>
              <div className="brut-border" style={{ padding: 12, marginBottom: 12, background: "var(--inset)" }}>
                <p className="mono" style={{ fontSize: 12, color: "var(--text)", margin: 0, lineHeight: 1.6, whiteSpace: "pre-wrap" }}>{desc.ioc_narrative}</p>
              </div>
            </>
          )}
          {desc.attribution_hints && (
            <>
              <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.2em", marginBottom: 6 }}>ATTRIBUTION HINTS</div>
              <div className="brut-border" style={{ padding: 12, marginBottom: 12, background: "var(--inset)" }}>
                <p className="mono" style={{ fontSize: 12, color: "var(--text-dim)", margin: 0, lineHeight: 1.6 }}>{desc.attribution_hints}</p>
              </div>
            </>
          )}
          {desc.recommended_actions?.length > 0 && (
            <>
              <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.2em", marginBottom: 6 }}>RECOMMENDED ACTIONS</div>
              <ul className="mono" style={{ fontSize: 12, color: "var(--accent)", paddingLeft: 18, margin: 0 }}>
                {desc.recommended_actions.map((a, i) => <li key={i} style={{ marginBottom: 4 }}>{a}</li>)}
              </ul>
            </>
          )}
        </div>
      )}
      {desc?.error && <div className="mono" style={{ color: "var(--high)", fontSize: 11 }}>Description error: {desc.error}</div>}
      {verdict?.error && <div className="mono" style={{ color: "var(--high)", fontSize: 11 }}>Verdict error: {verdict.error}</div>}
    </div>
  );
}

function ChainTab({ chain }) {
  if (!chain.length) return <EmptyState label="No decode chain — run a recipe to populate" />;
  return (
    <div className="stagger">
      {chain.map((c, i) => (
        <div key={i} className="brut-border" style={{ padding: 10, marginBottom: 8, background: "var(--inset)" }} data-testid={`chain-step-${i}`}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <div className="mono" style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.18em" }}>
              STEP {String(i + 1).padStart(2, "0")} · {c.op}
            </div>
            {c.custom && (
              <span className="badge warn" data-testid={`chain-custom-badge-${i}`} title={c.model_name ? `Applied from Model Studio recipe: ${c.model_name}` : "Custom recipe"}>
                ✦ CUSTOM {c.model_name ? " · " + c.model_name : ""}
              </span>
            )}
          </div>
          {c.reason && <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>{c.reason}</div>}
          {c.output_preview && (
            <pre className="mono" style={{
              margin: "6px 0 0 0", fontSize: 10, color: "var(--text-mute)",
              background: "transparent", whiteSpace: "pre-wrap", wordBreak: "break-all",
            }}>{c.output_preview.slice(0, 200)}{(c.output_preview.length || 0) > 200 ? "…" : ""}</pre>
          )}
        </div>
      ))}
    </div>
  );
}
