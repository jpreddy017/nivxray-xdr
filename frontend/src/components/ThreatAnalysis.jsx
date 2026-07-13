import { useState } from "react";
import { Copy } from "lucide-react";

function severityBadgeClass(sev) {
  return { high: "high", medium: "medium", low: "low", safe: "safe" }[sev] || "neutral";
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

export default function ThreatAnalysis({ analysis, loading }) {
  const tabs = ["MITRE", "RULES", "IOCs", "TI-HITS", "OSINT", "AI", "CHAIN"];
  const [tab, setTab] = useState("MITRE");

  return (
    <aside
      className="brut-border"
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

        {analysis && tab === "MITRE" && <MitreTab items={analysis.mitre} />}
        {analysis && tab === "RULES" && <RulesTab items={analysis.yara} />}
        {analysis && tab === "IOCs" && <IocTab iocs={analysis.iocs} />}
        {analysis && tab === "TI-HITS" && <TiHitsTab hits={analysis.ti_hits} />}
        {analysis && tab === "OSINT" && <OsintTab osint={analysis.osint} />}
        {analysis && tab === "AI" && <AiTab desc={analysis.description} verdict={analysis.ai_verdict} />}
        {analysis && tab === "CHAIN" && <ChainTab chain={analysis.chain || []} />}
      </div>
    </aside>
  );
}

function MitreTab({ items = [] }) {
  if (!items.length) return <EmptyState label="No MITRE ATT&CK techniques matched" />;
  const byTactic = items.reduce((acc, m) => {
    (acc[m.tactic] ||= []).push(m);
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
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span className="mono" style={{ fontSize: 11, color: "var(--accent)" }}>{m.id}</span>
                <a className="mono" style={{ fontSize: 10, color: "var(--text-mute)", textDecoration: "none" }}
                   href={`https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`} target="_blank" rel="noreferrer">
                  attack.mitre.org ↗
                </a>
              </div>
              <div className="mono" style={{ fontSize: 12, color: "var(--text)", marginTop: 4 }}>{m.technique}</div>
            </div>
          ))}
        </div>
      ))}
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
  return (
    <div className="stagger">
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
          <div className="mono" style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.18em" }}>
            STEP {String(i + 1).padStart(2, "0")} · {c.op}
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
