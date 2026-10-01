/**
 * AnalystQuickActions — RC4.5.7 UX pack (Feb 21, 2026)
 *
 * Three high-ROI analyst-velocity features, ZERO decoder engine changes:
 *   1. "Explain like a CISO" — plain-language summary synthesized from the
 *      already-computed verdict + family + IOCs. No LLM call.
 *   2. Copy-as-block-rule buttons — one click per IOC gives the analyst
 *      firewall / EDR / SIEM-ready detection strings on the clipboard.
 *   3. Confidence breakdown chip — visualises the RiskContribution list
 *      that lives in verdict_card.contributions but was never surfaced.
 *
 * Props
 *   result:       full /api/decode/smart response OR case document
 *   className:    optional wrapper class
 *
 * Design contract:
 *   • Every button has a stable data-testid
 *   • Pure computation from existing fields — no new backend calls
 *   • Fails silently if a field is missing (defensive)
 */
import { useMemo, useState } from "react";
import { Copy, Check, ShieldAlert, FileText, Zap } from "lucide-react";

// ─── 1. CISO summary synthesizer ─────────────────────────────────────
function _cisoSummary(result) {
  if (!result) return null;
  const vc = result.verdict_card || {};
  const verdict = vc.label || result.verdict || "Undecoded";
  const conf = vc.confidence ?? result.confidence ?? 0;
  const family = (result.family || vc.family || {}).name || result.family_name;
  const iocs = result.iocs || {};
  const ips = iocs.ips || [];
  const urls = iocs.urls || [];
  const domains = iocs.domains || [];
  const mitre = (result.mitre || []).slice(0, 3).map((m) => m.id || m).filter(Boolean);
  const reachedShellcode = !!result.reached_shellcode;

  // Verdict opener
  let opener = "";
  if (verdict === "Malicious") opener = `This is a confirmed malicious payload (${conf}% confidence).`;
  else if (verdict === "Suspicious") opener = `This payload shows suspicious behaviour and needs review (${conf}% confidence).`;
  else if (verdict === "Benign") opener = "This payload appears benign after analysis.";
  else if (verdict === "Undecoded") opener = "The engine could not fully decode this payload.";
  else opener = `The engine returned a ${verdict} verdict (${conf}% confidence).`;

  // What it does
  const actions = [];
  if (family) actions.push(`identified as **${family}** malware family`);
  if (reachedShellcode) actions.push("reaches raw shellcode (final-stage code execution)");
  if (urls.length) actions.push(`contacts ${urls.length} external URL${urls.length > 1 ? "s" : ""}`);
  if (ips.length) actions.push(`connects to ${ips.length} C2 IP${ips.length > 1 ? "s" : ""}`);
  if (domains.length && !urls.length) actions.push(`resolves ${domains.length} domain${domains.length > 1 ? "s" : ""}`);
  if (mitre.length) actions.push(`maps to MITRE ${mitre.join(", ")}`);

  const actionSentence = actions.length
    ? `It ${actions.join("; ")}.`
    : "The engine did not extract any actionable indicators.";

  // Recommended action
  let recommend = "";
  if (verdict === "Malicious") {
    if (ips.length || urls.length) {
      recommend = `Recommend: block the extracted C2 indicators at the perimeter and hunt for these IOCs across your fleet.`;
    } else {
      recommend = `Recommend: raise an incident and share these findings with the IR team.`;
    }
  } else if (verdict === "Suspicious") {
    recommend = `Recommend: analyst review and additional context gathering before actioning.`;
  } else if (verdict === "Undecoded") {
    recommend = `Recommend: request a live sandbox detonation via Any.Run or Joe Sandbox.`;
  }
  return { opener, actionSentence, recommend };
}

// ─── 2. Block-rule generator per IOC ─────────────────────────────────
function _blockRules(kind, value) {
  const rules = {};
  if (kind === "ip") {
    rules["Firewall (Cisco ASA)"] = `access-list DENY_C2 deny ip any host ${value}`;
    rules["iptables"] = `iptables -A OUTPUT -d ${value} -j DROP`;
    rules["KQL (Sentinel)"] = `DeviceNetworkEvents | where RemoteIP == "${value}"`;
    rules["Splunk"] = `index=* dest_ip="${value}" | stats count by src_ip, user`;
    rules["Elastic EQL"] = `network where destination.ip == "${value}"`;
    rules["Sigma"] = `detection:\n  selection:\n    DestinationIp: '${value}'\n  condition: selection`;
  } else if (kind === "domain") {
    rules["DNS Sinkhole"] = `${value} A 127.0.0.1`;
    rules["KQL (Sentinel)"] = `DeviceNetworkEvents | where RemoteUrl contains "${value}"`;
    rules["Splunk"] = `index=* dest_host="*${value}*" | stats count`;
    rules["Sigma"] = `detection:\n  selection:\n    QueryName|contains: '${value}'\n  condition: selection`;
  } else if (kind === "url") {
    rules["Proxy Blocklist"] = value;
    rules["KQL (Sentinel)"] = `DeviceNetworkEvents | where RemoteUrl == "${value}"`;
    rules["Sigma"] = `detection:\n  selection:\n    c-uri: '${value}'\n  condition: selection`;
  } else if (kind === "hash") {
    rules["EDR Blocklist"] = value;
    rules["KQL (Sentinel)"] = `DeviceFileEvents | where SHA256 == "${value}"`;
    rules["Sigma"] = `detection:\n  selection:\n    Hashes|contains: '${value}'\n  condition: selection`;
    rules["YARA"] = `rule NivXRay_Hash_Match {\n  condition:\n    hash.sha256(0, filesize) == "${value}"\n}`;
  }
  return rules;
}

function CopyBlockRuleButton({ kind, value }) {
  const [copied, setCopied] = useState(false);
  const [open, setOpen] = useState(false);
  const rules = useMemo(() => _blockRules(kind, value), [kind, value]);
  const doCopy = (fmt, text) => {
    navigator.clipboard.writeText(text);
    setCopied(fmt);
    setTimeout(() => setCopied(false), 1600);
  };
  return (
    <div className="inline-block relative">
      <button
        data-testid={`copy-block-rule-${kind}-${value}`.replace(/[^\w-]/g, "_").slice(0, 60)}
        onClick={() => setOpen((v) => !v)}
        className="text-[10px] uppercase tracking-wider px-2 py-1 border border-slate-700/40 rounded hover:bg-slate-800/60 hover:border-cyan-500/40 transition"
        title="Copy detection/block rule to clipboard"
      >
        <Zap className="w-3 h-3 inline mr-1" /> Rules
      </button>
      {open && (
        <div className="absolute z-50 mt-1 right-0 w-72 bg-slate-900/95 border border-slate-700 rounded-lg shadow-xl backdrop-blur">
          <div className="px-3 py-2 text-[11px] text-cyan-400 border-b border-slate-800 font-mono">
            {kind.toUpperCase()} · {value.slice(0, 30)}{value.length > 30 ? "…" : ""}
          </div>
          <ul className="py-1 max-h-72 overflow-y-auto">
            {Object.entries(rules).map(([fmt, text]) => (
              <li key={fmt}>
                <button
                  onClick={() => doCopy(fmt, text)}
                  className="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-800/80 flex items-center justify-between"
                  data-testid={`copy-${kind}-${fmt.replace(/\W/g, "_")}`}
                >
                  <span className="text-slate-300">{fmt}</span>
                  {copied === fmt ? (
                    <Check className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3 text-slate-500" />
                  )}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ─── 3. Confidence breakdown mini-bar ────────────────────────────────
function ConfidenceBreakdown({ contributions, total }) {
  if (!contributions || !contributions.length) return null;
  return (
    <div className="mt-3" data-testid="confidence-breakdown">
      <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">
        Confidence Breakdown · {total}/100
      </div>
      <div className="flex h-2 rounded-full overflow-hidden bg-slate-800/60">
        {contributions.map((c, i) => (
          <div
            key={i}
            style={{
              width: `${(c.points / 100) * 100}%`,
              backgroundColor:
                c.source?.includes("family") ? "#f87171" :
                c.source?.includes("mitre")  ? "#fb923c" :
                c.source?.includes("lolbas") ? "#f59e0b" :
                c.source?.includes("ioc")    ? "#7ee3c9" :
                "#94a3b8",
            }}
            title={`${c.source}: ${c.points} pts — ${c.detail || ""}`}
          />
        ))}
      </div>
      <ul className="mt-2 space-y-0.5">
        {contributions.map((c, i) => (
          <li key={i} className="text-[11px] text-slate-400 flex justify-between font-mono">
            <span className="truncate">
              {c.source}
              {c.detail ? <span className="text-slate-600"> · {String(c.detail).slice(0, 60)}</span> : null}
            </span>
            <span className="text-cyan-400 ml-2">+{c.points}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ─── Main component ──────────────────────────────────────────────────
export default function AnalystQuickActions({ result, className = "" }) {
  // Hooks MUST be called unconditionally — see rules-of-hooks.
  // We gate rendering below via early-return AFTER all hooks have run.
  const ciso = useMemo(() => (result ? _cisoSummary(result) : null), [result]);

  if (!result) return null;
  const vc = result.verdict_card || {};
  const contributions = vc.contributions || vc.risk_contributions || [];
  const totalConf = vc.confidence ?? result.confidence ?? 0;
  const iocs = result.iocs || {};
  const ipList = iocs.ips || [];
  const domainList = iocs.domains || [];
  const urlList = iocs.urls || [];
  const hashList = [
    ...((iocs.hashes || {}).md5 || []),
    ...((iocs.hashes || {}).sha1 || []),
    ...((iocs.hashes || {}).sha256 || []),
  ];
  const hasIOCs = ipList.length + domainList.length + urlList.length + hashList.length > 0;

  return (
    <div className={`space-y-4 ${className}`} data-testid="analyst-quick-actions">
      {/* CISO summary */}
      {ciso && (ciso.opener || ciso.actionSentence) && (
        <div
          className="p-3 rounded-lg border border-cyan-900/40 bg-cyan-950/20"
          data-testid="ciso-summary"
        >
          <div className="flex items-center gap-2 mb-1.5">
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-[10px] uppercase tracking-wider text-cyan-400 font-semibold">
              Executive Summary
            </span>
          </div>
          <p className="text-sm text-slate-200 leading-relaxed">
            {ciso.opener} {ciso.actionSentence}
          </p>
          {ciso.recommend && (
            <p className="text-xs text-cyan-300/80 mt-1.5 italic">{ciso.recommend}</p>
          )}
        </div>
      )}

      {/* Confidence breakdown */}
      {contributions.length > 0 && (
        <ConfidenceBreakdown contributions={contributions} total={totalConf} />
      )}

      {/* Copy-as-block-rule per IOC */}
      {hasIOCs && (
        <div data-testid="block-rules-panel">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">
            One-Click Detection Rules · {ipList.length + domainList.length + urlList.length + hashList.length} IOCs
          </div>
          <ul className="space-y-1.5">
            {ipList.map((ip) => (
              <li key={ip} className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-300">
                  <ShieldAlert className="w-3 h-3 inline mr-1 text-red-400" />
                  {ip}
                  <span className="ml-2 text-[9px] text-slate-600 uppercase">IP</span>
                </span>
                <CopyBlockRuleButton kind="ip" value={ip} />
              </li>
            ))}
            {domainList.slice(0, 8).map((d) => (
              <li key={d} className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-300">
                  <ShieldAlert className="w-3 h-3 inline mr-1 text-amber-400" />
                  {d}
                  <span className="ml-2 text-[9px] text-slate-600 uppercase">Domain</span>
                </span>
                <CopyBlockRuleButton kind="domain" value={d} />
              </li>
            ))}
            {urlList.slice(0, 6).map((u) => (
              <li key={u} className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-300 truncate max-w-[280px]">
                  <ShieldAlert className="w-3 h-3 inline mr-1 text-orange-400" />
                  {u}
                  <span className="ml-2 text-[9px] text-slate-600 uppercase">URL</span>
                </span>
                <CopyBlockRuleButton kind="url" value={u} />
              </li>
            ))}
            {hashList.slice(0, 4).map((h) => (
              <li key={h} className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-300 truncate max-w-[280px]">
                  <ShieldAlert className="w-3 h-3 inline mr-1 text-purple-400" />
                  {h.slice(0, 24)}…
                  <span className="ml-2 text-[9px] text-slate-600 uppercase">Hash</span>
                </span>
                <CopyBlockRuleButton kind="hash" value={h} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
