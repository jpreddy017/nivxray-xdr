/**
 * ADR-0022 · Lab2 renderer for /nivxforge/investigate?lab2=1
 *
 * Mounts the LabV2 investigation workspace. The Lab2Provider stays
 * so downstream slices can reach workspace-level state, but the
 * intake experience now lives INSIDE LabV2 (Enhancement I) — one
 * textarea, no dropdown, content-aware routing owned by the same
 * backend the legacy renderer uses.
 */
import React, { useCallback, useState } from "react";
import api from "../../lib/api";
import { Lab2Provider } from "./Lab2Provider";
import LabV2 from "./LabV2";

// Copied verbatim from legacy renderer (ADR-0014 · Phase 1 content-based
// routing). We do NOT reimplement or diverge — one pipeline, two
// renderers.
function detectPipeline(text) {
  const raw = (text || "").trim();
  if (!raw) return "decode";
  const looksLikeJson = /^[\[{]/.test(raw) && /[\]}]$/.test(raw);
  if (looksLikeJson) {
    const vendorSignals =
      /"(connector_guid|computer|detection|falcon|CrowdStrike|Defender|SecurityAlert|QRadar|SentinelOne|threat_name|SHA256|sha256|ExecutedMalware|amp\.cisco\.com|xdr\.us\.security\.cisco\.com|Sysmon)"/i;
    if (vendorSignals.test(raw)) return "auto";
    if (/"(incident|alert|host|user|process|command_line|src_ip|dst_ip|hash)"/i.test(raw)) return "auto";
  }
  const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const incidentSignals =
    /\b(incident|alert|detection|malware|SIEM|SOC|IOC|SHA256|MD5|host\s*=|user\s*=|process\s*=|src_ip|dst_ip|ExecutedMalware|Quarantine|Cisco Secure|CrowdStrike|Falcon|Defender|QRadar|Splunk|SentinelOne|Sysmon)\b/i;
  if (incidentSignals.test(raw)) return "auto";
  if (lines.length >= 3) return "auto";
  return "decode";
}

export default function Lab2InvestigateRenderer() {
  const [cio, setCio] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const runAnalyze = useCallback(async (text) => {
    setLoading(true);
    setErr("");
    setCio(null);
    const pipeline = detectPipeline(text);
    try {
      const r =
        pipeline === "auto"
          ? await api.post("/v2/auto-investigate", { incident_text: text, focus: null })
          : await api.post("/decode/smart", { input: text });
      setCio(r.data?.cio || null);
    } catch (e) {
      setErr(e?.friendlyMessage || e?.response?.data?.detail || String(e?.message || e));
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <Lab2Provider initialCIO={cio}>
      <LabV2 onAnalyze={runAnalyze} isAnalyzing={loading} analyzeError={err} />
    </Lab2Provider>
  );
}
