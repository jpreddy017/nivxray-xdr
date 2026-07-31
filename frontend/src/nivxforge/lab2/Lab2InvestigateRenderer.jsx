/**
 * ADR-0022 · Lab2 renderer for /nivxforge/investigate?lab2=1
 *
 * Runs the CIO through `projectCIO()` and passes the resulting view
 * model to LabV2. This is the ONLY place the CIO is translated for
 * Lab v2 consumption — every panel inside LabV2 renders from `view`.
 *
 * §5: Backend contract unchanged. The Input Understanding Engine
 * (`POST /api/understand`) tells us which pipeline to dispatch to —
 * /decode/smart or /v2/auto-investigate — so the analyst never has
 * to pick manually.
 */
import React, { useCallback, useMemo, useState } from "react";
import api from "../../lib/api";
import { Lab2Provider } from "./Lab2Provider";
import LabV2 from "./LabV2";
import { projectCIO } from "./labv2.projector";
import { SelectionProvider } from "./SelectionBus";
import { EventBusProvider, useEventBus, EVT } from "./EventBus";

// Fallback local heuristic — only used if the backend IUE call fails.
// Same signals as before, kept as a safety net.
function fallbackDetectPipeline(text) {
  const raw = (text || "").trim();
  if (!raw) return "decode";
  const looksLikeJson = /^[[{]/.test(raw) && /[\]}]$/.test(raw);
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
  return (
    <EventBusProvider>
      <SelectionProvider>
        <Lab2InvestigateInner />
      </SelectionProvider>
    </EventBusProvider>
  );
}

function Lab2InvestigateInner() {
  const [cio, setCio] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [understanding, setUnderstanding] = useState(null);   // { type, label, route, confidence, ... }
  const { emit } = useEventBus();

  React.useEffect(() => {
    emit(EVT.INVESTIGATION_STARTED, { source: "lab2" });
  }, [emit]);

  const runAnalyze = useCallback(async (text, modeOverride) => {
    setLoading(true);
    setErr("");
    setCio(null);
    setUnderstanding(null);

    // Step 1 · Ask the backend Input Understanding Engine what this
    // input is. This is the "What did I receive?" question the tool
    // must always answer first (MDR-analyst mental model).
    let iue = null;
    try {
      const u = await api.post("/understand", { input: text });
      iue = u.data || null;
      setUnderstanding(iue);
    } catch (_e) {
      // IUE call failed; degrade to local heuristic. No hard error.
      iue = null;
    }

    // Step 2 · Resolve pipeline from IUE route, unless caller pinned
    // an explicit mode (legacy button behaviour).
    let pipeline;
    if (modeOverride === "auto" || modeOverride === "decode") {
      pipeline = modeOverride;
    } else if (iue && iue.route) {
      pipeline = iue.route === "auto-investigate" ? "auto" : "decode";
    } else {
      pipeline = fallbackDetectPipeline(text);
    }

    emit(EVT.ANALYZE_SUBMITTED, {
      mode: pipeline,
      chars: text.length,
      iue_type: iue?.type || "unknown",
      iue_confidence: iue?.confidence || 0,
    });
    try {
      const r =
        pipeline === "auto"
          ? await api.post("/v2/auto-investigate", { incident_text: text, focus: null })
          : await api.post("/decode/smart", { input: text });
      const nextCio = r.data?.cio || null;
      setCio(nextCio);
      if (nextCio) {
        emit(EVT.CIO_RECEIVED, {
          cio_id: nextCio.cio_id,
          node_count: (nextCio.evidence_graph?.nodes || []).length,
          decode_layers: (nextCio.decode_chain || []).length,
          verdict: nextCio.verdict?.label,
        });
      }
    } catch (e) {
      const msg = e?.friendlyMessage || e?.response?.data?.detail || String(e?.message || e);
      setErr(msg);
      emit(EVT.ERROR_RAISED, { where: "runAnalyze", message: msg });
    } finally {
      setLoading(false);
    }
  }, [emit]);

  const { view } = useMemo(() => projectCIO(cio), [cio]);

  // Attach the IUE result to the view so LabV2's topbar can show
  // the analyst-facing label instead of the raw input_kind.
  const enrichedView = useMemo(() => {
    if (!understanding) return view;
    return {
      ...view,
      understanding,
      // Prefer the IUE label if present — analysts recognise "Cisco
      // XDR Incident" more than a generic "TEXT" badge. Uppercase to
      // match the topbar visual style.
      inputType: String(understanding.label || view.inputType || "").toUpperCase(),
    };
  }, [view, understanding]);

  return (
    <Lab2Provider initialCIO={cio}>
      <LabV2
        view={enrichedView}
        onAnalyze={runAnalyze}
        isAnalyzing={loading}
        analyzeError={err}
      />
    </Lab2Provider>
  );
}
