import { useState, useEffect } from "react";
import { Save, Download, Database } from "lucide-react";
import api from "@/lib/api";

/**
 * ThreatIntelAdminPanel — Feb-2026 #6 + #8 admin controls:
 *   - VirusTotal / OTX / AbuseIPDB key configuration + enable toggles
 *   - Fine-tune dataset summary + JSONL download
 */
export default function ThreatIntelAdminPanel() {
  const [cfg, setCfg] = useState({});
  const [summary, setSummary] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");

  useEffect(() => {
    api.get("/threat-intel/config").then((r) => setCfg(r.data.config || {})).catch(() => {});
    api.get("/admin/finetune/dataset/summary").then((r) => setSummary(r.data)).catch(() => {});
  }, []);

  const update = (k, v) => setCfg((s) => ({ ...s, [k]: v }));

  const save = async () => {
    setSaving(true);
    setSaveMsg("");
    try {
      const payload = { ...cfg };
      ["virustotal_api_key", "otx_api_key", "abuseipdb_api_key"].forEach((k) => {
        if (typeof payload[k] === "string" && payload[k].startsWith("*")) delete payload[k];
      });
      const r = await api.post("/threat-intel/config", payload);
      setCfg(r.data.config || {});
      setSaveMsg("Saved.");
      setTimeout(() => setSaveMsg(""), 3000);
    } catch (e) {
      setSaveMsg(`Error: ${e.response?.data?.detail || e.message}`);
    } finally {
      setSaving(false);
    }
  };

  const downloadDataset = () => {
    // Streaming JSONL — trigger a browser download via a hidden auth link.
    // api.defaults.baseURL includes /api prefix; we need the same for the file.
    const url = `${api.defaults.baseURL}/admin/finetune/dataset.jsonl`;
    const token = localStorage.getItem("token") || "";
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => res.blob())
      .then((blob) => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "nivxray_finetune.jsonl";
        a.click();
      });
  };

  return (
    <div className="nvx-card" data-testid="threat-intel-admin-panel" style={{ marginBottom: 16 }}>
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <span className="dot" />
          THREAT INTELLIGENCE + FINE-TUNING DATA
        </div>
        <div style={{ marginLeft: "auto", fontSize: 10, color: "#94a3b8" }}>
          VT / OTX / AbuseIPDB · JSONL export
        </div>
      </div>
      <div className="nvx-card-body">
        {/* Threat Intel keys */}
        <div style={{ fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 8, letterSpacing: 0.5 }}>
          THREAT INTEL PROVIDERS
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 10, alignItems: "center", marginBottom: 12 }}>
          {[
            { key: "virustotal", api: "virustotal_api_key", enable: "enable_virustotal", label: "VirusTotal" },
            { key: "otx", api: "otx_api_key", enable: "enable_otx", label: "AlienVault OTX" },
            { key: "abuseipdb", api: "abuseipdb_api_key", enable: "enable_abuseipdb", label: "AbuseIPDB (IPs only)" },
          ].map((p) => (
            <>
              <label key={`${p.key}-lbl`} style={{ fontSize: 11, color: "#c9d1d9" }}>{p.label}</label>
              <input
                key={`${p.key}-input`}
                type="password"
                className="nvx-input"
                placeholder="API key"
                value={cfg[p.api] || ""}
                onChange={(e) => update(p.api, e.target.value)}
                data-testid={`ti-${p.key}-key`}
              />
              <label key={`${p.key}-tog`} style={{ fontSize: 11, color: "#94a3b8", display: "flex", alignItems: "center", gap: 4 }}>
                <input
                  type="checkbox"
                  checked={!!cfg[p.enable]}
                  onChange={(e) => update(p.enable, e.target.checked)}
                  data-testid={`ti-${p.key}-enable`}
                />
                enabled
              </label>
            </>
          ))}
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 20 }}>
          <button
            className="nvx-btn sm"
            onClick={save}
            disabled={saving}
            data-testid="ti-save"
          >
            <Save size={12} /> {saving ? "SAVING…" : "SAVE"}
          </button>
          {saveMsg && (
            <span style={{ fontSize: 11, color: saveMsg.startsWith("Error") ? "#f87171" : "#7ee3c9" }}>
              {saveMsg}
            </span>
          )}
          <span style={{ fontSize: 11, color: "#94a3b8", marginLeft: "auto" }}>
            Cache TTL: 60min · Analysts can click any IOC chip in Candidate Explorer to enrich.
          </span>
        </div>

        {/* Fine-tune dataset */}
        <div style={{ fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 8, letterSpacing: 0.5 }}>
          <Database size={12} style={{ display: "inline", marginRight: 4 }} />
          OFFLINE FINE-TUNING DATASET
        </div>
        {summary && (
          <div style={{ fontSize: 11, color: "#c9d1d9", marginBottom: 8 }}>
            <div style={{ display: "flex", gap: 16, marginBottom: 6 }}>
              <span>
                regression_corpus:{" "}
                <b style={{ color: "#7ee3c9" }}>{summary.counts.regression_corpus}</b>
              </span>
              <span>
                sample_library:{" "}
                <b style={{ color: "#7ee3c9" }}>{summary.counts.sample_library}</b>
              </span>
              <span>
                learning_events:{" "}
                <b style={{ color: "#7ee3c9" }}>{summary.counts.learning_events}</b>
              </span>
              <span>
                TOTAL: <b style={{ color: "#c9d1d9" }}>{summary.total_before_dedupe}</b>
              </span>
            </div>
            <div style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace" }}>
              Schema:{" "}
              {"{"}id, source, instruction, input, expected_output, expected_chain, notes, created_at{"}"}
            </div>
          </div>
        )}
        <button
          className="nvx-btn sm"
          onClick={downloadDataset}
          data-testid="finetune-download"
        >
          <Download size={12} /> DOWNLOAD JSONL
        </button>
      </div>
    </div>
  );
}
