import { useState, useEffect } from "react";
import { Save, ShieldQuestion } from "lucide-react";
import api from "@/lib/api";

/**
 * EnrichmentAdminPanel — Feb-2026 #6 config UI for VT / OTX / AbuseIPDB.
 */
export default function EnrichmentAdminPanel() {
  const [cfg, setCfg] = useState({});
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    api.get("/enrichment/config").then((r) => setCfg(r.data.config || {})).catch(() => {});
  }, []);

  const update = (k, v) => setCfg((s) => ({ ...s, [k]: v }));

  const save = async () => {
    setSaving(true);
    setMsg("");
    try {
      const payload = { ...cfg };
      // Drop redacted "*****" tokens on save so we don't overwrite with stars
      ["vt_api_key", "otx_api_key", "abuseipdb_api_key"].forEach((k) => {
        if (typeof payload[k] === "string" && payload[k].startsWith("*")) {
          delete payload[k];
        }
      });
      const r = await api.post("/enrichment/config", payload);
      setCfg(r.data.config || {});
      setMsg("Saved.");
      setTimeout(() => setMsg(""), 3000);
    } catch (e) {
      setMsg(`Error: ${e.response?.data?.detail || e.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="nvx-card" data-testid="enrichment-admin-panel" style={{ marginBottom: 16 }}>
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <span className="dot" />
          THREAT-INTEL ENRICHMENT
        </div>
        <div style={{ marginLeft: "auto", fontSize: 10, color: "#94a3b8" }}>
          VirusTotal · AlienVault OTX · AbuseIPDB
        </div>
      </div>
      <div className="nvx-card-body">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            VIRUSTOTAL API KEY
            <input
              type="password"
              className="nvx-input"
              value={cfg.vt_api_key || ""}
              onChange={(e) => update("vt_api_key", e.target.value)}
              placeholder="sk-*"
              data-testid="enrichment-vt-key"
            />
          </label>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            <input
              type="checkbox"
              checked={cfg.enable_vt !== false}
              onChange={(e) => update("enable_vt", e.target.checked)}
              style={{ marginRight: 6 }}
              data-testid="enrichment-vt-enable"
            />
            Enable VirusTotal lookups
          </label>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            ALIENVAULT OTX API KEY
            <input
              type="password"
              className="nvx-input"
              value={cfg.otx_api_key || ""}
              onChange={(e) => update("otx_api_key", e.target.value)}
              data-testid="enrichment-otx-key"
            />
          </label>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            <input
              type="checkbox"
              checked={cfg.enable_otx !== false}
              onChange={(e) => update("enable_otx", e.target.checked)}
              style={{ marginRight: 6 }}
              data-testid="enrichment-otx-enable"
            />
            Enable OTX lookups
          </label>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            ABUSEIPDB API KEY
            <input
              type="password"
              className="nvx-input"
              value={cfg.abuseipdb_api_key || ""}
              onChange={(e) => update("abuseipdb_api_key", e.target.value)}
              data-testid="enrichment-abuseipdb-key"
            />
          </label>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            <input
              type="checkbox"
              checked={cfg.enable_abuseipdb !== false}
              onChange={(e) => update("enable_abuseipdb", e.target.checked)}
              style={{ marginRight: 6 }}
              data-testid="enrichment-abuseipdb-enable"
            />
            Enable AbuseIPDB lookups (IPv4 only)
          </label>
          <label style={{ fontSize: 11, color: "#94a3b8", gridColumn: "1 / -1" }}>
            CACHE TTL (hours)
            <input
              type="number"
              min="1"
              max="720"
              className="nvx-input"
              value={cfg.cache_ttl_hours || 24}
              onChange={(e) => update("cache_ttl_hours", parseInt(e.target.value || "24", 10))}
              style={{ maxWidth: 120 }}
              data-testid="enrichment-cache-ttl"
            />
          </label>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            className="nvx-btn sm"
            onClick={save}
            disabled={saving}
            data-testid="enrichment-save"
          >
            <Save size={12} /> {saving ? "SAVING…" : "SAVE CONFIG"}
          </button>
          {msg && (
            <span style={{ fontSize: 11, color: msg.startsWith("Error") ? "#f87171" : "#7ee3c9" }}>
              {msg}
            </span>
          )}
        </div>
        <div
          style={{
            marginTop: 12, padding: 10, background: "rgba(148,163,184,0.06)",
            borderRadius: 4, fontSize: 11, color: "#94a3b8", lineHeight: 1.5,
          }}
        >
          <ShieldQuestion size={12} style={{ marginRight: 4, verticalAlign: -2 }} />
          Get API keys: <b>VirusTotal</b> → virustotal.com/gui/join-us · <b>OTX</b> → otx.alienvault.com/api ·
          <b> AbuseIPDB</b> → abuseipdb.com/register. Without a key the provider returns
          <b> no-key</b> cleanly and the aggregate verdict falls back to the others.
        </div>
      </div>
    </div>
  );
}
