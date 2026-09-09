import { useState, useEffect } from "react";
import { Save, TestTube2, Send, ExternalLink } from "lucide-react";
import api from "@/lib/api";

/**
 * TaxiiAdminPanel — Feb-2026 P1 UI for configuring the TAXII 2.1 push target.
 *
 * Renders inside AdminPage. Lets the admin:
 *   - Set server URL, collection ID, api root
 *   - Choose auth type (none / basic / bearer / header)
 *   - Test the connection (hits /taxii2/ discovery endpoint)
 *   - View recent push history
 */
export default function TaxiiAdminPanel() {
  const [cfg, setCfg] = useState({});
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    api.get("/admin/taxii/config").then((r) => setCfg(r.data.config || {})).catch(() => {});
    api.get("/admin/taxii/history?limit=10").then((r) => setHistory(r.data.events || [])).catch(() => {});
  }, []);

  const update = (k, v) => setCfg((s) => ({ ...s, [k]: v }));

  const save = async () => {
    setSaving(true);
    setSaveMsg("");
    try {
      const payload = { ...cfg };
      // Drop redacted stars from token/password fields when unchanged
      ["token", "password", "auth_header_value"].forEach((k) => {
        if (typeof payload[k] === "string" && payload[k].startsWith("*")) {
          delete payload[k];
        }
      });
      const r = await api.post("/admin/taxii/config", payload);
      setCfg(r.data.config || {});
      setSaveMsg("Saved.");
      setTimeout(() => setSaveMsg(""), 3000);
    } catch (e) {
      setSaveMsg(`Error: ${e.response?.data?.detail || e.message}`);
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const r = await api.post("/admin/taxii/test", {});
      setTestResult(r.data);
    } catch (e) {
      setTestResult({ ok: false, error: e.response?.data?.detail || e.message });
    } finally {
      setTesting(false);
    }
  };

  const refreshHistory = async () => {
    const r = await api.get("/admin/taxii/history?limit=10");
    setHistory(r.data.events || []);
  };

  return (
    <div className="nvx-card" data-testid="taxii-admin-panel" style={{ marginBottom: 16 }}>
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <span className="dot" />
          TAXII 2.1 PUSH
        </div>
        <div style={{ marginLeft: "auto", fontSize: 10, color: "#94a3b8" }}>
          STIX 2.1 · Publish IOCs to your TAXII server
        </div>
      </div>
      <div className="nvx-card-body">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            SERVER URL
            <input
              className="nvx-input"
              placeholder="https://taxii.example.com"
              value={cfg.server_url || ""}
              onChange={(e) => update("server_url", e.target.value)}
              data-testid="taxii-server-url"
            />
          </label>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            COLLECTION ID
            <input
              className="nvx-input"
              placeholder="uuid"
              value={cfg.collection_id || ""}
              onChange={(e) => update("collection_id", e.target.value)}
              data-testid="taxii-collection-id"
            />
          </label>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            API ROOT
            <input
              className="nvx-input"
              placeholder="taxii2"
              value={cfg.api_root || "taxii2"}
              onChange={(e) => update("api_root", e.target.value)}
              data-testid="taxii-api-root"
            />
          </label>
          <label style={{ fontSize: 11, color: "#94a3b8" }}>
            AUTH TYPE
            <select
              className="nvx-input"
              value={cfg.auth_type || "none"}
              onChange={(e) => update("auth_type", e.target.value)}
              data-testid="taxii-auth-type"
            >
              <option value="none">none</option>
              <option value="basic">basic (user + password)</option>
              <option value="bearer">bearer (token)</option>
              <option value="header">custom header</option>
            </select>
          </label>
          {cfg.auth_type === "basic" && (
            <>
              <label style={{ fontSize: 11, color: "#94a3b8" }}>
                USERNAME
                <input
                  className="nvx-input"
                  value={cfg.username || ""}
                  onChange={(e) => update("username", e.target.value)}
                  data-testid="taxii-username"
                />
              </label>
              <label style={{ fontSize: 11, color: "#94a3b8" }}>
                PASSWORD
                <input
                  type="password"
                  className="nvx-input"
                  value={cfg.password || ""}
                  onChange={(e) => update("password", e.target.value)}
                  data-testid="taxii-password"
                />
              </label>
            </>
          )}
          {cfg.auth_type === "bearer" && (
            <label style={{ fontSize: 11, color: "#94a3b8", gridColumn: "1 / -1" }}>
              BEARER TOKEN
              <input
                type="password"
                className="nvx-input"
                value={cfg.token || ""}
                onChange={(e) => update("token", e.target.value)}
                data-testid="taxii-token"
              />
            </label>
          )}
          {cfg.auth_type === "header" && (
            <>
              <label style={{ fontSize: 11, color: "#94a3b8" }}>
                HEADER KEY
                <input
                  className="nvx-input"
                  value={cfg.auth_header_key || ""}
                  onChange={(e) => update("auth_header_key", e.target.value)}
                  placeholder="X-API-Key"
                  data-testid="taxii-header-key"
                />
              </label>
              <label style={{ fontSize: 11, color: "#94a3b8" }}>
                HEADER VALUE
                <input
                  type="password"
                  className="nvx-input"
                  value={cfg.auth_header_value || ""}
                  onChange={(e) => update("auth_header_value", e.target.value)}
                  data-testid="taxii-header-value"
                />
              </label>
            </>
          )}
          <label style={{ fontSize: 11, color: "#94a3b8", display: "flex", alignItems: "center", gap: 8 }}>
            <input
              type="checkbox"
              checked={cfg.verify_tls !== false}
              onChange={(e) => update("verify_tls", e.target.checked)}
              data-testid="taxii-verify-tls"
            />
            Verify TLS certificate
          </label>
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            className="nvx-btn sm"
            onClick={save}
            disabled={saving}
            data-testid="taxii-save"
          >
            <Save size={12} /> {saving ? "SAVING…" : "SAVE CONFIG"}
          </button>
          <button
            className="nvx-btn sm ghost"
            onClick={test}
            disabled={testing || !cfg.server_url}
            data-testid="taxii-test"
          >
            <TestTube2 size={12} /> {testing ? "TESTING…" : "TEST CONNECTION"}
          </button>
          {saveMsg && (
            <span style={{ fontSize: 11, color: saveMsg.startsWith("Error") ? "#f87171" : "#7ee3c9" }}>
              {saveMsg}
            </span>
          )}
        </div>

        {testResult && (
          <div
            style={{
              marginTop: 12,
              padding: 10,
              borderRadius: 4,
              background: testResult.ok ? "rgba(126,227,201,0.08)" : "rgba(248,113,113,0.08)",
              border: `1px solid ${testResult.ok ? "rgba(126,227,201,0.3)" : "rgba(248,113,113,0.3)"}`,
              fontSize: 11,
              fontFamily: "monospace",
              color: "#c9d1d9",
            }}
            data-testid="taxii-test-result"
          >
            <div style={{ color: testResult.ok ? "#7ee3c9" : "#f87171", fontWeight: 600, marginBottom: 4 }}>
              {testResult.ok ? "✓ CONNECTED" : "✗ FAILED"}{" "}
              {testResult.status_code && `(HTTP ${testResult.status_code})`}
            </div>
            {testResult.error && <div>Error: {testResult.error}</div>}
            {testResult.response_preview && (
              <div style={{ marginTop: 4, opacity: 0.7 }}>{testResult.response_preview.slice(0, 300)}</div>
            )}
          </div>
        )}

        <div style={{ marginTop: 16 }}>
          <div
            style={{
              fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 6,
              display: "flex", alignItems: "center", justifyContent: "space-between",
            }}
          >
            RECENT PUSHES ({history.length})
            <button
              className="nvx-btn sm ghost"
              onClick={refreshHistory}
              data-testid="taxii-history-refresh"
              style={{ fontSize: 10 }}
            >
              Refresh
            </button>
          </div>
          {history.length === 0 ? (
            <div style={{ fontSize: 11, color: "#94a3b8" }}>No pushes yet.</div>
          ) : (
            <div style={{ fontSize: 11, fontFamily: "monospace" }}>
              {history.map((h, i) => (
                <div
                  key={i}
                  style={{
                    padding: "6px 8px",
                    borderRadius: 3,
                    marginBottom: 4,
                    background: h.result?.ok ? "rgba(126,227,201,0.05)" : "rgba(248,113,113,0.05)",
                    color: "#c9d1d9",
                    display: "flex",
                    gap: 8,
                    alignItems: "center",
                  }}
                >
                  <span style={{ color: h.result?.ok ? "#7ee3c9" : "#f87171" }}>
                    {h.result?.ok ? "✓" : "✗"}
                  </span>
                  <span style={{ color: "#94a3b8" }}>{h.created_at?.slice(0, 19)}</span>
                  <span>{h.object_count} objects</span>
                  {h.result?.status_code && <span>HTTP {h.result.status_code}</span>}
                  {h.result?.error && (
                    <span style={{ color: "#f87171", flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {h.result.error.slice(0, 80)}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
