import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/lib/auth";
import Header from "@/components/Header";
import api from "@/lib/api";
import {
  Plus, Trash2, Save, TestTube2, Sparkles, Cog, Zap, Cpu,
  Check, X, ChevronDown, ChevronRight, AlertTriangle, Play, ExternalLink,
} from "lucide-react";

const KIND_META = {
  detection_rule: { label: "DETECTION RULES", icon: Zap, color: "var(--warn)",
    blurb: "Custom LOLBAS-style rules matched against decoded output. Extend the LOLBAS scanner with private/org-specific rules." },
  decode_recipe: { label: "DECODE RECIPES", icon: Cog, color: "var(--accent)",
    blurb: "Auto-applied decode chains. If input matches the regex, Smart Decode / Auto-Investigate runs your recipe first." },
  ai_persona: { label: "AI PERSONAS", icon: Sparkles, color: "var(--high)",
    blurb: "Alternative system prompts for the AI Describe step. Analysts opt-in per investigation. Flagship: NivX Cognis." },
  ai_provider: { label: "LLM PROVIDERS", icon: Cpu, color: "#c58af9",
    blurb: "Switch between Claude, GPT, or Gemini for the AI analysis step. Uses the Emergent Universal Key." },
  playbook: { label: "PLAYBOOKS", icon: Sparkles, color: "#f7c17b",
    blurb: "Free-form analyst guidance auto-appended to every AI investigation. Teach the tool your triage rules, decoding techniques, and org-specific IOC context." },
};
const KINDS = ["detection_rule", "decode_recipe", "ai_persona", "ai_provider", "playbook"];

export default function ModelStudioPage() {
  const { user } = useAuth();
  const [activeKind, setActiveKind] = useState("detection_rule");
  const [models, setModels] = useState([]);
  const [catalog, setCatalog] = useState(null);
  const [editing, setEditing] = useState(null); // null | new-shape | existing model with .id
  const [testSample, setTestSample] = useState("");
  const [testResult, setTestResult] = useState(null);
  const [testingId, setTestingId] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const [m, c] = await Promise.all([
        api.get("/admin/models"),
        api.get("/admin/models/catalog"),
      ]);
      setModels(m.data);
      setCatalog(c.data);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    }
  };

  useEffect(() => { if (user?.role === "admin") load(); }, [user]);

  const filtered = useMemo(() => models.filter((m) => m.kind === activeKind), [models, activeKind]);

  if (user?.role !== "admin") {
    return (
      <div style={{ minHeight: "100vh", background: "var(--bg)" }}>
        <Header />
        <div style={{ padding: 40, color: "var(--text-mute)" }}>Admin access required.</div>
      </div>
    );
  }

  const saveModel = async () => {
    if (!editing) return;
    setSaving(true); setError("");
    try {
      if (editing.id) {
        await api.put(`/admin/models/${editing.id}`, {
          name: editing.name,
          enabled: editing.enabled,
          config: editing.config,
        });
      } else {
        await api.post("/admin/models", {
          kind: editing.kind,
          name: editing.name,
          enabled: editing.enabled ?? true,
          config: editing.config,
        });
      }
      setEditing(null);
      await load();
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    } finally {
      setSaving(false);
    }
  };

  const deleteModel = async (id) => {
    if (!window.confirm("Delete this model? This cannot be undone.")) return;
    try {
      await api.delete(`/admin/models/${id}`);
      await load();
    } catch (e) {
      alert(e?.response?.data?.detail || e.message);
    }
  };

  const toggleEnabled = async (m) => {
    await api.put(`/admin/models/${m.id}`, { enabled: !m.enabled });
    await load();
  };

  const runTest = async (id) => {
    setTestingId(id); setTestResult(null);
    try {
      const r = await api.post(`/admin/models/${id}/test`, { sample: testSample });
      setTestResult(r.data);
    } catch (e) {
      setTestResult({ error: e?.response?.data?.detail || e.message });
    } finally {
      setTestingId(null);
    }
  };

  const startNew = () => {
    const templates = {
      detection_rule: { binary_regex: "", argv_regex: "", mitre: [], purposes: [], severity: "medium", description: "" },
      decode_recipe:  { match_regex: "", ops: [{ op: "base64-decode" }], notes: "" },
      ai_persona:     { system_prompt: "", notes: "" },
      ai_provider:    { provider: "anthropic", model: "claude-sonnet-4-5-20250929", default: false },
      playbook:       { body: "", applies_to: ["ai"] },
    };
    setEditing({ id: null, kind: activeKind, name: "", enabled: true, config: templates[activeKind] });
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)" }} data-testid="model-studio-page">
      <Header />
      <div style={{ padding: 24, maxWidth: 1400, margin: "0 auto" }}>
        <div className="brut-border" style={{ background: "var(--surface)", padding: 20, marginBottom: 20 }}>
          <h1 className="mono" style={{ fontSize: 22, letterSpacing: "0.16em", margin: 0, color: "var(--accent)" }}>
            ▸ MODEL STUDIO
          </h1>
          <p className="mono" style={{ fontSize: 12, color: "var(--text-mute)", marginTop: 8, lineHeight: 1.6 }}>
            Teach NivXRay new tricks. Add custom detection rules, decode recipes, AI personas, or switch LLM providers.
            Every change takes effect immediately on the next investigation.
          </p>
        </div>

        {/* Kind tabs */}
        <div style={{ display: "flex", gap: 6, marginBottom: 16, flexWrap: "wrap" }} data-testid="ms-kind-tabs">
          {KINDS.map((k) => {
            const KM = KIND_META[k];
            const Icon = KM.icon;
            const count = models.filter((m) => m.kind === k).length;
            return (
              <button
                key={k}
                className={`nvx-btn ${activeKind === k ? "primary" : "ghost"}`}
                onClick={() => { setActiveKind(k); setEditing(null); setTestResult(null); }}
                data-testid={`ms-tab-${k}`}
              >
                <Icon size={12} /> {KM.label} <span style={{ opacity: 0.7 }}>· {count}</span>
              </button>
            );
          })}
        </div>

        {error && (
          <div className="brut-border" style={{ padding: 12, background: "rgba(217,108,108,0.1)", borderColor: "var(--high)", marginBottom: 16 }}>
            <AlertTriangle size={13} style={{ marginRight: 6 }} /> {error}
          </div>
        )}

        <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginBottom: 12, lineHeight: 1.6 }}>
          {KIND_META[activeKind].blurb}
        </div>

        {/* Toolbar */}
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12, gap: 10, flexWrap: "wrap" }}>
          <button className="nvx-btn primary" onClick={startNew} data-testid="ms-btn-new">
            <Plus size={12} /> NEW {KIND_META[activeKind].label.replace(/S$/, "")}
          </button>
          <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)" }}>
            {filtered.length} model{filtered.length !== 1 ? "s" : ""} · {filtered.filter((m) => m.enabled).length} enabled
          </div>
        </div>

        {/* List */}
        <div style={{ display: "grid", gap: 10 }} data-testid="ms-list">
          {filtered.map((m) => (
            <ModelRow key={m.id} model={m} onEdit={() => { setEditing(m); setTestResult(null); }}
                       onDelete={() => deleteModel(m.id)}
                       onToggle={() => toggleEnabled(m)} />
          ))}
          {filtered.length === 0 && (
            <div className="mono" style={{ color: "var(--text-mute)", fontSize: 12, padding: 20, textAlign: "center", border: "1px dashed var(--border)" }}>
              No {activeKind.replace("_", " ")}s yet. Click <b>NEW</b> above to create one.
            </div>
          )}
        </div>

        {/* Editor drawer */}
        {editing && (
          <ModelEditor
            model={editing}
            catalog={catalog}
            onChange={setEditing}
            onCancel={() => { setEditing(null); setTestResult(null); }}
            onSave={saveModel}
            saving={saving}
            testSample={testSample}
            setTestSample={setTestSample}
            onTest={() => editing.id ? runTest(editing.id) : setTestResult({ note: "Save first to enable Test" })}
            testResult={testResult}
            testing={testingId === editing.id}
          />
        )}
      </div>
    </div>
  );
}

function ModelRow({ model, onEdit, onDelete, onToggle }) {
  const KM = KIND_META[model.kind];
  const Icon = KM.icon;
  const cfg = model.config || {};
  const summary = model.kind === "detection_rule" ? `${cfg.binary_regex || "—"}${cfg.argv_regex ? "  ▸  " + cfg.argv_regex : ""}`
                : model.kind === "decode_recipe" ? `match: ${cfg.match_regex} → ${(cfg.ops || []).map((o) => o.op).join(" → ")}`
                : model.kind === "ai_persona" ? (cfg.system_prompt || "").slice(0, 140) + "…"
                : model.kind === "playbook" ? `applies_to: ${(cfg.applies_to || ["ai"]).join(", ")} · ${(cfg.body || "").slice(0, 100)}…`
                : `${cfg.provider} · ${cfg.model}${cfg.default ? " · DEFAULT" : ""}`;
  return (
    <div className="brut-border" style={{ padding: 14, background: "var(--surface)", display: "grid", gridTemplateColumns: "1fr auto", gap: 12 }}
         data-testid={`ms-row-${model.id}`}>
      <div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 4, flexWrap: "wrap" }}>
          <Icon size={14} color={KM.color} />
          <span className="mono" style={{ fontSize: 13, color: "var(--text)", fontWeight: 700 }}>{model.name}</span>
          {model.protected && <span className="badge">BUILT-IN</span>}
          {!model.enabled && <span className="badge" style={{ opacity: 0.6 }}>DISABLED</span>}
          <span className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginLeft: "auto" }}>
            used {model.usage_count || 0}×
          </span>
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", wordBreak: "break-all", lineHeight: 1.5 }}>
          {summary}
        </div>
      </div>
      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
        <button className="nvx-btn sm ghost" onClick={onToggle} data-testid={`ms-toggle-${model.id}`}>
          {model.enabled ? <X size={11} /> : <Check size={11} />}
          {model.enabled ? "DISABLE" : "ENABLE"}
        </button>
        <button className="nvx-btn sm" onClick={onEdit} data-testid={`ms-edit-${model.id}`}>EDIT</button>
        {!model.protected && (
          <button className="nvx-btn sm ghost" onClick={onDelete} data-testid={`ms-delete-${model.id}`}
                  style={{ borderColor: "var(--high)", color: "var(--high)" }}>
            <Trash2 size={11} />
          </button>
        )}
      </div>
    </div>
  );
}

function ModelEditor({ model, catalog, onChange, onCancel, onSave, saving, testSample, setTestSample, onTest, testResult, testing }) {
  const KM = KIND_META[model.kind];
  const cfg = model.config || {};
  const set = (patch) => onChange({ ...model, ...patch });
  const setCfg = (patch) => onChange({ ...model, config: { ...cfg, ...patch } });
  return (
    <div className="brut-border" style={{ background: "var(--inset)", padding: 20, marginTop: 20 }} data-testid="ms-editor">
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 14 }}>
        <div className="mono" style={{ fontSize: 12, color: KM.color, letterSpacing: "0.2em" }}>
          ▸ {model.id ? "EDIT" : "NEW"} {KM.label.replace(/S$/, "")}
        </div>
        <button className="nvx-btn sm ghost" onClick={onCancel}><X size={11} /> CLOSE</button>
      </div>

      <div style={{ display: "grid", gap: 12 }}>
        <div>
          <Label>Name</Label>
          <input className="brut-input" value={model.name} onChange={(e) => set({ name: e.target.value })} placeholder="Descriptive name" data-testid="ms-input-name" />
        </div>

        {model.kind === "detection_rule" && <DetectionRuleFields cfg={cfg} setCfg={setCfg} />}
        {model.kind === "decode_recipe"  && <DecodeRecipeFields  cfg={cfg} setCfg={setCfg} catalog={catalog} />}
        {model.kind === "ai_persona"     && <AiPersonaFields     cfg={cfg} setCfg={setCfg} />}
        {model.kind === "ai_provider"    && <AiProviderFields    cfg={cfg} setCfg={setCfg} catalog={catalog} />}
        {model.kind === "playbook"       && <PlaybookFields      cfg={cfg} setCfg={setCfg} />}

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" checked={model.enabled ?? true} onChange={(e) => set({ enabled: e.target.checked })} id="enabled-cb" data-testid="ms-input-enabled" />
          <label htmlFor="enabled-cb" className="mono" style={{ fontSize: 12, color: "var(--text)" }}>ENABLED — applied to live investigations</label>
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <button className="nvx-btn primary" onClick={onSave} disabled={saving || !model.name} data-testid="ms-btn-save">
            <Save size={12} /> {saving ? "SAVING…" : "SAVE"}
          </button>
          <button className="nvx-btn ghost" onClick={onCancel}>CANCEL</button>
        </div>

        {/* Test surface */}
        <div className="brut-border" style={{ padding: 14, background: "var(--bg)", marginTop: 8 }}>
          <div className="mono" style={{ fontSize: 11, color: "var(--accent)", letterSpacing: "0.2em", marginBottom: 8 }}>
            ▸ TEST
          </div>
          <textarea className="brut-input" style={{ minHeight: 100, fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}
            placeholder={model.kind === "ai_persona" || model.kind === "ai_provider"
              ? "Optional: paste a sample decoded payload the persona/provider would receive."
              : "Paste a sample input — matches, decodes, or checks show live below."}
            value={testSample} onChange={(e) => setTestSample(e.target.value)}
            data-testid="ms-input-test-sample" />
          <div style={{ marginTop: 8 }}>
            <button className="nvx-btn" onClick={onTest} disabled={testing} data-testid="ms-btn-test">
              <Play size={11} /> {testing ? "TESTING…" : "RUN TEST"}
            </button>
          </div>
          {testResult && <TestResult result={testResult} />}
        </div>
      </div>
    </div>
  );
}

function DetectionRuleFields({ cfg, setCfg }) {
  return (
    <>
      <div>
        <Label>Binary regex <Hint>(required — matched against decoded output)</Hint></Label>
        <input className="brut-input" value={cfg.binary_regex || ""} onChange={(e) => setCfg({ binary_regex: e.target.value })}
               placeholder="\\brundll32(?:\\.exe)?\\b" data-testid="ms-input-binary-regex" />
      </div>
      <div>
        <Label>Argv regex <Hint>(optional — matched in the 500 chars after the binary match)</Hint></Label>
        <input className="brut-input" value={cfg.argv_regex || ""} onChange={(e) => setCfg({ argv_regex: e.target.value })}
               placeholder="shell32\\.dll,Control_RunDLL" data-testid="ms-input-argv-regex" />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div>
          <Label>MITRE technique IDs <Hint>(comma-separated)</Hint></Label>
          <input className="brut-input" value={(cfg.mitre || []).join(", ")}
                 onChange={(e) => setCfg({ mitre: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
                 placeholder="T1218.011, T1059.003" data-testid="ms-input-mitre" />
        </div>
        <div>
          <Label>Purposes <Hint>(comma-separated)</Hint></Label>
          <input className="brut-input" value={(cfg.purposes || []).join(", ")}
                 onChange={(e) => setCfg({ purposes: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
                 placeholder="Execute, AWL Bypass" />
        </div>
      </div>
      <div>
        <Label>Severity</Label>
        <select className="brut-input" value={cfg.severity || "medium"} onChange={(e) => setCfg({ severity: e.target.value })}>
          <option value="low">LOW</option>
          <option value="medium">MEDIUM</option>
          <option value="high">HIGH</option>
          <option value="critical">CRITICAL</option>
        </select>
      </div>
      <div>
        <Label>Description</Label>
        <textarea className="brut-input" style={{ minHeight: 60 }} value={cfg.description || ""}
                  onChange={(e) => setCfg({ description: e.target.value })}
                  placeholder="What this rule detects and why it matters." />
      </div>
    </>
  );
}

function DecodeRecipeFields({ cfg, setCfg, catalog }) {
  const ops = cfg.ops || [];
  const setOp = (i, patch) => {
    const next = [...ops]; next[i] = { ...next[i], ...patch };
    setCfg({ ops: next });
  };
  const addOp = () => setCfg({ ops: [...ops, { op: "base64-decode" }] });
  const removeOp = (i) => setCfg({ ops: ops.filter((_, k) => k !== i) });
  const moveUp = (i) => {
    if (i === 0) return;
    const next = [...ops]; [next[i - 1], next[i]] = [next[i], next[i - 1]]; setCfg({ ops: next });
  };
  return (
    <>
      <div>
        <Label>Match regex <Hint>(required — applied to raw input; if it fires, this recipe runs)</Hint></Label>
        <input className="brut-input" value={cfg.match_regex || ""} onChange={(e) => setCfg({ match_regex: e.target.value })}
               placeholder="^[A-Fa-f0-9]{20,}$" data-testid="ms-input-match-regex" />
      </div>
      <div>
        <Label>Ops chain <Hint>(runs top → bottom on the raw input)</Hint></Label>
        <div style={{ display: "grid", gap: 6 }} data-testid="ms-recipe-ops">
          {ops.map((step, i) => (
            <div key={i} style={{ display: "grid", gridTemplateColumns: "24px 1fr 24px 24px", gap: 6, alignItems: "center" }}>
              <span className="mono" style={{ fontSize: 10, color: "var(--text-mute)" }}>{String(i + 1).padStart(2, "0")}</span>
              <select className="brut-input" value={step.op} onChange={(e) => setOp(i, { op: e.target.value })} data-testid={`ms-op-select-${i}`}>
                {(catalog?.operations || []).map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
              <button className="nvx-btn sm ghost" onClick={() => moveUp(i)} disabled={i === 0} title="Move up">↑</button>
              <button className="nvx-btn sm ghost" onClick={() => removeOp(i)} title="Remove"
                      style={{ borderColor: "var(--high)", color: "var(--high)" }}>×</button>
            </div>
          ))}
        </div>
        <button className="nvx-btn sm" onClick={addOp} style={{ marginTop: 6 }} data-testid="ms-btn-add-op">
          <Plus size={11} /> ADD STEP
        </button>
      </div>
      <div>
        <Label>Notes</Label>
        <textarea className="brut-input" style={{ minHeight: 50 }} value={cfg.notes || ""} onChange={(e) => setCfg({ notes: e.target.value })} />
      </div>
    </>
  );
}

function AiPersonaFields({ cfg, setCfg }) {
  return (
    <>
      <div>
        <Label>System prompt <Hint>(required — this replaces the default Threat-Analyst prompt when selected)</Hint></Label>
        <textarea className="brut-input" style={{ minHeight: 260, fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}
                  value={cfg.system_prompt || ""} onChange={(e) => setCfg({ system_prompt: e.target.value })}
                  placeholder="ROLE AND PURPOSE: You are ..." data-testid="ms-input-system-prompt" />
        <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 4 }}>
          Tip: NivXRay auto-appends a JSON output contract so the persona still fills the standard Threat Analysis tabs.
        </div>
      </div>
      <div>
        <Label>Notes</Label>
        <textarea className="brut-input" style={{ minHeight: 50 }} value={cfg.notes || ""} onChange={(e) => setCfg({ notes: e.target.value })} />
      </div>
    </>
  );
}

function AiProviderFields({ cfg, setCfg, catalog }) {
  const presets = catalog?.providers || [];
  return (
    <>
      <div>
        <Label>Preset <Hint>(pick a preset or edit provider/model manually below)</Hint></Label>
        <select className="brut-input" value={`${cfg.provider}|${cfg.model}`} onChange={(e) => {
          const [p, m] = e.target.value.split("|");
          setCfg({ provider: p, model: m });
        }}>
          {presets.map((p) => <option key={p.model} value={`${p.provider}|${p.model}`}>{p.label} — {p.provider}/{p.model}</option>)}
          <option value={`${cfg.provider}|${cfg.model}`}>(custom)</option>
        </select>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 12 }}>
        <div>
          <Label>Provider</Label>
          <select className="brut-input" value={cfg.provider || "anthropic"} onChange={(e) => setCfg({ provider: e.target.value })}>
            <option value="anthropic">anthropic</option>
            <option value="openai">openai</option>
            <option value="google">google</option>
          </select>
        </div>
        <div>
          <Label>Model</Label>
          <input className="brut-input" value={cfg.model || ""} onChange={(e) => setCfg({ model: e.target.value })}
                 placeholder="claude-sonnet-4-5-20250929" />
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <input type="checkbox" checked={!!cfg.default} onChange={(e) => setCfg({ default: e.target.checked })} id="provider-default" />
        <label htmlFor="provider-default" className="mono" style={{ fontSize: 12, color: "var(--text)" }}>
          Use as DEFAULT provider when no explicit choice is made
        </label>
      </div>
    </>
  );
}

function PlaybookFields({ cfg, setCfg }) {
  const applies = cfg.applies_to || ["ai"];
  const toggle = (t) => setCfg({ applies_to: applies.includes(t) ? applies.filter((x) => x !== t) : [...applies, t] });
  return (
    <>
      <div>
        <Label>Playbook body <Hint>(required — free-form guidance / rules / instructions appended to every AI investigation)</Hint></Label>
        <textarea
          className="brut-input"
          style={{ minHeight: 300, fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}
          value={cfg.body || ""}
          onChange={(e) => setCfg({ body: e.target.value })}
          placeholder={"WHEN YOU SEE X, DO Y.\n\nEXAMPLE:\n- H4sIA prefix -> base64 then gzip-decompress\n- [Byte[]]$var_code = ... -> isolate quoted base64 first\n- If a -bxor <N> loop is present, apply XOR with key N after base64 decode"}
          data-testid="ms-input-playbook-body"
        />
      </div>
      <div>
        <Label>Applies to</Label>
        <div style={{ display: "flex", gap: 12 }}>
          {["ai", "magic", "smart"].map((t) => (
            <label key={t} className="mono" style={{ fontSize: 12, color: "var(--text)", display: "flex", gap: 6, alignItems: "center" }}>
              <input type="checkbox" checked={applies.includes(t)} onChange={() => toggle(t)} data-testid={`ms-applies-${t}`} />
              {t.toUpperCase()}
            </label>
          ))}
        </div>
        <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 4 }}>
          <b>ai</b> — appended to every AI investigation system prompt (recommended). <b>magic</b>/<b>smart</b> reserved for future deterministic hooks.
        </div>
      </div>
    </>
  );
}



function TestResult({ result }) {
  if (result.error) return (
    <div className="mono" style={{ fontSize: 11, color: "var(--high)", padding: 10, marginTop: 10, borderLeft: "3px solid var(--high)" }}>
      ERROR: {result.error}
    </div>
  );
  if (result.note) return <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", padding: 10, marginTop: 10 }}>{result.note}</div>;
  return (
    <div style={{ marginTop: 12, padding: 12, background: "var(--surface)", border: "1px solid var(--border)" }} data-testid="ms-test-result">
      <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap", fontSize: 11, color: "var(--text)", maxHeight: 340, overflow: "auto" }}>
        {JSON.stringify(result, null, 2)}
      </pre>
    </div>
  );
}

function Label({ children }) {
  return (
    <div className="mono" style={{ fontSize: 10, letterSpacing: "0.16em", color: "var(--text-mute)", marginBottom: 4, textTransform: "uppercase" }}>
      {children}
    </div>
  );
}
function Hint({ children }) {
  return <span style={{ opacity: 0.6, fontWeight: 400, marginLeft: 6 }}>{children}</span>;
}
