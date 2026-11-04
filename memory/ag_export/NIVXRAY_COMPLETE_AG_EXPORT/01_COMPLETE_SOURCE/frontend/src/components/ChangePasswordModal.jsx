/**
 * ChangePasswordModal — lightweight in-header modal for rotating the
 * signed-in user's password. Hits POST /api/auth/change-password.
 *
 * UX:
 *   - three fields: current / new / confirm
 *   - client-side rules: min 12 chars, mix of upper+lower+digit, must
 *     differ from current, confirm must match
 *   - on success: swaps the JWT (endpoint returns a fresh token), shows
 *     a green confirmation, closes on Enter or "Done"
 *   - Escape closes; click-outside closes; disabled while submitting
 */
import { useEffect, useState } from "react";
import { X, Check, ShieldCheck, AlertTriangle } from "lucide-react";
import api from "@/lib/api";

const MIN_LEN = 12;

function scorePassword(pw) {
  if (!pw) return { level: "empty", pct: 0, notes: [] };
  const notes = [];
  const has = {
    len:   pw.length >= MIN_LEN,
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    digit: /\d/.test(pw),
    sym:   /[^A-Za-z0-9]/.test(pw),
  };
  if (!has.len)   notes.push(`≥ ${MIN_LEN} chars`);
  if (!has.upper) notes.push("uppercase");
  if (!has.lower) notes.push("lowercase");
  if (!has.digit) notes.push("digit");
  const passed = Object.values(has).filter(Boolean).length;
  const pct = Math.min(100, Math.round((passed / 5) * 100));
  const level = pct >= 90 ? "strong" : pct >= 65 ? "ok" : "weak";
  return { level, pct, notes, has };
}

export default function ChangePasswordModal({ open, onClose }) {
  const [cur, setCur] = useState("");
  const [nxt, setNxt] = useState("");
  const [cnf, setCnf] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [ok, setOk] = useState(false);

  useEffect(() => {
    if (!open) { setCur(""); setNxt(""); setCnf(""); setErr(null); setOk(false); setBusy(false); }
  }, [open]);

  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape" && open && !busy) onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, busy, onClose]);

  if (!open) return null;

  const strength = scorePassword(nxt);
  const canSubmit =
    cur.length > 0 &&
    strength.has?.len && strength.has?.upper && strength.has?.lower && strength.has?.digit &&
    nxt === cnf && nxt !== cur && !busy;

  const submit = async () => {
    setErr(null);
    if (!canSubmit) return;
    setBusy(true);
    try {
      const r = await api.post("/auth/change-password", {
        current_password: cur, new_password: nxt,
      });
      // Swap JWT so the gated must_change_password state clears immediately
      if (r?.data?.access_token) {
        localStorage.setItem("nvx_token", r.data.access_token);
      }
      setOk(true);
      setTimeout(() => onClose(), 1400);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || "Password change failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      data-testid="change-password-modal"
      onClick={(e) => { if (e.target === e.currentTarget && !busy) onClose(); }}
      style={{
        position: "fixed", inset: 0, zIndex: 100,
        background: "rgba(6,7,8,0.72)", backdropFilter: "blur(6px)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
    >
      <div
        style={{
          width: 440, background: "var(--surface, #171a1c)",
          border: "1px solid var(--border, #2d3135)",
          padding: 22, boxShadow: "0 24px 60px rgba(0,0,0,0.5)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <ShieldCheck size={16} color="var(--accent)" />
            <div className="mono" style={{ fontSize: 12, letterSpacing: "0.14em", color: "var(--accent)" }}>
              CHANGE PASSWORD
            </div>
          </div>
          <button
            className="nvx-btn sm ghost"
            data-testid="cp-close"
            onClick={onClose}
            disabled={busy}
            style={{ padding: 4 }}
            aria-label="Close"
          ><X size={14} /></button>
        </div>

        {ok ? (
          <div data-testid="cp-success" style={{
            padding: "20px 6px", textAlign: "center",
            color: "var(--accent)", fontFamily: "Chivo, sans-serif",
          }}>
            <Check size={38} style={{ marginBottom: 8 }} />
            <div style={{ fontSize: 15, fontWeight: 700 }}>Password updated.</div>
            <div style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 6 }}>
              Fresh token issued · session preserved.
            </div>
          </div>
        ) : (
          <>
            <Field label="Current password" value={cur} onChange={setCur}
                   testid="cp-current" autoFocus disabled={busy} />
            <Field label="New password" value={nxt} onChange={setNxt}
                   testid="cp-new" disabled={busy} />
            <StrengthBar strength={strength} />
            <Field label="Confirm new password" value={cnf} onChange={setCnf}
                   testid="cp-confirm" disabled={busy}
                   onEnter={submit}
                   invalid={cnf.length > 0 && cnf !== nxt} />

            {nxt && nxt === cur && (
              <RuleLine bad text="New password must differ from current." />
            )}
            {cnf && cnf !== nxt && (
              <RuleLine bad text="Confirmation doesn't match." />
            )}
            {err && (
              <div data-testid="cp-error" style={{
                marginTop: 10, padding: "8px 10px", fontSize: 12,
                background: "rgba(229,90,74,0.08)",
                border: "1px solid rgba(229,90,74,0.35)",
                color: "var(--high, #e55a4a)", display: "flex", gap: 8, alignItems: "center",
              }}>
                <AlertTriangle size={13} /> {err}
              </div>
            )}

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
              <button className="nvx-btn sm ghost" data-testid="cp-cancel"
                      onClick={onClose} disabled={busy}>CANCEL</button>
              <button className="nvx-btn primary sm" data-testid="cp-submit"
                      onClick={submit} disabled={!canSubmit}>
                {busy ? "UPDATING…" : "UPDATE PASSWORD"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function Field({ label, value, onChange, testid, autoFocus, disabled, invalid, onEnter }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <label className="mono" style={{ fontSize: 10, letterSpacing: "0.14em",
                                       color: "var(--text-mute)" }}>{label.toUpperCase()}</label>
      <input
        type="password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoFocus={autoFocus}
        disabled={disabled}
        data-testid={testid}
        onKeyDown={(e) => { if (e.key === "Enter" && onEnter) onEnter(); }}
        style={{
          width: "100%", padding: "9px 10px", marginTop: 4,
          background: "rgba(10,11,12,0.9)", color: "var(--text)",
          border: `1px solid ${invalid ? "rgba(229,90,74,0.6)" : "var(--border)"}`,
          fontFamily: "JetBrains Mono, Consolas, monospace", fontSize: 13,
          outline: "none",
        }}
      />
    </div>
  );
}

function StrengthBar({ strength }) {
  if (strength.level === "empty") return null;
  const color =
    strength.level === "strong" ? "var(--accent)" :
    strength.level === "ok"     ? "#e2a05d" : "#e55a4a";
  return (
    <div data-testid="cp-strength" style={{ margin: "-6px 0 12px" }}>
      <div style={{ height: 3, background: "rgba(255,255,255,0.05)" }}>
        <div style={{ width: `${strength.pct}%`, height: 3, background: color,
                       transition: "width 200ms ease" }} />
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 4 }}>
        strength: <span style={{ color }}>{strength.level.toUpperCase()}</span>
        {strength.notes.length > 0 && (
          <> · missing: {strength.notes.join(", ")}</>
        )}
      </div>
    </div>
  );
}

function RuleLine({ text, bad }) {
  return (
    <div style={{
      fontSize: 11, color: bad ? "var(--high, #e55a4a)" : "var(--text-mute)",
      marginTop: -6, marginBottom: 8,
    }}>{text}</div>
  );
}
