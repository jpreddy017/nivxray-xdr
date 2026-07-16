/**
 * InputToolbar — 3 icon buttons pinned to the top-right of any <textarea>:
 *   📋  Copy value to clipboard
 *   ✏️  Toggle read-only ↔ editable (locks the field so accidental
 *        modification of a captured payload can't happen mid-analysis)
 *   🗑️  Clear value (asks confirm when value is > 20 chars)
 *
 * All buttons are keyboard-accessible and expose data-testids so the
 * testing agent can drive them (`{scope}-copy`, `{scope}-edit`,
 * `{scope}-clear`).
 *
 * Usage:
 *   <div style={{ position:"relative" }}>
 *     <textarea value={v} onChange={...} readOnly={locked} />
 *     <InputToolbar
 *        scope="workspace-input"
 *        value={v}
 *        onClear={() => setV("")}
 *        onToggleEdit={() => setLocked(l => !l)}
 *        locked={locked}
 *     />
 *   </div>
 */
import { Copy, Lock, Unlock, Trash2, Check } from "lucide-react";
import { useState } from "react";

export default function InputToolbar({
  scope,
  value,
  onClear,
  onToggleEdit,
  locked = false,
  extraButtons = null,
}) {
  const [copied, setCopied] = useState(false);

  const doCopy = async () => {
    try {
      await navigator.clipboard.writeText(value || "");
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // fallback for HTTP contexts / blocked permission
      try {
        const ta = document.createElement("textarea");
        ta.value = value || "";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      } catch {}
    }
  };

  const doClear = () => {
    const chars = (value || "").length;
    if (chars > 20 && !window.confirm(`Clear ${chars} chars from this field?`)) return;
    onClear?.();
  };

  const btnStyle = {
    background: "rgba(0,0,0,0.55)",
    border: "1px solid var(--border)",
    color: "var(--text-mute)",
    padding: "3px 6px",
    borderRadius: 3,
    cursor: "pointer",
    fontSize: 10,
    display: "inline-flex",
    alignItems: "center",
    gap: 3,
    lineHeight: 1,
  };
  const activeBtn = { ...btnStyle, color: "var(--accent)", borderColor: "var(--accent)" };

  return (
    <div
      style={{
        position: "absolute",
        top: 4,
        right: 6,
        display: "flex",
        gap: 4,
        zIndex: 3,
      }}
      onClick={(e) => e.stopPropagation()}
    >
      {extraButtons}
      <button
        type="button"
        style={copied ? activeBtn : btnStyle}
        data-testid={`${scope}-copy`}
        onClick={doCopy}
        title={copied ? "Copied!" : "Copy field contents"}
        aria-label="Copy field contents"
      >
        {copied ? <Check size={11} /> : <Copy size={11} />}
      </button>
      {onToggleEdit && (
        <button
          type="button"
          style={locked ? activeBtn : btnStyle}
          data-testid={`${scope}-edit`}
          onClick={onToggleEdit}
          title={locked ? "Field is LOCKED — click to enable edits" : "Lock field to prevent edits"}
          aria-label={locked ? "Unlock field" : "Lock field"}
        >
          {locked ? <Lock size={11} /> : <Unlock size={11} />}
        </button>
      )}
      {onClear && (
        <button
          type="button"
          style={btnStyle}
          data-testid={`${scope}-clear`}
          onClick={doClear}
          disabled={!value}
          title="Clear field"
          aria-label="Clear field"
        >
          <Trash2 size={11} />
        </button>
      )}
    </div>
  );
}
