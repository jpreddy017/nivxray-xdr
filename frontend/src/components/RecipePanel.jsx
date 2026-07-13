import { X, ArrowUp, ArrowDown, GripVertical } from "lucide-react";

export default function RecipePanel({ steps, setSteps, ops }) {
  const remove = (idx) => setSteps(steps.filter((_, i) => i !== idx));
  const move = (idx, dir) => {
    const j = idx + dir;
    if (j < 0 || j >= steps.length) return;
    const next = [...steps];
    [next[idx], next[j]] = [next[j], next[idx]];
    setSteps(next);
  };
  const opName = (id) => ops.find((o) => o.id === id)?.name || id;
  const opMeta = (id) => ops.find((o) => o.id === id);
  const setArg = (idx, key, value) => {
    const next = [...steps];
    next[idx] = { ...next[idx], args: { ...(next[idx].args || {}), [key]: value } };
    setSteps(next);
  };

  return (
    <section
      className="brut-border"
      style={{
        borderTop: "1px solid var(--border)",
        borderBottom: "1px solid var(--border)",
        borderLeft: "none",
        borderRight: "none",
        background: "var(--surface)",
      }}
      data-testid="recipe-panel"
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 14px",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>
          ▸ RECIPE
        </div>
        <span className="badge neutral" data-testid="recipe-step-count">
          {steps.length} steps
        </span>
      </div>

      <div style={{ padding: 12, minHeight: 90 }}>
        {steps.length === 0 && (
          <div
            className="mono"
            style={{
              color: "var(--text-mute)",
              fontSize: 12,
              padding: "18px 6px",
              textAlign: "center",
              border: "1px dashed var(--border)",
              background: "var(--inset)",
            }}
          >
            Click operations on the left to build a pipeline, or press{" "}
            <span style={{ color: "var(--accent)" }}>AUTO-DECODE</span> to let NivXary figure it out.
          </div>
        )}

        {steps.map((s, idx) => {
          const meta = opMeta(s.op);
          return (
            <div key={idx}>
              {idx > 0 && <div className="recipe-connector" />}
              <div className="recipe-step fade-in" data-testid={`recipe-step-${idx}`}>
                <span className="step-idx mono">{String(idx + 1).padStart(2, "0")}</span>
                <GripVertical size={12} color="var(--text-mute)" />
                <div style={{ flex: 1 }}>
                  <div className="mono" style={{ fontSize: 12, color: "var(--text)" }}>
                    {opName(s.op)}
                  </div>
                  {meta?.args?.length > 0 && (
                    <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
                      {meta.args.map((a) => (
                        <label key={a.name} className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
                          {a.name}:
                          <input
                            data-testid={`recipe-step-${idx}-arg-${a.name}`}
                            className="nvx-input"
                            value={(s.args && s.args[a.name]) ?? a.default ?? ""}
                            onChange={(e) => setArg(idx, a.name, e.target.value)}
                            style={{ width: 100, marginLeft: 4, display: "inline-block", padding: "3px 6px", fontSize: 10 }}
                          />
                        </label>
                      ))}
                    </div>
                  )}
                </div>
                <button className="nvx-btn sm ghost" onClick={() => move(idx, -1)} data-testid={`recipe-move-up-${idx}`} title="Move up">
                  <ArrowUp size={12} />
                </button>
                <button className="nvx-btn sm ghost" onClick={() => move(idx, 1)} data-testid={`recipe-move-down-${idx}`} title="Move down">
                  <ArrowDown size={12} />
                </button>
                <button className="nvx-btn sm ghost" onClick={() => remove(idx)} data-testid={`recipe-remove-${idx}`} title="Remove">
                  <X size={13} />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
