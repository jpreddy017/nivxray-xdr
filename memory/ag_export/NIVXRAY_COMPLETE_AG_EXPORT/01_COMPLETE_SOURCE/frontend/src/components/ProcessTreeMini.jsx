import { useMemo } from "react";
import { TreePine } from "lucide-react";

/**
 * ProcessTreeMini — compact preview of a predicted ProcessTree.
 * Renders inside SocVerdictPanel to give the analyst a one-glance view of
 * what the payload WILL DO if detonated (without opening the full graph).
 */
export default function ProcessTreeMini({ tree }) {
  const flatChain = useMemo(() => {
    if (!tree?.root) return [];
    const chain = [];
    function walk(n, depth) {
      chain.push({ p: n.process, tactic: n.tactic, mitre: n.mitre_ids, depth,
                   inferred: n.evidence?.inferred });
      // Follow first-child chain for the linear mini-preview
      if (n.children?.length) walk(n.children[0], depth + 1);
    }
    walk(tree.root, 0);
    return chain;
  }, [tree]);

  if (!tree?.root) return null;

  return (
    <div className="brut-border" style={{
      padding: "10px 12px", background: "var(--surface)",
      fontFamily: "JetBrains Mono, monospace", fontSize: 11,
    }} data-testid="process-tree-mini">
      <div style={{ color: "var(--accent)", letterSpacing: "0.16em", fontSize: 10, marginBottom: 6, fontWeight: 700 }}>
        <TreePine size={10} style={{ verticalAlign: "middle", marginRight: 5 }} />
        PREDICTED PROCESS CHAIN
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6 }}>
        {flatChain.map((n, i) => (
          <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span style={{
              padding: "3px 8px",
              border: `1px solid ${n.inferred ? "var(--warn)" : "var(--accent)"}`,
              color: n.inferred ? "var(--warn)" : "var(--accent)",
              background: "var(--inset)",
              borderStyle: n.inferred ? "dashed" : "solid",
              fontWeight: 600,
            }}>
              {n.p}
            </span>
            {i < flatChain.length - 1 && (
              <span style={{ color: "var(--text-mute)" }}>→</span>
            )}
          </span>
        ))}
      </div>
      {tree.rationale?.verdict && (
        <div style={{ color: "var(--text-dim)", marginTop: 6, fontSize: 10 }}>
          {tree.rationale.verdict}
        </div>
      )}
    </div>
  );
}
