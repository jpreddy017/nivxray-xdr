/**
 * Unit test for TrajectoryDiagram's per-lane technique projection.
 *
 * Bug fixed 2026-02-09:
 *   When an ICE behavior cluster spanned multiple ATT&CK tactics
 *   (e.g. T1053.005 Execution + T1564.003 Defense Evasion) the
 *   trajectory rendered `techniques[0]` under EVERY lane node,
 *   surfacing the wrong technique in the wrong tactic lane.
 *
 * This test mirrors the fixed logic from
 * `TrajectoryDiagram.jsx::_layoutBehaviorNodes` so the invariant is
 * regression-locked without booting jsdom.
 *
 * Run with:
 *   node --test src/components/__tests__/trajectoryPerLane.test.mjs
 */
import test from "node:test";
import assert from "node:assert/strict";


// ── Mirror of the canonical-tactic helper (single source truth) ──
const _TACTIC_NORMALIZE = {
    "initial access":       "initial_access",
    "execution":            "execution",
    "persistence":          "persistence",
    "privilege escalation": "privilege_escalation",
    "defense evasion":      "defense_evasion",
    "credential access":    "credential_access",
    "discovery":            "discovery",
    "lateral movement":     "lateral_movement",
    "collection":           "collection",
    "command and control":  "command_and_control",
    "command & control":    "command_and_control",
    "exfiltration":         "exfiltration",
    "impact":               "impact",
};
function _canonTactic(x) {
    if (!x) return null;
    const k = String(x).toLowerCase().replace(/[_-]/g, " ").trim();
    return _TACTIC_NORMALIZE[k] || null;
}


/** Mirror of the fixed subtitle-picker (per-lane). */
function subtitleForLane(behavior, tactic) {
    const perTactic = {};
    for (const m of (behavior.mitre || [])) {
        if (!m || typeof m !== "object") continue;
        const canon = _canonTactic(m.tactic);
        const tid   = m.id;
        if (!canon || !tid) continue;
        (perTactic[canon] = perTactic[canon] || []).push(tid);
    }
    const flatTechniques = (behavior.mitre_techniques && behavior.mitre_techniques.length
                                ? behavior.mitre_techniques
                                : (behavior.mitre || []))
        .map((m) => (m == null ? null : (typeof m === "string" ? m : m.id)))
        .filter(Boolean);
    const laneTechs = (perTactic[tactic] && perTactic[tactic].length)
                            ? perTactic[tactic]
                            : flatTechniques;
    return laneTechs[0] || behavior.category || "";
}


// ══════════════════════════════════════════════════════════════════
// Regression cases
// ══════════════════════════════════════════════════════════════════
test("cluster with Execution+Defense-Evasion techniques splits per lane", () => {
    const b = {
        title: "Command execution",
        mitre: [
            { id: "T1564.003", name: "Hidden Window",     tactic: "defense_evasion" },
            { id: "T1053.005", name: "Scheduled Task",    tactic: "execution" },
        ],
    };
    assert.equal(subtitleForLane(b, "execution"),      "T1053.005");
    assert.equal(subtitleForLane(b, "defense_evasion"), "T1564.003");
});


test("multiple techniques in same lane pick the first one", () => {
    const b = {
        mitre: [
            { id: "T1059.001", name: "PowerShell", tactic: "execution" },
            { id: "T1059.003", name: "Cmd",         tactic: "execution" },
        ],
    };
    assert.equal(subtitleForLane(b, "execution"), "T1059.001");
});


test("fallback to flat technique list when per-technique tactic is absent", () => {
    // Older payload shape — mitre_techniques as bare strings.
    const b = {
        mitre_techniques: ["T1105"],
        mitre:            [],
    };
    assert.equal(subtitleForLane(b, "command_and_control"), "T1105");
});


test("no matching lane technique falls back to first flat technique", () => {
    const b = {
        mitre: [
            { id: "T1564.003", name: "Hidden Window", tactic: "defense_evasion" },
        ],
    };
    // Discovery lane has no techniques in this cluster → falls back
    // to the flat list.  Not ideal but preserves previous behavior
    // for legacy clusters lacking full per-lane data.
    assert.equal(subtitleForLane(b, "discovery"), "T1564.003");
});


test("empty mitre + no techniques → falls back to category, else empty", () => {
    assert.equal(subtitleForLane({ category: "reg" }, "execution"), "reg");
    assert.equal(subtitleForLane({}, "execution"), "");
});


test("robust against malformed mitre entries (strings, nulls)", () => {
    const b = {
        mitre: [null, "T1105", { id: "T1053.005", tactic: "execution" }],
    };
    // The null and bare string are skipped by the per-tactic
    // builder; the object with a proper tactic wins.
    assert.equal(subtitleForLane(b, "execution"), "T1053.005");
});


test("canonical tactic input handles 'Command & Control' aliases", () => {
    const b = {
        mitre: [
            { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
        ],
    };
    assert.equal(subtitleForLane(b, "command_and_control"), "T1105");
});
