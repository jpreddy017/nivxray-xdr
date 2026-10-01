/**
 * HistoryPage — full-page Investigation History.
 * ────────────────────────────────────────────────────────────
 * 2026-02 · owner-approved nav consolidation.
 *
 * INVESTIGATE tab has been removed from primary nav. HISTORY replaces
 * it as a full-page listing of every decoded investigation. Restoring
 * a case navigates back to "/" (Workspace) and rehydrates the full
 * state (input · output · trace · verdict · IEDDE decision trace ·
 * canonical confidence · terminal state · IOCs · MITRE · notes).
 *
 * State handoff to Workspace:
 *   sessionStorage["nvx_restore_history_id"] = <record.id>
 *   Workspace picks it up on mount and calls GET /api/history/{id}
 *   → rehydrateFromHistory(record) which restores every panel.
 */
import { useNavigate } from "react-router-dom";
import Header from "@/components/Header";
import HistoryDrawer from "@/components/HistoryDrawer";

export default function HistoryPage() {
  const nav = useNavigate();

  const onRehydrate = (rec) => {
    if (!rec || !rec.id) return;
    try {
      window.sessionStorage.setItem("nvx_restore_history_id", String(rec.id));
    } catch { /* noop */ }
    nav("/");
  };

  return (
    <div data-testid="history-page-root" style={{ minHeight: "100vh", background: "var(--bg)" }}>
      <Header />
      <div style={{ padding: "16px 20px" }}>
        <div style={{
          display: "flex", alignItems: "baseline", justifyContent: "space-between",
          marginBottom: 12,
        }}>
          <div>
            <div className="mono" style={{
              color: "var(--accent)", fontWeight: 800, letterSpacing: "0.24em", fontSize: 13,
            }}>
              📜 INVESTIGATION HISTORY
            </div>
            <div className="mono" style={{
              color: "var(--text-dim)", fontSize: 10, marginTop: 4, letterSpacing: "0.14em",
            }}>
              Every deterministic + AI decode is auto-recorded. Restore lands you back in
              the Workspace with the full investigation state.
            </div>
          </div>
        </div>
        <HistoryDrawer layout="page" onRehydrate={onRehydrate} />
      </div>
    </div>
  );
}
