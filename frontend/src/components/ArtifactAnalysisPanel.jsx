/**
 * ArtifactAnalysisPanel — Artifact Intelligence Layer dispatcher.
 * ────────────────────────────────────────────────────────────────
 * Phase 3 · Cycle A · owner-approved 2026-02.
 *
 * Receives the shape produced by `services.artifact_intelligence.dispatch`
 * (or the equivalent `iedde.binary_artifact` with `analysis` +
 * `artifact_type`) and delegates to the matching sub-panel:
 *
 *   pe   → <PEAnalysisPanel />
 *   pdf  → <PDFAnalysisPanel />
 *   ...  → <UnavailableCapabilityCard /> (unknown / not-yet-implemented)
 *
 * Backwards compat: the IEDDE pipeline still emits
 * `binary_artifact.pe_analysis` (the legacy PE-only field) — this panel
 * inspects both new (`artifact_type` + `analysis`) and legacy paths.
 */
import PEAnalysisPanel from "./PEAnalysisPanel";
import PDFAnalysisPanel from "./PDFAnalysisPanel";
import OfficeAnalysisPanel from "./OfficeAnalysisPanel";
import ThreatSummaryCard from "./ThreatSummaryCard";

function UnavailableCapabilityCard({ artifact_type, display_name, message }) {
  return (
    <div
      data-testid="artifact-unavailable-panel"
      style={{
        border: "1px dashed rgba(148,163,184,0.35)", borderRadius: 6,
        padding: "14px 18px", background: "rgba(2,6,23,0.35)", marginBottom: 12,
      }}
    >
      <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", letterSpacing: "0.14em" }}>
        {(display_name || artifact_type || "ARTIFACT").toUpperCase()} · CAPABILITY UNAVAILABLE
      </div>
      <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>
        {message || "This artifact type is recognized but no specialized analyzer is enabled in this deployment."}
      </div>
    </div>
  );
}

/**
 * Props:
 *   • routed  — shape produced by AIL `dispatch().to_dict()` — has
 *               `artifact_type`, `capability_available`, `analysis`,
 *               `hashes`, `size`. Preferred.
 *   • legacyPE — legacy `binary_artifact.pe_analysis` for backwards
 *                compat. Used only when `routed` is absent.
 */
export default function ArtifactAnalysisPanel({ routed, legacyPE }) {
  // Backwards-compat path (legacy PE-only)
  if (!routed && legacyPE) {
    return <PEAnalysisPanel pe={legacyPE} />;
  }
  if (!routed) return null;

  const { artifact_type, display_name, capability_available, analysis, hashes } = routed;

  if (!capability_available) {
    return (
      <UnavailableCapabilityCard
        artifact_type={artifact_type}
        display_name={display_name}
        message={analysis?.message}
      />
    );
  }

  if (artifact_type === "pe") {
    return (
      <>
        <ThreatSummaryCard routed={routed} />
        <PEAnalysisPanel pe={analysis} />
      </>
    );
  }
  if (artifact_type === "pdf") {
    return (
      <>
        <ThreatSummaryCard routed={routed} />
        <PDFAnalysisPanel pdf={analysis} hashes={hashes} />
      </>
    );
  }
  if (artifact_type === "office") {
    return (
      <>
        <ThreatSummaryCard routed={routed} />
        <OfficeAnalysisPanel office={analysis} hashes={hashes} />
      </>
    );
  }

  // Unknown / not-yet-implemented type — surface the graceful card.
  return (
    <UnavailableCapabilityCard
      artifact_type={artifact_type}
      display_name={display_name}
      message={
        analysis?.message ||
        "This artifact type isn't yet supported. Track it in the roadmap or use the raw canonical output above."
      }
    />
  );
}
