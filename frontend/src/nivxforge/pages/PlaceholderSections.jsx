/**
 * Section-specific placeholder pages. Each is a thin wrapper over
 * PlaceholderPage — no backend calls, no new analytical logic.
 */
import PlaceholderPage from "./PlaceholderPage";

export function ThreatIntelPage() {
  return (
    <PlaceholderPage
      testid="nivxforge-threat-intel"
      eyebrow="NivXForge · Threat Intelligence"
      title="Threat Intelligence"
      description="IOC and infrastructure lookup, malware family identification, and historical sightings — grounded in the same enrichment sources the Investigate pipeline already uses."
      plannedFeatures={[
        "IOC lookup (IP · Domain · URL · Hash · Email)",
        "Infrastructure history and WHOIS / ASN pivots",
        "Malware family indicators and known-TTP linkage",
        "Cross-case IOC recurrence within the frozen corpus",
      ]}
      evidenceGate="This section is a UX-driven platform surface. Its capabilities activate when analyst usage produces evidence of what enrichment matters most — per OPERATIONAL_LOOP.md and CAPABILITY_REGISTRY.md."
    />
  );
}

export function ThreatHuntingPage() {
  return (
    <PlaceholderPage
      testid="nivxforge-threat-hunting"
      eyebrow="NivXForge · Threat Hunting"
      title="Threat Hunting"
      description="Query the corpus of past investigations for recurring IOCs, commands, YARA hits, and ATT&CK chains. Turns operational history into a hunting asset."
      plannedFeatures={[
        "IOC search across REAL_WORLD_LOG.md and workspace_cases",
        "Command-line fragment search",
        "YARA rule search",
        "ATT&CK technique / tactic search",
        "Similar-investigation matching",
      ]}
      evidenceGate="Each hunt surface requires ≥3 recurring analyst needs recorded in REAL_WORLD_LOG.md before its ADR is drafted."
    />
  );
}

export function KnowledgeBasePage() {
  return (
    <PlaceholderPage
      testid="nivxforge-knowledge"
      eyebrow="NivXForge · Knowledge Base"
      title="Knowledge Base"
      description="Analyst reference material — malware family notes, LOLBAS index, ATT&CK navigator, detection rules, and playbooks."
      plannedFeatures={[
        "Malware family index (evidence-linked to real cases)",
        "LOLBAS binary catalog with usage examples",
        "ATT&CK navigator scoped to the corpus",
        "Detection rules library",
        "Investigation playbooks",
      ]}
      evidenceGate="Content grows from real corpus cases — no synthetic entries. Each family / LOLBAS entry cites the case IDs where it appeared."
    />
  );
}

export function ReportsPage() {
  return (
    <PlaceholderPage
      testid="nivxforge-reports"
      eyebrow="NivXForge · Reports"
      title="Reports"
      description="One-click investigation reports for SOC, IR, and executive audiences. Every report cites the underlying evidence — no fabricated narrative."
      plannedFeatures={[
        "SOC report (analyst-facing, evidence-cited)",
        "IR report (incident response format)",
        "Executive summary (concise, non-technical)",
        "Markdown export",
        "PDF export",
      ]}
      evidenceGate="Report layouts are informed by analyst usage of the Investigate surface — driven by real workflow observations, not templates chosen in advance."
    />
  );
}

export function HistoryPage() {
  return (
    <PlaceholderPage
      testid="nivxforge-history"
      eyebrow="NivXForge · History"
      title="History"
      description="Searchable archive of previous investigations. Compare artifacts across time and identify recurring TTPs in your own operational corpus."
      plannedFeatures={[
        "Timeline of previous investigations",
        "Saved-case library",
        "Full-text and IOC search",
        "Side-by-side case comparison",
        "Reference-quality case highlights (from Corpus v1+)",
      ]}
      evidenceGate="History requires the workspace_cases + investigations corpus to reach a stable schema — no new backend structure is introduced by NivXForge for this section."
    />
  );
}
