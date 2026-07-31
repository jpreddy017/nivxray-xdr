/**
 * ADR-0020 · Extended CIO types (Lab 2.0 consumer-facing).
 *
 * The auto-generated `cio.ts` mirrors the JSON Schema exactly, which
 * leaves `verdict` / `summary` / `metadata` as open records because
 * the underlying Pydantic models use `additionalProperties=True`.
 *
 * This file layers concrete, analyst-facing types on top of those
 * open records so components can consume them without `as any`. It
 * does NOT re-declare fields; it only narrows.
 *
 * When the schema tightens these shapes (future ADR), delete the
 * duplicates here and re-generate.
 */
import type {
  CanonicalInvestigationObject,
  EvidenceGraph,
  ReasoningStep,
  Node as CIONode,
  Edge as CIOEdge,
} from "./cio";

export type VerdictLabel =
  | "Malicious"
  | "Suspicious"
  | "Runtime Dependent"
  | "Informational"
  | "Undetermined";

export interface VerdictContribution {
  node_id: string;
  kind: string;
  /** integer 0..10 */
  weight: number;
  /** float 0..1 */
  confidence: number;
  category: string | null;
  label: string;
}

export interface VerdictNode {
  label: VerdictLabel;
  /** 0..1 */
  confidence: number;
  /** 0..100 */
  confidence_pct: number;
  reason: string;
  contributors: VerdictContribution[];
  not_counted: VerdictContribution[];
  engine: string;
}

export interface KeyFinding {
  id: string;
  label: string;
  weight: number;
  confidence: number;
  evidence_node_ids: string[];
}

export interface SummaryShape {
  executive: string;
  analyst: string;
  technical: string;
  attack_story: string;
  key_findings: KeyFinding[];
  unknowns: unknown[];
  recommendations: unknown[];
  confidence: number;
  evidence_digest: Record<string, unknown>;
  attack_chain: unknown[];
  entities_digest: Record<string, unknown>;
  mitre_digest: Record<string, unknown>;
  timeline_digest: Record<string, unknown>;
  report_sections: Record<string, unknown>;
  composer_version: string;
}

/**
 * Consumer-facing CIO with narrowed slots. Prefer this everywhere in
 * Lab 2.0 components; only the generator script uses the raw
 * `CanonicalInvestigationObject`.
 */
export interface CIO extends CanonicalInvestigationObject {
  verdict?: VerdictNode | null;
  summary?: SummaryShape;
  evidence_graph?: EvidenceGraph;
}

export type { EvidenceGraph, ReasoningStep, CIONode, CIOEdge };
