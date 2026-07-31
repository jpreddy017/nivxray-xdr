/**
 * AUTO-GENERATED — DO NOT EDIT BY HAND.
 *
 * Source of truth: /api/schemas/v1/cio.schema.json
 *                  (backend/nivxforge/schemas/cio.schema.v1.json)
 * Regenerate with: yarn gen:cio
 *
 * ADR-0014 · ADR-0020
 */

export type SchemaVersion = "0.1";
/**
 * Unique CIO id (uuid-derived).
 */
export type CioId = string;
export type CreatedAt = string;
/**
 * 'lab' | 'workspace' | 'api' | 'cli' | ...
 */
export type Surface = string;
export type Endpoint = string | null;
export type CorrelationId = string | null;
/**
 * Raw input under investigation.
 */
export type InputText = string;
/**
 * Detected input kind (input-agnostic principle §1.1.8).
 */
export type InputKind = string;
/**
 * Attached artifacts (files/logs); Slice-A leaves empty.
 */
export type Artifacts = {
  [k: string]: unknown;
}[];
export type DecodeChain = {
  [k: string]: unknown;
}[];
/**
 * Unique node id within the CIO, e.g. 'N-001'.
 */
export type Id = string;
export type Kind =
  | "artifact"
  | "decoded_fragment"
  | "ioc"
  | "mitre_technique"
  | "lolbin"
  | "family_match"
  | "behaviour"
  | "reasoning_step"
  | "verdict";
/**
 * Analyst-facing label (short, humanised).
 */
export type Label = string;
/**
 * Canonical value (IOC value, technique id, LOLBIN name, etc).
 */
export type Value = string | null;
/**
 * Node confidence 0..1.
 */
export type Confidence = number;
/**
 * Producer tag (e.g. 'decoder:base64', 'extractor:ioc', 'rule:command_analyzer').
 */
export type Provenance = string;
export type Nodes = Node[];
/**
 * Source node id.
 */
export type Source = string;
/**
 * Target node id.
 */
export type Target = string;
export type Kind1 =
  "produces" | "contributes_to" | "contradicts" | "supports" | "derived_from" | "references" | "escalates_to";
/**
 * Edge weight 0..1 (contribution strength).
 */
export type Weight = number;
export type Edges = Edge[];
/**
 * Dense monotonic id within the CIO, e.g. 'RS-001'.
 */
export type StepId = string;
export type Timestamp = string;
/**
 * Internal rule identifier — never surfaced to prose.
 */
export type Rule = string;
/**
 * Graph node ids this step read.
 */
export type InputNodes = string[];
/**
 * Graph node ids this step produced.
 */
export type OutputNodes = string[];
export type ConfidenceBefore = number;
export type ConfidenceAfter = number;
/**
 * Analyst-facing humanised explanation.
 */
export type Explanation = string;
export type ReasoningSteps = ReasoningStep[];
export type Confidence1 = number;
/**
 * Populated by Slice-C Reasoning Engine unification.
 */
export type Verdict = {
  [k: string]: unknown;
} | null;
export type Timeline = {
  [k: string]: unknown;
}[];
export type Recommendations = {
  [k: string]: unknown;
}[];

/**
 * NivXRay Canonical Investigation Object (CIO) — the single source of truth produced by the deterministic Investigation Engine. See ADR-0014.
 */
export interface CanonicalInvestigationObject {
  schema_version?: SchemaVersion;
  cio_id: CioId;
  created_at?: CreatedAt;
  source: CIOSource;
  input_text?: InputText;
  input_kind?: InputKind;
  artifacts?: Artifacts;
  decode_chain?: DecodeChain;
  evidence_graph?: EvidenceGraph;
  reasoning_steps?: ReasoningSteps;
  confidence?: Confidence1;
  verdict?: Verdict;
  timeline?: Timeline;
  summary?: Summary;
  recommendations?: Recommendations;
  reports?: Reports;
  metadata?: Metadata;
}
/**
 * Where the investigation was initiated from.
 */
export interface CIOSource {
  surface?: Surface;
  endpoint?: Endpoint;
  correlation_id?: CorrelationId;
}
/**
 * The Evidence Graph — nodes + typed edges = the investigation.
 */
export interface EvidenceGraph {
  nodes?: Nodes;
  edges?: Edges;
}
/**
 * A single node in the Evidence Graph.
 */
export interface Node {
  id: Id;
  kind: Kind;
  label: Label;
  value?: Value;
  confidence?: Confidence;
  provenance?: Provenance;
  attrs?: Attrs;
}
/**
 * Kind-specific attributes (kept small).
 */
export interface Attrs {
  [k: string]: unknown;
}
/**
 * A directed, typed edge in the Evidence Graph.
 */
export interface Edge {
  source: Source;
  target: Target;
  kind: Kind1;
  weight?: Weight;
}
/**
 * One replayable decision recorded by the Investigation Engine.
 *
 * Enables replay, debugging, explainability, analyst audit, training
 * data, and LLM context — one structure covers all seven use cases
 * (§1.1 principle 7).
 */
export interface ReasoningStep {
  step_id: StepId;
  timestamp?: Timestamp;
  rule: Rule;
  input_nodes?: InputNodes;
  output_nodes?: OutputNodes;
  confidence_before?: ConfidenceBefore;
  confidence_after?: ConfidenceAfter;
  explanation?: Explanation;
}
export interface Summary {
  [k: string]: unknown;
}
export interface Reports {
  [k: string]: unknown;
}
export interface Metadata {
  [k: string]: unknown;
}
