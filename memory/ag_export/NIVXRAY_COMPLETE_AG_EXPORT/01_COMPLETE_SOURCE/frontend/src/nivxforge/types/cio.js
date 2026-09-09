/**
 * ADR-0014 · CIO Type Definitions (JSDoc)
 *
 * These typedefs mirror `cio.schema.v1.json` and give editors + linters
 * intellisense without requiring a TypeScript build step. When the
 * project migrates to TS (Phase A slice-N), regenerate `cio.ts` via
 * `json-schema-to-typescript` and delete this file.
 *
 * Contract source of truth: /api/schemas/v1/cio.schema.json
 */

/**
 * @typedef {Object} VerdictContribution
 * @property {string} node_id
 * @property {string} kind
 * @property {number} weight        - integer 0..10
 * @property {number} confidence    - float 0..1
 * @property {string|null} category
 * @property {string} label
 */

/**
 * @typedef {Object} VerdictNode
 * @property {"Malicious"|"Suspicious"|"Runtime Dependent"|"Informational"|"Undetermined"} label
 * @property {number} confidence     - float 0..1
 * @property {number} confidence_pct - integer 0..100
 * @property {string} reason
 * @property {VerdictContribution[]} contributors
 * @property {VerdictContribution[]} not_counted
 * @property {string} engine
 */

/**
 * @typedef {Object} KeyFinding
 * @property {string} id
 * @property {string} label
 * @property {number} weight
 * @property {number} confidence
 * @property {string[]} evidence_node_ids
 */

/**
 * @typedef {Object} Summary
 * @property {string} executive
 * @property {string} analyst
 * @property {string} technical
 * @property {string} attack_story
 * @property {KeyFinding[]} key_findings
 * @property {Array} unknowns
 * @property {Array} recommendations
 * @property {number} confidence
 * @property {Object} evidence_digest
 * @property {Array} attack_chain
 * @property {Object} entities_digest
 * @property {Object} mitre_digest
 * @property {Object} timeline_digest
 * @property {Object} report_sections
 * @property {string} composer_version
 */

/**
 * @typedef {Object} CIO
 * @property {"0.1"} schema_version
 * @property {string} cio_id
 * @property {string} created_at
 * @property {Object} source
 * @property {string} input_text
 * @property {string} input_kind
 * @property {Array} decode_chain
 * @property {Object} evidence_graph  - { nodes[], edges[] }
 * @property {Array} reasoning_steps
 * @property {number} confidence
 * @property {VerdictNode|null} verdict
 * @property {Array} timeline
 * @property {Summary} summary
 * @property {Array} recommendations
 * @property {Object} reports
 * @property {Object} metadata
 */

export {}; // ensure this file is treated as a module
