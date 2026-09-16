/**
 * Investigation Canvas Engine · public entry point.
 *
 * The engine is the FOUNDATION for every NivXRay investigation view.
 * Consumers import ONLY from this file — never reach into internals.
 *
 *   import { InvestigationCanvas } from "@/v2/canvas_engine";
 *
 * Data contract (v1.0):
 *
 *   Row   { key: string
 *         , label: string
 *         , band: string                  // grouping label
 *         , worstVerdict: 'benign'|'suspicious'|'malicious'
 *         , firstTs: number | ISO         // ms epoch or ISO string
 *         , lastTs:  number | ISO
 *         , meta?: any                    // consumer-defined
 *         }
 *
 *   Event { id: string                    // unique per event
 *         , rowKey: string                // must match a Row.key
 *         , ts: number | ISO
 *         , kind: 'execute'|'create'|'delete'|'network'|'file'
 *                |'registry'|'detect'|'compromise'|'exploit'|'scan'|'restore'
 *         , verdict: 'benign'|'suspicious'|'malicious'
 *         , label?: string                // for tooltips / evidence panel
 *         , mitre?: string[]              // optional MITRE codes
 *         , meta?: any                    // consumer-defined evidence blob
 *         }
 *
 *   Edge  { from: string                  // rowKey
 *         , to:   string                  // rowKey
 *         , kind?: 'spawn'|'load'|'write'|'net'
 *         }
 */
export { default as InvestigationCanvas } from "./InvestigationCanvas";
