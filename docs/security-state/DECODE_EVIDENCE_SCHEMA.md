# NivXRay XDR — Decode Evidence Schema & Data Contract

## 1. Objective & Specification

This document defines the formal data contract for all decoded intelligence, multi-stage forensic evidence, and carved artifact relationships produced by the NivXRay XDR Content Intelligence & Deobfuscation Layer.

---

## 2. Complete Evidence JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "NivXRayDecodeEvidence",
  "type": "object",
  "required": [
    "schema_version",
    "event_id",
    "original",
    "stages",
    "effective_payload",
    "stop_reason",
    "semantic_intelligence"
  ],
  "properties": {
    "schema_version": {
      "type": "string",
      "enum": ["2.0.0"]
    },
    "event_id": {
      "type": "string",
      "description": "Unique identifier of the originating security event"
    },
    "tenant_id": {
      "type": "string",
      "description": "Enterprise tenant scope for multi-tenant isolation"
    },
    "original": {
      "type": "object",
      "required": ["raw_content", "length", "sha256"],
      "properties": {
        "raw_content": { "type": "string", "description": "Immutable original string/bytes" },
        "length": { "type": "integer" },
        "sha256": { "type": "string", "pattern": "^[a-f0-9]{64}$" }
      }
    },
    "stages": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "stage_index",
          "decoder",
          "input_hash",
          "output_hash",
          "input_length",
          "output_length",
          "why_selected",
          "confidence",
          "status",
          "output_payload"
        ],
        "properties": {
          "stage_index": { "type": "integer" },
          "decoder": { "type": "string", "description": "Authoritative codec/operator ID" },
          "op": { "type": "string", "description": "Universal alias for decoder" },
          "input_hash": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
          "output_hash": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
          "input_length": { "type": "integer" },
          "output_length": { "type": "integer" },
          "duration_ms": { "type": "number" },
          "why_selected": { "type": "string", "description": "Deterministic regex/heuristic reason" },
          "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
          "status": { "type": "string", "enum": ["success", "partial", "error", "skipped"] },
          "preview": { "type": "string", "description": "First 128 characters of output" },
          "output_payload": { "type": "string", "description": "Size-bounded output (<= 64KB)" },
          "tradecraft": { "type": "array", "items": { "type": "string" } }
        }
      }
    },
    "effective_payload": {
      "type": "string",
      "description": "Final recovered plaintext or terminal representation"
    },
    "stop_reason": {
      "type": "string",
      "enum": [
        "terminal_plaintext_reached",
        "terminal_binary_reached",
        "no_transformation_identified",
        "already_plaintext",
        "cycle_detected",
        "depth_limit_exceeded",
        "time_budget_exhausted",
        "decompression_bomb_detected"
      ]
    },
    "carved_artifacts": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["child_id", "artifact_type", "offset", "size", "sha256"],
        "properties": {
          "child_id": { "type": "string" },
          "artifact_type": { "type": "string", "enum": ["pe", "elf", "macho", "shellcode", "archive", "script"] },
          "offset": { "type": "integer" },
          "size": { "type": "integer" },
          "sha256": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
          "analysis": { "type": "object" }
        }
      }
    },
    "semantic_intelligence": {
      "type": "object",
      "required": ["language", "iocs", "mitre_techniques", "lolbas"],
      "properties": {
        "language": { "type": "string" },
        "intent": { "type": "string" },
        "lolbas": { "type": "array", "items": { "type": "string" } },
        "mitre_techniques": { "type": "array", "items": { "type": "string" } },
        "malware_families": { "type": "array", "items": { "type": "string" } },
        "iocs": {
          "type": "object",
          "properties": {
            "ips": { "type": "array", "items": { "type": "string" } },
            "urls": { "type": "array", "items": { "type": "string" } },
            "domains": { "type": "array", "items": { "type": "string" } },
            "hashes": { "type": "array", "items": { "type": "string" } },
            "registry_keys": { "type": "array", "items": { "type": "string" } },
            "mutexes": { "type": "array", "items": { "type": "string" } },
            "apis": { "type": "array", "items": { "type": "string" } }
          }
        }
      }
    }
  }
}
```
