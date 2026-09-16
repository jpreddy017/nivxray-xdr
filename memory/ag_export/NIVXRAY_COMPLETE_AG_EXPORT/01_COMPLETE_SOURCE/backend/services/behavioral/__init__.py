"""Behavioral evidence adapters — telemetry adapters that produce
canonical evidence records for the existing investigation engine.

Per ADR-0023 (four principles): telemetry adapters are EVIDENCE
PRODUCERS ONLY. They do not run their own MITRE mapper, verdict
scorer, or process-tree engine. They normalize the wire format and
hand the evidence off to the existing pipeline.
"""
