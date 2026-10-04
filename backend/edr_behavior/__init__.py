"""NivXForge E3 behavioral + sequence detection engine (additive, contract-bound)."""
ENGINE_ID = "nivxforge.edr_behavior.sequence_engine"
ENGINE_VERSION = "e3-seq-1.1.0"
CONTRACT_VERSION = "e3.behavior.v1"
# An ML signal alone never creates a Detection; it may only join real evidence in a chain.
ML_BOUNDARY_VERSION = "e3.ml-boundary.v1"
ML_ONLY_REASON = f"ML signal evidence alone cannot create a detection ({ML_BOUNDARY_VERSION})"
