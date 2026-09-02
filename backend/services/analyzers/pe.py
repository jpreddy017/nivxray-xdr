"""PE analyzer scaffold · Gate 2D-B1.

Migration target for Gate 2D-B2:
  · services/uaie/plugins/pe_analyzer
  · services/uaie/plugins/pe_extractor
  · services/uaie/plugins/pe_dotnet_recognizer
  · services/uaie/plugins/validator_pe_bytes

Contract: an analyzer accepts bytes/text, returns structured
metadata + optional child artifacts. It is NEVER invoked via
the codec/DDO path; the caller must produce explicit evidence
(MZ magic byte) before invocation.
"""
