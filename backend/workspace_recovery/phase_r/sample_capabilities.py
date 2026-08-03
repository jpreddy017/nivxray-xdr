"""
Phase R \u00b7 Central per-sample capability tag map.

Maps every R1 sample ID to a list of capability tags drawn from
:mod:`workspace_recovery.phase_r.capabilities.KNOWN_CAPABILITIES`.

Kept as a single file so a) capability additions can be reviewed
in one place, b) the family builders stay focused on the payload
data, and c) the ``test_every_r1_sample_carries_known_capability``
governance test has one source of truth.

Post-build injection
--------------------
The R1 fingerprint generator (and family builders) call
:func:`inject_capabilities_into_family` after emitting the JSON so
every sample carries ``expected.capabilities`` in the on-disk
corpus. Missing entries are treated as a fatal build error.
"""
from __future__ import annotations

import json
from pathlib import Path

from workspace_recovery.phase_r.capabilities import KNOWN_CAPABILITIES


# ---------------------------------------------------------------------------
# Per-sample capability tags. Every R1 sample MUST appear here with at least
# one tag drawn from KNOWN_CAPABILITIES.
# ---------------------------------------------------------------------------
SAMPLE_CAPABILITIES: dict[str, list[str]] = {
    # ============ Cobalt Strike ==========================================
    "CS001": ["download_cradle", "beacon_c2"],
    "CS002": ["download_cradle", "beacon_c2"],
    "CS003": ["iwr_pipeline_download", "beacon_c2"],
    "CS004": ["string_concat_obfuscation", "variable_propagation_obfuscation", "download_cradle"],
    "CS005": ["string_concat_obfuscation", "variable_propagation_obfuscation", "download_cradle"],
    "CS006": ["string_concat_obfuscation", "variable_propagation_obfuscation", "download_cradle"],
    "CS007": ["encoded_command", "download_cradle"],
    "CS008": ["encoded_command"],
    "CS009": ["encoded_command", "hidden_window", "download_cradle"],
    "CS010": ["cmd_ps_handoff", "encoded_command"],
    "CS011": ["cmd_ps_handoff", "cmd_caret_obfuscation", "encoded_command", "download_cradle"],
    "CS012": ["env_var_reconstruction", "join_array_reconstruction", "download_cradle"],
    "CS013": ["iwr_pipeline_download", "beacon_c2"],
    "CS014": ["curl_alias_download", "beacon_c2"],
    "CS015": ["string_concat_obfuscation", "variable_propagation_obfuscation", "iwr_pipeline_download"],
    "CS016": ["multi_layer_encoding", "download_cradle"],
    "CS017": ["encoded_command", "download_cradle"],
    "CS018": ["backtick_obfuscation", "iwr_pipeline_download"],
    "CS019": ["variable_propagation_obfuscation", "download_cradle"],
    "CS020": ["variable_propagation_obfuscation", "string_concat_obfuscation", "download_cradle"],
    "CS021": ["cmd_ps_handoff", "cmd_caret_obfuscation", "encoded_command", "download_cradle"],
    "CS022": ["encoded_command"],
    "CS023": ["encoded_command", "download_cradle"],
    "CS024": ["cmd_ps_handoff", "cmd_caret_obfuscation", "encoded_command", "download_cradle"],
    "CS025": ["backtick_obfuscation", "iwr_pipeline_download"],
    "CS026": ["case_obfuscation", "download_cradle"],
    "CS027": ["encoded_command", "process_discovery"],
    "CS028": ["encoded_command", "reflective_loader"],
    "CS029": ["backtick_obfuscation", "iwr_pipeline_download"],
    "CS030": ["download_cradle", "beacon_c2"],
    "CS031": ["join_array_reconstruction", "download_cradle"],
    "CS032": ["join_array_reconstruction", "download_cradle"],
    "CS033": ["string_index_slice", "join_array_reconstruction", "download_cradle"],
    "CS034": ["numeric_constant_folding_obf", "time_based_evasion", "download_cradle"],
    "CS035": ["shellcode_staging", "variable_propagation_obfuscation"],

    # ============ GootLoader =============================================
    "GL001": ["download_cradle", "seo_poisoning_delivery"],
    "GL002": ["download_cradle", "seo_poisoning_delivery"],
    "GL003": ["download_cradle", "seo_poisoning_delivery"],
    "GL004": ["iwr_pipeline_download", "seo_poisoning_delivery"],
    "GL005": ["iwr_pipeline_download", "seo_poisoning_delivery"],
    "GL006": ["variable_propagation_obfuscation", "string_concat_obfuscation", "download_cradle"],
    "GL007": ["variable_propagation_obfuscation", "string_concat_obfuscation", "download_cradle"],
    "GL008": ["variable_propagation_obfuscation", "download_cradle"],
    "GL009": ["string_concat_obfuscation", "download_cradle"],
    "GL010": ["string_concat_obfuscation", "download_cradle"],
    "GL011": ["encoded_command", "download_cradle"],
    "GL012": ["encoded_command", "hidden_window", "download_cradle"],
    "GL013": ["encoded_command", "beacon_c2"],
    "GL014": ["encoded_command", "registry_run_key_persistence"],
    "GL015": ["env_var_reconstruction", "join_array_reconstruction", "download_cradle"],
    "GL016": ["env_var_reconstruction", "join_array_reconstruction"],
    "GL017": ["backtick_obfuscation", "download_cradle"],
    "GL018": ["backtick_obfuscation", "iwr_pipeline_download"],
    "GL019": ["case_obfuscation", "download_cradle"],
    "GL020": ["case_obfuscation", "iwr_pipeline_download"],
    "GL021": ["cmd_ps_handoff", "cmd_caret_obfuscation", "encoded_command", "download_cradle"],
    "GL022": ["multi_layer_encoding", "download_cradle"],
    "GL023": ["js_unicode_escape_obf", "javascript_to_powershell_handoff"],
    "GL024": ["js_atob_obf", "javascript_to_powershell_handoff"],
    "GL025": ["js_split_shuffle_obf", "javascript_to_powershell_handoff"],
    "GL026": ["js_split_shuffle_obf", "javascript_to_powershell_handoff"],

    # ============ DarkGate ===============================================
    "DG001": ["xor_byte_array_decoder", "reverse_shell"],
    "DG002": ["xor_byte_array_decoder", "beacon_c2"],
    "DG003": ["encoded_command", "download_cradle", "beacon_c2"],
    "DG004": ["encoded_command", "hidden_window", "registry_run_key_persistence"],
    "DG005": ["cmd_ps_handoff", "cmd_caret_obfuscation", "encoded_command", "download_cradle"],
    "DG006": ["download_cradle", "beacon_c2"],
    "DG007": ["download_cradle", "beacon_c2"],
    "DG008": ["string_concat_obfuscation", "variable_propagation_obfuscation", "download_cradle"],
    "DG009": ["shellcode_staging", "variable_propagation_obfuscation"],
    "DG010": ["backtick_obfuscation", "iwr_pipeline_download"],
    "DG011": ["case_obfuscation", "download_cradle"],

    # ============ Linux Droppers =========================================
    "LD001": ["reverse_shell"],
    "LD002": ["reverse_shell"],
    "LD003": ["reverse_shell", "multi_layer_encoding"],

    # ============ Lumma Stealer ==========================================
    "LU001": ["download_cradle"],
    "LU002": ["iwr_pipeline_download"],
    "LU003": ["mshta_cradle"],
    "LU004": ["encoded_command", "download_cradle"],
    "LU005": ["encoded_command", "hidden_window", "registry_run_key_persistence"],
    "LU006": ["encoded_command", "clipboard_monitor", "beacon_c2"],
    "LU007": ["cmd_ps_handoff", "cmd_caret_obfuscation", "encoded_command", "download_cradle"],
    "LU008": ["string_concat_obfuscation", "variable_propagation_obfuscation", "download_cradle"],
    "LU009": ["backtick_obfuscation", "iwr_pipeline_download"],
    "LU010": ["shellcode_staging", "variable_propagation_obfuscation"],

    # ============ SocGholish =============================================
    "SG001": ["js_unicode_escape_obf", "seo_poisoning_delivery"],
    "SG002": ["js_unicode_escape_obf", "javascript_to_powershell_handoff"],
    "SG003": ["js_atob_obf", "seo_poisoning_delivery"],
    "SG004": ["js_atob_obf", "javascript_to_powershell_handoff"],
    "SG005": ["js_split_shuffle_obf", "seo_poisoning_delivery"],
    "SG006": ["js_split_shuffle_obf", "seo_poisoning_delivery"],
    "SG007": ["encoded_command", "download_cradle"],
    "SG008": ["string_concat_obfuscation", "variable_propagation_obfuscation", "download_cradle"],
    "SG009": ["download_cradle", "beacon_c2"],
    "SG010": ["iwr_pipeline_download", "beacon_c2"],
    "SG011": ["backtick_obfuscation", "iwr_pipeline_download"],
}


def get(sample_id: str) -> list[str]:
    """Return the capability tag list for ``sample_id``. Raises on unknown."""
    if sample_id not in SAMPLE_CAPABILITIES:
        raise KeyError(f"No capability tags registered for sample {sample_id!r}")
    tags = SAMPLE_CAPABILITIES[sample_id]
    unknown = [t for t in tags if t not in KNOWN_CAPABILITIES]
    if unknown:
        raise ValueError(
            f"Sample {sample_id!r} carries unknown capability tags: {unknown}"
        )
    return list(tags)


def inject_capabilities_into_family(family_json_path: Path) -> int:
    """Post-build step: walk a family JSON file and set
    ``sample.expected.capabilities`` from :data:`SAMPLE_CAPABILITIES`.
    Returns the number of samples tagged. Raises if any sample is
    missing from the mapping."""
    with family_json_path.open("r", encoding="utf-8") as fh:
        doc = json.load(fh)
    n = 0
    for tech in doc.get("techniques") or []:
        for sample in tech.get("samples") or []:
            sid = sample["id"]
            tags = get(sid)
            sample.setdefault("expected", {})["capabilities"] = tags
            n += 1
    family_json_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return n


__all__ = [
    "SAMPLE_CAPABILITIES",
    "get",
    "inject_capabilities_into_family",
]
