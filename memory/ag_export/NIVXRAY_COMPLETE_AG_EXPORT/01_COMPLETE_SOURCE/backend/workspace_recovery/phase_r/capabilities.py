"""
Phase R \u00b7 Malware Capability Vocabulary.

Controlled vocabulary of reusable malware capability tags. Every
R1 corpus sample carries one or more of these tags as
``expected.capabilities``. This is intentionally kept as
**metadata only** for now \u2014 no dashboard integration, no
registry object, no cross-referencing. It's the seed that later
enables a full Malware Capability Registry without a schema
migration (per the owner's Phase R architectural note).

Guidelines
----------
* Capability names describe *what the code does* at analyst-visible
  granularity \u2014 the equivalent of ATT&CK sub-techniques but in
  malware-analyst vernacular.
* Keep the vocabulary **small and precise**: adding "another word
  for the same thing" degrades the metric. Prefer reusing an
  existing tag over minting a new one.
* Every new family builder MUST tag every sample with at least one
  capability from this vocabulary. The
  ``test_every_r1_sample_carries_known_capability`` gate enforces
  this.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# The controlled vocabulary. All capability strings MUST come from this set.
# Adding a new capability requires updating this file and re-running the
# fingerprint generator (fingerprints are content-only \u2014 they don't include
# capability tags \u2014 so this is drift-free).
# ---------------------------------------------------------------------------

KNOWN_CAPABILITIES: frozenset[str] = frozenset(
    {
        # ---- Delivery & Staging ----
        "download_cradle",              # IEX + DownloadString classic
        "iwr_pipeline_download",        # iwr $url -useb | iex pipeline
        "curl_alias_download",          # PowerShell `curl` alias
        "encoded_command",              # PS -EncodedCommand base64 UTF-16LE
        "cmd_ps_handoff",               # CMD launches PowerShell
        "mshta_cradle",                 # mshta.exe scriptlet
        "shellcode_staging",            # [Convert]::FromBase64String + IEX
        "reflective_loader",            # [Reflection.Assembly]::Load
        "multi_layer_encoding",         # hex \u2192 b64 \u2192 UTF-16LE chains

        # ---- Obfuscation Techniques ----
        "string_concat_obfuscation",    # '+ concat URL reconstruction
        "variable_propagation_obfuscation",  # $u='...'; ... $u ...
        "env_var_reconstruction",       # $env:ComSpec[4,15,25] slicing
        "join_array_reconstruction",    # -join / [String]::Join arrays
        "string_index_slice",           # $s[a..b], $s[a,b,c]
        "backtick_obfuscation",         # I`E`X mid-identifier
        "case_obfuscation",             # iEx / nEw-oBjEcT random case
        "cmd_caret_obfuscation",        # c^m^d /c p^ow^ers^he^ll
        "numeric_constant_folding_obf", # (30+30) style arithmetic
        "js_unicode_escape_obf",        # '\\u00XX...' in JS
        "js_atob_obf",                  # atob() / nested atob()
        "js_split_shuffle_obf",         # .split().reverse().join()
        "xor_byte_array_decoder",       # 0xNN,0xNN,... xor 0xNN

        # ---- Behavior / Objective ----
        "beacon_c2",                    # C2 URL check-in
        "reverse_shell",                # nc / bash -i / etc.
        "registry_run_key_persistence", # HKCU\\...\\Run persistence
        "hidden_window",                # -W Hidden / -WindowStyle Hidden
        "process_discovery",            # Get-Process, ps
        "time_based_evasion",           # Sleep with jitter
        "javascript_to_powershell_handoff",  # JS \u2192 PS pivot
        "seo_poisoning_delivery",       # GootLoader / SocGholish pattern

        # ---- Family-specific (reused across many families) ----
        "clipboard_monitor",            # Lumma / RedLine / Vidar / StealC
        # NOTE: additional stealer capabilities like
        # ``browser_credential_theft`` and ``crypto_wallet_theft`` will
        # be added to this vocabulary when a family (e.g. Lumma binary
        # unpacker, RedLine, Vidar) actually exercises them. Per Phase R
        # doctrine: keep the vocabulary small and precise.
    }
)


def is_known(cap: str) -> bool:
    return cap in KNOWN_CAPABILITIES


def sorted_known() -> tuple[str, ...]:
    return tuple(sorted(KNOWN_CAPABILITIES))


__all__ = ["KNOWN_CAPABILITIES", "is_known", "sorted_known"]
