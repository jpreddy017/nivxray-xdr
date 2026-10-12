"""Existing server-owned operation registration; no app/DB/auth import."""
def register_operations():
    import ops_extended  # noqa: F401  — registers +42 operations
    from decoders import ps_encodedcommand_multilayer  # noqa: F401
    from decoders import ps_inline_eval  # noqa: F401  — powershell-hex-csv-inline + powershell-xor-inline-key
    from decoders import batch_envvar_substitute  # noqa: F401  — batch-envvar-substitute + cmd-envvar-substring-picker
    from decoders import ps_reverse_swap  # noqa: F401  — powershell-reverse-string + powershell-reverse-regex-swap
    from decoders import ps_semantic_mini  # noqa: F401  — RC4.2 chain evaluator
    from decoders import ps_normalizer  # noqa: F401  — RC4.3 PS normalizer + runtime simulator
    from decoders import cmd_runtime_reconstruct  # noqa: F401  — RC4.4 CMD env-var runtime reconstruction engine
    from decoders import ps_backtick_normalizer  # noqa: F401  — RC4.5 PS backtick / line-continuation normalizer
    from decoders import ps_alias_normalizer  # noqa: F401  — RC4.5 PS cmdlet-alias normalizer
    from decoders import crypto_api_annotator  # noqa: F401  — crypto-api-annotator (RC4.1)
    from decoders import rc4_inline_decrypt  # noqa: F401  — rc4-inline-decrypt (RC4.1)
    from decoders import rc40_orchestrator_plugins  # noqa: F401  — orchestrator plugins for RC4.0 decoders
    import ops_base_family  # noqa: F401  — registers base58/base62/base64url/z85
