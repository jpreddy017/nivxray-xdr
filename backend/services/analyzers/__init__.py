"""Artifact analyzers — separate from codecs (owner architectural rule).

PE + shellcode are *analyzers* / parsers, not codecs. The Universal
Decoder invokes them via a clean adapter when evidence indicates an
artifact; they never become part of the base/encoding/compression/
crypto codec surface.

Migration from `services/uaie/plugins/{pe_*,shellcode_*}` and
`services/die/preprocessor/recursive_decoder` PE/shellcode paths is
scheduled for Gate 2D-B2.
"""
