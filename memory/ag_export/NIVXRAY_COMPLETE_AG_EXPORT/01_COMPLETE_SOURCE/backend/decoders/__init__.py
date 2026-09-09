"""NivXRay L2 decoders — plugin package.

Every submodule instantiates a BaseDecoder subclass and calls
`DecoderRegistry.register(instance)` at import time. Auto-discovery is
driven by `engine.registry`; you should never import from this package
directly at runtime — use the registry instead.
"""
