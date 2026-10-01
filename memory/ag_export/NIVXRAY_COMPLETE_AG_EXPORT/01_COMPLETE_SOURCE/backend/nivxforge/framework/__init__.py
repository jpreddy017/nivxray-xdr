"""ADR-0001 · artifact-agnostic Handler Framework.

Framework only. Zero concrete handlers. Every future handler earns
its own ADR referencing operational evidence.

Layers (top → bottom):
  Artifact               a raw input plus metadata
      ↓
  Shape Classifier       determines the artifact family (opaque token)
      ↓
  Handler Registry       maps family → handler(s) + metadata + evidence links
      ↓
  Coverage Reporter      surfaces which family fired, which handler ran,
                         and whether the residual output still looks obfuscated
"""
