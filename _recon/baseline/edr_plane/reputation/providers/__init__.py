"""Reputation providers. Adding one requires an adapter here and nothing
else — no change to canonical evidence and none to detection semantics.
"""
from .local_ioc import LocalIOCProvider

__all__ = ["LocalIOCProvider"]
