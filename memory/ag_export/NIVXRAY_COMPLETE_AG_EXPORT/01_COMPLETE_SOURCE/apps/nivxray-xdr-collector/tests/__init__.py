"""Shared pytest fixtures for Phase B collector tests."""
import os
import sys

# Make the app package importable when pytest runs from repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
