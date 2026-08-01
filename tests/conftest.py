"""Shared pytest fixtures."""
import sys
from pathlib import Path

# Make etc/proteus/bin importable as a top-level package so tests can
# `from dispatcher_logic import ...` without changing PYTHONPATH at runtime.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "etc" / "proteus" / "bin"))
