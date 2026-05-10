"""FEAT detector framework + registry.

Detectors register themselves at import time. Use load_detectors() to get
the subset relevant to a given (platform, binary_kind) tuple.
"""
from __future__ import annotations

from .base import Detector, DetectorContext, FeatureCandidate

# Populated at module import time when concrete detectors are loaded.
_REGISTRY: list[Detector] = []


def register(detector: Detector) -> None:
    """Add a detector to the global registry."""
    _REGISTRY.append(detector)


def load_detectors(platform: str, binary_kind: str) -> list[Detector]:
    """Return detectors that apply to (platform, binary_kind)."""
    return [
        d for d in _REGISTRY
        if platform in d.platforms and binary_kind in d.binary_kinds
    ]


__all__ = [
    "Detector",
    "DetectorContext",
    "FeatureCandidate",
    "register",
    "load_detectors",
]
