"""Detector framework base classes."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FeatureCandidate:
    """One auto-detected FEAT candidate emitted by a detector."""
    slug: str
    name: str
    description: str
    detector: str
    detector_version: str
    evidence_type: str
    evidence_value: str
    weight: int
    user_observable: str
    capability_hints: list[str] = field(default_factory=list)
    source_hints: list[str] = field(default_factory=list)
    input_hints: list[str] = field(default_factory=list)
    anchor_hints: list[dict] = field(default_factory=list)
    ux_string_hints: list[str] = field(default_factory=list)


@dataclass
class DetectorContext:
    """Per-detector input bundle."""
    binary_path: Path
    decomp_dir: Path | None
    function_index: dict[str, Any]
    chains: dict[str, Any] | None
    re_block: dict[str, Any]
    existing_yaml: dict[str, Any]


class Detector(ABC):
    """Each detector parses one signal source and emits FeatureCandidate(s)."""
    name: str = ""
    version: str = "0"
    platforms: set[str] = set()
    binary_kinds: set[str] = set()
    representative_cve: str = ""

    @abstractmethod
    def detect(self, ctx: DetectorContext) -> list[FeatureCandidate]:
        """Return zero or more candidates extracted from ctx."""
