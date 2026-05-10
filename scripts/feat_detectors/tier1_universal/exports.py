"""Detect features by clustering exported function names by prefix.

Signal: PE/ELF exports table. When >=2 exports share a non-trivial prefix
(matching `<Prefix>_<Word>`), emit one FEAT candidate per cluster.

Representative CVE: not bug-class-specific - exported function clusters
are how vendor SDKs surface features (BdUpdate*, McsScan*, AvgPolicy*).
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .. import register
from ..base import Detector, DetectorContext, FeatureCandidate


# Capture the prefix portion of `<Prefix>_<Word>`. The full prefix (up to the
# last underscore before the final word) must be >=3 chars to avoid garbage
# clusters from short names like `A_b`. The terminal word must also be alnum.
PREFIX_RE = re.compile(r"^([A-Z][A-Za-z0-9_]*)_([A-Za-z0-9]+)$")


def _slug(prefix: str) -> str:
    """Convert e.g. `Bd_Update_` -> `bd-update`."""
    bare = prefix.rstrip("_")
    # Insert a dash between camel transitions and downcase.
    out = re.sub(r"(?<=[a-z0-9])([A-Z])", r"-\1", bare)
    out = re.sub(r"_+", "-", out).lower()
    return out


class ExportsDetector(Detector):
    name = "exports"
    version = "1.0"
    platforms = {"windows", "linux", "macos"}
    binary_kinds = {"exe", "dll", "sys", "so", "dylib"}
    representative_cve = "n/a - generic feature surface"

    def detect(self, ctx: DetectorContext) -> list[FeatureCandidate]:
        exports: list[dict[str, Any]] = ctx.function_index.get("exports") or []
        clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in exports:
            name = e.get("name", "")
            m = PREFIX_RE.match(name)
            if not m:
                continue
            raw_prefix = m.group(1)
            if len(raw_prefix) < 3:
                continue
            prefix = raw_prefix + "_"
            clusters[prefix].append(e)

        candidates: list[FeatureCandidate] = []
        for prefix, members in clusters.items():
            if len(members) < 2:
                continue
            slug = _slug(prefix)
            anchors = [
                {"function": m["name"], "rva": m.get("rva", ""), "role": "source"}
                for m in members
            ]
            candidates.append(FeatureCandidate(
                slug=slug,
                name=f"Exported {prefix}* surface",
                description=f"Cluster of {len(members)} exported functions sharing prefix `{prefix}`.",
                detector=self.name,
                detector_version=self.version,
                evidence_type="export_prefix",
                evidence_value=prefix,
                weight=2,
                user_observable=f"Callable via DLL export - any process with the right import declaration",
                capability_hints=[],
                source_hints=[],
                input_hints=[],
                anchor_hints=anchors,
                ux_string_hints=[],
            ))
        return candidates


register(ExportsDetector())
