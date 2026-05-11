"""Pass 0 — composed deterministic detectors.

Pure-Python: project discovery + IAT wrapper detection + pcode-hash carryforward.
Returns a Pass0Result dict that the reconstruct.py orchestrator merges into
`manifest.json#passes[]`.
"""
from __future__ import annotations

from typing import Optional

import reconstruct_pass0_carryforward as cf  # type: ignore
import reconstruct_pass0_discovery as discovery  # type: ignore
import reconstruct_pass0_iat as iat  # type: ignore

_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _dedupe_by_addr_keeping_highest_confidence(renames: list[dict]) -> list[dict]:
    best: dict[str, dict] = {}
    for r in renames:
        addr = r["addr"]
        cur = best.get(addr)
        if cur is None or _CONFIDENCE_RANK[r["confidence"]] > _CONFIDENCE_RANK[cur["confidence"]]:
            best[addr] = r
    return sorted(best.values(), key=lambda r: r["addr"])


def run(function_index: dict, prior_manifest: Optional[dict]) -> dict:
    """Compose the Pass 0 detectors and return the Pass0Result.

    Result shape:
        {
          "pass": "pass0",
          "tools_used": ["project_discovery", "iat_wrapper_detection", ...],
          "project_discovery": {...},   # from reconstruct_pass0_discovery.extract
          "proposed_renames": [...],     # deduped by addr, highest confidence wins
          "renames_by_source": {"iat_wrapper_detection": N, ...},
        }
    """
    proj = discovery.extract(function_index)
    iat_renames = iat.detect_wrappers(function_index)
    cf_renames = cf.carryforward(function_index, prior_manifest=prior_manifest)

    combined = _dedupe_by_addr_keeping_highest_confidence(iat_renames + cf_renames)

    tools_used = ["project_discovery"]
    if iat_renames:
        tools_used.append("iat_wrapper_detection")
    if cf_renames:
        tools_used.append("pcode_hash_carryforward")

    renames_by_source: dict[str, int] = {}
    for r in combined:
        renames_by_source[r["source"]] = renames_by_source.get(r["source"], 0) + 1

    return {
        "pass": "pass0",
        "tools_used": tools_used,
        "project_discovery": proj,
        "proposed_renames": combined,
        "renames_by_source": renames_by_source,
    }
