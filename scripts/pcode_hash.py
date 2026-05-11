"""Structural hash of a function for carryforward matching.

Foundation-quality stub: hashes a deterministic subset of `function_index.json`
record fields. The real PCode-aware implementation (which uses LibGhidra to
normalize PCode and hash the normalized form) lands in the Pass 0 sub-plan.

The hash MUST be stable across binary versions when the function body is
unchanged, and MUST change when the body changes. Foundation approximates
this via `code_hash + instruction_count + size`. The Pass 0 sub-plan replaces
this with the canonical PCode hash; tests added then prove cross-version
stability under recompile.
"""
from __future__ import annotations

import hashlib
import json
from typing import Iterable, Mapping

# Fields included in the structural hash. Notably EXCLUDES `name`, `callers`,
# `callees` (neighbor-dependent), and any per-pass derived fields.
_STRUCTURAL_FIELDS = ("code_hash", "instruction_count", "size")


def hash_function_record(rec: Mapping) -> str:
    """Return a hex SHA-256 of the function's structural fingerprint.

    A function with the same body (same `code_hash`, same instruction count,
    same size) produces the same hash regardless of name or neighbor metadata.
    """
    payload = {k: rec.get(k) for k in _STRUCTURAL_FIELDS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def aggregate_hash(records: Iterable[Mapping]) -> str:
    """Return a hex SHA-256 over the sorted per-function hashes.

    Order-independent: re-ordering the input iterable does not change the
    aggregate hash. Use this for `manifest.json#binary.pcode_hash_aggregate`.
    """
    per_func = sorted(hash_function_record(r) for r in records)
    canonical = "\n".join(per_func)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
