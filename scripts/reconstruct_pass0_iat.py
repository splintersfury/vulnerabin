"""IAT wrapper detection.

A function is an "IAT wrapper" if:
- Its name starts with `FUN_` (i.e. unnamed by Ghidra).
- It has <=2 instructions.
- It has exactly one external callee.
- It is itself a user-defined function (is_external=False, is_thunk=False).

Such functions are proposed as renames to `<ImportName>_wrapper` with
medium confidence. This is the simplest possible deterministic naming
heuristic and produces 5-15% yield on a typical Windows binary.
"""
from __future__ import annotations

import re

_FUN_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")
_WRAPPER_INSTRUCTION_THRESHOLD = 2


def detect_wrappers(function_index: dict) -> list[dict]:
    """Return a list of proposed rename records for IAT wrappers.

    Each record matches the manifest.json#passes[].proposed_renames schema.
    """
    records = function_index.get("functions", [])
    by_addr = {r["address"]: r for r in records}
    proposed: list[dict] = []

    for r in records:
        if r.get("is_external") or r.get("is_thunk"):
            continue
        name = r.get("name", "")
        if not _FUN_RE.match(name):
            continue
        if r.get("instruction_count", 0) > _WRAPPER_INSTRUCTION_THRESHOLD:
            continue
        callees = r.get("callees") or []
        external_callees = [
            by_addr[c]
            for c in callees
            if c in by_addr and by_addr[c].get("is_external")
        ]
        if len(external_callees) != 1:
            continue
        target = external_callees[0]
        target_name = target.get("name", "")
        if not target_name:
            continue
        proposed.append({
            "addr": r["address"],
            "from": name,
            "to": f"{target_name}_wrapper",
            "confidence": "medium",
            "source": "iat_wrapper_detection",
            "rationale": (
                f"{r['instruction_count']}-instruction function with single "
                f"external callee {target_name} at {target['address']}"
            ),
        })
    return proposed
