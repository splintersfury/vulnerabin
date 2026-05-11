"""IAT wrapper detection.

A function is an "IAT wrapper" if:
- Its name starts with `FUN_` (i.e. unnamed by Ghidra).
- It has <=2 instructions.
- It has exactly one "import-like" callee — i.e. a function flagged
  `is_external=True` OR `is_thunk=True`. Real decomp.py output rarely
  flags `is_external`; thunks are the canonical IAT representation in
  Ghidra's PE handling. We treat both as imports.
- It is itself a user-defined function (is_external=False, is_thunk=False).

Such functions are proposed as renames to `<ImportName>_wrapper` with
medium confidence.

Real-data note: callees in `function_index.json` may be encoded as either
addresses (synthetic fixtures) or names (real decomp.py output). The
resolver tries name lookup first, then address lookup, then 0x-prefix
fallbacks.
"""
from __future__ import annotations

import re

_FUN_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")
_WRAPPER_INSTRUCTION_THRESHOLD = 2


def _resolve_callee(callee_ref: str, by_addr: dict[str, dict], by_name: dict[str, dict]) -> dict | None:
    if not callee_ref:
        return None
    rec = by_name.get(callee_ref)
    if rec is not None:
        return rec
    rec = by_addr.get(callee_ref)
    if rec is not None:
        return rec
    if callee_ref.startswith("0x"):
        return by_addr.get(callee_ref[2:]) or by_addr.get(callee_ref)
    return by_addr.get("0x" + callee_ref)


def _is_import_like(rec: dict) -> bool:
    """True if the function should be treated as an import / IAT entry."""
    return bool(rec.get("is_external") or rec.get("is_thunk"))


def detect_wrappers(function_index: dict) -> list[dict]:
    """Return a list of proposed rename records for IAT wrappers."""
    records = function_index.get("functions", [])
    by_addr = {r["address"]: r for r in records}
    by_name = {r.get("name"): r for r in records if r.get("name")}
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
        import_callees: list[dict] = []
        for c in callees:
            target = _resolve_callee(c, by_addr, by_name)
            if target is not None and _is_import_like(target):
                import_callees.append(target)
        if len(import_callees) != 1:
            continue
        target = import_callees[0]
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
                f"import-like callee {target_name} at {target['address']}"
            ),
        })
    return proposed
