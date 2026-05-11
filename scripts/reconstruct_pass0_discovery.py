"""Project discovery: extract a `project_discovery` block from a parsed
`function_index.json` dict.

Pure-Python; does not require LibGhidra. Reads only the data already produced
by `scripts/decomp.py`'s headless Ghidra export. The output dict is the same
shape declared in the reconstruct spec §3.1.

Real-data note: decomp.py output uses bare-hex addresses (`'140001008'`),
encodes callees as NAMES (e.g. `'atexit'`, `'FUN_140001640'`), and rarely
flags `is_exported` / `is_external`. Entrypoint detection therefore uses
name-pattern heuristics; reachability resolves callees through a `by_name`
index alongside `by_addr`.
"""
from __future__ import annotations

from typing import Iterable

# Well-known entrypoint names emitted by linkers + Ghidra autonaming.
_ENTRYPOINT_NAMES = {
    "entry", "_entry", "_start",
    "DriverEntry", "_DriverEntry",
    "DllMain", "_DllMain", "_DllMainCRTStartup",
    "WinMain", "wWinMain", "wWinMainCRTStartup",
    "main", "wmain", "mainCRTStartup", "wmainCRTStartup",
}


def _is_user_defined(rec: dict) -> bool:
    return not rec.get("is_external") and not rec.get("is_thunk")


def _exported(rec: dict) -> bool:
    """A function is treated as an export if Ghidra flagged it, OR its name
    matches an ordinal-export pattern, OR its name is a well-known entrypoint.
    """
    if rec.get("is_exported"):
        return True
    name = rec.get("name") or ""
    if name in _ENTRYPOINT_NAMES:
        return True
    if name.startswith("Ordinal_"):
        return True
    return False


def _resolve_callee(callee_ref: str, by_addr: dict[str, dict], by_name: dict[str, dict]) -> dict | None:
    """Resolve a callee reference (which may be a name OR an address) to its
    function record. Returns None if not found.
    """
    if not callee_ref:
        return None
    # Direct name lookup (most real data).
    rec = by_name.get(callee_ref)
    if rec is not None:
        return rec
    # Bare-hex address lookup (real data, some references).
    rec = by_addr.get(callee_ref)
    if rec is not None:
        return rec
    # 0x-prefixed address lookup (synthetic fixtures).
    if callee_ref.startswith("0x"):
        return by_addr.get(callee_ref[2:]) or by_addr.get(callee_ref)
    # Try with 0x prefix as a last resort.
    return by_addr.get("0x" + callee_ref)


def _reachable_user_defined(records: list[dict]) -> list[str]:
    """BFS from every exported (or entrypoint-named) user-defined function
    over `callees`, skipping externals and thunks. Returns sorted addresses.

    Callee references may be names or addresses; both are resolved via
    `_resolve_callee`.
    """
    by_addr = {r["address"]: r for r in records}
    by_name = {r.get("name"): r for r in records if r.get("name")}
    roots = [
        r["address"]
        for r in records
        if _is_user_defined(r) and _exported(r)
    ]
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        addr = stack.pop()
        if addr in seen:
            continue
        rec = by_addr.get(addr)
        if rec is None or not _is_user_defined(rec):
            continue
        seen.add(addr)
        for callee_ref in rec.get("callees", []) or []:
            target = _resolve_callee(callee_ref, by_addr, by_name)
            if target is None or not _is_user_defined(target):
                continue
            target_addr = target["address"]
            if target_addr not in seen:
                stack.append(target_addr)
    return sorted(seen)


def _entrypoints(records: Iterable[dict]) -> list[str]:
    """Returns addresses of user-defined functions whose name is a well-known
    entrypoint (entry, DriverEntry, DllMain, main, …).
    """
    return sorted(
        r["address"]
        for r in records
        if _is_user_defined(r) and r.get("name") in _ENTRYPOINT_NAMES
    )


def extract(function_index: dict) -> dict:
    """Compute the `project_discovery` block for `manifest.json`."""
    records = function_index.get("functions", [])
    user_defined = [r for r in records if _is_user_defined(r)]

    exports = sorted(
        (
            {"name": r["name"], "address": r["address"]}
            for r in user_defined
            if _exported(r)
        ),
        key=lambda e: e["name"],
    )

    strings_by_function: dict[str, list[str]] = {}
    for r in user_defined:
        ss = r.get("strings") or []
        if ss:
            strings_by_function[r["address"]] = list(ss)

    counts = {
        "total": len(records),
        "user_defined": sum(1 for r in records if _is_user_defined(r)),
        "external": sum(1 for r in records if r.get("is_external")),
        "thunk": sum(1 for r in records if r.get("is_thunk")),
    }

    return {
        "binary": function_index.get("binary"),
        "arch": function_index.get("arch"),
        "format": function_index.get("format"),
        "address_size": function_index.get("address_size"),
        "function_counts": counts,
        "exports": exports,
        "entrypoints": _entrypoints(records),
        "reachable_user_defined": _reachable_user_defined(records),
        "strings_by_function": strings_by_function,
    }
