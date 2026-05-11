"""Project discovery: extract a `project_discovery` block from a parsed
`function_index.json` dict.

Pure-Python; does not require LibGhidra. Reads only the data already produced
by `scripts/decomp.py`'s headless Ghidra export. The output dict is the same
shape declared in the reconstruct spec §3.1.
"""
from __future__ import annotations

from typing import Iterable


def _is_user_defined(rec: dict) -> bool:
    return not rec.get("is_external") and not rec.get("is_thunk")


def _exported(rec: dict) -> bool:
    return bool(rec.get("is_exported"))


def _reachable_user_defined(records: list[dict]) -> list[str]:
    """BFS from every exported user-defined function over `callees`,
    skipping externals and thunks. Returns sorted addresses.
    """
    by_addr = {r["address"]: r for r in records}
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
        for callee_addr in rec.get("callees", []):
            if callee_addr not in seen:
                stack.append(callee_addr)
    return sorted(seen)


def _entrypoints(records: Iterable[dict]) -> list[str]:
    """Canonical entrypoint names produced by Ghidra: `entry` for PE main.

    Returns a sorted list of addresses for any user-defined function whose
    name is `entry`. (Other entrypoint kinds — exports, DllMain — surface
    through the `exports` list separately.)
    """
    return sorted(
        r["address"]
        for r in records
        if _is_user_defined(r) and r.get("name") == "entry"
    )


def extract(function_index: dict) -> dict:
    """Compute the `project_discovery` block for `manifest.json`.

    Input: parsed `function_index.json` from `scripts/decomp.py`.
    Output: dict suitable for `manifest.json#project_discovery`.
    """
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
