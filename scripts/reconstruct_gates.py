"""Reachability + naming gate computation for reconstruct phase.

Reads `function_index.json` and a reconstruct `manifest.json` and computes:
- hard_gate_pass: 100% of `project_discovery.reachable_user_defined` are named
- soft_gate_pass: >=80% of remaining user-defined (the "tail") are named
- recommended_status: "complete" iff both pass, else "partial"

"Named" predicate (matches spec §1.5):
- Function's own name is not `FUN_<hex>` / `sub_<hex>`, OR
- There exists a `proposed_renames` entry for the function whose:
  - source is one of the LLM sources (`llm_rename`, `llm_retype`, etc.),
    regardless of confidence, OR
  - source is a deterministic Pass 0 source AND confidence is `medium`
    or `high`.

Low-confidence Pass 0 string-xref renames are intentionally NOT counted.
"""
from __future__ import annotations

import re

_FUN_RE = re.compile(r"^(FUN_|sub_)[0-9a-fA-F]+$")
_LLM_SOURCES = {"llm_rename", "llm_retype", "llm_structify", "llm_comment"}


def _is_unnamed(name: str) -> bool:
    return bool(_FUN_RE.match(name or ""))


def _rename_counts(manifest: dict) -> dict[str, dict]:
    """Return a dict keyed by addr containing the highest-priority rename for
    that address (across all passes). Priority:
        - LLM source at any confidence beats Pass 0 deterministic
        - Higher confidence beats lower
    """
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[str, dict] = {}
    pass_origin: dict[str, str] = {}
    for p in manifest.get("passes", []):
        which = p.get("pass", "")
        for rec in p.get("proposed_renames", []) or []:
            addr = rec.get("addr")
            if not addr:
                continue
            cur = best.get(addr)
            if cur is None:
                best[addr] = rec
                pass_origin[addr] = which
                continue
            cur_llm = cur.get("source") in _LLM_SOURCES
            new_llm = rec.get("source") in _LLM_SOURCES
            if new_llm and not cur_llm:
                best[addr] = rec
                pass_origin[addr] = which
                continue
            if cur_llm and not new_llm:
                continue
            if confidence_rank.get(rec.get("confidence"), 0) > confidence_rank.get(cur.get("confidence"), 0):
                best[addr] = rec
                pass_origin[addr] = which
    return {addr: {"rec": rec, "pass": pass_origin[addr]} for addr, rec in best.items()}


def _rename_counts_as_named(rename_rec: dict) -> bool:
    """Apply the spec §1.5 predicate to a single rename record."""
    if not rename_rec:
        return False
    source = rename_rec.get("source", "")
    confidence = rename_rec.get("confidence", "")
    if source in _LLM_SOURCES:
        return True
    return confidence in ("medium", "high")


def _user_defined(function_index: dict) -> list[dict]:
    return [
        r for r in function_index.get("functions", [])
        if not r.get("is_external") and not r.get("is_thunk")
    ]


def compute_gate_state(function_index: dict, manifest: dict) -> dict:
    """Return a dict with hard/soft gate verdicts + named breakdown."""
    user_defined = _user_defined(function_index)
    by_addr = {r["address"]: r for r in user_defined}

    pd = manifest.get("project_discovery") or {}
    reachable_set = set(pd.get("reachable_user_defined") or [])
    reachable_set = {a for a in reachable_set if a in by_addr}

    renames = _rename_counts(manifest)

    def is_named(addr: str) -> tuple[bool, str | None]:
        rec = by_addr.get(addr)
        if rec is None:
            return False, None
        rename_info = renames.get(addr)
        if rename_info and _rename_counts_as_named(rename_info["rec"]):
            return True, rename_info["pass"]
        if rec.get("name") and not _is_unnamed(rec["name"]):
            return True, None
        return False, None

    reachable_named = 0
    tail_named = 0
    tail_total = 0
    from_pass: dict[str, int] = {}
    for rec in user_defined:
        addr = rec["address"]
        named, origin = is_named(addr)
        if named:
            if origin:
                from_pass[origin] = from_pass.get(origin, 0) + 1
        if addr in reachable_set:
            if named:
                reachable_named += 1
        else:
            tail_total += 1
            if named:
                tail_named += 1

    reachable_total = len(reachable_set)
    hard_pass = reachable_total == 0 or reachable_named == reachable_total
    soft_pass = tail_total == 0 or (tail_named / tail_total) >= 0.80

    recommended_status = "complete" if (hard_pass and soft_pass) else "partial"

    return {
        "hard_gate_pass": hard_pass,
        "soft_gate_pass": soft_pass,
        "recommended_status": recommended_status,
        "reachable_total": reachable_total,
        "tail_total": tail_total,
        "named": {
            "reachable": reachable_named,
            "tail": tail_named,
            "from_pass0": from_pass.get("pass0", 0),
            "from_pass1": from_pass.get("pass1", 0),
            "from_pass2": from_pass.get("pass2", 0),
            "from_pass3": from_pass.get("pass3", 0),
        },
    }
