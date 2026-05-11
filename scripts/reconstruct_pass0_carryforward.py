"""Pcode-hash carryforward.

If a prior reconstruction of this binary exists, match each function in the
current `function_index.json` against the prior manifest by `pcode_hash`. For
every match where the prior version had a non-FUN_ rename, propose the same
rename in the current pass with `source=pcode_hash_carryforward` and `confidence=high`.

The hash function is the foundation stub `pcode_hash.hash_function_record`;
a future LibGhidra-integration sub-plan replaces it with a PCode-aware hash.
"""
from __future__ import annotations

import re
from typing import Optional

import pcode_hash  # type: ignore

_FUN_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")


def _proposed_lookup_by_addr(prior_manifest: dict) -> dict[str, dict]:
    """Flatten all `proposed_renames` from every prior pass into a single map
    keyed by addr. Later passes override earlier passes if both renamed the
    same address.
    """
    out: dict[str, dict] = {}
    for p in prior_manifest.get("passes", []):
        for rec in p.get("proposed_renames", []):
            addr = rec.get("addr")
            if addr:
                out[addr] = rec
    return out


def carryforward(function_index: dict, prior_manifest: Optional[dict]) -> list[dict]:
    """Return proposed renames carried forward from the prior reconstruction.

    Returns an empty list if `prior_manifest` is None or contains no usable
    rename evidence.
    """
    if not prior_manifest:
        return []
    prior_hashes: dict[str, str] = prior_manifest.get("pcode_hashes_by_addr", {})
    if not prior_hashes:
        return []
    prior_renames_by_addr = _proposed_lookup_by_addr(prior_manifest)
    # Invert: hash -> addr that had this hash in the prior version.
    prior_hash_to_addr = {h: a for a, h in prior_hashes.items()}
    prior_version = (prior_manifest.get("binary") or {}).get("version_tag", "prior")

    out: list[dict] = []
    for rec in function_index.get("functions", []):
        if rec.get("is_external") or rec.get("is_thunk"):
            continue
        name = rec.get("name", "")
        if not _FUN_RE.match(name):
            continue
        h = pcode_hash.hash_function_record(rec)
        prior_addr = prior_hash_to_addr.get(h)
        if not prior_addr:
            continue
        prior_rename = prior_renames_by_addr.get(prior_addr)
        if not prior_rename:
            continue
        prior_to = prior_rename.get("to", "")
        if not prior_to or _FUN_RE.match(prior_to):
            continue
        out.append({
            "addr": rec["address"],
            "from": name,
            "to": prior_to,
            "confidence": "high",
            "source": "pcode_hash_carryforward",
            "rationale": (
                f"pcode_hash match with prior version {prior_version} "
                f"at {prior_addr} (previously named {prior_to})"
            ),
        })
    return out
