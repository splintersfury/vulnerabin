#!/usr/bin/env python3
"""reconstruct.py — phase orchestrator (Pass 0 MVP).

Drives Pass 0 deterministic detection (project discovery + IAT wrapper
detection + pcode-hash carryforward) against an existing engagement's
decomp output. Produces / updates `manifest.json` and `coverage.json`
under `catalog/reconstructed/<stem>_<tag>/`.

Subsequent LLM passes (1, 2, 3a/b/c, 4 cleanup) land in a follow-on
sub-plan. The status transition `partial -> complete` happens then.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)
sys.path.insert(0, str(ROOT / "scripts"))

import yaml  # type: ignore

import libghidra_connect  # type: ignore
import pcode_hash  # type: ignore
import reconstruct_pass0  # type: ignore


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_recon_dir(stem: str, version_tag: str) -> Path:
    return ROOT / "catalog" / "reconstructed" / f"{stem}_{version_tag}"


def _load_function_index(engagement: str) -> dict:
    p = ROOT / "engagements" / engagement / "decomp" / "function_index.json"
    if not p.is_file():
        raise SystemExit(f"function_index.json missing: {p}")
    return json.loads(p.read_text())


def _find_prior_version(stem: str, current_version_tag: str) -> tuple[str | None, dict | None]:
    """Find the most recent prior reconstruction dir for this stem (excluding
    the current one). Returns (prior_version_tag, prior_manifest_dict) or (None, None).
    """
    base = ROOT / "catalog" / "reconstructed"
    if not base.is_dir():
        return None, None
    candidates = []
    for d in base.iterdir():
        if not d.is_dir():
            continue
        if not d.name.startswith(f"{stem}_"):
            continue
        if d.name == f"{stem}_{current_version_tag}":
            continue
        m = d / "manifest.json"
        if m.is_file():
            candidates.append((d, m))
    if not candidates:
        return None, None
    # Newest by mtime — good enough for MVP; spec sub-plan can prefer version order.
    d, m = max(candidates, key=lambda dm: dm[1].stat().st_mtime)
    prior_tag = d.name[len(stem) + 1:]
    return prior_tag, json.loads(m.read_text())


def _normalize_addr(a: str) -> str:
    """Canonical lowercase 0x-prefixed hex, no leading-zero padding."""
    if not a:
        return a
    s = a.lower()
    if s.startswith("0x"):
        s = "0x" + s[2:].lstrip("0") or "0x0"
    return s


def _compute_coverage(function_index: dict, proposed_renames: list[dict]) -> dict:
    fns = function_index.get("functions", [])
    user_defined = [r for r in fns if not r.get("is_external") and not r.get("is_thunk")]
    renamed_addrs = {_normalize_addr(r["addr"]) for r in proposed_renames}
    # Reachable set = user-defined functions reachable from exports (computed in discovery).
    # For coverage purposes here, we approximate "named" as: not FUN_* OR appears in proposed_renames.
    import re
    fun_re = re.compile(r"^FUN_[0-9a-fA-F]+$")
    named_total = sum(
        1 for r in user_defined
        if not fun_re.match(r.get("name", "")) or _normalize_addr(r["address"]) in renamed_addrs
    )
    return {
        "hard_gate_pass": False,   # Pass 0 alone cannot satisfy hard gate; needs LLM passes.
        "soft_gate_pass": False,
        "totals": {
            "user_defined_functions": len(user_defined),
            "external_imports_skipped": sum(1 for r in fns if r.get("is_external")),
            "thunks_skipped": sum(1 for r in fns if r.get("is_thunk")),
        },
        "named": {
            "total_named": named_total,
            "from_pass0": len(renamed_addrs),
        },
        "low_confidence_named_addresses": [
            r["addr"] for r in proposed_renames if r.get("confidence") == "low"
        ],
    }


def _set_status(binary_yaml: Path, status: str) -> None:
    data = yaml.safe_load(binary_yaml.read_text()) or {}
    recon = data.setdefault("reconstruction", {})
    recon["status"] = status
    binary_yaml.write_text(yaml.safe_dump(data, sort_keys=False))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--engagement", required=True, help="Engagement slug under engagements/")
    ap.add_argument("--binary", required=True, help="Binary stem (matches catalog/binaries/<stem>.yml)")
    ap.add_argument("--version", required=True, help="Version tag, e.g. v27_1_1_28")
    args = ap.parse_args(argv)

    stem = args.binary
    version_tag = args.version
    recon_dir = _resolve_recon_dir(stem, version_tag)
    if not recon_dir.is_dir():
        print(f"error: catalog/reconstructed/{stem}_{version_tag} does not exist; "
              f"run vb-add reconstruction --binary {stem} --version {version_tag} first",
              file=sys.stderr)
        return 2

    binary_yaml = ROOT / "catalog" / "binaries" / f"{stem}.yml"
    if not binary_yaml.is_file():
        print(f"error: catalog/binaries/{stem}.yml not found", file=sys.stderr)
        return 2

    lock_path = recon_dir / ".lock"
    lf = libghidra_connect.acquire_exclusive_lock(lock_path, blocking=False)
    if lf is None:
        print(f"error: lock held on {lock_path}; another reconstruct process is running",
              file=sys.stderr)
        return 3

    try:
        _set_status(binary_yaml, "in_progress")

        function_index = _load_function_index(args.engagement)
        prior_tag, prior_manifest = _find_prior_version(stem, version_tag)

        started_at = _now_utc_iso()
        pass0_result = reconstruct_pass0.run(function_index, prior_manifest=prior_manifest)
        ended_at = _now_utc_iso()

        # Compute pcode_hashes_by_addr for THIS version so the next version
        # can carry forward from us.
        pcode_hashes_by_addr = {
            r["address"]: pcode_hash.hash_function_record(r)
            for r in function_index.get("functions", [])
            if not r.get("is_external") and not r.get("is_thunk")
        }

        manifest_path = recon_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
        manifest.setdefault("binary", {}).update({
            "stem": stem,
            "version_tag": version_tag,
            "status": "partial",
        })
        manifest.setdefault("passes", [])
        # Replace any existing pass0 entry (idempotent re-runs).
        manifest["passes"] = [p for p in manifest["passes"] if p.get("pass") != "pass0"]
        pass0_entry = {
            "pass": "pass0",
            "started_at": started_at,
            "ended_at": ended_at,
            "tools_used": pass0_result["tools_used"],
            "renames_applied": 0,
            "proposed_renames": pass0_result["proposed_renames"],
            "renames_by_source": pass0_result["renames_by_source"],
            "tokens_spent": 0,
            "snapshot": None,
            "prior_version_consulted": (
                f"{stem}_{prior_tag}" if prior_tag else None
            ),
        }
        manifest["passes"].append(pass0_entry)
        manifest["project_discovery"] = pass0_result["project_discovery"]
        manifest["pcode_hashes_by_addr"] = pcode_hashes_by_addr
        manifest_path.write_text(json.dumps(manifest, indent=2))

        coverage = _compute_coverage(function_index, pass0_result["proposed_renames"])
        (recon_dir / "coverage.json").write_text(json.dumps(coverage, indent=2))

        _set_status(binary_yaml, "partial")

        print(f"pass0 complete: {len(pass0_result['proposed_renames'])} renames proposed "
              f"({pass0_result['renames_by_source']}); "
              f"prior_version={prior_tag or 'none'}")
        return 0
    finally:
        libghidra_connect.release_lock(lf)


if __name__ == "__main__":
    sys.exit(main())
