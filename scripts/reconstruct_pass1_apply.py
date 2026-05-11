"""Pass 1 apply — validate worker result + merge into manifest + recompute coverage.

The strategist (a Claude Code session) writes a worker result JSON to
<reconstruction.ref>/pass1_batches/result_<NNN>.json (matching the
batch_<NNN>.json that was sent to the worker). This script reads that
result, validates it against the Pass 1 contract, and merges the
proposed renames into manifest.json's pass1 entry.

After applying all batch results, this script also recomputes coverage.json
based on the cumulative pass0 + pass1 proposed_renames.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)

_CONFIDENCES = {"high", "medium", "low"}
_HEX_ADDR_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_worker_result(result: dict) -> list[str]:
    """Return a list of human-readable validation error strings.

    An empty list means the result is well-formed.
    """
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["worker result must be a JSON object"]

    if result.get("pass") != "pass1":
        errors.append("`pass` field must equal 'pass1'")
    if not result.get("batch_id"):
        errors.append("`batch_id` field is required")

    renames = result.get("renames")
    if not isinstance(renames, list):
        errors.append("`renames` must be a list")
        return errors

    for i, rec in enumerate(renames):
        if not isinstance(rec, dict):
            errors.append(f"renames[{i}]: must be a JSON object")
            continue
        addr = rec.get("addr")
        if not addr or not isinstance(addr, str) or not _HEX_ADDR_RE.match(addr):
            errors.append(f"renames[{i}]: `addr` missing or not a 0x-hex string")
        name = rec.get("to")
        if not name or not isinstance(name, str) or name.strip() == "":
            errors.append(f"renames[{i}]: `to` empty or missing (must be a non-empty name)")
        conf = rec.get("confidence")
        if conf not in _CONFIDENCES:
            errors.append(
                f"renames[{i}]: `confidence` must be one of {sorted(_CONFIDENCES)}, got {conf!r}"
            )
        if not rec.get("rationale"):
            errors.append(f"renames[{i}]: `rationale` field is required")

    return errors


def _pass0_locked_addrs(manifest: dict) -> set[str]:
    locked: set[str] = set()
    for p in manifest.get("passes", []):
        if p.get("pass") != "pass0":
            continue
        for rec in p.get("proposed_renames", []):
            if rec.get("confidence") in ("medium", "high"):
                locked.add(rec.get("addr", ""))
    return locked


def merge_into_manifest(manifest: dict, worker_result: dict, function_index: dict) -> dict:
    """Apply worker_result.renames into the manifest's pass1 entry.

    Behavior:
    - Returns a NEW manifest dict (does not mutate input).
    - Creates a pass1 entry if absent; otherwise appends to it.
    - Skips any rename whose addr is in the Pass 0 locked set.
    - Deduplicates by addr within pass1: if the new result proposes for an
      addr already present in pass1.proposed_renames, the NEW one wins
      (worker resubmissions override prior).
    - Updates renames_by_source and tools_used on the pass1 entry.
    - Sets the manifest binary.status to 'partial' (unchanged from pass0).
    """
    out = json.loads(json.dumps(manifest))   # deep copy
    locked = _pass0_locked_addrs(out)
    by_addr_in_fi = {r["address"]: r for r in function_index.get("functions", [])}

    passes = out.setdefault("passes", [])
    pass1 = next((p for p in passes if p.get("pass") == "pass1"), None)
    if pass1 is None:
        pass1 = {
            "pass": "pass1",
            "started_at": _now_utc_iso(),
            "ended_at": _now_utc_iso(),
            "tools_used": ["llm_rename"],
            "renames_applied": 0,
            "proposed_renames": [],
            "renames_by_source": {},
            "tokens_spent": 0,
            "snapshot": None,
            "prior_version_consulted": None,
        }
        passes.append(pass1)
    else:
        pass1["ended_at"] = _now_utc_iso()
        if "llm_rename" not in pass1.get("tools_used", []):
            pass1.setdefault("tools_used", []).append("llm_rename")

    existing_by_addr = {r["addr"]: r for r in pass1.get("proposed_renames", [])}
    accepted: list[dict] = []
    rejected: list[dict] = []
    for rec in worker_result.get("renames", []):
        addr = rec.get("addr")
        if addr in locked:
            rejected.append({"addr": addr, "reason": "addr locked by Pass 0 (>=medium confidence)"})
            continue
        # Source field defaults to llm_rename for Pass 1.
        from_name = by_addr_in_fi.get(addr, {}).get("name", "")
        full = {
            "addr": addr,
            "from": from_name,
            "to": rec["to"],
            "confidence": rec["confidence"],
            "source": "llm_rename",
            "rationale": rec["rationale"],
        }
        existing_by_addr[addr] = full

    pass1["proposed_renames"] = sorted(existing_by_addr.values(), key=lambda r: r["addr"])
    rbs: dict[str, int] = {}
    for r in pass1["proposed_renames"]:
        rbs[r["source"]] = rbs.get(r["source"], 0) + 1
    pass1["renames_by_source"] = rbs

    out.setdefault("binary", {})["status"] = "partial"
    return out


def recompute_coverage(function_index: dict, manifest: dict) -> dict:
    """Aggregate every pass's proposed_renames and compute coverage stats."""
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "scripts"))
    import reconstruct_gates as gates  # type: ignore

    fns = function_index.get("functions", [])
    user_defined = [r for r in fns if not r.get("is_external") and not r.get("is_thunk")]
    renamed_addrs: set[str] = set()
    from_pass0 = 0
    from_pass1 = 0
    for p in manifest.get("passes", []):
        which = p.get("pass")
        for rec in p.get("proposed_renames", []):
            renamed_addrs.add(rec.get("addr", ""))
            if which == "pass0":
                from_pass0 += 1
            elif which == "pass1":
                from_pass1 += 1

    fun_re = re.compile(r"^FUN_[0-9a-fA-F]+$")
    named_total = sum(
        1 for r in user_defined
        if not fun_re.match(r.get("name", "")) or r["address"] in renamed_addrs
    )

    gate_state = gates.compute_gate_state(function_index, manifest)

    return {
        "hard_gate_pass": gate_state["hard_gate_pass"],
        "soft_gate_pass": gate_state["soft_gate_pass"],
        "recommended_status": gate_state["recommended_status"],
        "totals": {
            "user_defined_functions": len(user_defined),
            "external_imports_skipped": sum(1 for r in fns if r.get("is_external")),
            "thunks_skipped": sum(1 for r in fns if r.get("is_thunk")),
        },
        "named": {
            "total_named": named_total,
            "from_pass0": from_pass0,
            "from_pass1": from_pass1,
        },
        "low_confidence_named_addresses": [
            rec["addr"]
            for p in manifest.get("passes", [])
            for rec in p.get("proposed_renames", [])
            if rec.get("confidence") == "low"
        ],
    }


def _load_function_index(engagement: str) -> dict:
    p = ROOT / "engagements" / engagement / "decomp" / "function_index.json"
    if not p.is_file():
        raise SystemExit(f"function_index.json missing: {p}")
    return json.loads(p.read_text())


def _update_batch_index_status(recon_dir: Path, batch_id: str, new_status: str) -> None:
    idx_path = recon_dir / "pass1_batches" / "index.json"
    if not idx_path.is_file():
        return
    idx = json.loads(idx_path.read_text())
    for b in idx.get("batches", []):
        if b.get("batch_id") == batch_id:
            b["status"] = new_status
            break
    idx_path.write_text(json.dumps(idx, indent=2))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--result", required=True,
                    help="Path to worker result JSON (relative to ROOT or absolute)")
    args = ap.parse_args(argv)

    recon_dir = ROOT / "catalog" / "reconstructed" / f"{args.binary}_{args.version}"
    manifest_path = recon_dir / "manifest.json"
    if not manifest_path.is_file():
        print(f"error: manifest.json missing at {manifest_path}", file=sys.stderr)
        return 2

    result_path = Path(args.result)
    if not result_path.is_absolute():
        result_path = ROOT / result_path
    if not result_path.is_file():
        print(f"error: result file not found at {result_path}", file=sys.stderr)
        return 2

    result = json.loads(result_path.read_text())
    errors = validate_worker_result(result)
    if errors:
        print("worker result validation failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 3

    function_index = _load_function_index(args.engagement)
    manifest = json.loads(manifest_path.read_text())
    new_manifest = merge_into_manifest(manifest, result, function_index)
    manifest_path.write_text(json.dumps(new_manifest, indent=2))

    coverage = recompute_coverage(function_index, new_manifest)
    (recon_dir / "coverage.json").write_text(json.dumps(coverage, indent=2))

    # Update binary YAML status if the gates indicate completion.
    binary_yaml = ROOT / "catalog" / "binaries" / f"{args.binary}.yml"
    if binary_yaml.is_file():
        import yaml as _y  # type: ignore
        data = _y.safe_load(binary_yaml.read_text()) or {}
        data.setdefault("reconstruction", {})["status"] = coverage.get(
            "recommended_status", "partial"
        )
        binary_yaml.write_text(_y.safe_dump(data, sort_keys=False))

    batch_id = result.get("batch_id")
    if batch_id:
        _update_batch_index_status(recon_dir, batch_id, "applied")

    pass1 = next(p for p in new_manifest["passes"] if p["pass"] == "pass1")
    print(
        f"applied {batch_id or '<no batch_id>'}: "
        f"pass1 now has {len(pass1['proposed_renames'])} proposed renames; "
        f"coverage.json updated."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
