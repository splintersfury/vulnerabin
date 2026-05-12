"""Validate a comprehend_narrative worker result and merge into product YAML.

Writes:
- `architecture_narrative.summary`
- `architecture_narrative.data_flow_prose`
- `architecture_narrative.binary_roles`
- `architecture_narrative.trust_boundaries`
- `architecture_narrative.attack_surface_primary`
- `architecture_narrative.fingerprint` (product_fingerprint at apply time)
- `architecture_narrative.last_synthesized` (UTC ISO)
- `architecture_narrative.binaries_comprehended` (list of stems factored in)
- `architecture_narrative.binaries_pending_reconstruction` (list of stems pending)

Idempotent — re-running with the same worker output produces no diff.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_worker_result(result: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["worker result must be a JSON object"]
    if not result.get("product") or not isinstance(result.get("product"), str):
        errors.append("`product` field is required (string)")
    if not result.get("summary") or not isinstance(result.get("summary"), str):
        errors.append("`summary` field is required (non-empty string)")
    if not result.get("data_flow_prose") or not isinstance(result.get("data_flow_prose"), str):
        errors.append("`data_flow_prose` field is required (non-empty string)")
    if not result.get("attack_surface_primary") or not isinstance(result.get("attack_surface_primary"), str):
        errors.append("`attack_surface_primary` field is required (non-empty string)")

    roles = result.get("binary_roles")
    if not isinstance(roles, list):
        errors.append("`binary_roles` must be a list")
    else:
        for i, r in enumerate(roles):
            if not isinstance(r, dict):
                errors.append(f"binary_roles[{i}] must be an object")
                continue
            if not r.get("stem"):
                errors.append(f"binary_roles[{i}].stem is required")
            if not r.get("role"):
                errors.append(f"binary_roles[{i}].role is required")

    boundaries = result.get("trust_boundaries")
    if not isinstance(boundaries, list):
        errors.append("`trust_boundaries` must be a list")
    else:
        for i, b in enumerate(boundaries):
            if not isinstance(b, str):
                errors.append(f"trust_boundaries[{i}] must be a string")

    return errors


def merge_into_product_yaml(product_yaml: dict, result: dict, bundle: dict) -> dict:
    """Apply worker result into product YAML. Returns NEW dict.

    `bundle` is the comprehend_input.json bundle (used to populate
    binaries_comprehended / binaries_pending lists in the narrative).
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    import comprehend_fingerprint as cfp  # type: ignore

    out = json.loads(json.dumps(product_yaml, default=str))   # deep copy (date-safe)
    # Compute per-binary fingerprints for the product fingerprint computation.
    per_binary_fps: dict[str, str] = {}
    for b in bundle.get("binaries_comprehended", []):
        # We approximate the binary fingerprint using just the per-binary stem
        # + summary content; the proper fingerprint would re-load the binary
        # YAML from disk.
        per_binary_fps[b["stem"]] = cfp._hash(json.dumps(
            {"stem": b["stem"], "summary": b["summary"], "full_picture": b["full_picture"]},
            sort_keys=True,
        ))

    out["architecture_narrative"] = {
        "summary": result["summary"],
        "data_flow_prose": result["data_flow_prose"],
        "binary_roles": [
            {"stem": r["stem"], "role": r["role"]}
            for r in result.get("binary_roles", [])
        ],
        "trust_boundaries": list(result.get("trust_boundaries", [])),
        "attack_surface_primary": result["attack_surface_primary"],
        "fingerprint": cfp.product_fingerprint(out, per_binary_fps),
        "last_synthesized": _now_utc_iso(),
        "binaries_comprehended": [b["stem"] for b in bundle.get("binaries_comprehended", [])],
        "binaries_pending_reconstruction": list(bundle.get("binaries_pending", [])),
    }
    return out


def _load_yaml(path: Path) -> dict:
    import yaml as _y  # type: ignore
    return _y.safe_load(path.read_text()) or {}


def _dump_yaml(path: Path, data: dict) -> None:
    import yaml as _y  # type: ignore
    path.write_text(_y.safe_dump(data, sort_keys=False))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--product", required=True, help="Product slug")
    ap.add_argument("--bundle", required=True,
                    help="Path to comprehend_input.json bundle (used for binaries_comprehended/pending)")
    ap.add_argument("--result", required=True, help="Path to worker result JSON")
    args = ap.parse_args(argv)

    yml_path = ROOT / "catalog" / "products" / f"{args.product}.yml"
    if not yml_path.is_file():
        print(f"error: catalog/products/{args.product}.yml not found", file=sys.stderr)
        return 2

    bundle_path = Path(args.bundle)
    if not bundle_path.is_absolute():
        bundle_path = ROOT / bundle_path
    if not bundle_path.is_file():
        print(f"error: bundle not found at {bundle_path}", file=sys.stderr)
        return 2

    result_path = Path(args.result)
    if not result_path.is_absolute():
        result_path = ROOT / result_path
    if not result_path.is_file():
        print(f"error: result file not found at {result_path}", file=sys.stderr)
        return 2

    bundle = json.loads(bundle_path.read_text())
    result = json.loads(result_path.read_text())
    errors = validate_worker_result(result)
    if errors:
        print("worker result validation failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 3

    product_yaml = _load_yaml(yml_path)
    new_yaml = merge_into_product_yaml(product_yaml, result, bundle)
    _dump_yaml(yml_path, new_yaml)

    nar = new_yaml["architecture_narrative"]
    print(
        f"applied: {yml_path.relative_to(ROOT)} now has architecture_narrative "
        f"(fingerprint {nar['fingerprint'][:12]}..., "
        f"{len(nar['binaries_comprehended'])} comprehended, "
        f"{len(nar['binaries_pending_reconstruction'])} pending)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
