"""Validate a comprehend_binary worker result and merge into binary YAML.

Reads worker output (a JSON document with `stem`, `summary`, `full_picture`),
validates the schema, then writes:
- `summary` (one-sentence ELI5)
- `full_picture` (block with loaded_by/start_trigger/ipc_peers/etc.)
- `summary_fingerprint` (binary_fingerprint at apply time)
- `last_comprehended` (UTC ISO timestamp)

into `catalog/binaries/<stem>.yml`. Idempotent — re-running with the same
worker output produces no diff.
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
    """Return validation error strings; empty list means valid."""
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["worker result must be a JSON object"]

    stem = result.get("stem")
    if not stem or not isinstance(stem, str):
        errors.append("`stem` field is required (string)")

    summary = result.get("summary")
    if not summary or not isinstance(summary, str):
        errors.append("`summary` field is required (non-empty string)")
    elif len(summary) > 240:
        errors.append(f"`summary` must be <=240 chars, got {len(summary)}")

    fp = result.get("full_picture")
    if not isinstance(fp, dict):
        errors.append("`full_picture` field is required (object)")
        return errors

    list_keys = (
        "loaded_by", "start_trigger", "accepted_inputs",
        "dangerous_operations_reachable", "defense_gaps_observed",
    )
    for k in list_keys:
        v = fp.get(k)
        if v is None:
            errors.append(f"full_picture.{k} is required (list of strings, may be empty)")
            continue
        if not isinstance(v, list):
            errors.append(f"full_picture.{k} must be a list")
            continue
        for i, item in enumerate(v):
            if not isinstance(item, str):
                errors.append(f"full_picture.{k}[{i}] must be a string")

    peers = fp.get("ipc_peers")
    if peers is None:
        errors.append("full_picture.ipc_peers is required (list, may be empty)")
    elif not isinstance(peers, list):
        errors.append("full_picture.ipc_peers must be a list")
    else:
        for i, p in enumerate(peers):
            if not isinstance(p, dict):
                errors.append(f"full_picture.ipc_peers[{i}] must be an object")
                continue
            if not p.get("name"):
                errors.append(f"full_picture.ipc_peers[{i}].name is required")
            if not p.get("transport"):
                errors.append(f"full_picture.ipc_peers[{i}].transport is required")
            if p.get("direction") not in ("in", "out", "bidirectional"):
                errors.append(
                    f"full_picture.ipc_peers[{i}].direction must be 'in'|'out'|'bidirectional'"
                )

    return errors


def merge_into_binary_yaml(binary_yaml: dict, result: dict) -> dict:
    """Apply worker result into binary YAML. Returns NEW dict."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import comprehend_fingerprint as cfp  # type: ignore

    out = json.loads(json.dumps(binary_yaml, default=str))   # deep copy via JSON round-trip (date-safe)
    out["summary"] = result["summary"]
    out["full_picture"] = {
        "loaded_by": list(result["full_picture"].get("loaded_by") or []),
        "start_trigger": list(result["full_picture"].get("start_trigger") or []),
        "ipc_peers": [dict(p) for p in (result["full_picture"].get("ipc_peers") or [])],
        "accepted_inputs": list(result["full_picture"].get("accepted_inputs") or []),
        "dangerous_operations_reachable": list(
            result["full_picture"].get("dangerous_operations_reachable") or []
        ),
        "defense_gaps_observed": list(
            result["full_picture"].get("defense_gaps_observed") or []
        ),
    }
    # Compute fingerprint AFTER applying summary/full_picture so a re-run with
    # same input produces a stable fingerprint.
    out["summary_fingerprint"] = cfp.binary_fingerprint(out)
    out["last_comprehended"] = _now_utc_iso()
    return out


def _load_yaml(path: Path) -> dict:
    import yaml as _y  # type: ignore
    return _y.safe_load(path.read_text()) or {}


def _dump_yaml(path: Path, data: dict) -> None:
    import yaml as _y  # type: ignore
    path.write_text(_y.safe_dump(data, sort_keys=False))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, help="Binary stem (matches catalog/binaries/<stem>.yml)")
    ap.add_argument("--result", required=True, help="Path to worker result JSON")
    args = ap.parse_args(argv)

    yml_path = ROOT / "catalog" / "binaries" / f"{args.binary}.yml"
    if not yml_path.is_file():
        print(f"error: catalog/binaries/{args.binary}.yml not found", file=sys.stderr)
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

    binary_yaml = _load_yaml(yml_path)
    new_yaml = merge_into_binary_yaml(binary_yaml, result)
    _dump_yaml(yml_path, new_yaml)

    print(f"applied: {yml_path.relative_to(ROOT)} now has summary + full_picture (fingerprint {new_yaml['summary_fingerprint'][:12]}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
