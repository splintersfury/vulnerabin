"""Pass 3a apply — validate worker result + merge into manifest.

The strategist writes a worker result JSON to
<reconstruction.ref>/pass3a_batches/result_<NNN>.json. This script validates
it, merges the consolidated typedef into manifest.json's pass3a entry.
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


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_field(rec: dict, prefix: str) -> list[str]:
    errors: list[str] = []
    if "offset" not in rec:
        errors.append(f"{prefix}: `offset` field is required")
    elif not isinstance(rec.get("offset"), int):
        errors.append(f"{prefix}: `offset` must be an integer, got {type(rec.get('offset')).__name__}")
    if not rec.get("type"):
        errors.append(f"{prefix}: `type` field is required")
    if not rec.get("name"):
        errors.append(f"{prefix}: `name` field is required")
    if not rec.get("rationale"):
        errors.append(f"{prefix}: `rationale` field is required")
    return errors


def validate_worker_result(result: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["worker result must be a JSON object"]

    if result.get("pass") != "pass3a":
        errors.append("`pass` field must equal 'pass3a'")
    if not result.get("batch_id"):
        errors.append("`batch_id` field is required")

    structs = result.get("structs")
    if not isinstance(structs, list):
        errors.append("`structs` must be a list")
        return errors

    for i, s in enumerate(structs):
        if not isinstance(s, dict):
            errors.append(f"structs[{i}]: must be a JSON object")
            continue
        name = s.get("name")
        if not name or not isinstance(name, str) or name.strip() == "":
            errors.append(f"structs[{i}]: `name` empty or missing")
        conf = s.get("confidence")
        if conf not in _CONFIDENCES:
            errors.append(
                f"structs[{i}]: `confidence` must be one of {sorted(_CONFIDENCES)}, got {conf!r}"
            )
        if not s.get("rationale"):
            errors.append(f"structs[{i}]: struct-level `rationale` is required")
        supporters = s.get("supporting_functions")
        if not isinstance(supporters, list) or not supporters:
            errors.append(f"structs[{i}]: `supporting_functions` must be a non-empty list")

        fields = s.get("fields", [])
        if not isinstance(fields, list):
            errors.append(f"structs[{i}]: `fields` must be a list")
            fields = []
        for j, fld in enumerate(fields):
            if not isinstance(fld, dict):
                errors.append(f"structs[{i}].fields[{j}]: must be a JSON object")
                continue
            errors.extend(_validate_field(fld, f"structs[{i}].fields[{j}]"))

    return errors


def merge_into_manifest(manifest: dict, worker_result: dict) -> dict:
    """Apply worker_result.structs into manifest's pass3a entry.

    Returns a NEW manifest dict. Creates pass3a entry if absent. Later results
    for the same struct name override earlier (full-replace semantics — no
    per-field merging since a struct definition is atomic).
    """
    out = json.loads(json.dumps(manifest))
    passes = out.setdefault("passes", [])
    pass3a = next((p for p in passes if p.get("pass") == "pass3a"), None)
    if pass3a is None:
        pass3a = {
            "pass": "pass3a",
            "started_at": _now_utc_iso(),
            "ended_at": _now_utc_iso(),
            "tools_used": ["llm_structify"],
            "structs": [],
            "tokens_spent": 0,
            "snapshot": None,
            "prior_version_consulted": None,
        }
        passes.append(pass3a)
    else:
        pass3a["ended_at"] = _now_utc_iso()
        if "llm_structify" not in pass3a.get("tools_used", []):
            pass3a.setdefault("tools_used", []).append("llm_structify")

    existing_by_name: dict[str, dict] = {s["name"]: s for s in pass3a.get("structs", [])}
    for s in worker_result.get("structs", []):
        name = s.get("name")
        if not name:
            continue
        existing_by_name[name] = {
            "name": name,
            "supporting_functions": list(s.get("supporting_functions", [])),
            "fields": list(s.get("fields", [])),
            "confidence": s.get("confidence"),
            "source": "llm_structify",
            "rationale": s.get("rationale", ""),
        }

    pass3a["structs"] = sorted(existing_by_name.values(), key=lambda s: s["name"])
    return out


def _update_batch_index_status(recon_dir: Path, batch_id: str, new_status: str) -> None:
    idx_path = recon_dir / "pass3a_batches" / "index.json"
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
    ap.add_argument("--binary", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--result", required=True)
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

    manifest = json.loads(manifest_path.read_text())
    new_manifest = merge_into_manifest(manifest, result)
    manifest_path.write_text(json.dumps(new_manifest, indent=2))

    batch_id = result.get("batch_id")
    if batch_id:
        _update_batch_index_status(recon_dir, batch_id, "applied")

    pass3a = next(p for p in new_manifest["passes"] if p["pass"] == "pass3a")
    print(
        f"applied {batch_id or '<no batch_id>'}: "
        f"pass3a now defines {len(pass3a['structs'])} struct(s)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
