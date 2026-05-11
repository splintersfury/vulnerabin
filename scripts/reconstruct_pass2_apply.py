"""Pass 2 apply — validate worker result + merge into manifest + recompute coverage.

The strategist writes a worker result JSON to
<reconstruction.ref>/pass2_batches/result_<NNN>.json. This script validates
it, merges the proposed retypes into manifest.json's pass2 entry, then
recomputes coverage.json.
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
_HEX_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_typed_record(rec: dict, prefix: str) -> list[str]:
    errors: list[str] = []
    to = rec.get("to")
    if not to or not isinstance(to, str) or to.strip() == "":
        errors.append(f"{prefix}: `to` empty or missing")
    conf = rec.get("confidence")
    if conf not in _CONFIDENCES:
        errors.append(
            f"{prefix}: `confidence` must be one of {sorted(_CONFIDENCES)}, got {conf!r}"
        )
    if not rec.get("rationale"):
        errors.append(f"{prefix}: `rationale` field is required")
    return errors


def validate_worker_result(result: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["worker result must be a JSON object"]

    if result.get("pass") != "pass2":
        errors.append("`pass` field must equal 'pass2'")
    if not result.get("batch_id"):
        errors.append("`batch_id` field is required")

    retypes = result.get("retypes")
    if not isinstance(retypes, list):
        errors.append("`retypes` must be a list")
        return errors

    for i, rec in enumerate(retypes):
        if not isinstance(rec, dict):
            errors.append(f"retypes[{i}]: must be a JSON object")
            continue
        addr = rec.get("addr")
        if not addr or not isinstance(addr, str) or not _HEX_ADDR_RE.match(addr):
            errors.append(f"retypes[{i}]: `addr` missing or not a 0x-hex string")

        params = rec.get("params", [])
        if not isinstance(params, list):
            errors.append(f"retypes[{i}]: `params` must be a list")
            params = []
        for j, p in enumerate(params):
            if not isinstance(p, dict):
                errors.append(f"retypes[{i}].params[{j}]: must be a JSON object")
                continue
            if not isinstance(p.get("index"), int):
                errors.append(f"retypes[{i}].params[{j}]: `index` missing or not int")
            errors.extend(_validate_typed_record(p, f"retypes[{i}].params[{j}]"))

        locals_ = rec.get("locals", [])
        if not isinstance(locals_, list):
            errors.append(f"retypes[{i}]: `locals` must be a list")
            locals_ = []
        for j, l in enumerate(locals_):
            if not isinstance(l, dict):
                errors.append(f"retypes[{i}].locals[{j}]: must be a JSON object")
                continue
            if not l.get("name"):
                errors.append(f"retypes[{i}].locals[{j}]: local `name` is required")
            errors.extend(_validate_typed_record(l, f"retypes[{i}].locals[{j}]"))

    return errors


def merge_into_manifest(manifest: dict, worker_result: dict) -> dict:
    """Apply worker_result.retypes into the manifest's pass2 entry.

    Returns a NEW manifest dict. Creates pass2 entry if absent; merges with
    existing pass2 entry otherwise, with later retypes overriding earlier for
    the same (addr, param-index) or (addr, local-name) key.
    """
    out = json.loads(json.dumps(manifest))
    passes = out.setdefault("passes", [])
    pass2 = next((p for p in passes if p.get("pass") == "pass2"), None)
    if pass2 is None:
        pass2 = {
            "pass": "pass2",
            "started_at": _now_utc_iso(),
            "ended_at": _now_utc_iso(),
            "tools_used": ["llm_retype"],
            "renames_applied": 0,
            "retypes": [],
            "tokens_spent": 0,
            "snapshot": None,
            "prior_version_consulted": None,
        }
        passes.append(pass2)
    else:
        pass2["ended_at"] = _now_utc_iso()
        if "llm_retype" not in pass2.get("tools_used", []):
            pass2.setdefault("tools_used", []).append("llm_retype")

    existing_by_addr: dict[str, dict] = {r["addr"]: r for r in pass2.get("retypes", [])}
    for rec in worker_result.get("retypes", []):
        addr = rec.get("addr")
        if not addr:
            continue
        existing = existing_by_addr.get(addr, {"addr": addr, "params": [], "locals": []})
        params_by_index = {p.get("index"): p for p in existing.get("params", [])}
        for p in rec.get("params", []):
            idx = p.get("index")
            params_by_index[idx] = {
                "index": idx,
                "from": p.get("from", ""),
                "to": p["to"],
                "confidence": p["confidence"],
                "source": "llm_retype",
                "rationale": p["rationale"],
            }
        existing["params"] = sorted(params_by_index.values(),
                                    key=lambda p: p.get("index", 0))
        locals_by_name = {l.get("name"): l for l in existing.get("locals", [])}
        for l in rec.get("locals", []):
            nm = l.get("name")
            locals_by_name[nm] = {
                "name": nm,
                "from": l.get("from", ""),
                "to": l["to"],
                "confidence": l["confidence"],
                "source": "llm_retype",
                "rationale": l["rationale"],
            }
        existing["locals"] = sorted(locals_by_name.values(),
                                    key=lambda l: l.get("name", ""))
        existing_by_addr[addr] = existing

    pass2["retypes"] = sorted(existing_by_addr.values(),
                              key=lambda r: r["addr"])
    out.setdefault("binary", {})["status"] = "partial"
    return out


def recompute_coverage(function_index: dict, manifest: dict) -> dict:
    """Coverage update for Pass 2.

    Pass 2 adds a `typed` block to the existing coverage data so the Layer 8
    page can surface how many functions have type info.
    """
    fns = function_index.get("functions", [])
    user_defined = [r for r in fns if not r.get("is_external") and not r.get("is_thunk")]
    renamed_addrs: set[str] = set()
    typed_addrs: set[str] = set()
    from_pass0 = 0
    from_pass1 = 0
    from_pass2 = 0
    for p in manifest.get("passes", []):
        which = p.get("pass")
        for rec in p.get("proposed_renames", []) or []:
            renamed_addrs.add(rec.get("addr", ""))
            if which == "pass0":
                from_pass0 += 1
            elif which == "pass1":
                from_pass1 += 1
        for rec in p.get("retypes", []) or []:
            addr = rec.get("addr", "")
            if rec.get("params") or rec.get("locals"):
                typed_addrs.add(addr)
                if which == "pass2":
                    from_pass2 += 1

    fun_re = re.compile(r"^FUN_[0-9a-fA-F]+$")
    named_total = sum(
        1 for r in user_defined
        if not fun_re.match(r.get("name", "")) or r["address"] in renamed_addrs
    )

    return {
        "hard_gate_pass": False,
        "soft_gate_pass": False,
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
        "typed": {
            "total_typed": len(typed_addrs),
            "from_pass2": from_pass2,
        },
        "low_confidence_named_addresses": [
            rec["addr"]
            for p in manifest.get("passes", [])
            for rec in (p.get("proposed_renames") or [])
            if rec.get("confidence") == "low"
        ],
    }


def _load_function_index(engagement: str) -> dict:
    p = ROOT / "engagements" / engagement / "decomp" / "function_index.json"
    if not p.is_file():
        raise SystemExit(f"function_index.json missing: {p}")
    return json.loads(p.read_text())


def _update_batch_index_status(recon_dir: Path, batch_id: str, new_status: str) -> None:
    idx_path = recon_dir / "pass2_batches" / "index.json"
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

    function_index = _load_function_index(args.engagement)
    manifest = json.loads(manifest_path.read_text())
    new_manifest = merge_into_manifest(manifest, result)
    manifest_path.write_text(json.dumps(new_manifest, indent=2))

    coverage = recompute_coverage(function_index, new_manifest)
    (recon_dir / "coverage.json").write_text(json.dumps(coverage, indent=2))

    batch_id = result.get("batch_id")
    if batch_id:
        _update_batch_index_status(recon_dir, batch_id, "applied")

    pass2 = next(p for p in new_manifest["passes"] if p["pass"] == "pass2")
    print(
        f"applied {batch_id or '<no batch_id>'}: "
        f"pass2 now has retypes for {len(pass2['retypes'])} function(s); "
        f"coverage.json updated."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
