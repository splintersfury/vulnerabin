"""Pass 2 batch emission — retype candidates + per-batch input bundles.

Pass 2 candidates are user-defined functions whose name is NOT FUN_<hex>
(i.e., they were either renamed by Pass 0/1 OR were originally exported
with a semantic name like 'entry', 'DllMain', 'Ordinal_42').

This module bundles candidate metadata + neighbor context for an LLM
retype worker. It does NOT read decompiled .c bodies — without LibGhidra
the body text would not carry post-rename names, so the cost-benefit of
parsing engagement .c files is low for this MVP.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)

BATCH_SIZE = 20
_FUN_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")


def _all_renames_by_addr(manifest: dict) -> dict[str, dict]:
    """Flatten pass0 + pass1 proposed renames into a single map keyed by addr.
    Later passes override earlier ones if both renamed the same address."""
    out: dict[str, dict] = {}
    for p in manifest.get("passes", []):
        if p.get("pass") not in ("pass0", "pass1"):
            continue
        for rec in p.get("proposed_renames", []):
            addr = rec.get("addr")
            if addr:
                out[addr] = rec
    return out


def _effective_name(rec: dict, renames_by_addr: dict[str, dict]) -> str:
    rename = renames_by_addr.get(rec.get("address", ""))
    if rename and rename.get("to"):
        return rename["to"]
    return rec.get("name", "")


def identify_candidates(function_index: dict, manifest: dict) -> list[dict]:
    """User-defined functions with non-FUN_ effective name."""
    renames = _all_renames_by_addr(manifest)
    out: list[dict] = []
    for rec in function_index.get("functions", []):
        if rec.get("is_external") or rec.get("is_thunk"):
            continue
        eff = _effective_name(rec, renames)
        if not eff or _FUN_RE.match(eff):
            continue
        out.append(rec)
    out.sort(key=lambda r: r.get("address", ""))
    return out


def make_batches(candidates: list[dict], batch_size: int = BATCH_SIZE) -> list[list[dict]]:
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    return [candidates[i:i + batch_size] for i in range(0, len(candidates), batch_size)]


def _neighbor_names_post_rename(
    rec: dict, by_addr: dict[str, dict], renames: dict[str, dict],
) -> dict:
    def _nm(addr: str) -> str:
        target = by_addr.get(addr)
        if target is None:
            return addr
        return _effective_name(target, renames)
    return {
        "callers": [_nm(a) for a in (rec.get("callers") or [])],
        "callees": [_nm(a) for a in (rec.get("callees") or [])],
    }


def build_batch_input(
    batch: list[dict], function_index: dict, manifest: dict,
) -> dict:
    by_addr = {r["address"]: r for r in function_index.get("functions", [])}
    renames = _all_renames_by_addr(manifest)
    items: list[dict] = []
    for rec in batch:
        items.append({
            "addr": rec["address"],
            "name": _effective_name(rec, renames),
            "instruction_count": rec.get("instruction_count", 0),
            "size": rec.get("size", 0),
            "strings": rec.get("strings", []),
            "neighbors": _neighbor_names_post_rename(rec, by_addr, renames),
        })
    return {"functions": items}


def write_batches(
    recon_dir: Path,
    function_index: dict,
    manifest: dict,
    *,
    batch_size: int = BATCH_SIZE,
) -> dict:
    candidates = identify_candidates(function_index, manifest)
    batches = make_batches(candidates, batch_size=batch_size)

    batches_dir = recon_dir / "pass2_batches"
    batches_dir.mkdir(parents=True, exist_ok=True)

    index_entries: list[dict] = []
    for i, b in enumerate(batches):
        batch_id = f"batch_{i:03d}"
        payload = build_batch_input(b, function_index, manifest)
        payload["batch_id"] = batch_id
        (batches_dir / f"{batch_id}.json").write_text(json.dumps(payload, indent=2))
        index_entries.append({
            "batch_id": batch_id,
            "function_count": len(b),
            "status": "pending",
        })

    (batches_dir / "index.json").write_text(json.dumps({
        "batches": index_entries,
        "candidate_count": len(candidates),
    }, indent=2))

    return {
        "batch_count": len(batches),
        "candidate_count": len(candidates),
        "batches_dir": str(batches_dir),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    ap.add_argument("--decomp-dir", default="decomp",
                    help="Decomp subdirectory under engagements/<eng>/ (default: 'decomp')")
    args = ap.parse_args(argv)

    recon_dir = ROOT / "catalog" / "reconstructed" / f"{args.binary}_{args.version}"
    if not recon_dir.is_dir():
        print(f"error: {recon_dir} not found", file=sys.stderr)
        return 2
    manifest_path = recon_dir / "manifest.json"
    if not manifest_path.is_file():
        print(f"error: manifest.json missing at {manifest_path}", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text())

    fi_path = ROOT / "engagements" / args.engagement / args.decomp_dir / "function_index.json"
    if not fi_path.is_file():
        print(f"error: function_index.json missing at {fi_path}", file=sys.stderr)
        return 2
    function_index = json.loads(fi_path.read_text())

    summary = write_batches(recon_dir, function_index, manifest, batch_size=args.batch_size)
    print(
        f"wrote {summary['batch_count']} pass2 batch(es) covering "
        f"{summary['candidate_count']} candidate(s) under "
        f"{Path(summary['batches_dir']).relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
