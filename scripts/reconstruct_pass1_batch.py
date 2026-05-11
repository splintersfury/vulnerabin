"""Pass 1 batch emission — survivor detection + per-batch input bundles.

Reads the engagement's function_index.json and the catalog reconstruct dir's
manifest.json (Pass 0 complete). Identifies FUN_* survivors that Pass 0 did
not lock. Groups them into batches of <=BATCH_SIZE and writes each batch as
a JSON file under <reconstruction.ref>/pass1_batches/.

This module does NOT call any LLM. The strategist (a Claude Code session)
reads each emitted batch file, dispatches an Agent (via the Task tool) using
prompts/workers/reconstruct_rename.md, and then runs reconstruct_pass1_apply.py
to merge the worker's result back into manifest.json.
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


def _pass0_locked_addrs(manifest: dict) -> set[str]:
    """Addresses that Pass 0 named with confidence >= medium.

    These are locked: Pass 1 must not propose new renames for them.
    Low-confidence Pass 0 names are NOT locked.
    """
    locked: set[str] = set()
    for p in manifest.get("passes", []):
        if p.get("pass") != "pass0":
            continue
        for rec in p.get("proposed_renames", []):
            if rec.get("confidence") in ("medium", "high"):
                locked.add(rec.get("addr", ""))
    return locked


def identify_survivors(function_index: dict, manifest: dict) -> list[dict]:
    """Return the list of function records that Pass 1 should rename.

    Selection criteria (all must be true):
    - is_external == False AND is_thunk == False
    - name matches FUN_<hex>
    - address NOT in Pass 0 locked set (medium/high-confidence Pass 0 renames)
    """
    locked = _pass0_locked_addrs(manifest)
    out: list[dict] = []
    for rec in function_index.get("functions", []):
        if rec.get("is_external") or rec.get("is_thunk"):
            continue
        name = rec.get("name", "")
        if not _FUN_RE.match(name):
            continue
        if rec.get("address") in locked:
            continue
        out.append(rec)
    # Stable order: by address for deterministic batches.
    out.sort(key=lambda r: r.get("address", ""))
    return out


def make_batches(survivors: list[dict], batch_size: int = BATCH_SIZE) -> list[list[dict]]:
    """Greedy address-sorted batching. Each batch holds <= batch_size records.

    A future refinement is callgraph-proximity grouping; current implementation
    is intentionally simple — every batch is a contiguous address slice of the
    sorted survivor list.
    """
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    return [survivors[i:i + batch_size] for i in range(0, len(survivors), batch_size)]


def _neighbor_names(rec: dict, by_addr: dict[str, dict]) -> dict:
    """Return a dict with `callers` and `callees` lists of name strings
    (not full records) for the given function record.
    """
    def _nm(addr: str) -> str:
        r = by_addr.get(addr)
        return r.get("name", addr) if r else addr
    return {
        "callers": [_nm(a) for a in (rec.get("callers") or [])],
        "callees": [_nm(a) for a in (rec.get("callees") or [])],
    }


def build_batch_input(batch: list[dict], function_index: dict) -> dict:
    """Build the JSON document a worker reads. Includes per-function metadata
    plus immediate neighbor names. Does NOT bundle decompiled .c bodies in
    this MVP — the worker prompt instructs the LLM to use only metadata and
    neighbor context. Future increments may add .c snippets.
    """
    by_addr = {r["address"]: r for r in function_index.get("functions", [])}
    items: list[dict] = []
    for rec in batch:
        items.append({
            "addr": rec["address"],
            "name": rec.get("name"),
            "instruction_count": rec.get("instruction_count", 0),
            "size": rec.get("size", 0),
            "strings": rec.get("strings", []),
            "neighbors": _neighbor_names(rec, by_addr),
        })
    return {"functions": items}


def write_batches(
    recon_dir: Path, function_index: dict, manifest: dict, *, batch_size: int = BATCH_SIZE,
) -> dict:
    """Emit pass1_batches/batch_<NNN>.json files + an index.json under recon_dir.

    Returns a summary dict {"batch_count": N, "survivor_count": M, "batches_dir": <path>}.
    """
    survivors = identify_survivors(function_index, manifest)
    batches = make_batches(survivors, batch_size=batch_size)

    batches_dir = recon_dir / "pass1_batches"
    batches_dir.mkdir(parents=True, exist_ok=True)

    index_entries: list[dict] = []
    for i, b in enumerate(batches):
        batch_id = f"batch_{i:03d}"
        payload = build_batch_input(b, function_index)
        payload["batch_id"] = batch_id
        (batches_dir / f"{batch_id}.json").write_text(json.dumps(payload, indent=2))
        index_entries.append({
            "batch_id": batch_id,
            "function_count": len(b),
            "status": "pending",
        })

    (batches_dir / "index.json").write_text(json.dumps({
        "batches": index_entries,
        "survivor_count": len(survivors),
    }, indent=2))

    return {
        "batch_count": len(batches),
        "survivor_count": len(survivors),
        "batches_dir": str(batches_dir),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--engagement", required=True, help="Engagement slug under engagements/")
    ap.add_argument("--binary", required=True, help="Binary stem")
    ap.add_argument("--version", required=True, help="Version tag")
    ap.add_argument("--batch-size", type=int, default=BATCH_SIZE,
                    help="Max functions per batch (default 20)")
    ap.add_argument("--decomp-dir", default="decomp",
                    help="Decomp subdirectory under engagements/<eng>/ (default: 'decomp')")
    args = ap.parse_args(argv)

    recon_dir = ROOT / "catalog" / "reconstructed" / f"{args.binary}_{args.version}"
    if not recon_dir.is_dir():
        print(f"error: {recon_dir} not found; run vb-add reconstruction first",
              file=sys.stderr)
        return 2
    manifest_path = recon_dir / "manifest.json"
    if not manifest_path.is_file():
        print(f"error: manifest.json missing at {manifest_path}; run reconstruct.py for Pass 0 first",
              file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text())

    fi_path = ROOT / "engagements" / args.engagement / args.decomp_dir / "function_index.json"
    if not fi_path.is_file():
        print(f"error: function_index.json missing at {fi_path}", file=sys.stderr)
        return 2
    function_index = json.loads(fi_path.read_text())

    summary = write_batches(recon_dir, function_index, manifest, batch_size=args.batch_size)
    print(
        f"wrote {summary['batch_count']} batch(es) covering "
        f"{summary['survivor_count']} survivor(s) under "
        f"{Path(summary['batches_dir']).relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
