# Reconstruct Phase — Pass 1 LLM Rename (Sub-Plan 3/5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the **Pass 1 LLM rename** layer of the reconstruct phase. After Pass 0 names ~15% of `FUN_*` functions deterministically, Pass 1 runs an LLM rename worker on the remaining survivors. The Python plumbing (this plan) prepares per-batch input bundles on disk, validates worker output, merges renames into `manifest.json`, and updates `coverage.json`. The actual LLM call happens via Claude Code's Task tool dispatched by the **strategist** (Claude reading a session), not by an `anthropic`-SDK Python script.

**Architecture:** Two new scripts and two prompt files.
- `scripts/reconstruct_pass1_batch.py` — given an engagement + a Pass-0-complete manifest, emit `pass1_batches/batch_<N>.json` files under the catalog reconstruct dir, each containing ≤20 FUN_* survivors + their context (callers/callees/strings/decompilation snippets).
- `scripts/reconstruct_pass1_apply.py` — given a worker result JSON file, validate, then merge proposed renames into `manifest.json#passes[]` (creating or updating a `pass1` entry idempotently), then recompute `coverage.json`.
- `prompts/workers/reconstruct_rename.md` — the worker contract (input/output schema, naming rules, confidence semantics).
- `prompts/phases/reconstruct.md` — expand the foundation-era stub into a real strategist orchestration prompt that walks through Pass 0 → Pass 1 → coverage recompute.

Pass 2 retype, Pass 3a/b/c, Pass 4 cleanup are out of scope; they ship in sub-plan 3.5.

**Tech Stack:** Python 3.11, pytest, PyYAML, stdlib `json` / `argparse`. No new pip deps. Builds on Pass 0 MVP scripts (`reconstruct_pass0.py`, `reconstruct.py`) and foundation primitives (`libghidra_connect`, `pcode_hash`).

---

## File Structure

**Create:**
- `scripts/reconstruct_pass1_batch.py` — batch-emission orchestrator + helpers
- `scripts/reconstruct_pass1_apply.py` — worker-result validator + manifest merger + coverage recomputer
- `prompts/workers/reconstruct_rename.md` — Pass 1 worker prompt + I/O schema
- `tests/reconstruct/fixtures/sample_manifest_pass0_only.json` — manifest after Pass 0 only (input for batch tests)
- `tests/reconstruct/fixtures/sample_worker_result_valid.json` — example valid worker output
- `tests/reconstruct/fixtures/sample_worker_result_malformed.json` — example malformed worker output
- `tests/reconstruct/test_pass1_batch.py`
- `tests/reconstruct/test_pass1_apply.py`

**Modify:**
- `prompts/phases/reconstruct.md` — expand from foundation stub to a real strategist prompt that drives Pass 0 → Pass 1 → coverage update
- `CLAUDE.md` — append Pass 1 invocation docs under the existing reconstruct section

**Conventions established here:**

| Concept | Convention |
|---|---|
| Batch dir | `catalog/reconstructed/<stem>_<tag>/pass1_batches/` |
| Batch file | `batch_<NNN>.json` where NNN is zero-padded sequential (`batch_000.json`, `batch_001.json`, ...) |
| Batch index | `pass1_batches/index.json` — lists every batch + its status (`pending` / `dispatched` / `applied`) |
| Worker result file | `pass1_batches/result_<NNN>.json` written by the strategist after a Task dispatch returns |
| Pass 1 manifest entry | `passes[]` entry with `pass: "pass1"`, `proposed_renames`, `renames_by_source`, `tools_used: ["llm_rename"]`, `tokens_spent` (best-effort estimate or 0), `snapshot: null` |
| Confidence enum | `"high" \| "medium" \| "low"` (same as Pass 0) |
| Source string in proposed_renames | `"llm_rename"` |
| Batching strategy (this plan) | Greedy address-sorted, 20-per-batch. Callgraph-proximity batching is a follow-on optimization. |
| Pass 0 LOCK rule | Names assigned by Pass 0 with confidence ≥ medium are LOCKED — Pass 1 cannot override them. Apply enforces this by refusing renames for addresses already named in a Pass 0 entry (unless the Pass 0 confidence was `low`). |

---

## Task 1: Fixtures — Pass-0-complete manifest + worker result examples

Three small JSON fixtures used by every Pass 1 test.

**Files:**
- Create: `tests/reconstruct/fixtures/sample_manifest_pass0_only.json`
- Create: `tests/reconstruct/fixtures/sample_worker_result_valid.json`
- Create: `tests/reconstruct/fixtures/sample_worker_result_malformed.json`

- [ ] **Step 1: Create the Pass-0-complete manifest**

Create `tests/reconstruct/fixtures/sample_manifest_pass0_only.json`:

```json
{
  "binary": {
    "stem": "samplebin",
    "version_tag": "v1_2_3",
    "status": "partial"
  },
  "passes": [
    {
      "pass": "pass0",
      "started_at": "2026-05-11T16:00:00Z",
      "ended_at": "2026-05-11T16:00:42Z",
      "tools_used": ["project_discovery", "iat_wrapper_detection"],
      "renames_applied": 0,
      "proposed_renames": [
        {
          "addr": "0x140002000",
          "from": "FUN_140002000",
          "to": "RtlAllocateHeap_wrapper",
          "confidence": "medium",
          "source": "iat_wrapper_detection",
          "rationale": "2-instruction function with single external callee RtlAllocateHeap"
        }
      ],
      "renames_by_source": {"iat_wrapper_detection": 1},
      "tokens_spent": 0,
      "snapshot": null,
      "prior_version_consulted": null
    }
  ],
  "project_discovery": {
    "binary": "samplebin.exe",
    "arch": "x86_64",
    "format": "PE",
    "function_counts": {"total": 12, "user_defined": 8, "external": 3, "thunk": 1},
    "exports": [
      {"name": "entry", "address": "0x140001000"},
      {"name": "DllMain", "address": "0x140006000"}
    ],
    "entrypoints": ["0x140001000"],
    "reachable_user_defined": [
      "0x140001000", "0x140002000", "0x140003000", "0x140004000",
      "0x140005000", "0x140006000", "0x140007000"
    ],
    "strings_by_function": {
      "0x140040000": ["Initializing config", "C:\\ProgramData\\sample\\config.json"]
    }
  },
  "pcode_hashes_by_addr": {
    "0x140001000": "hash_entry",
    "0x140002000": "hash_2000",
    "0x140003000": "hash_3000",
    "0x140004000": "hash_4000",
    "0x140005000": "hash_5000",
    "0x140006000": "hash_6000",
    "0x140007000": "hash_7000",
    "0x140040000": "hash_orphan"
  }
}
```

This manifest has Pass 0 complete with only one renamed function (`0x140002000` → `RtlAllocateHeap_wrapper` at confidence `medium`). The remaining FUN_* survivors (`0x140003000`, `0x140004000`, `0x140005000`, `0x140007000`, `0x140040000`) are Pass 1 candidates. `entry` and `DllMain` are already named (not FUN_*) so they are NOT Pass 1 candidates.

- [ ] **Step 2: Create a valid worker result**

Create `tests/reconstruct/fixtures/sample_worker_result_valid.json`:

```json
{
  "pass": "pass1",
  "batch_id": "batch_000",
  "renames": [
    {
      "addr": "0x140003000",
      "to": "DispatchCommand",
      "confidence": "high",
      "rationale": "Receives an IPC request header and dispatches by type tag"
    },
    {
      "addr": "0x140004000",
      "to": "OpenConfigFile",
      "confidence": "medium",
      "rationale": "Wraps CreateFileW with a hard-coded path under ProgramData"
    },
    {
      "addr": "0x140005000",
      "to": "ProcessRequest",
      "confidence": "low",
      "rationale": "Calls Alloc/Open/memcpy but purpose unclear"
    }
  ]
}
```

- [ ] **Step 3: Create a malformed worker result**

Create `tests/reconstruct/fixtures/sample_worker_result_malformed.json`:

```json
{
  "pass": "pass1",
  "batch_id": "batch_001",
  "renames": [
    {
      "addr": "0x140007000",
      "to": "",
      "confidence": "unknown",
      "rationale": "Empty name with bogus confidence"
    },
    {
      "to": "MissingAddr",
      "confidence": "high",
      "rationale": "addr key missing"
    }
  ]
}
```

- [ ] **Step 4: Verify all three parse as JSON**

```bash
python3 -c "
import json
for p in ['sample_manifest_pass0_only.json', 'sample_worker_result_valid.json', 'sample_worker_result_malformed.json']:
    json.load(open('tests/reconstruct/fixtures/' + p))
print('OK')
"
```

Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add tests/reconstruct/fixtures/sample_manifest_pass0_only.json tests/reconstruct/fixtures/sample_worker_result_valid.json tests/reconstruct/fixtures/sample_worker_result_malformed.json
git commit -m "test(reconstruct): fixtures for Pass 1 batch + apply"
```

---

## Task 2: `reconstruct_pass1_batch.py` — survivor detection

Identify FUN_* survivors that need Pass 1 attention: not already renamed by Pass 0 with confidence ≥ medium, not external/thunk.

**Files:**
- Create: `scripts/reconstruct_pass1_batch.py`
- Test: `tests/reconstruct/test_pass1_batch.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_pass1_batch.py`:

```python
"""Tests for reconstruct_pass1_batch — survivor detection + batching."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass1_batch as batch  # type: ignore


def _function_index_with_survivors() -> dict:
    """Mirror the sample fixture's user-defined set so survivor detection
    has a real function_index to work against."""
    return {
        "binary": "samplebin.exe",
        "functions": [
            {"address": "0x140001000", "name": "entry", "callees": ["0x140003000"],
             "callers": [], "is_external": False, "is_thunk": False,
             "is_exported": True, "code_hash": "h1", "instruction_count": 42, "size": 256, "strings": []},
            {"address": "0x140002000", "name": "FUN_140002000",
             "callees": ["0x140020000"], "callers": ["0x140001000"],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h2", "instruction_count": 2, "size": 12, "strings": []},
            {"address": "0x140003000", "name": "FUN_140003000",
             "callees": ["0x140004000"], "callers": ["0x140001000"],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h3", "instruction_count": 128, "size": 512, "strings": []},
            {"address": "0x140004000", "name": "FUN_140004000",
             "callees": ["0x140021000"], "callers": ["0x140003000"],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h4", "instruction_count": 1, "size": 8, "strings": []},
            {"address": "0x140005000", "name": "FUN_140005000",
             "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h5", "instruction_count": 64, "size": 256, "strings": []},
            {"address": "0x140006000", "name": "DllMain",
             "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": True,
             "code_hash": "h6", "instruction_count": 32, "size": 128, "strings": []},
            {"address": "0x140007000", "name": "FUN_140007000",
             "callees": ["0x140003000"], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h7", "instruction_count": 8, "size": 32, "strings": []},
            {"address": "0x140020000", "name": "RtlAllocateHeap",
             "callees": [], "callers": ["0x140002000"],
             "is_external": True, "is_thunk": False, "is_exported": False,
             "code_hash": "0", "instruction_count": 0, "size": 0, "strings": []},
            {"address": "0x140021000", "name": "CreateFileW",
             "callees": [], "callers": ["0x140004000"],
             "is_external": True, "is_thunk": False, "is_exported": False,
             "code_hash": "0", "instruction_count": 0, "size": 0, "strings": []},
            {"address": "0x140030000", "name": "j_CreateFileW",
             "callees": ["0x140021000"], "callers": [],
             "is_external": False, "is_thunk": True, "is_exported": False,
             "code_hash": "0", "instruction_count": 1, "size": 6, "strings": []},
            {"address": "0x140040000", "name": "FUN_140040000",
             "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h_orphan", "instruction_count": 24, "size": 96,
             "strings": ["Initializing config", "C:\\ProgramData\\sample\\config.json"]},
        ],
    }


def _pass0_manifest() -> dict:
    return json.loads((FIXTURES / "sample_manifest_pass0_only.json").read_text())


def test_identify_survivors_excludes_already_renamed_at_medium_confidence():
    """0x140002000 was renamed by Pass 0 at confidence medium — must be excluded."""
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140002000" not in addrs


def test_identify_survivors_includes_FUN_with_no_pass0_rename():
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    # The Pass 1 candidates from the fixture:
    # 0x140003000, 0x140004000, 0x140005000, 0x140007000, 0x140040000
    assert {"0x140003000", "0x140004000", "0x140005000",
            "0x140007000", "0x140040000"} <= addrs


def test_identify_survivors_excludes_externals():
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140020000" not in addrs   # RtlAllocateHeap external
    assert "0x140021000" not in addrs   # CreateFileW external


def test_identify_survivors_excludes_thunks():
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140030000" not in addrs   # j_CreateFileW thunk


def test_identify_survivors_excludes_already_semantically_named():
    """entry, DllMain — these are not FUN_* so they are NOT Pass 1 candidates."""
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140001000" not in addrs   # entry
    assert "0x140006000" not in addrs   # DllMain


def test_identify_survivors_includes_pass0_low_confidence_for_override():
    """Pass 0 low-confidence renames are NOT locked; Pass 1 may override them.
    Construct a manifest where 0x140003000 has a low-confidence Pass 0 rename
    and verify it appears in the survivor list.
    """
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    # Append a low-confidence Pass 0 rename for 0x140003000.
    manifest["passes"][0]["proposed_renames"].append({
        "addr": "0x140003000",
        "from": "FUN_140003000",
        "to": "try_open_file_3000",
        "confidence": "low",
        "source": "string_xref",
        "rationale": "(test)",
    })
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140003000" in addrs   # low-confidence still eligible
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass1_batch.py -v
```

Expected: 6 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/reconstruct_pass1_batch.py`** with EXACT content:

```python
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

    fi_path = ROOT / "engagements" / args.engagement / "decomp" / "function_index.json"
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass1_batch.py -v
```

Expected: 6 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconstruct_pass1_batch.py tests/reconstruct/test_pass1_batch.py
git commit -m "feat(reconstruct): pass 1 survivor detection from Pass-0 manifest"
```

---

## Task 3: `reconstruct_pass1_batch.py` — batching + I/O

The survivor detector exists; this task adds the batching logic and end-to-end batch-file emission tests.

**Files:**
- Test: `tests/reconstruct/test_pass1_batch.py` (append)

- [ ] **Step 1: Append the batching tests**

Append to `tests/reconstruct/test_pass1_batch.py`:

```python
def test_make_batches_groups_in_chunks_of_batch_size():
    survivors = [{"address": f"0x{i:08x}"} for i in range(45)]
    batches = batch.make_batches(survivors, batch_size=20)
    assert len(batches) == 3
    assert len(batches[0]) == 20
    assert len(batches[1]) == 20
    assert len(batches[2]) == 5


def test_make_batches_handles_empty_input():
    assert batch.make_batches([], batch_size=20) == []


def test_make_batches_rejects_zero_batch_size():
    with pytest.raises(ValueError):
        batch.make_batches([{"address": "0x1"}], batch_size=0)


def test_build_batch_input_includes_neighbor_names():
    fi = _function_index_with_survivors()
    survivors = batch.identify_survivors(fi, _pass0_manifest())
    payload = batch.build_batch_input(survivors[:2], fi)
    assert "functions" in payload
    items = payload["functions"]
    # Each item has neighbors with caller/callee names (not addresses).
    for it in items:
        assert "neighbors" in it
        assert "callers" in it["neighbors"]
        assert "callees" in it["neighbors"]
    # Confirm one specific neighbor mapping: 0x140003000's callee 0x140004000
    # should appear as the *name* "FUN_140004000" (not the raw address) since
    # we resolve via function_index lookup.
    by_addr = {it["addr"]: it for it in items}
    if "0x140003000" in by_addr:
        callees = by_addr["0x140003000"]["neighbors"]["callees"]
        assert "FUN_140004000" in callees


def test_write_batches_emits_batch_files_and_index(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    (recon_dir / "manifest.json").write_text(
        (FIXTURES / "sample_manifest_pass0_only.json").read_text()
    )
    fi = _function_index_with_survivors()
    summary = batch.write_batches(recon_dir, fi, json.loads(
        (FIXTURES / "sample_manifest_pass0_only.json").read_text()
    ))
    bdir = recon_dir / "pass1_batches"
    assert (bdir / "batch_000.json").is_file()
    assert (bdir / "index.json").is_file()
    idx = json.loads((bdir / "index.json").read_text())
    assert idx["survivor_count"] == summary["survivor_count"]
    assert len(idx["batches"]) == summary["batch_count"]
    assert all(b["status"] == "pending" for b in idx["batches"])
    b0 = json.loads((bdir / "batch_000.json").read_text())
    assert b0["batch_id"] == "batch_000"
    assert "functions" in b0


def test_cli_writes_batches_against_seeded_engagement(tmp_path):
    """End-to-end via subprocess: scaffold + pass0 manifest + function_index +
    invoke reconstruct_pass1_batch.py with VULNERABIN_ROOT."""
    # Seed engagement + decomp.
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    fi = _function_index_with_survivors()
    (eng / "decomp" / "function_index.json").write_text(json.dumps(fi))

    # Seed catalog dir + Pass 0 manifest.
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    shutil.copy(
        FIXTURES / "sample_manifest_pass0_only.json",
        recon_dir / "manifest.json",
    )

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass1_batch.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert (recon_dir / "pass1_batches" / "batch_000.json").is_file()
    assert (recon_dir / "pass1_batches" / "index.json").is_file()


def test_cli_refuses_when_catalog_dir_missing(tmp_path):
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass1_batch.py"),
         "--engagement", "anything",
         "--binary", "missing", "--version", "v0"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "not found" in (result.stdout + result.stderr).lower()
```

- [ ] **Step 2: Run the new tests**

```bash
pytest tests/reconstruct/test_pass1_batch.py -v
```

Expected: 13 PASSED (6 from Task 2 + 7 new).

- [ ] **Step 3: Run ALL reconstruct tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: 94 PASSED (81 prior + 13 new).

- [ ] **Step 4: Commit**

```bash
git add tests/reconstruct/test_pass1_batch.py
git commit -m "test(reconstruct): pass 1 batching + I/O coverage"
```

---

## Task 4: `reconstruct_pass1_apply.py` — schema validation

Validate that a worker-result JSON conforms to the contract.

**Files:**
- Create: `scripts/reconstruct_pass1_apply.py`
- Test: `tests/reconstruct/test_pass1_apply.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_pass1_apply.py`:

```python
"""Tests for reconstruct_pass1_apply — worker result validation + manifest merge."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass1_apply as apply_mod  # type: ignore


def test_validate_accepts_well_formed_result():
    result = json.loads((FIXTURES / "sample_worker_result_valid.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    assert errors == []


def test_validate_rejects_missing_pass_field():
    result = {"batch_id": "x", "renames": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass" in e.lower() for e in errors)


def test_validate_rejects_wrong_pass_value():
    result = {"pass": "pass2", "batch_id": "x", "renames": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass1" in e.lower() for e in errors)


def test_validate_rejects_empty_rename_target():
    result = {
        "pass": "pass1", "batch_id": "x",
        "renames": [{"addr": "0x1", "to": "", "confidence": "high", "rationale": "r"}],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("name" in e.lower() and "empty" in e.lower() for e in errors)


def test_validate_rejects_unknown_confidence():
    result = {
        "pass": "pass1", "batch_id": "x",
        "renames": [{"addr": "0x1", "to": "Foo", "confidence": "bogus", "rationale": "r"}],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("confidence" in e.lower() for e in errors)


def test_validate_rejects_record_missing_addr():
    result = json.loads((FIXTURES / "sample_worker_result_malformed.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    # The fixture has both an empty name AND a missing addr; both should error.
    joined = " ".join(errors).lower()
    assert "addr" in joined
    assert "name" in joined or "confidence" in joined


def test_validate_rejects_renames_not_a_list():
    result = {"pass": "pass1", "batch_id": "x", "renames": "not-a-list"}
    errors = apply_mod.validate_worker_result(result)
    assert any("renames" in e.lower() for e in errors)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass1_apply.py -v
```

Expected: 7 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/reconstruct_pass1_apply.py`** with EXACT content:

```python
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
_HEX_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+$")


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

    return {
        "hard_gate_pass": False,   # Pass 1 alone does not yet enforce reachability;
                                    # hard gate semantics ship with the reachability
                                    # sub-plan.
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass1_apply.py -v
```

Expected: 7 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconstruct_pass1_apply.py tests/reconstruct/test_pass1_apply.py
git commit -m "feat(reconstruct): pass 1 apply — worker result validator"
```

---

## Task 5: `reconstruct_pass1_apply.py` — manifest merge + coverage recompute tests

The script exists; this task adds behavior tests for the merge + coverage logic.

**Files:**
- Test: `tests/reconstruct/test_pass1_apply.py` (append)

- [ ] **Step 1: Append the tests**

Append to `tests/reconstruct/test_pass1_apply.py`:

```python
def _function_index_for_merge():
    return {
        "binary": "samplebin.exe",
        "functions": [
            {"address": "0x140001000", "name": "entry", "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": True,
             "code_hash": "h1", "instruction_count": 42, "size": 256, "strings": []},
            {"address": "0x140002000", "name": "FUN_140002000", "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h2", "instruction_count": 2, "size": 12, "strings": []},
            {"address": "0x140003000", "name": "FUN_140003000", "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h3", "instruction_count": 128, "size": 512, "strings": []},
            {"address": "0x140004000", "name": "FUN_140004000", "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h4", "instruction_count": 1, "size": 8, "strings": []},
        ],
    }


def test_merge_creates_pass1_entry_when_absent():
    manifest = json.loads((FIXTURES / "sample_manifest_pass0_only.json").read_text())
    assert not any(p["pass"] == "pass1" for p in manifest["passes"])
    result = json.loads((FIXTURES / "sample_worker_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result, _function_index_for_merge())
    pass1 = next(p for p in out["passes"] if p["pass"] == "pass1")
    addrs = {r["addr"] for r in pass1["proposed_renames"]}
    # The valid worker result targets 0x140003000, 0x140004000, 0x140005000.
    # Pass 0 locked NO addresses with medium/high in our valid fixture path
    # because the only Pass 0 rename in the manifest fixture is for 0x140002000,
    # so all three new renames should be accepted.
    assert {"0x140003000", "0x140004000", "0x140005000"} <= addrs


def test_merge_does_not_override_pass0_locked_addr():
    manifest = json.loads((FIXTURES / "sample_manifest_pass0_only.json").read_text())
    # Add a worker result that tries to rename 0x140002000 (Pass 0 medium-locked).
    result = {
        "pass": "pass1", "batch_id": "batch_attack",
        "renames": [
            {"addr": "0x140002000", "to": "Hijacked", "confidence": "high",
             "rationale": "attempted override"},
            {"addr": "0x140003000", "to": "Legit", "confidence": "high",
             "rationale": "legit rename"},
        ],
    }
    out = apply_mod.merge_into_manifest(manifest, result, _function_index_for_merge())
    pass1 = next(p for p in out["passes"] if p["pass"] == "pass1")
    addrs = [r["addr"] for r in pass1["proposed_renames"]]
    assert "0x140002000" not in addrs   # locked, must not appear
    assert "0x140003000" in addrs


def test_merge_dedupes_by_addr_within_pass1():
    """Re-applying the same worker result is idempotent: no duplicates."""
    manifest = json.loads((FIXTURES / "sample_manifest_pass0_only.json").read_text())
    result = json.loads((FIXTURES / "sample_worker_result_valid.json").read_text())
    first = apply_mod.merge_into_manifest(manifest, result, _function_index_for_merge())
    second = apply_mod.merge_into_manifest(first, result, _function_index_for_merge())
    pass1 = next(p for p in second["passes"] if p["pass"] == "pass1")
    addrs = [r["addr"] for r in pass1["proposed_renames"]]
    assert len(addrs) == len(set(addrs))   # no duplicates


def test_merge_later_result_overrides_earlier_for_same_addr():
    manifest = json.loads((FIXTURES / "sample_manifest_pass0_only.json").read_text())
    first_result = {
        "pass": "pass1", "batch_id": "b0",
        "renames": [{"addr": "0x140003000", "to": "OldName", "confidence": "medium", "rationale": "..."}],
    }
    second_result = {
        "pass": "pass1", "batch_id": "b1",
        "renames": [{"addr": "0x140003000", "to": "NewName", "confidence": "high", "rationale": "..."}],
    }
    after_first = apply_mod.merge_into_manifest(manifest, first_result, _function_index_for_merge())
    after_second = apply_mod.merge_into_manifest(after_first, second_result, _function_index_for_merge())
    pass1 = next(p for p in after_second["passes"] if p["pass"] == "pass1")
    rec = next(r for r in pass1["proposed_renames"] if r["addr"] == "0x140003000")
    assert rec["to"] == "NewName"
    assert rec["confidence"] == "high"


def test_merge_sets_renames_by_source_to_llm_rename():
    manifest = json.loads((FIXTURES / "sample_manifest_pass0_only.json").read_text())
    result = json.loads((FIXTURES / "sample_worker_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result, _function_index_for_merge())
    pass1 = next(p for p in out["passes"] if p["pass"] == "pass1")
    assert pass1["renames_by_source"].get("llm_rename") == 3
    for r in pass1["proposed_renames"]:
        assert r["source"] == "llm_rename"


def test_recompute_coverage_counts_all_pass_renames():
    manifest = json.loads((FIXTURES / "sample_manifest_pass0_only.json").read_text())
    result = json.loads((FIXTURES / "sample_worker_result_valid.json").read_text())
    after = apply_mod.merge_into_manifest(manifest, result, _function_index_for_merge())
    cov = apply_mod.recompute_coverage(_function_index_for_merge(), after)
    # function_index_for_merge has 4 user-defined functions; entry is already
    # named (not FUN_*), and Pass 1 names 0x140003000 + 0x140004000.
    # 0x140002000 is named by Pass 0. 0x140005000 is not in this function_index.
    # So named_total includes: entry (1) + 0x140002000 (1) + 0x140003000 (1) + 0x140004000 (1) = 4
    # but the merge accepts ALL three of pass1 renames regardless of whether
    # the addr exists in this function_index. That's OK — the count is bounded
    # by the function_index, not the manifest.
    assert cov["totals"]["user_defined_functions"] == 4
    assert cov["named"]["from_pass0"] == 1
    assert cov["named"]["from_pass1"] == 3
    # entry + 0x140002000 (pass0) + 0x140003000 (pass1) + 0x140004000 (pass1) = 4
    assert cov["named"]["total_named"] == 4


def test_cli_end_to_end_applies_result_and_updates_files(tmp_path):
    """Subprocess: scaffold engagement + recon dir + pass0 manifest + result file,
    invoke apply CLI, verify manifest + coverage updated, batch index status flipped."""
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    (eng / "decomp" / "function_index.json").write_text(json.dumps(_function_index_for_merge()))

    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass1_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass0_only.json", recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_worker_result_valid.json",
                recon_dir / "pass1_batches" / "result_000.json")
    # Seed batch index so we can verify status flip.
    (recon_dir / "pass1_batches" / "index.json").write_text(json.dumps({
        "batches": [{"batch_id": "batch_000", "function_count": 3, "status": "pending"}],
        "survivor_count": 3,
    }, indent=2))

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass1_apply.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass1_batches" / "result_000.json")],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    manifest = json.loads((recon_dir / "manifest.json").read_text())
    assert any(p["pass"] == "pass1" for p in manifest["passes"])
    assert (recon_dir / "coverage.json").is_file()
    cov = json.loads((recon_dir / "coverage.json").read_text())
    assert cov["named"]["from_pass1"] == 3

    idx = json.loads((recon_dir / "pass1_batches" / "index.json").read_text())
    assert idx["batches"][0]["status"] == "applied"


def test_cli_refuses_malformed_result(tmp_path):
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    (eng / "decomp" / "function_index.json").write_text(json.dumps(_function_index_for_merge()))
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass1_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass0_only.json", recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_worker_result_malformed.json",
                recon_dir / "pass1_batches" / "result_999.json")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass1_apply.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass1_batches" / "result_999.json")],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "validation failed" in (result.stdout + result.stderr).lower()
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass1_apply.py -v
```

Expected: 15 PASSED (7 from Task 4 + 8 new).

- [ ] **Step 3: Run ALL reconstruct tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: 102 PASSED (94 prior + 8 new).

- [ ] **Step 4: Commit**

```bash
git add tests/reconstruct/test_pass1_apply.py
git commit -m "test(reconstruct): pass 1 apply — merge + coverage + CLI"
```

---

## Task 6: Worker prompt `prompts/workers/reconstruct_rename.md`

Define the I/O contract for the LLM rename worker that the strategist dispatches via the Task tool.

**Files:**
- Create: `prompts/workers/reconstruct_rename.md`

- [ ] **Step 1: Create the prompt file** with EXACT content:

```markdown
# Worker: reconstruct_rename (Pass 1)

You are a reverse-engineering worker tasked with proposing semantic names for a batch of unnamed (`FUN_*`) functions in a binary. The strategist has selected up to 20 functions and provided their metadata + immediate neighbor context. Your job is to read each function's signal (caller/callee names, xref'd strings, instruction count, size) and propose a meaningful name.

## Input

You receive ONE JSON document with this shape:

```json
{
  "batch_id": "batch_000",
  "functions": [
    {
      "addr": "0x140012a0",
      "name": "FUN_140012a0",
      "instruction_count": 42,
      "size": 256,
      "strings": ["Initializing config", "..."],
      "neighbors": {
        "callers": ["entry", "FUN_140003000", "..."],
        "callees": ["RtlAllocateHeap", "CreateFileW", "..."]
      }
    },
    ...
  ]
}
```

## Output

Return EXACTLY ONE JSON document of this shape (no prose, no markdown fences):

```json
{
  "pass": "pass1",
  "batch_id": "<same as input>",
  "renames": [
    {
      "addr": "0x140012a0",
      "to": "ProcessConfigRequest",
      "confidence": "high",
      "rationale": "Calls CreateFileW with a path xref'd to ProgramData; loops over a header and dispatches by tag"
    },
    ...
  ]
}
```

## Naming rules

1. **One name per function.** Use UpperCamelCase or snake_case consistent with what the surrounding binary appears to use (look at `neighbors.callers` and `neighbors.callees` for the prevailing style).
2. **No `FUN_<hex>` outputs.** If you cannot propose a meaningful name, omit the function from `renames` rather than echoing the FUN_ name back.
3. **No empty names.** `to` must be a non-empty string with no leading/trailing whitespace.
4. **No collisions.** If two functions in the batch look like the same purpose, suffix with `_2`, `_3`, etc., or use a more specific name for the secondary.
5. **Reserved suffix `_wrapper`** — only use this suffix when the function's behavior is a single forwarding call to an imported API. Pass 0 already detects this case; if Pass 0 missed one, you may propose it.

## Confidence rules

- `high`: function has strong, unambiguous signal (e.g., xref'd format string spells out the purpose, callees pattern matches one well-known API sequence, or strings include the function's actual logged identifier).
- `medium`: function has plausible signal but alternatives exist (e.g., 2-3 callees suggesting a likely role but not pinpointing it).
- `low`: function has weak signal (e.g., generic utility shape, no strings, generic neighbors). Use `low` rather than omitting — low-confidence proposals are still useful for the strategist to review.

## Rationale rules

- One sentence, <=240 chars.
- Cite at least one concrete signal (a specific callee name, a specific xref'd string, a specific caller).
- DO NOT speculate about "this might be part of the X subsystem" without concrete evidence.

## Skipping rules

If a function has zero signal — no neighbors, no strings, 0 or 1 instruction — omit it from `renames`. The strategist will retry with a different batching strategy if needed.

## Lock awareness

The strategist will not include functions in your input that were already named at confidence ≥ medium by Pass 0. If you nonetheless want to propose a rename for an unusual edge case (e.g., a `*_wrapper` name that doesn't match the strategist's policy), the apply step will reject it. Trust the input.
```

- [ ] **Step 2: Verify the file is well-formed markdown**

```bash
head -3 prompts/workers/reconstruct_rename.md
```

Expected: shows `# Worker: reconstruct_rename (Pass 1)` and the first paragraph.

- [ ] **Step 3: Commit**

```bash
git add prompts/workers/reconstruct_rename.md
git commit -m "feat(prompts): Pass 1 rename worker contract"
```

---

## Task 7: Expand `prompts/phases/reconstruct.md` strategist prompt

The foundation shipped a stub. Replace it with a real strategist prompt that walks Pass 0 → Pass 1 → coverage update, including the worker-dispatch workflow.

**Files:**
- Modify: `prompts/phases/reconstruct.md`

- [ ] **Step 1: Read the current stub**

```bash
cat prompts/phases/reconstruct.md
```

This is the foundation-era stub; rewrite it.

- [ ] **Step 2: Rewrite the file** with EXACT content:

```markdown
# Reconstruct phase strategist

The reconstruct phase turns raw Ghidra decompilation into idiomatic reconstructed source. As of the Pass 1 sub-plan, the strategist drives two passes:

1. **Pass 0 (deterministic)** — `scripts/reconstruct.py` runs project discovery + IAT wrapper detection + pcode-hash carryforward. No LLM involvement.
2. **Pass 1 (LLM rename)** — `scripts/reconstruct_pass1_batch.py` emits per-batch input bundles; the strategist dispatches an Agent (Task tool) per batch with `prompts/workers/reconstruct_rename.md`; `scripts/reconstruct_pass1_apply.py` validates + merges each result.

## Pre-conditions

Before running this phase:

- The engagement has decomp output at `engagements/<eng>/decomp/function_index.json`.
- The binary has a catalog entry at `catalog/binaries/<stem>.yml`.
- The reconstruction dir is scaffolded: `vb-add reconstruction --binary <stem> --version <tag>`.
- (Pass 1 only) `LIBGHIDRA_HEALTHZ_URL` is set OR the user has opted out — the FSM `libghidra_alive` gate is informational at this stage; Pass 1 itself does not call LibGhidra.

## Pass 0 sequence

```
python3 scripts/reconstruct.py \
    --engagement <eng-slug> \
    --binary <stem> \
    --version <tag>
```

After Pass 0 completes:
- `catalog/reconstructed/<stem>_<tag>/manifest.json` has a `pass0` entry with `proposed_renames`, `project_discovery`, `pcode_hashes_by_addr`.
- `catalog/reconstructed/<stem>_<tag>/coverage.json` exists with `hard_gate_pass: false`, `soft_gate_pass: false`.
- `catalog/binaries/<stem>.yml#reconstruction.status` is `partial`.

## Pass 1 sequence

### Step 1 — emit batches

```
python3 scripts/reconstruct_pass1_batch.py \
    --engagement <eng-slug> \
    --binary <stem> \
    --version <tag>
```

This identifies FUN_* survivors (anything Pass 0 did not lock at confidence ≥ medium) and writes `catalog/reconstructed/<stem>_<tag>/pass1_batches/batch_NNN.json` + an `index.json`. Read `index.json` to learn how many batches there are.

### Step 2 — dispatch one worker per batch

For each pending batch in `pass1_batches/index.json`, dispatch a worker:

- Tool: Task (subagent_type: general-purpose, model: opus, temperature 0 if surfaced)
- Prompt: the content of `prompts/workers/reconstruct_rename.md` with the batch JSON appended as the worker's input
- Save the worker's returned JSON to `catalog/reconstructed/<stem>_<tag>/pass1_batches/result_NNN.json`

Dispatch SEQUENTIALLY for the first 2-3 batches to confirm the worker contract behaves as expected; after that, parallel dispatch is allowed (the apply step is idempotent so order does not matter).

### Step 3 — apply each result

```
python3 scripts/reconstruct_pass1_apply.py \
    --engagement <eng-slug> \
    --binary <stem> \
    --version <tag> \
    --result catalog/reconstructed/<stem>_<tag>/pass1_batches/result_NNN.json
```

Each apply call validates the worker result, merges accepted renames into `manifest.json#passes[]`, and recomputes `coverage.json`. The apply step:

- Rejects renames for addresses locked by Pass 0 (medium/high-confidence Pass 0 renames).
- Validates schema (`pass: pass1`, `batch_id`, `renames[].{addr,to,confidence,rationale}`, confidence in `{high, medium, low}`).
- Flips the matching `pass1_batches/index.json` entry's `status` from `pending` to `applied`.

If apply rejects a result, the strategist may either fix the worker prompt and re-dispatch, or skip that batch (the `index.json` entry remains `pending` so it's visible).

## Failure handling

- **Worker returns invalid JSON.** Re-dispatch with an explicit reminder of the schema. If the worker fails twice, mark the batch `failed` in `index.json` manually and skip.
- **Apply rejects renames for locked addresses.** Expected; the worker proposed a rename for a function Pass 0 already locked. Log the rejection and continue.
- **All batches applied but coverage is still low.** This is normal for the MVP — Pass 1 alone targets unnamed FUN_* survivors. Reachability gates (`reachable_named_100pct`) and additional naming sources (Pass 2 retype, Pass 3 structify) live in follow-on sub-plans.

## Post-conditions

- Every batch in `pass1_batches/index.json` has status `applied` or `failed`.
- `manifest.json#passes` contains both `pass0` and `pass1` entries.
- `coverage.json` reflects the cumulative Pass 0 + Pass 1 named count.
- `catalog/binaries/<stem>.yml#reconstruction.status` is still `partial` (hard gate semantics for `complete` status arrive with the reachability sub-plan).

## What this phase does NOT do (yet)

- Apply renames to a Ghidra project (`.gpr` mutation requires LibGhidra integration).
- Retype function parameters / locals (Pass 2 — separate sub-plan).
- Consolidate struct hypotheses (Pass 3a — separate sub-plan).
- Add decompiler comments (Pass 3b — separate sub-plan).
- Name globals (Pass 3c — separate sub-plan).
```

- [ ] **Step 3: Verify**

```bash
head -5 prompts/phases/reconstruct.md
```

Expected: shows the new content's first lines.

- [ ] **Step 4: Commit**

```bash
git add prompts/phases/reconstruct.md
git commit -m "feat(prompts): expand reconstruct strategist to Pass 0 + Pass 1"
```

---

## Task 8: Document Pass 1 in CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Find the existing reconstruct documentation**

```bash
grep -n "## Reconstruct phase (Pass 0 MVP)" CLAUDE.md
grep -n "^## " CLAUDE.md
```

The new sub-section goes inside the `## Reconstruct phase (Pass 0 MVP)` section, after the existing `### Layer 8 reconstruction detail page` block. The section's H2 title needs no rewording.

- [ ] **Step 2: Append a Pass 1 sub-section**

Using Edit (not redirection), insert this content after the `### Layer 8 reconstruction detail page` sub-section's closing paragraph, BEFORE the next `## ` heading:

````markdown

### Pass 1 — LLM rename (proposed-renames as data)

After Pass 0 completes, the strategist drives Pass 1 to propose semantic names for the remaining `FUN_*` survivors. The Python plumbing batches input on disk and merges results; the actual LLM call happens via Claude Code's Task tool dispatched by the strategist session.

```bash
# 1. Emit per-batch input bundles under catalog/reconstructed/<stem>_<tag>/pass1_batches/
python3 scripts/reconstruct_pass1_batch.py \
    --engagement <eng-slug> --binary <stem> --version <tag>

# 2. Strategist dispatches one Agent per batch using prompts/workers/reconstruct_rename.md,
#    writing each worker's JSON output to pass1_batches/result_<NNN>.json.

# 3. Apply each worker result to manifest.json and recompute coverage.json.
python3 scripts/reconstruct_pass1_apply.py \
    --engagement <eng-slug> --binary <stem> --version <tag> \
    --result catalog/reconstructed/<stem>_<tag>/pass1_batches/result_000.json
```

Pass 1 produces:
- `manifest.json#passes[]` gains a `pass1` entry with proposed renames (`source: "llm_rename"`).
- `coverage.json` updated: `named.from_pass1` reflects new names; `named.total_named` increases.
- `pass1_batches/index.json` tracks batch status (`pending` → `applied`).

Apply step is **idempotent**: re-applying the same `result_NNN.json` does not duplicate renames; re-applying with a different name for the same address overrides the earlier proposal.

Pass 1 does NOT override Pass 0 renames at confidence ≥ medium. Pass 0 names with confidence `low` (e.g., string-xref heuristics) ARE eligible for Pass 1 override.

The worker contract lives at `prompts/workers/reconstruct_rename.md`; the strategist orchestration prompt at `prompts/phases/reconstruct.md`.

````

- [ ] **Step 3: Verify**

```bash
grep -A2 "### Pass 1 — LLM rename" CLAUDE.md
```

Expected: shows the new sub-heading.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document Pass 1 LLM rename invocation"
```

---

## Done — Pass 1 LLM rename acceptance

When all 8 tasks above are complete:

- [ ] `pytest tests/reconstruct/ -v` reports all tests PASSED (~102 total: 81 from sub-plans 1-2-4 + ~21 new)
- [ ] `python3 scripts/reconstruct_pass1_batch.py --engagement <slug> --binary <stem> --version <tag>` writes `pass1_batches/batch_NNN.json` + `index.json`
- [ ] `python3 scripts/reconstruct_pass1_apply.py --result <path>` validates + merges a worker result, updates coverage.json, flips batch status to `applied`
- [ ] Strategist prompt at `prompts/phases/reconstruct.md` walks Pass 0 → Pass 1 → apply sequence
- [ ] Worker contract at `prompts/workers/reconstruct_rename.md`
- [ ] CLAUDE.md documents the new commands
- [ ] Layer 8 page (already shipped in sub-plan 4) now surfaces Pass 1 proposed renames alongside Pass 0's in the proposed renames table

**Next sub-plan candidates:**

- **Sub-plan 3.5 — Pass 2 retype + Pass 3a structify** — adds parameter/local retypes and struct consolidation. Higher complexity than Pass 1 because struct hypotheses span functions and need clustering.
- **Sub-plan 3.6 — Pass 3b commenting + Pass 3c global naming + Pass 4 cleanup** — fills the remaining LLM passes plus the cleanup pass that retries any survivors.
- **Sub-plan 2.5 — Pass 0 expansion** — Rich header parser, string-xref naming, IOCTL/NTSTATUS constant equates. Smallest remaining sub-plan; can land any time.
- **Sub-plan 2-libghidra — LibGhidra integration** — `vendor/bootstrap.sh --install`, FID + BSim, real `.gpr` snapshots, .c re-emit. Heaviest sub-plan; defer until the user has a Ghidra project to apply against.
- **Reachability gate semantics** — wire `coverage.json#hard_gate_pass` to actually require 100% of entrypoint-reachable functions to be named. Currently both gates are hardcoded `false`; this becomes possible once Pass 1+ produces enough names.
