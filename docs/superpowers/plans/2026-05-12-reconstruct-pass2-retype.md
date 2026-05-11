# Reconstruct Phase — Pass 2 LLM Retype (Sub-Plan 3.5/5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the **Pass 2 LLM retype** plumbing. After Pass 0 + Pass 1 give functions semantic names, Pass 2 proposes parameter and local-variable type retypes (`param_1 → IPC_REQUEST_HEADER *req`, `local_18 → NTSTATUS status`). Same shape as Pass 1: Python `batch` + `apply` scripts, a worker prompt, and a strategist expansion.

**Architecture:** Pass 2 candidates are functions that have a non-`FUN_*` name (either Pass 0/1 renamed them or they were originally exported). Without LibGhidra, the batch step does NOT read decompiled `.c` bodies — it bundles the same metadata Pass 1 saw plus the post-rename name. The worker proposes retypes based on naming patterns and neighbor APIs; without real type signatures, confidence is generally `medium` or `low`. **Struct hypotheses are explicitly out of scope** and ship in sub-plan 3.6 (Pass 3a structify) — Pass 2 here covers only scalar param/local retypes.

**Tech Stack:** Python 3.11, pytest, PyYAML, stdlib `json` / `argparse`. No new pip deps. Builds on Pass 1 patterns (`reconstruct_pass1_batch.py`, `reconstruct_pass1_apply.py`).

---

## File Structure

**Create:**
- `scripts/reconstruct_pass2_batch.py` — Pass 2 candidate detection + per-batch input bundles
- `scripts/reconstruct_pass2_apply.py` — Pass 2 worker-result validator + manifest merge + coverage touch-up
- `prompts/workers/reconstruct_retype.md` — Pass 2 worker contract (I/O schema, retype rules, confidence semantics)
- `tests/reconstruct/fixtures/sample_manifest_pass1_done.json` — manifest after Pass 0 + Pass 1 (input for Pass 2 batch tests)
- `tests/reconstruct/fixtures/sample_pass2_result_valid.json` — example valid Pass 2 worker output
- `tests/reconstruct/fixtures/sample_pass2_result_malformed.json` — example malformed Pass 2 worker output
- `tests/reconstruct/test_pass2_batch.py`
- `tests/reconstruct/test_pass2_apply.py`

**Modify:**
- `prompts/phases/reconstruct.md` — append a "Pass 2 sequence" section after the existing Pass 1 sequence
- `CLAUDE.md` — append a `### Pass 2 — LLM retype` sub-section after the existing Pass 1 docs

**Conventions:**

| Concept | Convention |
|---|---|
| Pass 2 batch dir | `catalog/reconstructed/<stem>_<tag>/pass2_batches/` |
| Batch file | `batch_<NNN>.json` |
| Worker result | `result_<NNN>.json` |
| Pass 2 manifest entry | `passes[]` entry with `pass: "pass2"`, `retypes` list (NOT `proposed_renames`), `tools_used: ["llm_retype"]` |
| Pass 2 candidate predicate | function is user-defined, NOT externally-imported/thunk, name is NOT `FUN_<hex>` (must already be semantically named), AND has either no entry in pass2 yet OR an existing pass2 entry that the new result will override |
| Source string | `"llm_retype"` (single source for now) |

**Pass 2 retype record schema:**

```json
{
  "addr": "0x140012a0",
  "params": [
    {"index": 0, "from": "LPVOID", "to": "IPC_REQUEST_HEADER *", "confidence": "medium", "rationale": "..."}
  ],
  "locals": [
    {"name": "local_18", "from": "DWORD", "to": "NTSTATUS", "confidence": "medium", "rationale": "..."}
  ]
}
```

`params[i].index` is the parameter position (0 = first arg). `locals[i].name` is the Ghidra-assigned local var name (e.g., `local_8`, `pvVar1`). `from` may be empty or `unknown` if the original type was not derivable from the input (the worker should fill in what it observed but is not strict about this).

---

## Task 1: Fixtures — Pass-1-complete manifest + worker result examples

**Files:**
- Create: `tests/reconstruct/fixtures/sample_manifest_pass1_done.json`
- Create: `tests/reconstruct/fixtures/sample_pass2_result_valid.json`
- Create: `tests/reconstruct/fixtures/sample_pass2_result_malformed.json`

- [ ] **Step 1: Create the Pass-1-done manifest**

Create `tests/reconstruct/fixtures/sample_manifest_pass1_done.json`:

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
    },
    {
      "pass": "pass1",
      "started_at": "2026-05-11T17:00:00Z",
      "ended_at": "2026-05-11T17:05:00Z",
      "tools_used": ["llm_rename"],
      "renames_applied": 0,
      "proposed_renames": [
        {
          "addr": "0x140003000",
          "from": "FUN_140003000",
          "to": "DispatchCommand",
          "confidence": "high",
          "source": "llm_rename",
          "rationale": "Receives an IPC request header and dispatches by type tag"
        },
        {
          "addr": "0x140004000",
          "from": "FUN_140004000",
          "to": "OpenConfigFile",
          "confidence": "medium",
          "source": "llm_rename",
          "rationale": "Wraps CreateFileW with hard-coded path under ProgramData"
        },
        {
          "addr": "0x140005000",
          "from": "FUN_140005000",
          "to": "ProcessRequest",
          "confidence": "low",
          "source": "llm_rename",
          "rationale": "Calls Alloc/Open/memcpy but purpose unclear"
        }
      ],
      "renames_by_source": {"llm_rename": 3},
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

- [ ] **Step 2: Create a valid Pass 2 worker result**

Create `tests/reconstruct/fixtures/sample_pass2_result_valid.json`:

```json
{
  "pass": "pass2",
  "batch_id": "batch_000",
  "retypes": [
    {
      "addr": "0x140003000",
      "params": [
        {"index": 0, "from": "undefined4 *", "to": "IPC_REQUEST_HEADER *", "confidence": "medium", "rationale": "Name DispatchCommand + signature suggests IPC header pointer"}
      ],
      "locals": [
        {"name": "local_18", "from": "DWORD", "to": "NTSTATUS", "confidence": "medium", "rationale": "Compared against STATUS_* constants in callers"}
      ]
    },
    {
      "addr": "0x140004000",
      "params": [
        {"index": 0, "from": "char *", "to": "LPCWSTR", "confidence": "high", "rationale": "Wrapper for CreateFileW; first arg is wide path"}
      ],
      "locals": []
    }
  ]
}
```

- [ ] **Step 3: Create a malformed Pass 2 worker result**

Create `tests/reconstruct/fixtures/sample_pass2_result_malformed.json`:

```json
{
  "pass": "pass2",
  "batch_id": "batch_001",
  "retypes": [
    {
      "params": [
        {"index": 0, "to": "OK", "confidence": "high", "rationale": "missing addr at retype level"}
      ]
    },
    {
      "addr": "0x140005000",
      "params": [
        {"index": 0, "to": "", "confidence": "high", "rationale": "empty to"}
      ],
      "locals": [
        {"name": "local_8", "to": "DWORD", "confidence": "ultra", "rationale": "bogus confidence"}
      ]
    }
  ]
}
```

- [ ] **Step 4: Verify all three parse as JSON**

```bash
python3 -c "
import json
for p in ['sample_manifest_pass1_done.json', 'sample_pass2_result_valid.json', 'sample_pass2_result_malformed.json']:
    json.load(open('tests/reconstruct/fixtures/' + p))
print('OK')
"
```

Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add tests/reconstruct/fixtures/sample_manifest_pass1_done.json tests/reconstruct/fixtures/sample_pass2_result_valid.json tests/reconstruct/fixtures/sample_pass2_result_malformed.json
git commit -m "test(reconstruct): fixtures for Pass 2 batch + apply"
```

---

## Task 2: `reconstruct_pass2_batch.py` — candidate detection + batching + I/O

A single file covering Pass 2's batch emission. Candidates are user-defined functions that are NOT named `FUN_<hex>` (i.e., already renamed by Pass 0/1 OR originally exported). The script writes `pass2_batches/batch_<NNN>.json` + an `index.json`.

**Files:**
- Create: `scripts/reconstruct_pass2_batch.py`
- Test: `tests/reconstruct/test_pass2_batch.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_pass2_batch.py`:

```python
"""Tests for reconstruct_pass2_batch — candidate detection + batching."""
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

import reconstruct_pass2_batch as batch  # type: ignore


def _function_index_for_pass2() -> dict:
    """Function index where Pass 0/1 have renamed several FUN_* entries.

    Note: this fixture deliberately uses the SAME names as the
    pass1-done manifest so the Pass 2 candidate detector can find them.
    The pass1-done manifest's renamed addresses (0x140003000, 0x140004000,
    0x140005000) are the Pass 2 candidates here.
    """
    return {
        "binary": "samplebin.exe",
        "functions": [
            {"address": "0x140001000", "name": "entry", "callees": [],
             "callers": [], "is_external": False, "is_thunk": False,
             "is_exported": True, "code_hash": "h1", "instruction_count": 42,
             "size": 256, "strings": []},
            {"address": "0x140002000", "name": "FUN_140002000",
             "callees": ["0x140020000"], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h2",
             "instruction_count": 2, "size": 12, "strings": []},
            {"address": "0x140003000", "name": "FUN_140003000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h3",
             "instruction_count": 128, "size": 512, "strings": []},
            {"address": "0x140004000", "name": "FUN_140004000",
             "callees": ["0x140021000"], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h4",
             "instruction_count": 1, "size": 8, "strings": []},
            {"address": "0x140005000", "name": "FUN_140005000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h5",
             "instruction_count": 64, "size": 256, "strings": []},
            {"address": "0x140006000", "name": "DllMain", "callees": [],
             "callers": [], "is_external": False, "is_thunk": False,
             "is_exported": True, "code_hash": "h6", "instruction_count": 32,
             "size": 128, "strings": []},
            {"address": "0x140007000", "name": "FUN_140007000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h7",
             "instruction_count": 8, "size": 32, "strings": []},
            {"address": "0x140020000", "name": "RtlAllocateHeap",
             "callees": [], "callers": ["0x140002000"], "is_external": True,
             "is_thunk": False, "is_exported": False, "code_hash": "0",
             "instruction_count": 0, "size": 0, "strings": []},
            {"address": "0x140021000", "name": "CreateFileW",
             "callees": [], "callers": ["0x140004000"], "is_external": True,
             "is_thunk": False, "is_exported": False, "code_hash": "0",
             "instruction_count": 0, "size": 0, "strings": []},
        ],
    }


def _manifest_pass1_done() -> dict:
    return json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())


def test_identify_candidates_includes_pass1_renamed_addresses():
    """The pass1-done fixture renamed 0x140003000/0x140004000/0x140005000.
    Those addresses should be Pass 2 candidates.
    """
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140003000" in addrs
    assert "0x140004000" in addrs
    assert "0x140005000" in addrs


def test_identify_candidates_includes_pass0_renamed_addresses():
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140002000" in addrs   # Pass 0 named it RtlAllocateHeap_wrapper


def test_identify_candidates_includes_originally_named_exports():
    """entry, DllMain — never went through Pass 0/1, but they have semantic
    names already. They ARE Pass 2 candidates.
    """
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140001000" in addrs   # entry
    assert "0x140006000" in addrs   # DllMain


def test_identify_candidates_excludes_FUN_survivors():
    """0x140007000 is still FUN_* in the manifest (not renamed by pass0/1)."""
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140007000" not in addrs


def test_identify_candidates_excludes_externals_and_thunks():
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140020000" not in addrs   # external
    assert "0x140021000" not in addrs   # external


def test_make_batches_chunks_correctly():
    cands = [{"address": f"0x{i:08x}"} for i in range(45)]
    batches = batch.make_batches(cands, batch_size=20)
    assert len(batches) == 3
    assert len(batches[0]) == 20
    assert len(batches[1]) == 20
    assert len(batches[2]) == 5


def test_build_batch_input_includes_effective_name(monkeypatch):
    """The batch input must show each function's POST-RENAME name (from
    pass1/pass0) rather than its raw function_index name.
    """
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    # Find 0x140003000 in cands; pass1 renamed it DispatchCommand.
    target = next(c for c in cands if c["address"] == "0x140003000")
    payload = batch.build_batch_input([target], fi, manifest)
    item = payload["functions"][0]
    assert item["addr"] == "0x140003000"
    assert item["name"] == "DispatchCommand"


def test_build_batch_input_includes_neighbor_names():
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    payload = batch.build_batch_input(cands[:2], fi, manifest)
    for item in payload["functions"]:
        assert "neighbors" in item
        assert "callers" in item["neighbors"]
        assert "callees" in item["neighbors"]


def test_write_batches_emits_files_and_index(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    (recon_dir / "manifest.json").write_text(
        (FIXTURES / "sample_manifest_pass1_done.json").read_text()
    )
    fi = _function_index_for_pass2()
    summary = batch.write_batches(
        recon_dir, fi, _manifest_pass1_done(),
    )
    bdir = recon_dir / "pass2_batches"
    assert (bdir / "batch_000.json").is_file()
    assert (bdir / "index.json").is_file()
    idx = json.loads((bdir / "index.json").read_text())
    assert idx["candidate_count"] == summary["candidate_count"]
    assert len(idx["batches"]) == summary["batch_count"]
    assert all(b["status"] == "pending" for b in idx["batches"])


def test_cli_writes_batches_end_to_end(tmp_path):
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    fi = _function_index_for_pass2()
    (eng / "decomp" / "function_index.json").write_text(json.dumps(fi))
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass1_done.json",
                recon_dir / "manifest.json")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass2_batch.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert (recon_dir / "pass2_batches" / "batch_000.json").is_file()


def test_cli_refuses_missing_catalog_dir(tmp_path):
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass2_batch.py"),
         "--engagement", "x", "--binary", "missing", "--version", "v0"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "not found" in (result.stdout + result.stderr).lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass2_batch.py -v
```

Expected: 11 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/reconstruct_pass2_batch.py`** with EXACT content:

```python
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
    """Flatten pass0 + pass1 + pass2 proposed renames into a single map
    keyed by addr. Later passes override earlier ones if both renamed
    the same address."""
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
    """Return the post-rename name if one exists, else the raw name."""
    rename = renames_by_addr.get(rec.get("address", ""))
    if rename and rename.get("to"):
        return rename["to"]
    return rec.get("name", "")


def identify_candidates(function_index: dict, manifest: dict) -> list[dict]:
    """Return user-defined functions eligible for Pass 2 retype.

    Selection criteria (all must be true):
    - is_external == False AND is_thunk == False
    - effective name (post-rename) does NOT match FUN_<hex>
    """
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
    """Return caller/callee names, applying post-rename names where available."""
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

    fi_path = ROOT / "engagements" / args.engagement / "decomp" / "function_index.json"
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass2_batch.py -v
```

Expected: 11 PASSED.

- [ ] **Step 5: Run ALL reconstruct tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: 120 PASSED (109 prior + 11 new).

- [ ] **Step 6: Commit**

```bash
git add scripts/reconstruct_pass2_batch.py tests/reconstruct/test_pass2_batch.py
git commit -m "feat(reconstruct): pass 2 candidate detection + batching"
```

---

## Task 3: `reconstruct_pass2_apply.py` — schema validator

**Files:**
- Create: `scripts/reconstruct_pass2_apply.py`
- Test: `tests/reconstruct/test_pass2_apply.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_pass2_apply.py`:

```python
"""Tests for reconstruct_pass2_apply — worker result validator + manifest merge."""
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

import reconstruct_pass2_apply as apply_mod  # type: ignore


def test_validate_accepts_well_formed_result():
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    assert errors == []


def test_validate_rejects_missing_pass_field():
    result = {"batch_id": "x", "retypes": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass" in e.lower() for e in errors)


def test_validate_rejects_wrong_pass_value():
    result = {"pass": "pass3", "batch_id": "x", "retypes": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass2" in e.lower() for e in errors)


def test_validate_rejects_retypes_not_a_list():
    result = {"pass": "pass2", "batch_id": "x", "retypes": "not-a-list"}
    errors = apply_mod.validate_worker_result(result)
    assert any("retypes" in e.lower() for e in errors)


def test_validate_rejects_missing_addr_on_retype():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{"params": [], "locals": []}],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("addr" in e.lower() for e in errors)


def test_validate_rejects_empty_param_to():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{
            "addr": "0x1",
            "params": [{"index": 0, "to": "", "confidence": "high", "rationale": "r"}],
            "locals": [],
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("`to`" in e or "empty" in e.lower() for e in errors)


def test_validate_rejects_unknown_confidence():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{
            "addr": "0x1",
            "params": [{"index": 0, "to": "Foo", "confidence": "ultra", "rationale": "r"}],
            "locals": [],
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("confidence" in e.lower() for e in errors)


def test_validate_rejects_local_without_name():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{
            "addr": "0x1",
            "params": [],
            "locals": [{"to": "DWORD", "confidence": "high", "rationale": "r"}],
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("local" in e.lower() and "name" in e.lower() for e in errors)


def test_validate_rejects_param_without_index():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{
            "addr": "0x1",
            "params": [{"to": "DWORD", "confidence": "high", "rationale": "r"}],
            "locals": [],
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("index" in e.lower() for e in errors)


def test_validate_rejects_malformed_fixture():
    result = json.loads((FIXTURES / "sample_pass2_result_malformed.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    # The malformed fixture has: missing addr, empty `to`, bogus confidence.
    joined = " ".join(errors).lower()
    assert "addr" in joined
    assert "to" in joined or "empty" in joined
    assert "confidence" in joined
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass2_apply.py -v
```

Expected: 10 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/reconstruct_pass2_apply.py`** with EXACT content:

```python
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
    """Validate a `params[i]` or `locals[i]` record. Returns error list."""
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
        # Merge params by index (new overrides existing).
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
        # Merge locals by name.
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass2_apply.py -v
```

Expected: 10 PASSED.

- [ ] **Step 5: Run ALL reconstruct tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: 130 PASSED (120 prior + 10 new).

- [ ] **Step 6: Commit**

```bash
git add scripts/reconstruct_pass2_apply.py tests/reconstruct/test_pass2_apply.py
git commit -m "feat(reconstruct): pass 2 apply — worker result validator"
```

---

## Task 4: Merge + coverage + CLI tests for `reconstruct_pass2_apply.py`

Tests for the merge logic + recompute_coverage + end-to-end CLI.

**Files:**
- Test: `tests/reconstruct/test_pass2_apply.py` (append)

- [ ] **Step 1: Append the tests**

Append to `tests/reconstruct/test_pass2_apply.py`:

```python
def _function_index_for_pass2_merge():
    return {
        "binary": "samplebin.exe",
        "functions": [
            {"address": "0x140003000", "name": "FUN_140003000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h3",
             "instruction_count": 128, "size": 512, "strings": []},
            {"address": "0x140004000", "name": "FUN_140004000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h4",
             "instruction_count": 1, "size": 8, "strings": []},
            {"address": "0x140005000", "name": "FUN_140005000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h5",
             "instruction_count": 64, "size": 256, "strings": []},
        ],
    }


def test_merge_creates_pass2_entry_when_absent():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    assert not any(p["pass"] == "pass2" for p in manifest["passes"])
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result)
    pass2 = next(p for p in out["passes"] if p["pass"] == "pass2")
    addrs = {r["addr"] for r in pass2["retypes"]}
    assert addrs == {"0x140003000", "0x140004000"}


def test_merge_attaches_source_llm_retype_to_each_record():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result)
    pass2 = next(p for p in out["passes"] if p["pass"] == "pass2")
    for r in pass2["retypes"]:
        for p in r.get("params", []):
            assert p["source"] == "llm_retype"
        for l in r.get("locals", []):
            assert l["source"] == "llm_retype"


def test_merge_is_idempotent_when_same_result_re_applied():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    first = apply_mod.merge_into_manifest(manifest, result)
    second = apply_mod.merge_into_manifest(first, result)
    pass2 = next(p for p in second["passes"] if p["pass"] == "pass2")
    # No duplicates in params or locals lists per addr.
    for r in pass2["retypes"]:
        param_indices = [p["index"] for p in r.get("params", [])]
        local_names = [l["name"] for l in r.get("locals", [])]
        assert len(param_indices) == len(set(param_indices))
        assert len(local_names) == len(set(local_names))


def test_merge_later_retype_overrides_earlier_for_same_param_index():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    first = {
        "pass": "pass2", "batch_id": "b0",
        "retypes": [{
            "addr": "0x140003000",
            "params": [{"index": 0, "to": "OldType", "confidence": "medium", "rationale": "..."}],
            "locals": [],
        }],
    }
    second = {
        "pass": "pass2", "batch_id": "b1",
        "retypes": [{
            "addr": "0x140003000",
            "params": [{"index": 0, "to": "NewType", "confidence": "high", "rationale": "..."}],
            "locals": [],
        }],
    }
    after_first = apply_mod.merge_into_manifest(manifest, first)
    after_second = apply_mod.merge_into_manifest(after_first, second)
    pass2 = next(p for p in after_second["passes"] if p["pass"] == "pass2")
    rec = next(r for r in pass2["retypes"] if r["addr"] == "0x140003000")
    p0 = next(p for p in rec["params"] if p["index"] == 0)
    assert p0["to"] == "NewType"
    assert p0["confidence"] == "high"


def test_recompute_coverage_includes_typed_block():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    after = apply_mod.merge_into_manifest(manifest, result)
    cov = apply_mod.recompute_coverage(_function_index_for_pass2_merge(), after)
    assert "typed" in cov
    assert cov["typed"]["from_pass2"] == 2
    assert cov["typed"]["total_typed"] == 2


def test_cli_end_to_end(tmp_path):
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    (eng / "decomp" / "function_index.json").write_text(
        json.dumps(_function_index_for_pass2_merge())
    )
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass2_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass1_done.json",
                recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_pass2_result_valid.json",
                recon_dir / "pass2_batches" / "result_000.json")
    (recon_dir / "pass2_batches" / "index.json").write_text(json.dumps({
        "batches": [{"batch_id": "batch_000", "function_count": 2, "status": "pending"}],
        "candidate_count": 2,
    }, indent=2))

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass2_apply.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass2_batches" / "result_000.json")],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    manifest = json.loads((recon_dir / "manifest.json").read_text())
    assert any(p["pass"] == "pass2" for p in manifest["passes"])
    cov = json.loads((recon_dir / "coverage.json").read_text())
    assert cov["typed"]["from_pass2"] == 2
    idx = json.loads((recon_dir / "pass2_batches" / "index.json").read_text())
    assert idx["batches"][0]["status"] == "applied"


def test_cli_refuses_malformed(tmp_path):
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    (eng / "decomp" / "function_index.json").write_text(
        json.dumps(_function_index_for_pass2_merge())
    )
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass2_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass1_done.json",
                recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_pass2_result_malformed.json",
                recon_dir / "pass2_batches" / "result_999.json")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass2_apply.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass2_batches" / "result_999.json")],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "validation failed" in (r.stdout + r.stderr).lower()
```

- [ ] **Step 2: Run the new tests**

```bash
pytest tests/reconstruct/test_pass2_apply.py -v
```

Expected: 17 PASSED (10 from Task 3 + 7 new).

- [ ] **Step 3: Run ALL reconstruct tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: 137 PASSED (130 prior + 7 new).

- [ ] **Step 4: Commit**

```bash
git add tests/reconstruct/test_pass2_apply.py
git commit -m "test(reconstruct): pass 2 apply — merge + coverage + CLI"
```

---

## Task 5: Worker prompt `prompts/workers/reconstruct_retype.md`

**Files:**
- Create: `prompts/workers/reconstruct_retype.md`

- [ ] **Step 1: Create the prompt file** with EXACT content:

```markdown
# Worker: reconstruct_retype (Pass 2)

You are a reverse-engineering worker tasked with proposing parameter and local-variable type retypes for a batch of (already-named) functions in a binary. The strategist has selected up to 20 functions, each already renamed by Pass 0 or Pass 1 (or originally exported with a meaningful name). Your job is to read each function's name + neighbor context and propose retypes for its parameters and locals.

**Important caveat for this MVP:** You do NOT receive decompiled function bodies — only metadata. Without the body, all type inference happens from the function's name, its callers' names, its callees' names, and any xref'd strings. Confidence will generally be `medium` or `low`, not `high`. That is expected and correct.

## Input

You receive ONE JSON document with this shape:

```json
{
  "batch_id": "batch_000",
  "functions": [
    {
      "addr": "0x140012a0",
      "name": "DispatchCommand",
      "instruction_count": 42,
      "size": 256,
      "strings": ["..."],
      "neighbors": {
        "callers": ["entry", "ProcessRequest"],
        "callees": ["RtlAllocateHeap", "ParseHeader"]
      }
    },
    ...
  ]
}
```

The `name` field is the POST-RENAME name (the strategist has applied pass0/pass1 renames before sending to you). Trust it.

## Output

Return EXACTLY ONE JSON document of this shape (no prose, no markdown fences):

```json
{
  "pass": "pass2",
  "batch_id": "<same as input>",
  "retypes": [
    {
      "addr": "0x140012a0",
      "params": [
        {"index": 0, "from": "undefined4 *", "to": "IPC_REQUEST_HEADER *", "confidence": "medium", "rationale": "Name DispatchCommand + caller ProcessRequest suggests IPC header pointer"}
      ],
      "locals": [
        {"name": "local_18", "from": "DWORD", "to": "NTSTATUS", "confidence": "low", "rationale": "Likely status code; cannot verify without body"}
      ]
    },
    ...
  ]
}
```

## Retype rules

1. **Only propose what you can justify.** If no signal points to a specific type, omit the param/local from the output rather than guessing.
2. **Use Windows / NT types where appropriate** for Windows binaries: `LPCWSTR`, `HANDLE`, `NTSTATUS`, `PVOID`, `DWORD`, `BYTE *`, `SIZE_T`, struct-pointers like `IPC_REQUEST_HEADER *`.
3. **Use POSIX types where appropriate** for Linux/ELF binaries.
4. **Empty `from` is OK** — you don't always know what Ghidra had it as. Leave empty string `""` if unknown.
5. **`params[].index` is the 0-based parameter position.** Don't guess at parameter counts beyond what's strongly signaled.
6. **`locals[].name` is the Ghidra-assigned local var name** (e.g., `local_8`, `pvVar1`). If you propose a retype for a local, also give it a semantic name in the rationale: "rename to `status`".

## Confidence rules

- `high`: signal is unambiguous (e.g., function name ends in `W` so first arg is wide string, or the function is a known IAT wrapper).
- `medium`: signal is plausible (e.g., function name suggests a struct, callees use it as a buffer pointer).
- `low`: signal is weak — use this freely. Without bodies, most retypes will land here.

## Rationale rules

- One sentence, <=240 chars.
- Cite at least one concrete signal (a specific caller, callee, or string).
- DO NOT speculate beyond what is in the input.

## Skipping rules

If a function has no signal for any param/local, omit the entire entry from `retypes`. Better to skip than to over-claim.
```

- [ ] **Step 2: Verify**

```bash
head -3 prompts/workers/reconstruct_retype.md
```

Expected: shows `# Worker: reconstruct_retype (Pass 2)`.

- [ ] **Step 3: Commit**

```bash
git add prompts/workers/reconstruct_retype.md
git commit -m "feat(prompts): Pass 2 retype worker contract"
```

---

## Task 6: Strategist prompt + CLAUDE.md docs

Two doc edits in one commit.

**Files:**
- Modify: `prompts/phases/reconstruct.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Append Pass 2 section to strategist prompt**

Append to the end of `prompts/phases/reconstruct.md` (after the existing Pass 1 section). Use Edit with a unique anchor like the existing "## What this phase does NOT do (yet)" heading — insert the new content BEFORE it.

New content:

````markdown

## Pass 2 sequence

### Step 1 — emit batches

```
python3 scripts/reconstruct_pass2_batch.py \
    --engagement <eng-slug> \
    --binary <stem> \
    --version <tag>
```

Identifies user-defined functions with a non-FUN_ name (post-pass0/1 rename or originally exported) and writes `pass2_batches/batch_NNN.json` + `index.json`.

### Step 2 — dispatch one worker per batch

For each pending batch, dispatch a worker using `prompts/workers/reconstruct_retype.md`. Save each worker's JSON output to `pass2_batches/result_NNN.json`.

### Step 3 — apply each result

```
python3 scripts/reconstruct_pass2_apply.py \
    --engagement <eng-slug> \
    --binary <stem> \
    --version <tag> \
    --result catalog/reconstructed/<stem>_<tag>/pass2_batches/result_NNN.json
```

Each apply call validates the result, merges retypes into `manifest.json#passes[].pass2`, and adds a `typed` block to `coverage.json`.

Pass 2 caveats:
- Without LibGhidra, the worker sees only metadata (no decompiled body). Confidence will be mostly `medium` or `low`. This is expected.
- Pass 2 does NOT modify Pass 0/1 renames; it ADDS type info to functions that are already named.
- Struct hypotheses are NOT collected in this MVP. They ship with Pass 3a structify in a follow-on sub-plan.

````

- [ ] **Step 2: Append Pass 2 section to CLAUDE.md**

Insert a `### Pass 2 — LLM retype` sub-section in CLAUDE.md after the existing `### Pass 1 — LLM rename (proposed-renames as data)` block, before the next `## ` heading. Use Edit with the next `## ` heading as the anchor.

New content to insert:

````markdown

### Pass 2 — LLM retype (parameter + local types)

After Pass 0 + Pass 1 give functions semantic names, Pass 2 proposes parameter and local-variable type retypes (`param_1 (LPVOID) → IPC_REQUEST_HEADER *req`, `local_18 (DWORD) → NTSTATUS status`).

```bash
# 1. Emit per-batch input bundles under catalog/reconstructed/<stem>_<tag>/pass2_batches/
python3 scripts/reconstruct_pass2_batch.py \
    --engagement <eng-slug> --binary <stem> --version <tag>

# 2. Strategist dispatches one Agent per batch using prompts/workers/reconstruct_retype.md,
#    writing each worker's JSON output to pass2_batches/result_<NNN>.json.

# 3. Apply each worker result to manifest.json and recompute coverage.json.
python3 scripts/reconstruct_pass2_apply.py \
    --engagement <eng-slug> --binary <stem> --version <tag> \
    --result catalog/reconstructed/<stem>_<tag>/pass2_batches/result_000.json
```

Pass 2 produces:
- `manifest.json#passes[]` gains a `pass2` entry with `retypes` (NOT `proposed_renames` — distinct schema for type info).
- `coverage.json` gains a `typed` block: `typed.total_typed`, `typed.from_pass2`.
- `pass2_batches/index.json` tracks batch status (`pending` → `applied`).

Without LibGhidra, the Pass 2 worker sees only function metadata + neighbor names (no decompiled body). Confidence will mostly be `medium`/`low`. Once LibGhidra integration ships, Pass 2 batch input will include real type signatures and quality improves dramatically.

Struct consolidation (turning `IPC_REQUEST_HEADER` hypotheses into a single typedef across all callsites) is Pass 3a — a separate sub-plan.

````

- [ ] **Step 3: Verify both edits landed**

```bash
grep -c "Pass 2 sequence" prompts/phases/reconstruct.md
grep -c "### Pass 2 — LLM retype" CLAUDE.md
```

Both should return `1`.

- [ ] **Step 4: Commit**

```bash
git add prompts/phases/reconstruct.md CLAUDE.md
git commit -m "docs: document Pass 2 retype workflow in strategist + CLAUDE.md"
```

---

## Done — Pass 2 retype acceptance

When all 6 tasks above are complete:

- [ ] `pytest tests/reconstruct/ -v` reports all tests PASSED (~137 total: 109 from prior sub-plans + 28 new)
- [ ] `python3 scripts/reconstruct_pass2_batch.py --engagement <slug> --binary <stem> --version <tag>` writes `pass2_batches/batch_NNN.json` + `index.json`
- [ ] `python3 scripts/reconstruct_pass2_apply.py --result <path>` validates + merges a Pass 2 result, updates coverage.json `typed` block, flips batch status
- [ ] Strategist prompt + CLAUDE.md document the new workflow
- [ ] Worker contract at `prompts/workers/reconstruct_retype.md`
- [ ] Layer 8 page (already shipped) renders the new `typed` coverage block automatically — its template iterates `coverage` keys generically

**Next sub-plan candidates:**

- **Sub-plan 3.6 — Pass 3a structify + Pass 3b commenting + Pass 3c global naming + Pass 4 cleanup** — fills the remaining LLM passes plus the cleanup retry pass. Pass 3a needs struct hypothesis aggregation across pass2 outputs; Pass 3b is commentary-only; Pass 3c is deterministic.
- **Sub-plan 2.5 — Pass 0 expansion** — Rich header parser, string-xref naming, IOCTL/NTSTATUS constant equates.
- **Sub-plan 2-libghidra — LibGhidra integration** — Pass 2 quality improves dramatically once LibGhidra produces real type signatures for the batch input.
- **Reachability gate semantics** — wire `coverage.json#hard_gate_pass` to require 100% reachable-from-entrypoints naming + typing. Small (2-3 tasks).
