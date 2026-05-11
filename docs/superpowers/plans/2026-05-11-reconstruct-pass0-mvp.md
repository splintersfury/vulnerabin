# Reconstruct Phase — Pass 0 MVP (Sub-Plan 2/5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a runnable Pass 0 deterministic pipeline that operates on existing engagement decomp output (`function_index.json`) without requiring LibGhidra to be installed. It produces proposed renames as data in `manifest.json#passes[0]`, writes a real `coverage.json`, and the `vb` CLI gains `python3 scripts/reconstruct.py --binary <stem> --version <tag> --engagement <slug>`.

**Architecture:** Three pure-Python detectors (project discovery, IAT wrapper detection, pcode-hash carryforward) compose into a Pass 0 entry point; an orchestrator wires lock acquisition, Pass 0 invocation, manifest/coverage writes, and binary YAML status transitions. All renames are produced as structured records — not applied to a Ghidra project in this sub-plan. Applying renames to Ghidra (FID/BSim/`.gpr` snapshot/re-emit) lands in a follow-on LibGhidra-integration sub-plan once `vendor/bootstrap.sh --install` is implemented.

**Tech Stack:** Python 3.11, pytest, PyYAML, stdlib `json` / `fcntl` / `argparse`. Builds on foundation sub-plan 1/5 (`scripts/libghidra_connect.py`, `scripts/pcode_hash.py`, `scripts/catalog_add.py reconstruction` subcommand, `pipeline.yml` phase declaration, FSM gates).

---

## File Structure

**Create:**
- `scripts/reconstruct.py` — orchestrator CLI entry: locks, dispatches Pass 0, writes manifest/coverage, updates binary YAML status
- `scripts/reconstruct_pass0.py` — composes the three detectors into a single Pass 0 run; emits a `Pass0Result` dict
- `scripts/reconstruct_pass0_discovery.py` — derives `project_discovery` block from `function_index.json`
- `scripts/reconstruct_pass0_iat.py` — detects IAT wrappers and emits proposed renames
- `scripts/reconstruct_pass0_carryforward.py` — matches functions against prior reconstruction by pcode_hash; emits inherited rename proposals
- `tests/reconstruct/fixtures/__init__.py`
- `tests/reconstruct/fixtures/sample_function_index.json` — synthetic 12-function fixture covering each detector path
- `tests/reconstruct/fixtures/prior_manifest_carryforward.json` — synthetic prior reconstruction manifest for carryforward tests
- `tests/reconstruct/test_pass0_discovery.py`
- `tests/reconstruct/test_pass0_iat.py`
- `tests/reconstruct/test_pass0_carryforward.py`
- `tests/reconstruct/test_reconstruct_orchestrator.py`

**Modify:**
- `scripts/catalog_add.py` — `cmd_reconstruction` lazily creates `manifest.json` with empty `passes: []`; Pass 0 appends to that array. (Already done in foundation; verify schema match.)
- `CLAUDE.md` — append `python3 scripts/reconstruct.py` invocation to the existing reconstruct phase docs block

**Conventions established here:**

| Concept | Convention |
|---|---|
| Pass entry in `manifest.json#passes[]` | `{"pass": "pass0", "started_at": "...", "ended_at": "...", "tools_used": [...], "renames_applied": 0, "proposed_renames": [...], "tokens_spent": 0, "snapshot": null}` |
| Proposed rename record | `{"addr": "0x140012a0", "from": "FUN_140012a0", "to": "RtlAllocateHeap_wrapper", "confidence": "medium", "source": "iat_wrapper_detection", "rationale": "..."}` |
| `confidence` enum | `"high" | "medium" | "low"` |
| `source` enum (pass 0) | `"project_discovery" | "iat_wrapper_detection" | "pcode_hash_carryforward"` |
| `addr` format | `"0x" + lowercase hex`, matches what `function_index.json` already produces |
| Pass 0 does NOT mutate Ghidra projects | All output is data; LibGhidra application is a separate sub-plan |

---

## Task 1: Synthetic `function_index.json` fixture

The synthetic fixture is the contract for every Pass 0 detector test. Get it right once.

**Files:**
- Create: `tests/reconstruct/fixtures/__init__.py` (empty)
- Create: `tests/reconstruct/fixtures/sample_function_index.json`

- [ ] **Step 1: Create fixture init**

Create `tests/reconstruct/fixtures/__init__.py` as an empty file.

- [ ] **Step 2: Create the fixture**

Create `tests/reconstruct/fixtures/sample_function_index.json` with this exact content:

```json
{
  "binary": "sample.exe",
  "arch": "x86_64",
  "address_size": 64,
  "format": "PE",
  "total_functions": 12,
  "call_graph": {},
  "functions": [
    {
      "address": "0x140001000",
      "name": "entry",
      "callers": [],
      "callees": ["0x140002000", "0x140003000"],
      "is_external": false,
      "is_thunk": false,
      "is_exported": true,
      "code_hash": "aaaa1111",
      "instruction_count": 42,
      "size": 256,
      "strings": []
    },
    {
      "address": "0x140002000",
      "name": "FUN_140002000",
      "callers": ["0x140001000"],
      "callees": ["0x140020000"],
      "is_external": false,
      "is_thunk": false,
      "is_exported": false,
      "code_hash": "bbbb2222",
      "instruction_count": 2,
      "size": 12,
      "strings": []
    },
    {
      "address": "0x140003000",
      "name": "FUN_140003000",
      "callers": ["0x140001000"],
      "callees": ["0x140004000", "0x140005000"],
      "is_external": false,
      "is_thunk": false,
      "is_exported": false,
      "code_hash": "cccc3333",
      "instruction_count": 128,
      "size": 512,
      "strings": []
    },
    {
      "address": "0x140004000",
      "name": "FUN_140004000",
      "callers": ["0x140003000"],
      "callees": ["0x140021000"],
      "is_external": false,
      "is_thunk": false,
      "is_exported": false,
      "code_hash": "dddd4444",
      "instruction_count": 1,
      "size": 8,
      "strings": []
    },
    {
      "address": "0x140005000",
      "name": "FUN_140005000",
      "callers": ["0x140003000"],
      "callees": ["0x140020000", "0x140021000", "0x140022000"],
      "is_external": false,
      "is_thunk": false,
      "is_exported": false,
      "code_hash": "eeee5555",
      "instruction_count": 64,
      "size": 256,
      "strings": []
    },
    {
      "address": "0x140006000",
      "name": "DllMain",
      "callers": [],
      "callees": [],
      "is_external": false,
      "is_thunk": false,
      "is_exported": true,
      "code_hash": "ffff6666",
      "instruction_count": 32,
      "size": 128,
      "strings": []
    },
    {
      "address": "0x140007000",
      "name": "Ordinal_42",
      "callers": [],
      "callees": ["0x140003000"],
      "is_external": false,
      "is_thunk": false,
      "is_exported": true,
      "code_hash": "1234abcd",
      "instruction_count": 8,
      "size": 32,
      "strings": []
    },
    {
      "address": "0x140020000",
      "name": "RtlAllocateHeap",
      "callers": ["0x140002000", "0x140005000"],
      "callees": [],
      "is_external": true,
      "is_thunk": false,
      "is_exported": false,
      "code_hash": "0",
      "instruction_count": 0,
      "size": 0,
      "strings": []
    },
    {
      "address": "0x140021000",
      "name": "CreateFileW",
      "callers": ["0x140004000", "0x140005000"],
      "callees": [],
      "is_external": true,
      "is_thunk": false,
      "is_exported": false,
      "code_hash": "0",
      "instruction_count": 0,
      "size": 0,
      "strings": []
    },
    {
      "address": "0x140022000",
      "name": "memcpy",
      "callers": ["0x140005000"],
      "callees": [],
      "is_external": true,
      "is_thunk": false,
      "is_exported": false,
      "code_hash": "0",
      "instruction_count": 0,
      "size": 0,
      "strings": []
    },
    {
      "address": "0x140030000",
      "name": "j_CreateFileW",
      "callers": [],
      "callees": ["0x140021000"],
      "is_external": false,
      "is_thunk": true,
      "is_exported": false,
      "code_hash": "thunkpe",
      "instruction_count": 1,
      "size": 6,
      "strings": []
    },
    {
      "address": "0x140040000",
      "name": "FUN_140040000",
      "callers": [],
      "callees": [],
      "is_external": false,
      "is_thunk": false,
      "is_exported": false,
      "code_hash": "deadbeef",
      "instruction_count": 24,
      "size": 96,
      "strings": ["Initializing config", "C:\\ProgramData\\sample\\config.json"]
    }
  ]
}
```

This fixture exercises:
- `entry` (PE entrypoint, exported, has callees)
- `DllMain` (named export, no body activity)
- `Ordinal_42` (exported by ordinal)
- `FUN_140002000` (small wrapper: 2 instructions, one callee that is external — should be detected as `RtlAllocateHeap_wrapper`)
- `FUN_140004000` (single-instruction wrapper for `CreateFileW`)
- `FUN_140003000`, `FUN_140005000` (large non-wrapper functions, should NOT be IAT-renamed)
- `RtlAllocateHeap`, `CreateFileW`, `memcpy` (externals — must be skipped by user-defined-function predicate)
- `j_CreateFileW` (thunk — must be skipped)
- `FUN_140040000` (orphan with strings — neither exported nor reachable from entry; tests project_discovery's reachability walk)

- [ ] **Step 3: Commit (stay on `feat/reconstruct-foundation` if you're continuing the same branch; otherwise create a new branch `feat/reconstruct-pass0` first)**

Verify current branch:

```bash
git branch --show-current
```

If on `main`, create + check out a new branch:

```bash
git checkout -b feat/reconstruct-pass0
```

Then commit:

```bash
git add tests/reconstruct/fixtures/__init__.py tests/reconstruct/fixtures/sample_function_index.json
git commit -m "test(reconstruct): synthetic function_index fixture for Pass 0"
```

---

## Task 2: `reconstruct_pass0_discovery.py` — project_discovery extraction

Pure-Python extractor that reads a parsed `function_index.json` dict and returns a `project_discovery` dict matching the schema declared in the reconstruct spec §3.1.

**Files:**
- Create: `scripts/reconstruct_pass0_discovery.py`
- Test: `tests/reconstruct/test_pass0_discovery.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_pass0_discovery.py`:

```python
"""Tests for reconstruct_pass0_discovery — extract project_discovery from function_index."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass0_discovery as discovery  # type: ignore


@pytest.fixture()
def sample_index() -> dict:
    return json.loads((FIXTURES / "sample_function_index.json").read_text())


def test_extracts_binary_metadata(sample_index):
    d = discovery.extract(sample_index)
    assert d["binary"] == "sample.exe"
    assert d["arch"] == "x86_64"
    assert d["format"] == "PE"
    assert d["address_size"] == 64


def test_extracts_exports_excluding_externals_and_thunks(sample_index):
    d = discovery.extract(sample_index)
    exports = d["exports"]
    # entry, DllMain, Ordinal_42 are exported user-defined.
    # RtlAllocateHeap is external — must not appear.
    # j_CreateFileW is a thunk — must not appear.
    assert {"entry", "DllMain", "Ordinal_42"} == {e["name"] for e in exports}
    for e in exports:
        assert "address" in e
        assert e["address"].startswith("0x")


def test_identifies_entrypoint_when_name_is_entry(sample_index):
    d = discovery.extract(sample_index)
    assert d["entrypoints"] == ["0x140001000"]


def test_function_counts_distinguish_user_defined_vs_external_vs_thunk(sample_index):
    d = discovery.extract(sample_index)
    c = d["function_counts"]
    # 12 total in fixture: 7 user-defined non-thunk, 3 external, 1 thunk.
    # entry, DllMain, Ordinal_42, FUN_140002000, FUN_140003000, FUN_140004000, FUN_140005000, FUN_140040000 = 8 user-defined
    assert c["total"] == 12
    assert c["user_defined"] == 8
    assert c["external"] == 3
    assert c["thunk"] == 1


def test_reachability_walk_includes_transitive_callees(sample_index):
    d = discovery.extract(sample_index)
    reachable = set(d["reachable_user_defined"])
    # From entry (0x140001000): direct callees 0x140002000, 0x140003000.
    # 0x140003000 calls 0x140004000, 0x140005000.
    # External callees (RtlAllocateHeap, CreateFileW, memcpy) excluded.
    # FUN_140040000 is an orphan — must NOT be reachable.
    assert "0x140001000" in reachable        # entry itself
    assert "0x140002000" in reachable
    assert "0x140003000" in reachable
    assert "0x140004000" in reachable
    assert "0x140005000" in reachable
    assert "0x140006000" in reachable        # DllMain is its own root
    assert "0x140007000" in reachable        # Ordinal_42 is its own root
    assert "0x140040000" not in reachable    # orphan
    assert "0x140020000" not in reachable    # external (RtlAllocateHeap)


def test_strings_aggregated_by_function(sample_index):
    d = discovery.extract(sample_index)
    s = d["strings_by_function"]
    assert s.get("0x140040000") == [
        "Initializing config",
        "C:\\ProgramData\\sample\\config.json",
    ]
    # Functions with no strings should not appear as empty entries.
    assert "0x140001000" not in s


def test_handles_missing_optional_fields_gracefully():
    minimal = {
        "binary": "tiny.exe",
        "functions": [
            {
                "address": "0x100",
                "name": "main",
                "callers": [],
                "callees": [],
                "is_external": False,
                "is_thunk": False,
                "is_exported": True,
                "code_hash": "0",
                "instruction_count": 1,
                "size": 4,
                "strings": [],
            }
        ],
    }
    d = discovery.extract(minimal)
    assert d["binary"] == "tiny.exe"
    assert d["arch"] is None
    assert d["function_counts"]["user_defined"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass0_discovery.py -v
```

Expected: 7 FAILED — `ModuleNotFoundError: No module named 'reconstruct_pass0_discovery'`.

- [ ] **Step 3: Create `scripts/reconstruct_pass0_discovery.py`** with this exact content:

```python
"""Project discovery: extract a `project_discovery` block from a parsed
`function_index.json` dict.

Pure-Python; does not require LibGhidra. Reads only the data already produced
by `scripts/decomp.py`'s headless Ghidra export. The output dict is the same
shape declared in the reconstruct spec §3.1.
"""
from __future__ import annotations

from typing import Iterable


def _is_user_defined(rec: dict) -> bool:
    return not rec.get("is_external") and not rec.get("is_thunk")


def _exported(rec: dict) -> bool:
    return bool(rec.get("is_exported"))


def _reachable_user_defined(records: list[dict]) -> list[str]:
    """BFS from every exported user-defined function over `callees`,
    skipping externals and thunks. Returns sorted addresses.
    """
    by_addr = {r["address"]: r for r in records}
    roots = [
        r["address"]
        for r in records
        if _is_user_defined(r) and _exported(r)
    ]
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        addr = stack.pop()
        if addr in seen:
            continue
        rec = by_addr.get(addr)
        if rec is None or not _is_user_defined(rec):
            continue
        seen.add(addr)
        for callee_addr in rec.get("callees", []):
            if callee_addr not in seen:
                stack.append(callee_addr)
    return sorted(seen)


def _entrypoints(records: Iterable[dict]) -> list[str]:
    """Canonical entrypoint names produced by Ghidra: `entry` for PE main.

    Returns a sorted list of addresses for any user-defined function whose
    name is `entry`. (Other entrypoint kinds — exports, DllMain — surface
    through the `exports` list separately.)
    """
    return sorted(
        r["address"]
        for r in records
        if _is_user_defined(r) and r.get("name") == "entry"
    )


def extract(function_index: dict) -> dict:
    """Compute the `project_discovery` block for `manifest.json`.

    Input: parsed `function_index.json` from `scripts/decomp.py`.
    Output: dict suitable for `manifest.json#project_discovery`.
    """
    records = function_index.get("functions", [])
    user_defined = [r for r in records if _is_user_defined(r)]

    exports = sorted(
        (
            {"name": r["name"], "address": r["address"]}
            for r in user_defined
            if _exported(r)
        ),
        key=lambda e: e["name"],
    )

    strings_by_function: dict[str, list[str]] = {}
    for r in user_defined:
        ss = r.get("strings") or []
        if ss:
            strings_by_function[r["address"]] = list(ss)

    counts = {
        "total": len(records),
        "user_defined": sum(1 for r in records if _is_user_defined(r)),
        "external": sum(1 for r in records if r.get("is_external")),
        "thunk": sum(1 for r in records if r.get("is_thunk")),
    }

    return {
        "binary": function_index.get("binary"),
        "arch": function_index.get("arch"),
        "format": function_index.get("format"),
        "address_size": function_index.get("address_size"),
        "function_counts": counts,
        "exports": exports,
        "entrypoints": _entrypoints(records),
        "reachable_user_defined": _reachable_user_defined(records),
        "strings_by_function": strings_by_function,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass0_discovery.py -v
```

Expected: 7 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconstruct_pass0_discovery.py tests/reconstruct/test_pass0_discovery.py
git commit -m "feat(reconstruct): pass 0 project discovery from function_index"
```

---

## Task 3: `reconstruct_pass0_iat.py` — IAT wrapper detection

Detects `FUN_<addr>` functions that are simple forwarders to a single external (imported) function — these get renamed to `<ImportName>_wrapper` with confidence `medium`.

**Files:**
- Create: `scripts/reconstruct_pass0_iat.py`
- Test: `tests/reconstruct/test_pass0_iat.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_pass0_iat.py`:

```python
"""Tests for reconstruct_pass0_iat — detect single-call IAT wrappers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass0_iat as iat  # type: ignore


@pytest.fixture()
def sample_index() -> dict:
    return json.loads((FIXTURES / "sample_function_index.json").read_text())


def test_detects_two_instruction_wrapper(sample_index):
    """FUN_140002000 in the fixture has 2 instructions and one external callee
    (RtlAllocateHeap). It must be proposed as `RtlAllocateHeap_wrapper`.
    """
    proposed = iat.detect_wrappers(sample_index)
    by_addr = {p["addr"]: p for p in proposed}
    assert "0x140002000" in by_addr
    p = by_addr["0x140002000"]
    assert p["to"] == "RtlAllocateHeap_wrapper"
    assert p["from"] == "FUN_140002000"
    assert p["confidence"] == "medium"
    assert p["source"] == "iat_wrapper_detection"
    assert "RtlAllocateHeap" in p["rationale"]


def test_detects_one_instruction_wrapper(sample_index):
    """FUN_140004000 has 1 instruction and one external callee (CreateFileW)."""
    proposed = iat.detect_wrappers(sample_index)
    by_addr = {p["addr"]: p for p in proposed}
    assert "0x140004000" in by_addr
    assert by_addr["0x140004000"]["to"] == "CreateFileW_wrapper"


def test_skips_large_functions_even_with_external_callee(sample_index):
    """FUN_140005000 has 64 instructions and 3 callees including externals.
    Threshold for wrapper = <=2 instructions. Must NOT be proposed.
    """
    proposed = iat.detect_wrappers(sample_index)
    by_addr = {p["addr"]: p for p in proposed}
    assert "0x140005000" not in by_addr


def test_skips_functions_with_no_callees(sample_index):
    """FUN_140040000 has 0 callees — not a wrapper."""
    proposed = iat.detect_wrappers(sample_index)
    by_addr = {p["addr"]: p for p in proposed}
    assert "0x140040000" not in by_addr


def test_skips_already_named_functions(sample_index):
    """`entry`, `DllMain`, `Ordinal_42` are not `FUN_*` — must be skipped."""
    proposed = iat.detect_wrappers(sample_index)
    for p in proposed:
        assert p["from"].startswith("FUN_"), f"shouldn't rename non-FUN_ name: {p}"


def test_skips_thunks_and_externals(sample_index):
    """j_CreateFileW is is_thunk=True; RtlAllocateHeap is is_external=True.
    Both must be skipped.
    """
    proposed = iat.detect_wrappers(sample_index)
    addrs = {p["addr"] for p in proposed}
    assert "0x140030000" not in addrs  # j_CreateFileW (thunk)
    assert "0x140020000" not in addrs  # RtlAllocateHeap (external)


def test_skips_functions_with_multiple_external_callees():
    """If a small function calls 2+ externals, we can't name it after one of them."""
    fi = {
        "binary": "tiny.exe",
        "functions": [
            {
                "address": "0x100",
                "name": "FUN_100",
                "callers": [],
                "callees": ["0x200", "0x300"],
                "is_external": False,
                "is_thunk": False,
                "is_exported": False,
                "code_hash": "x",
                "instruction_count": 2,
                "size": 8,
                "strings": [],
            },
            {
                "address": "0x200",
                "name": "ExternA",
                "callers": ["0x100"],
                "callees": [],
                "is_external": True,
                "is_thunk": False,
                "is_exported": False,
                "code_hash": "0",
                "instruction_count": 0,
                "size": 0,
                "strings": [],
            },
            {
                "address": "0x300",
                "name": "ExternB",
                "callers": ["0x100"],
                "callees": [],
                "is_external": True,
                "is_thunk": False,
                "is_exported": False,
                "code_hash": "0",
                "instruction_count": 0,
                "size": 0,
                "strings": [],
            },
        ],
    }
    proposed = iat.detect_wrappers(fi)
    assert proposed == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass0_iat.py -v
```

Expected: 7 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/reconstruct_pass0_iat.py`** with this exact content:

```python
"""IAT wrapper detection.

A function is an "IAT wrapper" if:
- Its name starts with `FUN_` (i.e. unnamed by Ghidra).
- It has <=2 instructions.
- It has exactly one external callee.
- It is itself a user-defined function (is_external=False, is_thunk=False).

Such functions are proposed as renames to `<ImportName>_wrapper` with
medium confidence. This is the simplest possible deterministic naming
heuristic and produces 5-15% yield on a typical Windows binary.
"""
from __future__ import annotations

import re

_FUN_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")
_WRAPPER_INSTRUCTION_THRESHOLD = 2


def detect_wrappers(function_index: dict) -> list[dict]:
    """Return a list of proposed rename records for IAT wrappers.

    Each record matches the manifest.json#passes[].proposed_renames schema.
    """
    records = function_index.get("functions", [])
    by_addr = {r["address"]: r for r in records}
    proposed: list[dict] = []

    for r in records:
        if r.get("is_external") or r.get("is_thunk"):
            continue
        name = r.get("name", "")
        if not _FUN_RE.match(name):
            continue
        if r.get("instruction_count", 0) > _WRAPPER_INSTRUCTION_THRESHOLD:
            continue
        callees = r.get("callees") or []
        external_callees = [
            by_addr[c]
            for c in callees
            if c in by_addr and by_addr[c].get("is_external")
        ]
        if len(external_callees) != 1:
            continue
        target = external_callees[0]
        target_name = target.get("name", "")
        if not target_name:
            continue
        proposed.append({
            "addr": r["address"],
            "from": name,
            "to": f"{target_name}_wrapper",
            "confidence": "medium",
            "source": "iat_wrapper_detection",
            "rationale": (
                f"{r['instruction_count']}-instruction function with single "
                f"external callee {target_name} at {target['address']}"
            ),
        })
    return proposed
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass0_iat.py -v
```

Expected: 7 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconstruct_pass0_iat.py tests/reconstruct/test_pass0_iat.py
git commit -m "feat(reconstruct): pass 0 IAT wrapper detection"
```

---

## Task 4: `reconstruct_pass0_carryforward.py` — pcode-hash carryforward

If a prior reconstruction exists for the same binary, port renames forward by matching functions on pcode_hash. Reads the prior `manifest.json` from a sibling directory under `catalog/reconstructed/`.

**Files:**
- Create: `tests/reconstruct/fixtures/prior_manifest_carryforward.json`
- Create: `scripts/reconstruct_pass0_carryforward.py`
- Test: `tests/reconstruct/test_pass0_carryforward.py`

- [ ] **Step 1: Create the prior manifest fixture**

Create `tests/reconstruct/fixtures/prior_manifest_carryforward.json` with this exact content:

```json
{
  "binary": {
    "stem": "sample",
    "version_tag": "vprior",
    "status": "complete"
  },
  "passes": [
    {
      "pass": "pass0",
      "started_at": "2026-01-01T00:00:00Z",
      "ended_at": "2026-01-01T00:00:30Z",
      "tools_used": ["iat_wrapper_detection"],
      "renames_applied": 0,
      "proposed_renames": [
        {
          "addr": "0x140002000",
          "from": "FUN_140002000",
          "to": "AllocBufferHelper",
          "confidence": "medium",
          "source": "iat_wrapper_detection",
          "rationale": "[prior version evidence]"
        },
        {
          "addr": "0x140003000",
          "from": "FUN_140003000",
          "to": "DispatchCommand",
          "confidence": "high",
          "source": "llm_rename",
          "rationale": "[prior version evidence]"
        }
      ],
      "tokens_spent": 0,
      "snapshot": null
    }
  ],
  "pcode_hashes_by_addr": {
    "0x140002000": "PRIOR_HASH_FOR_2000",
    "0x140003000": "PRIOR_HASH_FOR_3000",
    "0x140004000": "PRIOR_HASH_FOR_4000_OBSOLETE"
  }
}
```

- [ ] **Step 2: Write the failing tests**

Create `tests/reconstruct/test_pass0_carryforward.py`:

```python
"""Tests for reconstruct_pass0_carryforward — match by pcode_hash, port renames."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass0_carryforward as cf  # type: ignore
import pcode_hash  # type: ignore


def _current_records():
    """Two functions matching the prior manifest's pcode_hashes and one that doesn't."""
    return [
        {"address": "0x140002000", "name": "FUN_140002000", "code_hash": "match_2000",
         "instruction_count": 2, "size": 12, "callers": [], "callees": [],
         "is_external": False, "is_thunk": False, "is_exported": False, "strings": []},
        {"address": "0x140003000", "name": "FUN_140003000", "code_hash": "match_3000",
         "instruction_count": 128, "size": 512, "callers": [], "callees": [],
         "is_external": False, "is_thunk": False, "is_exported": False, "strings": []},
        {"address": "0x140005000", "name": "FUN_140005000", "code_hash": "fresh_5000",
         "instruction_count": 64, "size": 256, "callers": [], "callees": [],
         "is_external": False, "is_thunk": False, "is_exported": False, "strings": []},
    ]


def _prior_manifest():
    return json.loads((FIXTURES / "prior_manifest_carryforward.json").read_text())


def test_no_prior_manifest_returns_empty(tmp_path):
    function_index = {"binary": "sample", "functions": _current_records()}
    proposed = cf.carryforward(function_index, prior_manifest=None)
    assert proposed == []


def test_matches_by_pcode_hash_when_hashes_align(monkeypatch):
    """Force pcode_hash.hash_function_record to return the values the prior
    manifest declares, then verify the carryforward picks them up.
    """
    expected = {
        "0x140002000": "PRIOR_HASH_FOR_2000",
        "0x140003000": "PRIOR_HASH_FOR_3000",
        "0x140005000": "DIFFERENT_HASH_NO_MATCH",
    }
    def fake_hash(rec):
        return expected[rec["address"]]
    monkeypatch.setattr(pcode_hash, "hash_function_record", fake_hash)

    function_index = {"binary": "sample", "functions": _current_records()}
    proposed = cf.carryforward(function_index, prior_manifest=_prior_manifest())

    by_addr = {p["addr"]: p for p in proposed}
    # 0x140002000 and 0x140003000 match; 0x140005000 has no matching prior hash.
    assert set(by_addr) == {"0x140002000", "0x140003000"}
    assert by_addr["0x140002000"]["to"] == "AllocBufferHelper"
    assert by_addr["0x140003000"]["to"] == "DispatchCommand"
    for p in proposed:
        assert p["source"] == "pcode_hash_carryforward"
        assert p["confidence"] == "high"
        assert "vprior" in p["rationale"]


def test_skips_when_prior_function_only_has_FUN_name(monkeypatch):
    """If the prior reconstruction never renamed a function (i.e. its name
    in the prior manifest's proposed_renames is missing), don't propose
    anything for it.
    """
    prior = {
        "binary": {"stem": "sample", "version_tag": "vprior"},
        "passes": [
            {
                "pass": "pass0",
                "proposed_renames": [],
                "tools_used": [],
            }
        ],
        "pcode_hashes_by_addr": {"0x140002000": "PRIOR_HASH_FOR_2000"},
    }
    monkeypatch.setattr(
        pcode_hash, "hash_function_record",
        lambda rec: "PRIOR_HASH_FOR_2000" if rec["address"] == "0x140002000" else "MISS",
    )
    function_index = {"binary": "sample", "functions": _current_records()}
    proposed = cf.carryforward(function_index, prior_manifest=prior)
    assert proposed == []


def test_only_user_defined_functions_considered(monkeypatch):
    """External or thunk functions in the current index must be ignored."""
    monkeypatch.setattr(
        pcode_hash, "hash_function_record",
        lambda rec: "PRIOR_HASH_FOR_2000",
    )
    function_index = {
        "binary": "sample",
        "functions": [
            {"address": "0x140020000", "name": "RtlAllocateHeap", "code_hash": "ext",
             "instruction_count": 0, "size": 0, "callers": [], "callees": [],
             "is_external": True, "is_thunk": False, "is_exported": False, "strings": []},
        ],
    }
    proposed = cf.carryforward(function_index, prior_manifest=_prior_manifest())
    assert proposed == []
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass0_carryforward.py -v
```

Expected: 4 FAILED — `ModuleNotFoundError`.

- [ ] **Step 4: Create `scripts/reconstruct_pass0_carryforward.py`** with this exact content:

```python
"""Pcode-hash carryforward.

If a prior reconstruction of this binary exists, match each function in the
current `function_index.json` against the prior manifest by `pcode_hash`. For
every match where the prior version had a non-FUN_ rename, propose the same
rename in the current pass with `source=pcode_hash_carryforward` and `confidence=high`.

The hash function is the foundation stub `pcode_hash.hash_function_record`;
a future LibGhidra-integration sub-plan replaces it with a PCode-aware hash.
"""
from __future__ import annotations

import re
from typing import Optional

import pcode_hash  # type: ignore

_FUN_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")


def _proposed_lookup_by_addr(prior_manifest: dict) -> dict[str, dict]:
    """Flatten all `proposed_renames` from every prior pass into a single map
    keyed by addr. Later passes override earlier passes if both renamed the
    same address.
    """
    out: dict[str, dict] = {}
    for p in prior_manifest.get("passes", []):
        for rec in p.get("proposed_renames", []):
            addr = rec.get("addr")
            if addr:
                out[addr] = rec
    return out


def carryforward(function_index: dict, prior_manifest: Optional[dict]) -> list[dict]:
    """Return proposed renames carried forward from the prior reconstruction.

    Returns an empty list if `prior_manifest` is None or contains no usable
    rename evidence.
    """
    if not prior_manifest:
        return []
    prior_hashes: dict[str, str] = prior_manifest.get("pcode_hashes_by_addr", {})
    if not prior_hashes:
        return []
    prior_renames_by_addr = _proposed_lookup_by_addr(prior_manifest)
    # Invert: hash -> addr that had this hash in the prior version.
    prior_hash_to_addr = {h: a for a, h in prior_hashes.items()}
    prior_version = (prior_manifest.get("binary") or {}).get("version_tag", "prior")

    out: list[dict] = []
    for rec in function_index.get("functions", []):
        if rec.get("is_external") or rec.get("is_thunk"):
            continue
        name = rec.get("name", "")
        if not _FUN_RE.match(name):
            continue
        h = pcode_hash.hash_function_record(rec)
        prior_addr = prior_hash_to_addr.get(h)
        if not prior_addr:
            continue
        prior_rename = prior_renames_by_addr.get(prior_addr)
        if not prior_rename:
            continue
        prior_to = prior_rename.get("to", "")
        if not prior_to or _FUN_RE.match(prior_to):
            continue
        out.append({
            "addr": rec["address"],
            "from": name,
            "to": prior_to,
            "confidence": "high",
            "source": "pcode_hash_carryforward",
            "rationale": (
                f"pcode_hash match with prior version {prior_version} "
                f"at {prior_addr} (previously named {prior_to})"
            ),
        })
    return out
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass0_carryforward.py -v
```

Expected: 4 PASSED.

- [ ] **Step 6: Commit**

```bash
git add scripts/reconstruct_pass0_carryforward.py tests/reconstruct/test_pass0_carryforward.py tests/reconstruct/fixtures/prior_manifest_carryforward.json
git commit -m "feat(reconstruct): pass 0 pcode-hash carryforward"
```

---

## Task 5: `reconstruct_pass0.py` — compose the three detectors

Pass 0 is the orchestrator-level abstraction: takes a parsed `function_index`, an optional prior `manifest`, and returns a `Pass0Result` dict containing the discovery block, the combined proposed renames, and per-source counts.

**Files:**
- Create: `scripts/reconstruct_pass0.py`
- Test: `tests/reconstruct/test_pass0_compose.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_pass0_compose.py`:

```python
"""Tests for reconstruct_pass0 — the composed Pass 0 entry."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass0 as pass0  # type: ignore


@pytest.fixture()
def sample_index() -> dict:
    return json.loads((FIXTURES / "sample_function_index.json").read_text())


def test_pass0_result_shape(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    assert set(res.keys()) >= {
        "pass",
        "tools_used",
        "project_discovery",
        "proposed_renames",
        "renames_by_source",
    }
    assert res["pass"] == "pass0"


def test_pass0_includes_iat_wrappers(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    sources = {p["source"] for p in res["proposed_renames"]}
    assert "iat_wrapper_detection" in sources


def test_pass0_skips_carryforward_when_prior_absent(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    sources = {p["source"] for p in res["proposed_renames"]}
    assert "pcode_hash_carryforward" not in sources


def test_pass0_uses_carryforward_when_prior_present(sample_index, monkeypatch):
    import pcode_hash  # type: ignore
    # Force a hash match on 0x140002000 against the prior manifest fixture.
    expected = {r["address"]: "PRIOR_HASH_FOR_2000" if r["address"] == "0x140002000" else "miss"
                for r in sample_index["functions"] if not r.get("is_external") and not r.get("is_thunk")}
    monkeypatch.setattr(
        pcode_hash, "hash_function_record",
        lambda rec: expected.get(rec["address"], "miss"),
    )
    prior = json.loads((FIXTURES / "prior_manifest_carryforward.json").read_text())
    res = pass0.run(sample_index, prior_manifest=prior)
    cf_renames = [p for p in res["proposed_renames"] if p["source"] == "pcode_hash_carryforward"]
    assert any(p["to"] == "AllocBufferHelper" for p in cf_renames)


def test_pass0_no_duplicate_renames_for_same_addr(sample_index, monkeypatch):
    """If both IAT detector and carryforward propose for the same addr,
    carryforward wins (higher confidence: high vs medium).
    """
    import pcode_hash  # type: ignore
    monkeypatch.setattr(
        pcode_hash, "hash_function_record",
        lambda rec: "PRIOR_HASH_FOR_2000" if rec["address"] == "0x140002000" else "miss",
    )
    prior = json.loads((FIXTURES / "prior_manifest_carryforward.json").read_text())
    res = pass0.run(sample_index, prior_manifest=prior)
    addrs = [p["addr"] for p in res["proposed_renames"]]
    assert len(addrs) == len(set(addrs)), "duplicate addr in proposed_renames"
    # And the surviving rename for 0x140002000 must be the carryforward one (high).
    p = next(r for r in res["proposed_renames"] if r["addr"] == "0x140002000")
    assert p["source"] == "pcode_hash_carryforward"
    assert p["confidence"] == "high"


def test_renames_by_source_counts_align(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    rbs = res["renames_by_source"]
    assert rbs["iat_wrapper_detection"] == sum(
        1 for p in res["proposed_renames"] if p["source"] == "iat_wrapper_detection"
    )


def test_tools_used_reflects_active_detectors(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    assert "iat_wrapper_detection" in res["tools_used"]
    assert "pcode_hash_carryforward" not in res["tools_used"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass0_compose.py -v
```

Expected: 7 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/reconstruct_pass0.py`** with this exact content:

```python
"""Pass 0 — composed deterministic detectors.

Pure-Python: project discovery + IAT wrapper detection + pcode-hash carryforward.
Returns a Pass0Result dict that the reconstruct.py orchestrator merges into
`manifest.json#passes[]`.
"""
from __future__ import annotations

from typing import Optional

import reconstruct_pass0_carryforward as cf  # type: ignore
import reconstruct_pass0_discovery as discovery  # type: ignore
import reconstruct_pass0_iat as iat  # type: ignore

_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _dedupe_by_addr_keeping_highest_confidence(renames: list[dict]) -> list[dict]:
    best: dict[str, dict] = {}
    for r in renames:
        addr = r["addr"]
        cur = best.get(addr)
        if cur is None or _CONFIDENCE_RANK[r["confidence"]] > _CONFIDENCE_RANK[cur["confidence"]]:
            best[addr] = r
    return sorted(best.values(), key=lambda r: r["addr"])


def run(function_index: dict, prior_manifest: Optional[dict]) -> dict:
    """Compose the Pass 0 detectors and return the Pass0Result.

    Result shape:
        {
          "pass": "pass0",
          "tools_used": ["project_discovery", "iat_wrapper_detection", ...],
          "project_discovery": {...},   # from reconstruct_pass0_discovery.extract
          "proposed_renames": [...],     # deduped by addr, highest confidence wins
          "renames_by_source": {"iat_wrapper_detection": N, ...},
        }
    """
    proj = discovery.extract(function_index)
    iat_renames = iat.detect_wrappers(function_index)
    cf_renames = cf.carryforward(function_index, prior_manifest=prior_manifest)

    combined = _dedupe_by_addr_keeping_highest_confidence(iat_renames + cf_renames)

    tools_used = ["project_discovery"]
    if iat_renames:
        tools_used.append("iat_wrapper_detection")
    if cf_renames:
        tools_used.append("pcode_hash_carryforward")

    renames_by_source: dict[str, int] = {}
    for r in combined:
        renames_by_source[r["source"]] = renames_by_source.get(r["source"], 0) + 1

    return {
        "pass": "pass0",
        "tools_used": tools_used,
        "project_discovery": proj,
        "proposed_renames": combined,
        "renames_by_source": renames_by_source,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass0_compose.py -v
```

Expected: 7 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconstruct_pass0.py tests/reconstruct/test_pass0_compose.py
git commit -m "feat(reconstruct): pass 0 composed entry (discovery+IAT+carryforward)"
```

---

## Task 6: `reconstruct.py` orchestrator — CLI entry, lock, manifest, coverage

The orchestrator is the entry point an operator runs. It:
1. Reads `scope.json` from the engagement for the binary stem
2. Looks up `catalog/binaries/<stem>.yml#reconstruction.ref`
3. Acquires the `.lock` via `libghidra_connect.acquire_exclusive_lock`
4. Loads `engagements/<eng>/decomp/function_index.json`
5. Loads prior `manifest.json` from a prior `catalog/reconstructed/<stem>_*/` dir if any
6. Calls `reconstruct_pass0.run`
7. Writes/updates `<reconstruction.ref>/manifest.json` (appends Pass 0 to `passes[]`, sets `project_discovery`, sets `pcode_hashes_by_addr`)
8. Writes `<reconstruction.ref>/coverage.json`
9. Updates `catalog/binaries/<stem>.yml#reconstruction.status` from `not_started` → `in_progress` at start, → `partial` at end (since this MVP doesn't satisfy the hard gate without LLM passes)
10. Releases the lock

**Files:**
- Create: `scripts/reconstruct.py`
- Test: `tests/reconstruct/test_reconstruct_orchestrator.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_reconstruct_orchestrator.py`:

```python
"""End-to-end tests for the reconstruct.py orchestrator (Pass 0 only)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RECONSTRUCT = REPO_ROOT / "scripts" / "reconstruct.py"
CATALOG_ADD = REPO_ROOT / "scripts" / "catalog_add.py"
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"


def _seed_repo(tmp_path: Path, stem: str = "sample", version_tag: str = "vmvp") -> dict:
    """Set up engagement + catalog + scope.json + function_index.json."""
    (tmp_path / "catalog" / "binaries").mkdir(parents=True)
    (tmp_path / "engagements").mkdir()

    eng = tmp_path / "engagements" / "test-eng"
    eng.mkdir()
    (eng / "scope.json").write_text(json.dumps({
        "binary": stem, "target_type": "binary",
    }))
    (eng / "decomp").mkdir()
    shutil.copy(
        FIXTURES / "sample_function_index.json",
        eng / "decomp" / "function_index.json",
    )

    (tmp_path / "catalog" / "binaries" / f"{stem}.yml").write_text(yaml.safe_dump({
        "binary": stem,
        "product": "test-product",
    }))

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    # Scaffold via vb-add reconstruction (already shipped in foundation).
    r = subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", version_tag],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr

    return {
        "tmp_path": tmp_path,
        "stem": stem,
        "version_tag": version_tag,
        "engagement": "test-eng",
        "env": env,
        "recon_dir": tmp_path / "catalog" / "reconstructed" / f"{stem}_{version_tag}",
    }


def test_orchestrator_runs_end_to_end(tmp_path):
    seed = _seed_repo(tmp_path)
    result = subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_orchestrator_writes_manifest_with_pass0_entry(tmp_path):
    seed = _seed_repo(tmp_path)
    subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], check=True, capture_output=True, text=True,
    )
    manifest = json.loads((seed["recon_dir"] / "manifest.json").read_text())
    assert manifest["passes"], "manifest should have at least one pass entry"
    p0 = next(p for p in manifest["passes"] if p["pass"] == "pass0")
    assert "started_at" in p0
    assert "ended_at" in p0
    assert "iat_wrapper_detection" in p0["tools_used"]
    # IAT detector finds 0x140002000 and 0x140004000 (both 1-2 instructions
    # with single external callee).
    addrs = {r["addr"] for r in p0["proposed_renames"]}
    assert addrs == {"0x140002000", "0x140004000"}


def test_orchestrator_writes_coverage_json(tmp_path):
    seed = _seed_repo(tmp_path)
    subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], check=True, capture_output=True, text=True,
    )
    cov = json.loads((seed["recon_dir"] / "coverage.json").read_text())
    # In the fixture: 8 user-defined functions, 2 proposed renames from IAT.
    # Hard gate (reachable_named_100pct) is False since no LLM passes yet.
    # Soft gate also False — but the orchestrator must still populate the keys.
    assert cov["totals"]["user_defined_functions"] == 8
    assert cov["hard_gate_pass"] is False
    assert cov["soft_gate_pass"] is False


def test_orchestrator_updates_binary_yaml_status(tmp_path):
    seed = _seed_repo(tmp_path)
    subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], check=True, capture_output=True, text=True,
    )
    yml = yaml.safe_load(
        (tmp_path / "catalog" / "binaries" / f"{seed['stem']}.yml").read_text()
    )
    # After Pass 0 only, status is `partial` (hard gate not satisfied).
    assert yml["reconstruction"]["status"] == "partial"


def test_orchestrator_refuses_when_lock_held(tmp_path):
    import fcntl
    seed = _seed_repo(tmp_path)
    lock_path = seed["recon_dir"] / ".lock"
    lf = open(lock_path, "w")
    fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        result = subprocess.run(
            [sys.executable, str(RECONSTRUCT),
             "--engagement", seed["engagement"],
             "--binary", seed["stem"],
             "--version", seed["version_tag"]],
            env=seed["env"], capture_output=True, text=True,
        )
        assert result.returncode != 0
        out = result.stdout + result.stderr
        assert "lock" in out.lower()
    finally:
        fcntl.flock(lf, fcntl.LOCK_UN)
        lf.close()


def test_orchestrator_carries_forward_from_prior_version(tmp_path, monkeypatch):
    """If a prior reconstruction dir exists, the orchestrator loads its
    manifest as the carryforward source. We seed one manually.
    """
    seed = _seed_repo(tmp_path, version_tag="vcurrent")
    # Seed a prior version directory under the same stem.
    prior_dir = tmp_path / "catalog" / "reconstructed" / f"{seed['stem']}_vprior"
    prior_dir.mkdir(parents=True)
    shutil.copy(
        FIXTURES / "prior_manifest_carryforward.json",
        prior_dir / "manifest.json",
    )

    result = subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    manifest = json.loads((seed["recon_dir"] / "manifest.json").read_text())
    p0 = next(p for p in manifest["passes"] if p["pass"] == "pass0")
    # Even with no pcode_hash match in the fixture (current binary's stub
    # hashes won't equal "PRIOR_HASH_FOR_2000" without monkeypatching the
    # in-process pcode_hash), the carryforward tool must STILL be recorded
    # as inspected.
    # Behavior expectation: the orchestrator passes the prior manifest into
    # reconstruct_pass0.run, and tools_used includes "pcode_hash_carryforward"
    # only if cf produced at least one rename. Without monkeypatching, it
    # produces none — so check that the orchestrator at least discovered the
    # prior version and recorded it in pass0 metadata.
    assert p0.get("prior_version_consulted") == f"{seed['stem']}_vprior"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_reconstruct_orchestrator.py -v
```

Expected: 6 FAILED — `reconstruct.py` not found.

- [ ] **Step 3: Create `scripts/reconstruct.py`** with this exact content:

```python
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


def _compute_coverage(function_index: dict, proposed_renames: list[dict]) -> dict:
    fns = function_index.get("functions", [])
    user_defined = [r for r in fns if not r.get("is_external") and not r.get("is_thunk")]
    renamed_addrs = {r["addr"] for r in proposed_renames}
    # Reachable set = user-defined functions reachable from exports (computed in discovery).
    # For coverage purposes here, we approximate "named" as: not FUN_* OR appears in proposed_renames.
    import re
    fun_re = re.compile(r"^FUN_[0-9a-fA-F]+$")
    named_total = sum(
        1 for r in user_defined
        if not fun_re.match(r.get("name", "")) or r["address"] in renamed_addrs
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_reconstruct_orchestrator.py -v
```

Expected: 6 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconstruct.py tests/reconstruct/test_reconstruct_orchestrator.py
git commit -m "feat(reconstruct): pass 0 orchestrator with lock + manifest + coverage"
```

---

## Task 7: Verify full reconstruct test suite + smoke test

After tasks 1-6, the foundation smoke test from sub-plan 1 should STILL pass: it asserts that without a coverage.json, the post-gates fail. Now that Pass 0 produces coverage.json, this assertion needs verification.

**Files:**
- Test: `tests/reconstruct/test_pass0_smoke.py` (create — end-to-end fixture test that drives reconstruct.py and verifies fsm gates flip)

- [ ] **Step 1: Write the test**

Create `tests/reconstruct/test_pass0_smoke.py`:

```python
"""Smoke test: after Pass 0 runs end-to-end, fsm gate reads reflect new state."""
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
RECONSTRUCT = REPO_ROOT / "scripts" / "reconstruct.py"
CATALOG_ADD = REPO_ROOT / "scripts" / "catalog_add.py"
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"


def test_pass0_smoke_flips_post_gates(tmp_path, monkeypatch):
    """After Pass 0 runs, coverage.json exists with hard_gate_pass=False and
    soft_gate_pass=False. The fsm post-gates must read those values and
    report ok=False with non-coverage-missing evidence.
    """
    # Set up the layout the orchestrator + fsm both expect.
    (tmp_path / "catalog" / "binaries").mkdir(parents=True)
    (tmp_path / "engagements" / "smoke").mkdir(parents=True)
    (tmp_path / "engagements" / "smoke" / "scope.json").write_text(json.dumps({
        "binary": "smoke", "target_type": "binary",
    }))
    (tmp_path / "engagements" / "smoke" / "decomp").mkdir()
    shutil.copy(
        FIXTURES / "sample_function_index.json",
        tmp_path / "engagements" / "smoke" / "decomp" / "function_index.json",
    )
    (tmp_path / "catalog" / "binaries" / "smoke.yml").write_text(yaml.safe_dump({
        "binary": "smoke",
    }))
    (tmp_path / "pipeline.yml").write_text((REPO_ROOT / "pipeline.yml").read_text())

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}

    # Scaffold + run pass 0.
    subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", "smoke", "--version", "vsmoke"],
        env=env, check=True, capture_output=True, text=True,
    )
    r = subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", "smoke", "--binary", "smoke", "--version", "vsmoke"],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr

    # coverage.json must exist now.
    cov_path = tmp_path / "catalog" / "reconstructed" / "smoke_vsmoke" / "coverage.json"
    assert cov_path.is_file()
    cov = json.loads(cov_path.read_text())
    assert cov["hard_gate_pass"] is False
    assert cov["soft_gate_pass"] is False

    # Now run fsm gate_status and verify the gates read coverage.json
    # (not "coverage.json missing").
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", tmp_path / "catalog" / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)
    monkeypatch.setattr(fsm, "PIPELINE", tmp_path / "pipeline.yml")

    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "smoke",
        tmp_path / "engagements" / "smoke",
        "reconstruct",
        cfg["phases"]["reconstruct"],
    )
    hard = next(s for s in statuses if s["id"] == "reachable_named_100pct")
    soft = next(s for s in statuses if s["id"] == "tail_named_80pct")
    assert hard["ok"] is False
    assert "coverage.json missing" not in hard["evidence"]  # coverage now present
    assert soft["ok"] is False
    assert "coverage.json missing" not in soft["evidence"]


def test_full_reconstruct_suite_still_passes():
    """Sanity: every prior test in tests/reconstruct/ continues to pass."""
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/reconstruct/", "-q"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    # If this fails, the failures are in stdout/stderr.
    assert r.returncode == 0, r.stdout + r.stderr
```

- [ ] **Step 2: Run the smoke test alone**

```bash
pytest tests/reconstruct/test_pass0_smoke.py::test_pass0_smoke_flips_post_gates -v
```

Expected: PASSED.

- [ ] **Step 3: Run the full reconstruct suite**

```bash
pytest tests/reconstruct/ -v
```

Expected: all previous tests + 8 new test files' worth = ~60+ PASSED.

- [ ] **Step 4: Commit**

```bash
git add tests/reconstruct/test_pass0_smoke.py
git commit -m "test(reconstruct): pass 0 smoke flips fsm post-gate evidence"
```

---

## Task 8: Document Pass 0 invocation in CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Find the existing reconstruct documentation block**

```bash
grep -n "vb-add reconstruction" CLAUDE.md
```

Note the line number where the existing `vb-add reconstruction` entry lives — the new docs go in the same area (a separate small section after the `vb-add` block).

- [ ] **Step 2: Add a new section**

Using the Edit tool (not redirection), insert this section after the `## vb-add CLI` section's closing fence — find a stable anchor in the existing file like the next `##` heading and insert before it:

```markdown
## Reconstruct phase (Pass 0 MVP)

After running `vb-add reconstruction` to scaffold the catalog dir, drive Pass 0 against an existing engagement's decompilation output:

```bash
python3 scripts/reconstruct.py \
    --engagement <eng-slug> \
    --binary <stem> \
    --version <tag>
```

Pass 0 is deterministic and pure-Python — it requires no LibGhidra install. It runs three detectors:

1. **Project discovery** — derives entrypoints, exports, reachable user-defined function set, and per-function strings from `engagements/<eng>/decomp/function_index.json`.
2. **IAT wrapper detection** — proposes `<ImportName>_wrapper` renames for 1-2 instruction `FUN_*` functions that forward to a single external API.
3. **Pcode-hash carryforward** — if a prior reconstruction directory exists for the same binary stem, ports renames forward by matching functions on their structural hash.

Pass 0 produces:
- `catalog/reconstructed/<stem>_<tag>/manifest.json` — Pass 0 entry added to `passes[]` with `proposed_renames`, `project_discovery`, `pcode_hashes_by_addr`
- `catalog/reconstructed/<stem>_<tag>/coverage.json` — `hard_gate_pass: false` and `soft_gate_pass: false` (both gates require LLM passes 1-4 to satisfy)
- Updates `catalog/binaries/<stem>.yml#reconstruction.status` to `partial`

Pass 0 does NOT apply renames to a Ghidra project — they are produced as data. Applying renames to Ghidra (FID/BSim/`.gpr` snapshot/re-emit) is a separate sub-plan once `vendor/bootstrap.sh --install` ships.
```

- [ ] **Step 3: Verify**

```bash
grep -A4 "## Reconstruct phase (Pass 0 MVP)" CLAUDE.md
```

Expected: shows the new section header + first few lines.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document reconstruct.py Pass 0 invocation"
```

---

## Done — Pass 0 MVP acceptance

When all 8 tasks above are complete:

- [ ] `pytest tests/reconstruct/ -v` reports all tests PASSED (~60 total: 35 from foundation + ~25 new)
- [ ] `python3 scripts/reconstruct.py --engagement <slug> --binary <stem> --version <tag>` runs end-to-end on a real engagement that has `decomp/function_index.json` and produces `manifest.json` + `coverage.json` under the catalog
- [ ] `vb-add reconstruction` followed by `reconstruct.py` results in `catalog/binaries/<stem>.yml#reconstruction.status: partial`
- [ ] FSM post-gates now read real values from `coverage.json` (no longer "coverage.json missing")
- [ ] CLAUDE.md documents the new invocation

**Next sub-plan candidates** (each independent, pick whichever delivers most value next):

- **Sub-plan 2.5 — Pass 0 expansion** — adds Rich header parser, string-xref naming heuristic, constant equate detection (IOCTL codes, NTSTATUS) over the raw decomp .c files. Still pure-Python, no LibGhidra.
- **Sub-plan 3 — LLM Passes 1-4** — adds the rename / retype / structify / comment / cleanup LLM workers and the strategist. Requires LibGhidra to apply renames; can also be implemented as proposed-renames-only initially.
- **Sub-plan 2-libghidra — LibGhidra integration** — implements `vendor/bootstrap.sh --install`, adds FID + BSim, real `.gpr` snapshot, re-emit `.c` files. This is the heaviest sub-plan; defer until the user has a concrete need to apply renames against a real Ghidra project.
- **Sub-plan 4 — Catalog integration + Layer 8 page** — adds `catalog_re_extract.py --reconstructed-dir`, renders `catalog/pages/reconstructed/<stem>_<tag>.md`, updates binary page banner. Pure presentation; can land any time after Pass 0 produces real data.
