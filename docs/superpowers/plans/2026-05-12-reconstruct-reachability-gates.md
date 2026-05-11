# Reconstruct Phase — Reachability Gate Semantics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `coverage.json#hard_gate_pass` and `#soft_gate_pass` reflect real reachability + naming math, replacing the `False` stubs that have shipped since foundation. After this plan, `reconstruct.py` (Pass 0) and `reconstruct_pass{1,2}_apply.py` both compute the gates from `manifest.json#project_discovery.reachable_user_defined` × the accumulated `proposed_renames`. The FSM post-gates declared in `pipeline.yml` start emitting real verdicts. `catalog/binaries/<stem>.yml#reconstruction.status` transitions to `complete` when both gates pass.

**Architecture:** Add a single shared library `scripts/reconstruct_gates.py` with `compute_gate_state(function_index, manifest) -> dict`. Both `reconstruct.py` and the Pass 1/2 apply scripts call it instead of hardcoding `False`. The library reads `manifest.project_discovery.reachable_user_defined` as the reachability set, intersects with the union of all-pass `proposed_renames`, and computes hard/soft gate verdicts using the predicates declared in `pipeline.yml` (100% of reachable named, ≥80% of tail named).

**Tech Stack:** Python 3.11, pytest, stdlib. No new pip deps. No new external dependencies.

---

## File Structure

**Create:**
- `scripts/reconstruct_gates.py` — `compute_gate_state(function_index, manifest)` library
- `tests/reconstruct/test_reconstruct_gates.py`

**Modify:**
- `scripts/reconstruct.py` — replace `_compute_coverage` hardcoded `False` with `compute_gate_state` call; promote status to `complete` when both gates pass
- `scripts/reconstruct_pass1_apply.py` — same: `recompute_coverage` calls `compute_gate_state`
- `scripts/reconstruct_pass2_apply.py` — same: `recompute_coverage` calls `compute_gate_state`

**Counted-as-named predicate (from spec §1.5):**

A function counts as `named` for gate purposes iff **both**:

1. Its name in `function_index.functions[i].name` does NOT match `^(FUN_|sub_)[0-9a-f]+$`, OR there is a `proposed_renames` entry for its address in any pass.
2. If named via `proposed_renames`, the rename's `confidence` is `medium` or `high` (low-confidence Pass 0 string-xref names are excluded), OR the rename came from any LLM pass (`pass1`, `pass2`, `pass3a`, etc., regardless of confidence).

This matches the spec's intent: deterministic low-confidence Pass 0 names are weak signal and don't count; LLM renames at any confidence count (the LLM is more reliable than a regex on a string xref).

---

## Task 1: `compute_gate_state` library

**Files:**
- Create: `scripts/reconstruct_gates.py`
- Test: `tests/reconstruct/test_reconstruct_gates.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_reconstruct_gates.py`:

```python
"""Tests for reconstruct_gates — hard/soft gate computation."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_gates as gates  # type: ignore


def _function_index(named_addrs: list[str], unnamed_addrs: list[str]) -> dict:
    """Build a function_index with given addresses; named ones have semantic
    names (not FUN_*), unnamed have FUN_<addr>."""
    fns = []
    for a in named_addrs:
        fns.append({"address": a, "name": f"SemanticName_{a[2:]}",
                    "is_external": False, "is_thunk": False,
                    "is_exported": False,
                    "callers": [], "callees": [], "code_hash": "h",
                    "instruction_count": 10, "size": 32, "strings": []})
    for a in unnamed_addrs:
        fns.append({"address": a, "name": f"FUN_{a[2:]}",
                    "is_external": False, "is_thunk": False,
                    "is_exported": False,
                    "callers": [], "callees": [], "code_hash": "h",
                    "instruction_count": 10, "size": 32, "strings": []})
    return {"binary": "test", "functions": fns}


def _manifest(reachable: list[str], renames: list[dict] | None = None) -> dict:
    """Build a manifest with given reachability set + rename records."""
    return {
        "binary": {"stem": "t", "version_tag": "v1", "status": "partial"},
        "project_discovery": {"reachable_user_defined": list(reachable)},
        "passes": [{
            "pass": "pass0",
            "proposed_renames": renames or [],
        }],
    }


def test_hard_gate_passes_when_all_reachable_named():
    """All 3 reachable functions have semantic names; tail has 7 named out of 10
    (70% — below soft gate's 80% threshold, so soft should fail; hard should pass)."""
    reachable = ["0x100", "0x101", "0x102"]
    tail_named = [f"0x{i:03x}" for i in range(0x200, 0x207)]    # 7 tail named
    tail_unnamed = [f"0x{i:03x}" for i in range(0x300, 0x303)]  # 3 tail unnamed
    fi = _function_index(reachable + tail_named, tail_unnamed)
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True
    assert state["soft_gate_pass"] is False
    assert state["named"]["reachable"] == 3
    assert state["reachable_total"] == 3
    # Tail = 7 named + 3 unnamed = 10 total tail. Named ratio 70%.
    assert state["tail_total"] == 10
    assert state["named"]["tail"] == 7


def test_hard_gate_fails_when_reachable_function_unnamed():
    """One reachable function is unnamed (FUN_*) — hard gate must fail."""
    reachable = ["0x100", "0x101", "0x102"]
    fi = _function_index(["0x100", "0x101"], ["0x102"])   # 0x102 still FUN_*
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is False
    assert state["named"]["reachable"] == 2


def test_hard_gate_uses_rename_when_function_name_is_FUN_():
    """0x100 is FUN_100 in function_index, but pass1 renamed it. Should count as named."""
    reachable = ["0x100", "0x101"]
    fi = _function_index(["0x101"], ["0x100"])
    manifest = _manifest(reachable, renames=[
        {"addr": "0x100", "to": "Renamed", "confidence": "high",
         "source": "llm_rename"}
    ])
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True


def test_low_confidence_pass0_rename_does_not_count():
    """A Pass 0 rename at confidence=low (e.g. from string_xref) MUST NOT count."""
    reachable = ["0x100"]
    fi = _function_index([], ["0x100"])
    manifest = _manifest(reachable, renames=[
        {"addr": "0x100", "to": "try_open_file", "confidence": "low",
         "source": "string_xref"}
    ])
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is False


def test_low_confidence_llm_rename_does_count():
    """An LLM rename at confidence=low (source != Pass 0 deterministic) DOES count."""
    reachable = ["0x100"]
    fi = _function_index([], ["0x100"])
    manifest = _manifest(reachable, renames=[
        {"addr": "0x100", "to": "Unsure", "confidence": "low",
         "source": "llm_rename"}
    ])
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True


def test_soft_gate_passes_when_tail_above_80pct():
    reachable = ["0x100"]
    tail_named = [f"0x{i:03x}" for i in range(0x200, 0x208)]    # 8 named
    tail_unnamed = [f"0x{i:03x}" for i in range(0x300, 0x302)]  # 2 unnamed
    # 8 / 10 = 80% — meets the >=80% threshold.
    fi = _function_index(reachable + tail_named, tail_unnamed)
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["soft_gate_pass"] is True


def test_soft_gate_passes_when_tail_is_empty():
    """If there are no tail functions (everything is reachable), soft gate trivially passes."""
    reachable = ["0x100", "0x101"]
    fi = _function_index(reachable, [])
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["soft_gate_pass"] is True
    assert state["tail_total"] == 0


def test_hard_gate_passes_when_reachable_set_empty():
    """If there are no reachable functions declared, hard gate trivially passes.
    (Pathological case: project_discovery missing or empty.)"""
    fi = _function_index([], ["0x100", "0x101"])
    manifest = _manifest([])
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True


def test_named_breakdown_includes_pass0_pass1_pass2_origins():
    reachable = ["0x100", "0x101", "0x102", "0x103"]
    fi = _function_index([], ["0x100", "0x101", "0x102", "0x103"])
    manifest = {
        "binary": {"stem": "t", "version_tag": "v1", "status": "partial"},
        "project_discovery": {"reachable_user_defined": reachable},
        "passes": [
            {"pass": "pass0", "proposed_renames": [
                {"addr": "0x100", "to": "P0name", "confidence": "high",
                 "source": "iat_wrapper_detection"},
            ]},
            {"pass": "pass1", "proposed_renames": [
                {"addr": "0x101", "to": "P1name", "confidence": "high",
                 "source": "llm_rename"},
                {"addr": "0x102", "to": "P1name2", "confidence": "medium",
                 "source": "llm_rename"},
            ]},
            {"pass": "pass2", "retypes": [
                {"addr": "0x103",
                 "params": [{"index": 0, "to": "DWORD",
                             "confidence": "high", "rationale": "..."}],
                 "locals": []},
            ]},
        ],
    }
    state = gates.compute_gate_state(fi, manifest)
    breakdown = state["named"]
    assert breakdown["from_pass0"] == 1
    assert breakdown["from_pass1"] == 2
    # Pass 2 contributes types not names, so it does NOT increment named-count.
    # But 0x103 has no rename anywhere, so hard gate must fail.
    assert state["hard_gate_pass"] is False
    assert breakdown["reachable"] == 3


def test_compute_gate_state_handles_missing_project_discovery():
    """If project_discovery is absent, treat reachable set as empty."""
    fi = _function_index([], [])
    manifest = {"binary": {"stem": "t"}, "passes": []}
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True   # vacuously
    assert state["reachable_total"] == 0


def test_status_recommendation_complete_when_both_gates_pass():
    """When both gates pass, the state['recommended_status'] is 'complete'."""
    reachable = ["0x100"]
    fi = _function_index(reachable, [])
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["recommended_status"] == "complete"


def test_status_recommendation_partial_when_only_hard_passes():
    reachable = ["0x100"]
    tail_named = [f"0x{i:03x}" for i in range(0x200, 0x205)]    # 5 named
    tail_unnamed = [f"0x{i:03x}" for i in range(0x300, 0x305)]  # 5 unnamed
    # 5/10 = 50% — soft gate fails
    fi = _function_index(reachable + tail_named, tail_unnamed)
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True
    assert state["soft_gate_pass"] is False
    assert state["recommended_status"] == "partial"


def test_status_recommendation_partial_when_hard_fails():
    """Hard gate failure also yields 'partial' status, not 'failed'."""
    reachable = ["0x100"]
    fi = _function_index([], ["0x100"])
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is False
    assert state["recommended_status"] == "partial"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_reconstruct_gates.py -v
```

Expected: 13 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/reconstruct_gates.py`** with EXACT content:

```python
"""Reachability + naming gate computation for reconstruct phase.

Reads `function_index.json` and a reconstruct `manifest.json` and computes:
- hard_gate_pass: 100% of `project_discovery.reachable_user_defined` are named
- soft_gate_pass: >=80% of remaining user-defined (the "tail") are named
- recommended_status: "complete" iff both pass, else "partial"

"Named" predicate (matches spec §1.5):
- Function's own name is not `FUN_<hex>` / `sub_<hex>`, OR
- There exists a `proposed_renames` entry for the function whose:
  - source is one of the LLM sources (`llm_rename`, `llm_retype`, etc.), regardless of confidence, OR
  - source is a deterministic Pass 0 source AND confidence is `medium` or `high`.

Low-confidence Pass 0 string-xref renames are intentionally NOT counted.
"""
from __future__ import annotations

import re
from typing import Iterable

_FUN_RE = re.compile(r"^(FUN_|sub_)[0-9a-fA-F]+$")
_LLM_SOURCES = {"llm_rename", "llm_retype", "llm_structify", "llm_comment"}


def _is_unnamed(name: str) -> bool:
    return bool(_FUN_RE.match(name or ""))


def _rename_counts(manifest: dict) -> dict[str, dict]:
    """Return a dict keyed by addr containing the highest-priority rename for
    that address (across all passes). Priority:
        - LLM source at any confidence beats Pass 0 deterministic
        - Higher confidence beats lower
    """
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[str, dict] = {}
    pass_origin: dict[str, str] = {}
    for p in manifest.get("passes", []):
        which = p.get("pass", "")
        for rec in p.get("proposed_renames", []) or []:
            addr = rec.get("addr")
            if not addr:
                continue
            cur = best.get(addr)
            if cur is None:
                best[addr] = rec
                pass_origin[addr] = which
                continue
            # New rec wins if: LLM source over deterministic, or higher confidence
            cur_llm = cur.get("source") in _LLM_SOURCES
            new_llm = rec.get("source") in _LLM_SOURCES
            if new_llm and not cur_llm:
                best[addr] = rec
                pass_origin[addr] = which
                continue
            if cur_llm and not new_llm:
                continue
            # Tie on source class -> compare confidence
            if confidence_rank.get(rec.get("confidence"), 0) > confidence_rank.get(cur.get("confidence"), 0):
                best[addr] = rec
                pass_origin[addr] = which
    return {addr: {"rec": rec, "pass": pass_origin[addr]} for addr, rec in best.items()}


def _rename_counts_as_named(rename_rec: dict) -> bool:
    """Apply the spec §1.5 predicate to a single rename record."""
    if not rename_rec:
        return False
    source = rename_rec.get("source", "")
    confidence = rename_rec.get("confidence", "")
    if source in _LLM_SOURCES:
        # Any LLM rename counts regardless of confidence.
        return True
    # Deterministic Pass 0 source must be medium or high confidence to count.
    return confidence in ("medium", "high")


def _user_defined(function_index: dict) -> list[dict]:
    return [
        r for r in function_index.get("functions", [])
        if not r.get("is_external") and not r.get("is_thunk")
    ]


def compute_gate_state(function_index: dict, manifest: dict) -> dict:
    """Return a dict with hard/soft gate verdicts + named breakdown.

    Schema:
        {
          "hard_gate_pass": bool,
          "soft_gate_pass": bool,
          "recommended_status": "complete" | "partial",
          "reachable_total": int,
          "tail_total": int,
          "named": {
            "reachable": int,
            "tail": int,
            "from_pass0": int,
            "from_pass1": int,
            "from_pass2": int,
            "from_pass3": int,
          }
        }
    """
    user_defined = _user_defined(function_index)
    by_addr = {r["address"]: r for r in user_defined}

    pd = manifest.get("project_discovery") or {}
    reachable_set = set(pd.get("reachable_user_defined") or [])
    # Filter reachable to addresses that ARE user-defined functions in this index.
    reachable_set = {a for a in reachable_set if a in by_addr}

    renames = _rename_counts(manifest)

    def is_named(addr: str) -> tuple[bool, str | None]:
        rec = by_addr.get(addr)
        if rec is None:
            return False, None
        rename_info = renames.get(addr)
        if rename_info and _rename_counts_as_named(rename_info["rec"]):
            return True, rename_info["pass"]
        if rec.get("name") and not _is_unnamed(rec["name"]):
            return True, None   # Originally named by Ghidra (no rename pass attributed)
        return False, None

    reachable_named = 0
    tail_named = 0
    tail_total = 0
    from_pass: dict[str, int] = {}
    all_named: set[str] = set()
    for rec in user_defined:
        addr = rec["address"]
        named, origin = is_named(addr)
        if named:
            all_named.add(addr)
            if origin:
                from_pass[origin] = from_pass.get(origin, 0) + 1
        if addr in reachable_set:
            if named:
                reachable_named += 1
        else:
            tail_total += 1
            if named:
                tail_named += 1

    reachable_total = len(reachable_set)
    hard_pass = reachable_total == 0 or reachable_named == reachable_total
    soft_pass = tail_total == 0 or (tail_named / tail_total) >= 0.80

    recommended_status = "complete" if (hard_pass and soft_pass) else "partial"

    return {
        "hard_gate_pass": hard_pass,
        "soft_gate_pass": soft_pass,
        "recommended_status": recommended_status,
        "reachable_total": reachable_total,
        "tail_total": tail_total,
        "named": {
            "reachable": reachable_named,
            "tail": tail_named,
            "from_pass0": from_pass.get("pass0", 0),
            "from_pass1": from_pass.get("pass1", 0),
            "from_pass2": from_pass.get("pass2", 0),
            "from_pass3": from_pass.get("pass3", 0),
        },
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_reconstruct_gates.py -v
```

Expected: 13 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconstruct_gates.py tests/reconstruct/test_reconstruct_gates.py
git commit -m "feat(reconstruct): hard/soft gate computation library"
```

---

## Task 2: Wire `compute_gate_state` into `reconstruct.py` (Pass 0)

Replace the hardcoded `False` in `_compute_coverage`. Also promote status to `complete` when both gates pass.

**Files:**
- Modify: `scripts/reconstruct.py`
- Test: `tests/reconstruct/test_reconstruct_orchestrator.py` (append)

- [ ] **Step 1: Append test**

Append to `tests/reconstruct/test_reconstruct_orchestrator.py`:

```python
def test_orchestrator_promotes_status_to_complete_when_gates_pass(tmp_path):
    """If a binary has all-reachable functions originally named (no FUN_*
    survivors and no tail), Pass 0 should compute hard_gate_pass=True,
    soft_gate_pass=True, and flip status to 'complete'.
    """
    eng = tmp_path / "engagements" / "complete-eng"
    eng.mkdir(parents=True)
    (eng / "scope.json").write_text(json.dumps({"binary": "fullyNamed", "target_type": "binary"}))
    (eng / "decomp").mkdir()
    # Build a function_index with everything user-defined already named (no FUN_*).
    fi = {
        "binary": "fullyNamed.exe",
        "arch": "x86_64",
        "format": "PE",
        "functions": [
            {"address": "0x140001000", "name": "entry",
             "callees": ["0x140002000"], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": True,
             "code_hash": "h1", "instruction_count": 10, "size": 32, "strings": []},
            {"address": "0x140002000", "name": "DoWork",
             "callees": [], "callers": ["0x140001000"],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h2", "instruction_count": 20, "size": 64, "strings": []},
        ],
    }
    (eng / "decomp" / "function_index.json").write_text(json.dumps(fi))

    (tmp_path / "catalog" / "binaries").mkdir(parents=True)
    (tmp_path / "catalog" / "binaries" / "fullyNamed.yml").write_text(yaml.safe_dump({
        "binary": "fullyNamed", "product": "x",
    }))

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", "fullyNamed", "--version", "vfull"],
        env=env, check=True, capture_output=True, text=True,
    )
    r = subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", "complete-eng",
         "--binary", "fullyNamed", "--version", "vfull"],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr

    # coverage gates should reflect the fully-named state.
    cov = json.loads(
        (tmp_path / "catalog" / "reconstructed" / "fullyNamed_vfull" / "coverage.json").read_text()
    )
    assert cov["hard_gate_pass"] is True
    assert cov["soft_gate_pass"] is True

    # binary YAML status should be 'complete'.
    yml = yaml.safe_load(
        (tmp_path / "catalog" / "binaries" / "fullyNamed.yml").read_text()
    )
    assert yml["reconstruction"]["status"] == "complete"
```

- [ ] **Step 2: Modify `scripts/reconstruct.py` `_compute_coverage`**

Find the existing `_compute_coverage` function. Replace it entirely with:

```python
def _compute_coverage(function_index: dict, proposed_renames: list[dict]) -> dict:
    # Construct a minimal manifest that compute_gate_state can consume.
    fns = function_index.get("functions", [])
    user_defined = [r for r in fns if not r.get("is_external") and not r.get("is_thunk")]
    import re
    fun_re = re.compile(r"^FUN_[0-9a-fA-F]+$")

    # Renamed set (from proposed_renames argument — the Pass 0 result, plus any
    # already in the manifest if present).
    sys.path.insert(0, str(ROOT / "scripts"))
    import reconstruct_gates as gates  # type: ignore

    # Synthesize a manifest-like dict around the in-flight Pass 0 result so
    # gate state can be computed without re-reading manifest.json.
    synthetic_manifest = {
        "passes": [{"pass": "pass0", "proposed_renames": proposed_renames}],
        "project_discovery": {
            "reachable_user_defined":
                # Best-effort reachability from exports — same logic as
                # reconstruct_pass0_discovery.extract.
                _reachable_from_exports(fns),
        },
    }
    gate_state = gates.compute_gate_state(function_index, synthetic_manifest)

    renamed_addrs = {_normalize_addr(r["addr"]) for r in proposed_renames}
    named_total = sum(
        1 for r in user_defined
        if not fun_re.match(r.get("name", "")) or _normalize_addr(r["address"]) in renamed_addrs
    )
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
            "from_pass0": len(renamed_addrs),
        },
        "low_confidence_named_addresses": [
            r["addr"] for r in proposed_renames if r.get("confidence") == "low"
        ],
    }


def _reachable_from_exports(records: list[dict]) -> list[str]:
    """Lightweight reachability walk used internally by _compute_coverage.
    Mirrors reconstruct_pass0_discovery._reachable_user_defined."""
    by_addr = {r["address"]: r for r in records}
    user_defined = [
        r for r in records
        if not r.get("is_external") and not r.get("is_thunk")
    ]
    roots = [r["address"] for r in user_defined if r.get("is_exported")]
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        addr = stack.pop()
        if addr in seen:
            continue
        rec = by_addr.get(addr)
        if rec is None or rec.get("is_external") or rec.get("is_thunk"):
            continue
        seen.add(addr)
        for callee in rec.get("callees", []) or []:
            if callee not in seen:
                stack.append(callee)
    return sorted(seen)
```

- [ ] **Step 3: Update `main()` to flip status based on gate state**

Find the line in `reconstruct.py`'s `main()` that says `_set_status(binary_yaml, "partial")` AFTER manifest + coverage writes. Replace with:

```python
        _set_status(binary_yaml, coverage.get("recommended_status", "partial"))
```

(The `coverage` variable is the dict returned by `_compute_coverage`, written to `coverage.json` immediately above.)

- [ ] **Step 4: Run all reconstruct tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: All existing tests still pass + the new `test_orchestrator_promotes_status_to_complete_when_gates_pass` passes. Count: 138 (137 prior + 1 new).

- [ ] **Step 5: Commit**

```bash
git add scripts/reconstruct.py tests/reconstruct/test_reconstruct_orchestrator.py
git commit -m "feat(reconstruct): wire reachability gates into Pass 0 orchestrator"
```

---

## Task 3: Wire `compute_gate_state` into Pass 1 + Pass 2 apply scripts

Both apply scripts have their own `recompute_coverage` function that hardcodes `hard_gate_pass: False, soft_gate_pass: False`. Replace with calls into `compute_gate_state`.

**Files:**
- Modify: `scripts/reconstruct_pass1_apply.py`
- Modify: `scripts/reconstruct_pass2_apply.py`
- Test: `tests/reconstruct/test_pass1_apply.py` (append) + `test_pass2_apply.py` (append)

- [ ] **Step 1: Append tests**

Append to `tests/reconstruct/test_pass1_apply.py`:

```python
def test_pass1_apply_recompute_coverage_uses_real_gates():
    """When pass1 renames cover all reachable functions, gates should flip true."""
    # Build a manifest with project_discovery declaring reachability, and
    # function_index where every reachable addr is named via pass1.
    fi = {
        "binary": "t.exe",
        "functions": [
            {"address": "0x100", "name": "FUN_100",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h",
             "instruction_count": 10, "size": 32, "strings": []},
            {"address": "0x101", "name": "entry",
             "callees": ["0x100"], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": True, "code_hash": "h",
             "instruction_count": 10, "size": 32, "strings": []},
        ],
    }
    manifest = {
        "binary": {"stem": "t", "version_tag": "v1", "status": "partial"},
        "project_discovery": {"reachable_user_defined": ["0x100", "0x101"]},
        "passes": [
            {"pass": "pass1", "proposed_renames": [
                {"addr": "0x100", "to": "Wrapped", "confidence": "high",
                 "source": "llm_rename", "from": "FUN_100", "rationale": "..."}
            ]},
        ],
    }
    cov = apply_mod.recompute_coverage(fi, manifest)
    assert cov["hard_gate_pass"] is True
    assert cov["soft_gate_pass"] is True
```

Append to `tests/reconstruct/test_pass2_apply.py`:

```python
def test_pass2_apply_recompute_coverage_uses_real_gates():
    """Pass 2 doesn't add new names; gates reflect Pass 0/1 state."""
    fi = {
        "binary": "t.exe",
        "functions": [
            {"address": "0x100", "name": "RenamedByPass1",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h",
             "instruction_count": 10, "size": 32, "strings": []},
            {"address": "0x101", "name": "entry",
             "callees": ["0x100"], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": True, "code_hash": "h",
             "instruction_count": 10, "size": 32, "strings": []},
        ],
    }
    manifest = {
        "binary": {"stem": "t", "version_tag": "v1", "status": "partial"},
        "project_discovery": {"reachable_user_defined": ["0x100", "0x101"]},
        "passes": [
            {"pass": "pass1", "proposed_renames": [
                {"addr": "0x100", "to": "RenamedByPass1", "confidence": "high",
                 "source": "llm_rename", "from": "FUN_100", "rationale": "..."}
            ]},
            {"pass": "pass2", "retypes": [
                {"addr": "0x100", "params": [
                    {"index": 0, "to": "DWORD", "confidence": "high",
                     "rationale": "...", "source": "llm_retype", "from": ""}
                ], "locals": []}
            ]},
        ],
    }
    cov = apply_mod.recompute_coverage(fi, manifest)
    assert cov["hard_gate_pass"] is True
    assert cov["soft_gate_pass"] is True
```

- [ ] **Step 2: Modify `scripts/reconstruct_pass1_apply.py` `recompute_coverage`**

Find the existing `recompute_coverage` function. Replace its `return` block to delegate gate computation to `reconstruct_gates`. The new function:

```python
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
```

The change is: import `reconstruct_gates`, replace `"hard_gate_pass": False, "soft_gate_pass": False` with the computed values + add `recommended_status`.

- [ ] **Step 3: Modify `scripts/reconstruct_pass2_apply.py` `recompute_coverage`**

Same pattern. The existing pass2 `recompute_coverage` already produces a `typed` block; the only change is to replace the hardcoded `False` values with calls into `compute_gate_state`.

Find the existing function and update its return value to include real gate values:

```python
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
```

Add the import at the top of the function:

```python
def recompute_coverage(function_index: dict, manifest: dict) -> dict:
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "scripts"))
    import reconstruct_gates as gates  # type: ignore
    # ... existing body computing from_pass0, from_pass1, typed_addrs, from_pass2, named_total ...
```

- [ ] **Step 4: Update apply CLI to flip status based on gate state**

In `scripts/reconstruct_pass1_apply.py` `main()`, find where coverage is written and add a status update afterwards:

```python
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
```

Apply the SAME status-update logic to `scripts/reconstruct_pass2_apply.py` `main()`.

- [ ] **Step 5: Run all reconstruct tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: 140 PASSED (138 prior + 2 new). Some existing tests may need adjustment if they asserted `hard_gate_pass: False` — if any FAIL, read the failure and check whether the test fixture happens to satisfy the gates (in which case the test assertion needs updating).

Specifically, the foundation smoke test (`test_pass0_smoke_flips_post_gates`) and the Pass 1 smoke test that expected `hard_gate_pass: False` might now legitimately produce `True` if the fixture's reachable set is small enough. **Examine each failure and update the test fixture or assertion to reflect the new semantics.**

For tests that need adjustment:
- If the fixture's `function_index` has all reachable functions originally named (no FUN_*), the test should now assert `hard_gate_pass: True`. Update the assertion.
- If the test wants to keep asserting `False`, add an unnamed reachable function to the fixture.

- [ ] **Step 6: Commit**

```bash
git add scripts/reconstruct_pass1_apply.py scripts/reconstruct_pass2_apply.py tests/reconstruct/test_pass1_apply.py tests/reconstruct/test_pass2_apply.py
git commit -m "feat(reconstruct): wire reachability gates into pass1+pass2 apply"
```

---

## Task 4: Document gate semantics in CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Find an anchor**

```bash
grep -n "### Pass 2 — LLM retype" CLAUDE.md
grep -n "^## " CLAUDE.md
```

Identify the next `^## ` heading after the Pass 2 sub-section. Insert the new sub-section content before it.

- [ ] **Step 2: Insert the new sub-section** using Edit

Content to prepend before the next `^## ` heading:

````markdown

### Reachability gates

`coverage.json` carries two gate verdicts derived from `manifest.json#project_discovery.reachable_user_defined` × the union of all-pass `proposed_renames`:

- **`hard_gate_pass`** — 100% of entrypoint-reachable user-defined functions are named (either originally semantic-named in Ghidra, or renamed by Pass 0 at confidence ≥ medium, or renamed by any LLM pass at any confidence).
- **`soft_gate_pass`** — ≥80% of the **tail** (user-defined functions NOT in the reachable set) are named by the same predicate.
- **`recommended_status`** — `"complete"` iff both gates pass, else `"partial"`.

The Pass 0 orchestrator (`reconstruct.py`) and the Pass 1/2 apply scripts both call `scripts/reconstruct_gates.py:compute_gate_state` to derive these values. After each apply, the binary YAML's `reconstruction.status` is updated to match `recommended_status`. A reconstruction becomes `complete` when both gates pass; otherwise it stays `partial` and the strategist can decide whether to run more passes or accept the current state.

**Predicate details:** Pass 0 deterministic low-confidence renames (e.g., from `string_xref` heuristics) do NOT count toward gate satisfaction — they're noisy. LLM renames count at any confidence level because the LLM's signal is more reliable than a regex on a single string xref. See `prompts/phases/reconstruct.md` for the full spec.

````

- [ ] **Step 3: Verify**

```bash
grep -c "### Reachability gates" CLAUDE.md
```

Expected: `1`.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document reachability gate semantics"
```

---

## Done — Reachability gate acceptance

When all 4 tasks above are complete:

- [ ] `pytest tests/reconstruct/ -v` reports all tests PASSED (~141 total: 137 from prior sub-plans + 4 new for this plan, modulo any fixture adjustments)
- [ ] `coverage.json#hard_gate_pass` and `#soft_gate_pass` reflect real reachability + naming math after Pass 0 / Pass 1 apply / Pass 2 apply
- [ ] `catalog/binaries/<stem>.yml#reconstruction.status` flips to `complete` when both gates pass
- [ ] CLAUDE.md documents the gate semantics
- [ ] `scripts/reconstruct_gates.py` is the single source of truth for the predicate; both Pass 0 and apply scripts delegate to it

**Next sub-plan candidates:**

- **Sub-plan 3.6 — Pass 3a structify + Pass 3b commenting + Pass 3c global naming + Pass 4 cleanup** — remaining LLM passes plus deterministic globals + cleanup retry.
- **Sub-plan 2.5 — Pass 0 expansion** — Rich header / string-xref / IOCTL+NTSTATUS equates.
- **Sub-plan 2-libghidra** — LibGhidra integration. Heaviest; needs real Ghidra install.
- **Comprehend phase** — per-binary ELI5 + product architecture_narrative (separate spec).
- **Acceptance test** — end-to-end against `bdservicehost.exe` real binary.
