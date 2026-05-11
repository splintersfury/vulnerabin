# Reconstruct Phase — Foundation (Sub-Plan 1/5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the scaffolding for the `reconstruct` pipeline phase: phase declaration in `pipeline.yml`, FSM gate stubs that return safe defaults, journal-allowed phase name, vendor pinning skeleton, `libghidra_connect` client primitives, `pcode_hash` library, and `vb-add reconstruction` subcommand. After this plan, the FSM recognizes `reconstruct` as a valid phase node, `vb-add reconstruction <binary> <version>` creates the catalog dir scaffold + writes a `reconstruction:` block into the binary YAML, and all four gate IDs are wired into `fsm.py` (returning sensible "not yet implemented" evidence). No LLM passes yet, no actual reconstruction yet — that lands in sub-plans 2 and 3.

**Architecture:** All changes are TDD-style: write a pytest test (`tests/reconstruct/test_*.py`), run it to see it fail, implement the minimum code to make it pass, run to confirm, commit. The foundation produces standalone-testable infrastructure that downstream sub-plans extend rather than replace. Scripts under `scripts/`, vendor skeleton under `vendor/`, tests under `tests/reconstruct/`.

**Tech Stack:** Python 3.11, pytest, PyYAML, stdlib `fcntl` for `flock`, stdlib `hashlib` for SHA-256, stdlib `urllib` for HTTP healthz, bash for `vendor/bootstrap.sh`.

---

## File Structure

**Create:**
- `scripts/libghidra_connect.py` — healthz HTTP probe, file-lock acquire/release via `fcntl.flock`, version-pin enforcement
- `scripts/pcode_hash.py` — deterministic structural hash of a function record (stub-quality; real PCode-aware impl deferred to Pass 0 sub-plan)
- `vendor/libghidra.version` — text: URL + commit SHA + sha256 checksum (3 lines)
- `vendor/ghidrasql_skills.version` — same shape
- `vendor/fid_db_versions.json` — JSON dict mapping FID DB name → version + checksum
- `vendor/bootstrap.sh` — bash script with `--check` mode (install mode deferred to Pass 0 sub-plan)
- `vendor/README.md` — explains the vendoring strategy
- `tests/reconstruct/__init__.py`
- `tests/reconstruct/test_libghidra_connect.py`
- `tests/reconstruct/test_pcode_hash.py`
- `tests/reconstruct/test_vb_add_reconstruction.py`
- `tests/reconstruct/test_fsm_reconstruct_phase.py`
- `tests/reconstruct/test_vendor_bootstrap.py`

**Modify:**
- `pipeline.yml` — append `reconstruct` phase block with gates and per-binary-kind reachability roots
- `scripts/fsm.py` — extend `gate_status()` with branches for `libghidra_alive`, `no_concurrent_writer`, `reachable_named_100pct`, `tail_named_80pct`
- `scripts/journal.py` — add `"reconstruct"` to `PHASES` set
- `scripts/catalog_add.py` — add `cmd_reconstruction` subcommand + register on argparse

---

## Task 1: Declare `reconstruct` phase in `pipeline.yml`

**Files:**
- Modify: `pipeline.yml` (append after the `preparation` phase block)

- [ ] **Step 1: Write the failing test**

Create `tests/reconstruct/__init__.py` (empty) and `tests/reconstruct/test_fsm_reconstruct_phase.py`:

```python
"""Tests for the reconstruct phase node in pipeline.yml."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from route_model import _load_yaml  # type: ignore


def test_pipeline_yml_declares_reconstruct_phase():
    cfg = _load_yaml(REPO_ROOT / "pipeline.yml")
    phases = cfg.get("phases", {})
    assert "reconstruct" in phases, "pipeline.yml must declare a 'reconstruct' phase"


def test_reconstruct_phase_sits_between_preparation_and_walk():
    cfg = _load_yaml(REPO_ROOT / "pipeline.yml")
    phases = cfg.get("phases", {})
    prep_next = phases["preparation"].get("next", [])
    assert "reconstruct" in prep_next, "preparation.next must include reconstruct"
    recon_next = phases["reconstruct"].get("next", [])
    assert "walk" in recon_next, "reconstruct.next must include walk"


def test_reconstruct_phase_has_all_four_gates():
    cfg = _load_yaml(REPO_ROOT / "pipeline.yml")
    gates = cfg["phases"]["reconstruct"].get("gates", [])
    gate_ids = {g["id"] for g in gates}
    assert gate_ids == {
        "libghidra_alive",
        "no_concurrent_writer",
        "reachable_named_100pct",
        "tail_named_80pct",
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mkdir -p tests/reconstruct
# Create the __init__.py and test file as above, then:
pytest tests/reconstruct/test_fsm_reconstruct_phase.py -v
```

Expected: 3 FAILED with `KeyError: 'reconstruct'` or `AssertionError`.

- [ ] **Step 3: Modify `pipeline.yml`**

Add the `reconstruct` phase block. Locate the `preparation` phase block (around line 30); update its `next` from `[walk, junction_hunt]` to `[reconstruct, junction_hunt]`, then insert the new block immediately after `preparation`:

```yaml
  reconstruct:
    prompt: prompts/phases/reconstruct.md
    requires_artifacts_any: [decomp/, extracted/, firmware/]
    produces_artifacts: []
    gates:
      - id: libghidra_alive
        kind: pre
        check: "LibGhidra API host responds to healthz probe"
        rationale: |
          Reconstruct phase cannot run without LibGhidra. healthz must
          pass before any pass dispatches.
      - id: no_concurrent_writer
        kind: pre
        check: "No other process holds the .lock in catalog/reconstructed/<stem>_<tag>/"
        rationale: |
          The Ghidra project is single-writer. MCP attached to the same
          project would cause corruption; refuse to start if so.
      - id: reachable_named_100pct
        kind: post
        check: "coverage.json#reachable_hard_gate_pass == true"
        rationale: |
          Every entrypoint-reachable user-defined function must be named
          and typed for downstream walk/triage to operate reliably.
      - id: tail_named_80pct
        kind: post
        check: "coverage.json#tail_soft_gate_pass == true (>=80% of non-reachable user-defined functions named)"
        rationale: |
          Soft gate: warns but does not block. Below threshold, downstream
          analysis still proceeds with degraded mental model.
    next: [walk]

  # Per-binary-kind reachability roots used by Pass 0 to compute the
  # transitive closure that the reachable_named_100pct gate keys on.
  reconstruct_reachability_roots:
    windows_sys:
      - DriverEntry
      - "IRP_MJ_*"           # registered in DriverObject->MajorFunction[]
      - ioctl_dispatch_arms  # reached from IRP_MJ_DEVICE_CONTROL handler
    windows_exe:
      - pe_entrypoint
      - "*"                  # every export
      - thread_function_args # CreateThread/RtlCreateUserThread targets
      - ipc_server_entrypoints
    windows_dll:
      - DllMain
      - "*"                  # every export
      - callback_registrations
    linux_elf_exec:
      - main
      - dynsym_entries
      - init_array_entries
    linux_elf_so:
      - dynsym_entries
      - init_array_entries
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/reconstruct/test_fsm_reconstruct_phase.py -v
```

Expected: 3 PASSED.

- [ ] **Step 5: Commit**

```bash
git add pipeline.yml tests/reconstruct/__init__.py tests/reconstruct/test_fsm_reconstruct_phase.py
git commit -m "feat(pipeline): declare reconstruct phase with gates and reachability roots"
```

---

## Task 2: Allow `reconstruct` as a journal phase

**Files:**
- Modify: `scripts/journal.py:48-49`
- Test: `tests/reconstruct/test_fsm_reconstruct_phase.py`

- [ ] **Step 1: Add the failing test**

Append to `tests/reconstruct/test_fsm_reconstruct_phase.py`:

```python
def test_journal_allows_reconstruct_phase():
    import journal  # type: ignore
    assert "reconstruct" in journal.PHASES
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/reconstruct/test_fsm_reconstruct_phase.py::test_journal_allows_reconstruct_phase -v
```

Expected: FAILED — `"reconstruct" not in journal.PHASES`.

- [ ] **Step 3: Modify `scripts/journal.py`**

Locate line 48 in `scripts/journal.py`:

```python
PHASES = {"acquisition", "preparation", "triage", "deep", "validation",
          "exec", "report", "kb", "meta"}
```

Replace with:

```python
PHASES = {"acquisition", "preparation", "reconstruct", "triage", "deep",
          "validation", "exec", "report", "kb", "meta"}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/reconstruct/test_fsm_reconstruct_phase.py::test_journal_allows_reconstruct_phase -v
```

Expected: PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/journal.py tests/reconstruct/test_fsm_reconstruct_phase.py
git commit -m "feat(journal): allow reconstruct phase in journal events"
```

---

## Task 3: Stub `libghidra_alive` gate in `fsm.py`

The reconstruct phase declares the gate; `fsm.py` must produce evidence when asked. For foundation, the check returns `False` with explicit "endpoint not configured" evidence — sub-plan 3 wires it to a real LibGhidra port.

**Files:**
- Modify: `scripts/fsm.py` (`gate_status` function, around the existing `elif gid == ...` chain)
- Test: `tests/reconstruct/test_fsm_reconstruct_phase.py`

- [ ] **Step 1: Add the failing test**

Append to `tests/reconstruct/test_fsm_reconstruct_phase.py`:

```python
import subprocess


def test_fsm_libghidra_alive_gate_returns_evidence(tmp_path):
    """The libghidra_alive gate must run when reconstruct is the current phase.

    For foundation: returns ok=False with evidence string mentioning libghidra.
    A real healthz probe is wired in sub-plan 3.
    """
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text('{"binary": "test", "target_type": "binary"}')
    (eng_dir / "target").mkdir()
    (eng_dir / "decomp").mkdir()
    (eng_dir / "decomp" / "function_index.json").write_text('{"functions": []}')

    # Drive fsm.py state with a custom engagement root via env.
    # The script computes ENG_ROOT from its own location, so we test the
    # gate_status function in-process instead.
    import sys
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore
    cfg = fsm.load_pipeline()
    phase_def = cfg["phases"]["reconstruct"]
    # Monkeypatch the ENG_ROOT so gate checks point at our fixture.
    orig = fsm.ENG_ROOT
    try:
        fsm.ENG_ROOT = tmp_path / "engagements"
        statuses = fsm.gate_status("fixture", eng_dir, "reconstruct", phase_def)
    finally:
        fsm.ENG_ROOT = orig

    gate_ids = {s["id"] for s in statuses}
    assert "libghidra_alive" in gate_ids
    libg = next(s for s in statuses if s["id"] == "libghidra_alive")
    assert libg["ok"] is False
    assert "libghidra" in libg["evidence"].lower() or "endpoint" in libg["evidence"].lower()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/reconstruct/test_fsm_reconstruct_phase.py::test_fsm_libghidra_alive_gate_returns_evidence -v
```

Expected: FAILED — gate is recognized but `evidence == "unknown gate id — manual check required"`.

- [ ] **Step 3: Add the gate branch to `scripts/fsm.py`**

Find the `gate_status` function (around line 130). Inside the loop over `phase_def.get("gates", [])`, locate the final `else:` branch (currently `evidence = "unknown gate id — manual check required"`). Add new `elif` branches just before that `else`:

```python
        elif gid == "libghidra_alive":
            # Foundation: stub. Real healthz probe wired in sub-plan 3.
            # Reads LIBGHIDRA_HEALTHZ_URL env var; if unset, gate fails with
            # explicit evidence so operator knows to configure it.
            import os
            url = os.environ.get("LIBGHIDRA_HEALTHZ_URL", "")
            if not url:
                ok = False
                evidence = "LIBGHIDRA_HEALTHZ_URL not set; libghidra endpoint not configured"
            else:
                # Probe deferred to sub-plan 3 — for now treat as configured-but-unverified.
                ok = False
                evidence = f"libghidra endpoint configured at {url} but probe not yet implemented"
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/reconstruct/test_fsm_reconstruct_phase.py::test_fsm_libghidra_alive_gate_returns_evidence -v
```

Expected: PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/fsm.py tests/reconstruct/test_fsm_reconstruct_phase.py
git commit -m "feat(fsm): stub libghidra_alive gate with env-var endpoint check"
```

---

## Task 4: Implement `no_concurrent_writer` gate in `fsm.py`

This gate looks for a `.lock` file under `catalog/reconstructed/<stem>_<tag>/.lock`. If present and `flock`-locked by another process, the gate fails. Reads the binary's `reconstruction.ref` from the catalog YAML.

**Files:**
- Modify: `scripts/fsm.py` (new gate branch in `gate_status`)
- Test: `tests/reconstruct/test_fsm_reconstruct_phase.py`

- [ ] **Step 1: Add the failing test**

Append to `tests/reconstruct/test_fsm_reconstruct_phase.py`:

```python
def test_no_concurrent_writer_gate_no_lock_passes(tmp_path, monkeypatch):
    """When no lock file exists, gate passes (nothing to conflict with)."""
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(
        '{"binary": "test_stem", "target_type": "binary"}'
    )
    (eng_dir / "decomp").mkdir()
    (eng_dir / "decomp" / "function_index.json").write_text('{"functions": []}')

    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(
        "reconstruction:\n  ref: catalog/reconstructed/test_stem_vfoundation\n"
        "  status: not_started\n"
    )
    (catalog / "reconstructed" / "test_stem_vfoundation").mkdir(parents=True)

    import sys
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)

    cfg = fsm.load_pipeline()
    phase_def = cfg["phases"]["reconstruct"]
    statuses = fsm.gate_status("fixture", eng_dir, "reconstruct", phase_def)

    g = next(s for s in statuses if s["id"] == "no_concurrent_writer")
    assert g["ok"] is True
    assert "no lock" in g["evidence"].lower() or "not held" in g["evidence"].lower()


def test_no_concurrent_writer_gate_held_lock_fails(tmp_path, monkeypatch):
    """When .lock exists AND is flock-held by another process, gate fails."""
    import fcntl

    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(
        '{"binary": "test_stem", "target_type": "binary"}'
    )
    (eng_dir / "decomp").mkdir()
    (eng_dir / "decomp" / "function_index.json").write_text('{"functions": []}')

    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(
        "reconstruction:\n  ref: catalog/reconstructed/test_stem_vfoundation\n"
        "  status: not_started\n"
    )
    recon_dir = catalog / "reconstructed" / "test_stem_vfoundation"
    recon_dir.mkdir(parents=True)
    lock_path = recon_dir / ".lock"
    lock_path.touch()

    # Acquire the lock in the test process; the gate should see it held.
    lf = open(lock_path, "w")
    fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        import sys
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import fsm  # type: ignore
        monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
        monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
        monkeypatch.setattr(fsm, "ROOT", tmp_path)

        cfg = fsm.load_pipeline()
        phase_def = cfg["phases"]["reconstruct"]
        statuses = fsm.gate_status("fixture", eng_dir, "reconstruct", phase_def)
        g = next(s for s in statuses if s["id"] == "no_concurrent_writer")
        assert g["ok"] is False
        assert "held" in g["evidence"].lower() or "locked" in g["evidence"].lower()
    finally:
        fcntl.flock(lf, fcntl.LOCK_UN)
        lf.close()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/reconstruct/test_fsm_reconstruct_phase.py -k no_concurrent -v
```

Expected: 2 FAILED — both with `"unknown gate id"` evidence.

- [ ] **Step 3: Add the gate branch to `scripts/fsm.py`**

In `gate_status`, just after the `libghidra_alive` branch added in Task 3, add:

```python
        elif gid == "no_concurrent_writer":
            import fcntl, json as _json
            try:
                import yaml as _y  # type: ignore
            except Exception as e:
                ok, evidence = False, f"PyYAML unavailable: {e}"
            else:
                scope = eng_dir / "scope.json"
                stem = ""
                if scope.is_file():
                    try:
                        stem = _json.loads(scope.read_text()).get("binary", "")
                    except Exception:
                        stem = ""
                if not stem:
                    ok, evidence = False, "scope.json#binary not set"
                else:
                    yml = CATALOG_BINARIES / f"{stem}.yml"
                    if not yml.is_file():
                        ok, evidence = True, f"no lock to check: catalog/binaries/{stem}.yml absent"
                    else:
                        try:
                            ydata = _y.safe_load(yml.read_text()) or {}
                        except Exception as e:
                            ok, evidence = False, f"parse error on {yml.name}: {e}"
                        else:
                            ref = (ydata.get("reconstruction") or {}).get("ref")
                            if not ref:
                                ok, evidence = True, "no reconstruction.ref set; no lock to check"
                            else:
                                lock_path = ROOT / ref / ".lock"
                                if not lock_path.is_file():
                                    ok, evidence = True, f"no lock file at {lock_path.relative_to(ROOT)}"
                                else:
                                    # Try to acquire non-blocking exclusive flock; release immediately.
                                    try:
                                        lf = open(lock_path, "w")
                                        try:
                                            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                            fcntl.flock(lf, fcntl.LOCK_UN)
                                            ok, evidence = True, f"lock file present but not held: {lock_path.name}"
                                        except BlockingIOError:
                                            ok, evidence = False, f"lock held by another process on {lock_path.relative_to(ROOT)}"
                                        finally:
                                            lf.close()
                                    except Exception as e:
                                        ok, evidence = False, f"flock probe error: {e}"
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/reconstruct/test_fsm_reconstruct_phase.py -k no_concurrent -v
```

Expected: 2 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/fsm.py tests/reconstruct/test_fsm_reconstruct_phase.py
git commit -m "feat(fsm): implement no_concurrent_writer gate via flock probe"
```

---

## Task 5: Implement `reachable_named_100pct` and `tail_named_80pct` gates in `fsm.py`

Both gates read `catalog/reconstructed/<stem>_<tag>/coverage.json` and check the precomputed boolean flags.

**Files:**
- Modify: `scripts/fsm.py` (two new gate branches)
- Test: `tests/reconstruct/test_fsm_reconstruct_phase.py`

- [ ] **Step 1: Add the failing tests**

Append to `tests/reconstruct/test_fsm_reconstruct_phase.py`:

```python
def _make_coverage_fixture(tmp_path, monkeypatch, hard: bool, soft: bool):
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(
        '{"binary": "test_stem", "target_type": "binary"}'
    )
    (eng_dir / "decomp").mkdir()
    (eng_dir / "decomp" / "function_index.json").write_text('{"functions": []}')

    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(
        "reconstruction:\n  ref: catalog/reconstructed/test_stem_vfix\n"
        "  status: complete\n"
    )
    recon_dir = catalog / "reconstructed" / "test_stem_vfix"
    recon_dir.mkdir(parents=True)
    import json as _json
    (recon_dir / "coverage.json").write_text(_json.dumps({
        "hard_gate_pass": hard,
        "soft_gate_pass": soft,
        "reachable": {"function_count": 100, "named": 100 if hard else 90},
        "tail": {"function_count": 1000, "named": 850 if soft else 700},
    }))

    import sys
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)
    return fsm, eng_dir


def test_reachable_named_gate_passes_when_coverage_says_so(tmp_path, monkeypatch):
    fsm, eng_dir = _make_coverage_fixture(tmp_path, monkeypatch, hard=True, soft=True)
    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "fixture", eng_dir, "reconstruct", cfg["phases"]["reconstruct"]
    )
    g = next(s for s in statuses if s["id"] == "reachable_named_100pct")
    assert g["ok"] is True


def test_reachable_named_gate_fails_when_coverage_says_so(tmp_path, monkeypatch):
    fsm, eng_dir = _make_coverage_fixture(tmp_path, monkeypatch, hard=False, soft=True)
    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "fixture", eng_dir, "reconstruct", cfg["phases"]["reconstruct"]
    )
    g = next(s for s in statuses if s["id"] == "reachable_named_100pct")
    assert g["ok"] is False
    assert "90" in g["evidence"] or "100" in g["evidence"]


def test_tail_named_gate_reads_soft_gate_flag(tmp_path, monkeypatch):
    fsm, eng_dir = _make_coverage_fixture(tmp_path, monkeypatch, hard=True, soft=False)
    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "fixture", eng_dir, "reconstruct", cfg["phases"]["reconstruct"]
    )
    g = next(s for s in statuses if s["id"] == "tail_named_80pct")
    assert g["ok"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_fsm_reconstruct_phase.py -k "reachable_named or tail_named" -v
```

Expected: 3 FAILED — gates have `"unknown gate id"` evidence.

- [ ] **Step 3: Add the gate branches to `scripts/fsm.py`**

In `gate_status`, immediately after the `no_concurrent_writer` branch from Task 4, add:

```python
        elif gid in ("reachable_named_100pct", "tail_named_80pct"):
            import json as _json
            try:
                import yaml as _y  # type: ignore
            except Exception as e:
                ok, evidence = False, f"PyYAML unavailable: {e}"
            else:
                scope = eng_dir / "scope.json"
                stem = ""
                if scope.is_file():
                    try:
                        stem = _json.loads(scope.read_text()).get("binary", "")
                    except Exception:
                        stem = ""
                if not stem:
                    ok, evidence = False, "scope.json#binary not set"
                else:
                    yml = CATALOG_BINARIES / f"{stem}.yml"
                    if not yml.is_file():
                        ok, evidence = False, f"catalog/binaries/{stem}.yml missing"
                    else:
                        try:
                            ydata = _y.safe_load(yml.read_text()) or {}
                        except Exception as e:
                            ok, evidence = False, f"parse error on {yml.name}: {e}"
                        else:
                            ref = (ydata.get("reconstruction") or {}).get("ref")
                            if not ref:
                                ok, evidence = False, "no reconstruction.ref in binary YAML"
                            else:
                                cov_path = ROOT / ref / "coverage.json"
                                if not cov_path.is_file():
                                    ok, evidence = False, f"coverage.json missing at {cov_path.relative_to(ROOT)}"
                                else:
                                    try:
                                        cov = _json.loads(cov_path.read_text())
                                    except Exception as e:
                                        ok, evidence = False, f"parse error on coverage.json: {e}"
                                    else:
                                        if gid == "reachable_named_100pct":
                                            ok = bool(cov.get("hard_gate_pass"))
                                            r = cov.get("reachable", {})
                                            evidence = f"reachable named {r.get('named', '?')}/{r.get('function_count', '?')}"
                                        else:  # tail_named_80pct
                                            ok = bool(cov.get("soft_gate_pass"))
                                            t = cov.get("tail", {})
                                            evidence = f"tail named {t.get('named', '?')}/{t.get('function_count', '?')}"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_fsm_reconstruct_phase.py -k "reachable_named or tail_named" -v
```

Expected: 3 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/fsm.py tests/reconstruct/test_fsm_reconstruct_phase.py
git commit -m "feat(fsm): implement reachable_named_100pct + tail_named_80pct gates"
```

---

## Task 6: Vendor skeleton — version files and README

**Files:**
- Create: `vendor/libghidra.version`
- Create: `vendor/ghidrasql_skills.version`
- Create: `vendor/fid_db_versions.json`
- Create: `vendor/README.md`
- Test: `tests/reconstruct/test_vendor_bootstrap.py`

- [ ] **Step 1: Write the failing test**

Create `tests/reconstruct/test_vendor_bootstrap.py`:

```python
"""Tests for vendor pinning skeleton."""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VENDOR = REPO_ROOT / "vendor"


def test_libghidra_version_file_present_and_well_formed():
    p = VENDOR / "libghidra.version"
    assert p.is_file()
    lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.strip().startswith("#")]
    keys = {ln.split("=", 1)[0]: ln.split("=", 1)[1] for ln in lines if "=" in ln}
    assert "url" in keys, "libghidra.version must declare url"
    assert "commit" in keys, "libghidra.version must declare commit"
    assert "sha256" in keys, "libghidra.version must declare sha256"


def test_ghidrasql_skills_version_file_present_and_well_formed():
    p = VENDOR / "ghidrasql_skills.version"
    assert p.is_file()
    lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.strip().startswith("#")]
    keys = {ln.split("=", 1)[0]: ln.split("=", 1)[1] for ln in lines if "=" in ln}
    assert {"url", "commit", "sha256"} <= set(keys)


def test_fid_db_versions_json_is_well_formed():
    p = VENDOR / "fid_db_versions.json"
    assert p.is_file()
    data = json.loads(p.read_text())
    assert isinstance(data, dict)
    # At minimum, declare the two baseline DBs that the spec calls out.
    assert "msvc_crt_19" in data
    assert "winapi_thunks" in data
    for name, meta in data.items():
        assert "version" in meta
        assert "sha256" in meta


def test_vendor_readme_present():
    p = VENDOR / "README.md"
    assert p.is_file()
    text = p.read_text()
    assert "libghidra" in text.lower()
    assert "ghidrasql" in text.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_vendor_bootstrap.py -v
```

Expected: 4 FAILED — files missing.

- [ ] **Step 3: Create vendor files**

`vendor/libghidra.version`:

```
# LibGhidra Java extension pin.
# Update by running `vendor/bootstrap.sh --install` after editing this file.
url=https://github.com/0xeb/libghidra
commit=TO_BE_SET_DURING_FIRST_INSTALL
sha256=TO_BE_SET_DURING_FIRST_INSTALL
```

`vendor/ghidrasql_skills.version`:

```
# GhidraSQL skill set pin (cloned into .claude/skills/ghidrasql/).
url=https://github.com/0xeb/ghidrasql
commit=TO_BE_SET_DURING_FIRST_INSTALL
sha256=TO_BE_SET_DURING_FIRST_INSTALL
```

`vendor/fid_db_versions.json`:

```json
{
  "msvc_crt_19": {
    "version": "0.0.0",
    "sha256": "TO_BE_SET_DURING_FIRST_INSTALL",
    "source": "Built from MSVC 19.x .lib files; generation steps documented in fid_db/README.md (Pass 0 sub-plan)."
  },
  "winapi_thunks": {
    "version": "0.0.0",
    "sha256": "TO_BE_SET_DURING_FIRST_INSTALL",
    "source": "Generated from Windows SDK 10 import thunks; see fid_db/README.md."
  }
}
```

`vendor/README.md`:

```markdown
# vendor/ — Third-Party Pinning for the Reconstruct Phase

This directory pins external dependencies used by the `reconstruct` pipeline
phase. The reconstruct phase refuses to run if these pins are inconsistent
with what is actually installed on disk.

## Files

| File | Purpose |
|---|---|
| `libghidra.version` | URL + commit SHA + sha256 of the LibGhidra Java extension (0xeb/libghidra) |
| `ghidrasql_skills.version` | URL + commit SHA + sha256 of the GhidraSQL skill set (0xeb/ghidrasql) |
| `fid_db_versions.json` | Per-FID-DB version + checksum (Ghidra Function ID databases) |
| `bootstrap.sh` | `--check` verifies pins match installed; `--install` (Pass 0 sub-plan) installs from pinned commit |

## Workflow

- After cloning the repo: `vendor/bootstrap.sh --check` reports which
  dependencies are missing.
- Pass 0 sub-plan adds `vendor/bootstrap.sh --install` which downloads
  and builds LibGhidra from the pinned commit, clones the GhidraSQL skill
  set into `.claude/skills/ghidrasql/`, and generates the FID DBs.
- Bumping a pin: edit the relevant `.version` or `.json` file, rerun
  `vendor/bootstrap.sh --install`, run `pytest tests/reconstruct/` to
  ensure tests still pass, commit the updated pin + lockfile.

## Why not check in the binary blobs?

LibGhidra and the FID DBs are large (50-200 MB). Pinning by URL + commit
SHA + checksum keeps the repo light while preserving reproducibility.
A single bootstrap script makes the install a one-shot operation on any
clone.
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_vendor_bootstrap.py -v
```

Expected: 4 PASSED.

- [ ] **Step 5: Commit**

```bash
git add vendor/ tests/reconstruct/test_vendor_bootstrap.py
git commit -m "feat(vendor): skeleton for LibGhidra + GhidraSQL + FID DB pinning"
```

---

## Task 7: `vendor/bootstrap.sh --check` mode

**Files:**
- Create: `vendor/bootstrap.sh`
- Test: `tests/reconstruct/test_vendor_bootstrap.py` (append)

- [ ] **Step 1: Add the failing test**

Append to `tests/reconstruct/test_vendor_bootstrap.py`:

```python
import subprocess


def test_bootstrap_check_reports_missing_when_install_not_run():
    """--check exits non-zero and reports each missing dep when nothing is installed."""
    result = subprocess.run(
        ["bash", str(VENDOR / "bootstrap.sh"), "--check"],
        capture_output=True,
        text=True,
    )
    # When commit/sha are placeholders, --check should fail with clear evidence.
    assert result.returncode != 0
    out = result.stdout + result.stderr
    assert "libghidra" in out.lower()
    assert "ghidrasql" in out.lower()


def test_bootstrap_check_help_flag_works():
    result = subprocess.run(
        ["bash", str(VENDOR / "bootstrap.sh"), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--check" in result.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_vendor_bootstrap.py -k bootstrap_check -v
```

Expected: 2 FAILED — bootstrap.sh missing.

- [ ] **Step 3: Create `vendor/bootstrap.sh`**

```bash
#!/usr/bin/env bash
# vendor/bootstrap.sh — verify or install pinned reconstruct-phase dependencies.
#
# Usage:
#   vendor/bootstrap.sh --check    # verify installed deps match pinned versions
#   vendor/bootstrap.sh --install  # download + install per pins (Pass 0 sub-plan)
#   vendor/bootstrap.sh --help

set -euo pipefail

VENDOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$VENDOR_DIR/.." && pwd)"

usage() {
    cat <<EOF
vendor/bootstrap.sh — manage pinned reconstruct-phase dependencies.

Usage:
  $0 --check      Verify each pinned dep is present and matches its checksum.
  $0 --install    Download/build/install each dep from its pinned commit.
                  (Implemented in the Pass 0 sub-plan; --check only for now.)
  $0 --help       Show this message.

Pinned dependencies:
  vendor/libghidra.version          LibGhidra Java extension
  vendor/ghidrasql_skills.version   GhidraSQL skill set
  vendor/fid_db_versions.json       Ghidra Function ID databases
EOF
}

read_pin_value() {
    local file="$1" key="$2"
    grep -E "^${key}=" "$file" 2>/dev/null | head -n1 | cut -d= -f2- || true
}

check_libghidra() {
    local f="$VENDOR_DIR/libghidra.version"
    local commit sha
    commit=$(read_pin_value "$f" commit)
    sha=$(read_pin_value "$f" sha256)
    if [[ "$commit" == "TO_BE_SET_DURING_FIRST_INSTALL" || "$sha" == "TO_BE_SET_DURING_FIRST_INSTALL" ]]; then
        echo "MISSING: libghidra pin is placeholder; run --install after the Pass 0 sub-plan ships."
        return 1
    fi
    if [[ ! -d "$REPO_ROOT/vendor/libghidra-build" ]]; then
        echo "MISSING: libghidra not installed (vendor/libghidra-build/ absent)."
        return 1
    fi
    echo "OK: libghidra pin=$commit"
    return 0
}

check_ghidrasql() {
    local f="$VENDOR_DIR/ghidrasql_skills.version"
    local commit sha
    commit=$(read_pin_value "$f" commit)
    sha=$(read_pin_value "$f" sha256)
    if [[ "$commit" == "TO_BE_SET_DURING_FIRST_INSTALL" || "$sha" == "TO_BE_SET_DURING_FIRST_INSTALL" ]]; then
        echo "MISSING: ghidrasql_skills pin is placeholder; run --install after the Pass 0 sub-plan ships."
        return 1
    fi
    if [[ ! -d "$REPO_ROOT/.claude/skills/ghidrasql" ]]; then
        echo "MISSING: ghidrasql skills not installed at .claude/skills/ghidrasql/."
        return 1
    fi
    echo "OK: ghidrasql pin=$commit"
    return 0
}

check_fid_dbs() {
    local f="$VENDOR_DIR/fid_db_versions.json"
    if ! python3 -c "import json; json.load(open('$f'))" >/dev/null 2>&1; then
        echo "MISSING: fid_db_versions.json malformed or absent."
        return 1
    fi
    # Each named DB must exist under fid_db/<name>.fidb if version != "0.0.0".
    local any_missing=0
    while IFS=$'\t' read -r name version; do
        if [[ "$version" == "0.0.0" ]]; then
            echo "MISSING: fid_db/$name (placeholder version)."
            any_missing=1
        elif [[ ! -f "$REPO_ROOT/fid_db/$name.fidb" ]]; then
            echo "MISSING: fid_db/$name.fidb absent (pinned at $version)."
            any_missing=1
        else
            echo "OK: fid_db/$name @ $version"
        fi
    done < <(python3 -c "
import json
d = json.load(open('$f'))
for k, v in d.items():
    print(f'{k}\t{v[\"version\"]}')
")
    return $any_missing
}

case "${1:-}" in
    --check)
        rc=0
        check_libghidra || rc=1
        check_ghidrasql || rc=1
        check_fid_dbs || rc=1
        exit $rc
        ;;
    --install)
        echo "--install mode is implemented in the Pass 0 sub-plan. Run --check for now." >&2
        exit 2
        ;;
    --help|"")
        usage
        exit 0
        ;;
    *)
        echo "Unknown flag: $1" >&2
        usage >&2
        exit 64
        ;;
esac
```

- [ ] **Step 4: Make it executable and verify**

```bash
chmod +x vendor/bootstrap.sh
pytest tests/reconstruct/test_vendor_bootstrap.py -k bootstrap_check -v
```

Expected: 2 PASSED.

- [ ] **Step 5: Commit**

```bash
git add vendor/bootstrap.sh tests/reconstruct/test_vendor_bootstrap.py
git commit -m "feat(vendor): bootstrap.sh --check mode reports placeholder pins"
```

---

## Task 8: `scripts/pcode_hash.py` — input-dependent deterministic hash stub

The real PCode-aware hash requires LibGhidra and lands in the Pass 0 sub-plan. For foundation, a deterministic hash over the function's instruction bytes (already in `function_index.json`) is enough to validate the carryforward plumbing.

**Files:**
- Create: `scripts/pcode_hash.py`
- Test: `tests/reconstruct/test_pcode_hash.py`

- [ ] **Step 1: Write the failing test**

Create `tests/reconstruct/test_pcode_hash.py`:

```python
"""Tests for the pcode_hash stub library."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import pcode_hash  # type: ignore


def test_hash_function_record_is_deterministic():
    rec = {
        "address": "0x140012a0",
        "code_hash": "abcdef0123",
        "instruction_count": 42,
        "size": 256,
    }
    h1 = pcode_hash.hash_function_record(rec)
    h2 = pcode_hash.hash_function_record(rec)
    assert h1 == h2
    assert isinstance(h1, str)
    assert len(h1) == 64  # SHA-256 hex


def test_hash_function_record_changes_with_inputs():
    a = {"address": "0x140012a0", "code_hash": "abcd", "instruction_count": 42, "size": 256}
    b = dict(a, code_hash="ef01")
    assert pcode_hash.hash_function_record(a) != pcode_hash.hash_function_record(b)


def test_hash_function_record_ignores_irrelevant_fields():
    """Fields like callers/callees (which depend on neighbor naming) MUST NOT
    affect the structural hash — otherwise carryforward breaks across versions.
    """
    a = {"address": "0x140012a0", "code_hash": "abcd", "instruction_count": 42, "size": 256, "callers": ["FUN_a"]}
    b = dict(a, callers=["FUN_b"])
    assert pcode_hash.hash_function_record(a) == pcode_hash.hash_function_record(b)


def test_aggregate_hash_is_order_independent():
    records = [
        {"address": "0x100", "code_hash": "aaaa", "instruction_count": 5, "size": 20},
        {"address": "0x200", "code_hash": "bbbb", "instruction_count": 10, "size": 40},
    ]
    h1 = pcode_hash.aggregate_hash(records)
    h2 = pcode_hash.aggregate_hash(list(reversed(records)))
    assert h1 == h2
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pcode_hash.py -v
```

Expected: 4 FAILED — `ModuleNotFoundError: No module named 'pcode_hash'`.

- [ ] **Step 3: Create `scripts/pcode_hash.py`**

```python
"""Structural hash of a function for carryforward matching.

Foundation-quality stub: hashes a deterministic subset of `function_index.json`
record fields. The real PCode-aware implementation (which uses LibGhidra to
normalize PCode and hash the normalized form) lands in the Pass 0 sub-plan.

The hash MUST be stable across binary versions when the function body is
unchanged, and MUST change when the body changes. Foundation approximates
this via `code_hash + instruction_count + size`. The Pass 0 sub-plan replaces
this with the canonical PCode hash; tests added then prove cross-version
stability under recompile.
"""
from __future__ import annotations

import hashlib
import json
from typing import Iterable, Mapping

# Fields included in the structural hash. Notably EXCLUDES `name`, `callers`,
# `callees` (neighbor-dependent), and any per-pass derived fields.
_STRUCTURAL_FIELDS = ("code_hash", "instruction_count", "size")


def hash_function_record(rec: Mapping) -> str:
    """Return a hex SHA-256 of the function's structural fingerprint.

    A function with the same body (same `code_hash`, same instruction count,
    same size) produces the same hash regardless of name or neighbor metadata.
    """
    payload = {k: rec.get(k) for k in _STRUCTURAL_FIELDS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def aggregate_hash(records: Iterable[Mapping]) -> str:
    """Return a hex SHA-256 over the sorted per-function hashes.

    Order-independent: re-ordering the input iterable does not change the
    aggregate hash. Use this for `manifest.json#binary.pcode_hash_aggregate`.
    """
    per_func = sorted(hash_function_record(r) for r in records)
    canonical = "\n".join(per_func)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pcode_hash.py -v
```

Expected: 4 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/pcode_hash.py tests/reconstruct/test_pcode_hash.py
git commit -m "feat(pcode_hash): foundation stub for function structural hashing"
```

---

## Task 9: `scripts/libghidra_connect.py` — healthz probe and version pin enforcement

**Files:**
- Create: `scripts/libghidra_connect.py`
- Test: `tests/reconstruct/test_libghidra_connect.py`

- [ ] **Step 1: Write the failing test**

Create `tests/reconstruct/test_libghidra_connect.py`:

```python
"""Tests for libghidra_connect: healthz, version pin, lock primitives."""
from __future__ import annotations

import http.server
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import libghidra_connect  # type: ignore


class _OkHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/libghidra/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_a, **_kw):  # silence
        pass


@pytest.fixture()
def healthz_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _OkHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/libghidra/healthz"
    server.shutdown()
    thread.join(timeout=2)


def test_healthz_true_when_endpoint_responds_200(healthz_server):
    assert libghidra_connect.healthz(healthz_server, timeout=1.0) is True


def test_healthz_false_when_endpoint_unreachable():
    assert libghidra_connect.healthz(
        "http://127.0.0.1:1/nonexistent", timeout=0.5
    ) is False


def test_healthz_false_when_url_is_empty():
    assert libghidra_connect.healthz("", timeout=0.5) is False


def test_check_version_pin_reads_pin_file(tmp_path):
    pin = tmp_path / "libghidra.version"
    pin.write_text("url=https://example/repo\ncommit=abc123\nsha256=deadbeef\n")
    parsed = libghidra_connect.read_pin_file(pin)
    assert parsed == {
        "url": "https://example/repo",
        "commit": "abc123",
        "sha256": "deadbeef",
    }


def test_check_version_pin_rejects_placeholder_values(tmp_path):
    pin = tmp_path / "libghidra.version"
    pin.write_text(
        "url=https://example/repo\n"
        "commit=TO_BE_SET_DURING_FIRST_INSTALL\n"
        "sha256=TO_BE_SET_DURING_FIRST_INSTALL\n"
    )
    parsed = libghidra_connect.read_pin_file(pin)
    assert libghidra_connect.is_placeholder_pin(parsed) is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_libghidra_connect.py -v
```

Expected: 5 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/libghidra_connect.py`**

```python
"""Thin client for the LibGhidra Java extension's HTTP API host.

Foundation responsibilities only: healthz probe, version-pin parsing, and
lock primitives. The real LibGhidra Protobuf API calls (decompile, rename,
retype, etc.) land in the Pass 0 sub-plan and are loaded as GhidraSQL
skill files into the agent workspace at .claude/skills/ghidrasql/.
"""
from __future__ import annotations

import fcntl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Mapping

_PLACEHOLDER = "TO_BE_SET_DURING_FIRST_INSTALL"


def healthz(url: str, timeout: float = 2.0) -> bool:
    """Return True iff `url` responds with HTTP 200 within `timeout` seconds.

    Returns False on empty URL, connection error, timeout, or non-2xx status.
    """
    if not url:
        return False
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError, OSError):
        return False


def read_pin_file(path: Path) -> dict:
    """Parse a `key=value` pin file (e.g. vendor/libghidra.version).

    Ignores blank lines and `#`-prefixed comments. Returns a dict of the
    declared keys. Missing required keys are NOT an error here; use
    `is_placeholder_pin` to detect uninitialized pins.
    """
    out: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def is_placeholder_pin(parsed: Mapping[str, str]) -> bool:
    """Return True if any tracked field still holds the placeholder string."""
    for k in ("commit", "sha256"):
        if parsed.get(k) == _PLACEHOLDER:
            return True
    return False


def acquire_exclusive_lock(lock_path: Path, *, blocking: bool = False) -> "object | None":
    """Acquire a exclusive flock on `lock_path`. Returns the file handle on
    success (caller must keep it open until they want to release), or None if
    the lock is held by another process and `blocking=False`.

    Creates the lock file if it does not exist. Parent directory must exist.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lf = open(lock_path, "w")
    flag = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
    try:
        fcntl.flock(lf, flag)
    except BlockingIOError:
        lf.close()
        return None
    return lf


def release_lock(lf) -> None:
    """Release a flock previously acquired via `acquire_exclusive_lock`."""
    try:
        fcntl.flock(lf, fcntl.LOCK_UN)
    finally:
        lf.close()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_libghidra_connect.py -v
```

Expected: 5 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/libghidra_connect.py tests/reconstruct/test_libghidra_connect.py
git commit -m "feat(libghidra_connect): healthz probe, pin parser, lock primitives"
```

---

## Task 10: `libghidra_connect` lock primitives — round-trip test

The lock acquire/release functions exist; this task adds a behavioral test that another process is correctly blocked when the lock is held.

**Files:**
- Test: `tests/reconstruct/test_libghidra_connect.py` (append)

- [ ] **Step 1: Add the failing test**

Append to `tests/reconstruct/test_libghidra_connect.py`:

```python
def test_acquire_exclusive_lock_returns_handle_when_free(tmp_path):
    lock = tmp_path / "test.lock"
    lf = libghidra_connect.acquire_exclusive_lock(lock)
    try:
        assert lf is not None
        assert lock.is_file()
    finally:
        libghidra_connect.release_lock(lf)


def test_acquire_exclusive_lock_returns_none_when_held(tmp_path):
    lock = tmp_path / "test.lock"
    first = libghidra_connect.acquire_exclusive_lock(lock)
    try:
        # Second non-blocking attempt must return None.
        second = libghidra_connect.acquire_exclusive_lock(lock, blocking=False)
        assert second is None
    finally:
        libghidra_connect.release_lock(first)


def test_lock_can_be_reacquired_after_release(tmp_path):
    lock = tmp_path / "test.lock"
    first = libghidra_connect.acquire_exclusive_lock(lock)
    assert first is not None
    libghidra_connect.release_lock(first)
    second = libghidra_connect.acquire_exclusive_lock(lock)
    assert second is not None
    libghidra_connect.release_lock(second)
```

- [ ] **Step 2: Run tests to verify they pass (no impl change needed)**

```bash
pytest tests/reconstruct/test_libghidra_connect.py -k "lock" -v
```

Expected: 3 PASSED. (The implementation from Task 9 already supports these flows; this task adds behavioral coverage that the lock primitives compose correctly.)

If any FAIL, fix the implementation in `scripts/libghidra_connect.py` before proceeding.

- [ ] **Step 3: Commit**

```bash
git add tests/reconstruct/test_libghidra_connect.py
git commit -m "test(libghidra_connect): lock acquire/release/reacquire round-trip"
```

---

## Task 11: `vb-add reconstruction` subcommand in `scripts/catalog_add.py`

This subcommand creates the catalog dir scaffold and adds the `reconstruction:` block to the binary YAML.

**Files:**
- Modify: `scripts/catalog_add.py` (add `cmd_reconstruction` + register on argparse)
- Test: `tests/reconstruct/test_vb_add_reconstruction.py`

- [ ] **Step 1: Write the failing test**

Create `tests/reconstruct/test_vb_add_reconstruction.py`:

```python
"""Tests for the `vb-add reconstruction` subcommand."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CATALOG_ADD = REPO_ROOT / "scripts" / "catalog_add.py"


def _make_binary_yaml(tmp_path: Path, stem: str) -> Path:
    bdir = tmp_path / "catalog" / "binaries"
    bdir.mkdir(parents=True, exist_ok=True)
    f = bdir / f"{stem}.yml"
    f.write_text(yaml.safe_dump({
        "binary": stem,
        "product": "test-product",
        "sources": [],
        "sinks": [],
        "chains": [],
    }))
    return f


def test_vb_add_reconstruction_creates_catalog_dir(tmp_path, monkeypatch):
    stem = "sample_stem"
    _make_binary_yaml(tmp_path, stem)
    env = {**dict(__import__("os").environ), "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", "v1_0_0"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    recon_dir = tmp_path / "catalog" / "reconstructed" / f"{stem}_v1_0_0"
    assert recon_dir.is_dir(), f"{recon_dir} not created"
    assert (recon_dir / "manifest.json").is_file()
    assert (recon_dir / ".lock").is_file()


def test_vb_add_reconstruction_writes_block_to_binary_yaml(tmp_path):
    stem = "sample_stem"
    yml_path = _make_binary_yaml(tmp_path, stem)
    env = {**dict(__import__("os").environ), "VULNERABIN_ROOT": str(tmp_path)}
    subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", "v1_0_0"],
        capture_output=True, text=True, env=env, check=True,
    )
    data = yaml.safe_load(yml_path.read_text())
    assert "reconstruction" in data
    r = data["reconstruction"]
    assert r["ref"] == f"catalog/reconstructed/{stem}_v1_0_0"
    assert r["version_tag"] == "v1_0_0"
    assert r["status"] == "not_started"


def test_vb_add_reconstruction_is_idempotent_when_dir_exists(tmp_path):
    stem = "sample_stem"
    _make_binary_yaml(tmp_path, stem)
    env = {**dict(__import__("os").environ), "VULNERABIN_ROOT": str(tmp_path)}
    # First invocation: creates.
    subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", "v1_0_0"],
        env=env, check=True, capture_output=True, text=True,
    )
    # Second invocation: no-op.
    second = subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", "v1_0_0"],
        env=env, capture_output=True, text=True,
    )
    assert second.returncode == 0
    assert "already" in second.stdout.lower() or "exists" in second.stdout.lower() or "no-op" in second.stdout.lower()


def test_vb_add_reconstruction_refuses_unknown_binary(tmp_path):
    env = {**dict(__import__("os").environ), "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", "does_not_exist", "--version", "v1_0_0"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "binary" in result.stderr.lower() or "not found" in result.stderr.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_vb_add_reconstruction.py -v
```

Expected: 4 FAILED — `reconstruction` subcommand not recognized by argparse.

- [ ] **Step 3: Modify `scripts/catalog_add.py`**

First, near the top of the file (after the existing imports), add an environment-aware ROOT override so the test can drive it via `VULNERABIN_ROOT`. Locate the existing `ROOT` definition (around line 50) and replace it with:

```python
ROOT = Path(__import__("os").environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)
```

(If the file already imports `os` cleanly, use that instead of the import expression. Adapt to the existing import style at the top of the file.)

Next, add the `cmd_reconstruction` function. Place it after the existing `cmd_unreachable` function (around line 262):

```python
def cmd_reconstruction(args):
    """Scaffold a reconstruction catalog dir + add `reconstruction:` block."""
    import json
    stem = args.binary
    version_tag = args.version
    yml = ROOT / "catalog" / "binaries" / f"{stem}.yml"
    if not yml.is_file():
        print(f"error: catalog/binaries/{stem}.yml not found", file=sys.stderr)
        sys.exit(2)

    recon_dir = ROOT / "catalog" / "reconstructed" / f"{stem}_{version_tag}"
    already = recon_dir.is_dir()

    recon_dir.mkdir(parents=True, exist_ok=True)
    manifest = recon_dir / "manifest.json"
    if not manifest.is_file():
        manifest.write_text(json.dumps({
            "binary": {
                "stem": stem,
                "version_tag": version_tag,
                "status": "not_started",
            },
            "passes": [],
        }, indent=2))
    lock = recon_dir / ".lock"
    if not lock.is_file():
        lock.touch()

    # Update binary YAML in place: add `reconstruction:` block if absent.
    data = yaml.safe_load(yml.read_text()) or {}
    if "reconstruction" not in data:
        data["reconstruction"] = {
            "ref": f"catalog/reconstructed/{stem}_{version_tag}",
            "version_tag": version_tag,
            "status": "not_started",
        }
        yml.write_text(yaml.safe_dump(data, sort_keys=False))

    if already:
        print(f"no-op: {recon_dir.relative_to(ROOT)} already exists")
    else:
        print(f"scaffolded {recon_dir.relative_to(ROOT)} and updated {yml.relative_to(ROOT)}")
```

Finally, register the subcommand. Locate the `main()` function (around line 280) where `add_subparsers` is called and other commands are registered. Add this block alongside the existing subparser registrations (after `unreachable`):

```python
    r = sp.add_parser("reconstruction", parents=[common],
                      help="Scaffold a catalog/reconstructed/<stem>_<tag>/ dir and add reconstruction: block.")
    r.add_argument("--binary", required=True, help="Binary stem (matches catalog/binaries/<stem>.yml)")
    r.add_argument("--version", required=True, help="Version tag, e.g. v27_1_1_28")
    r.set_defaults(func=cmd_reconstruction)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_vb_add_reconstruction.py -v
```

Expected: 4 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/catalog_add.py tests/reconstruct/test_vb_add_reconstruction.py
git commit -m "feat(vb-add): reconstruction subcommand scaffolds catalog dir + YAML block"
```

---

## Task 12: Foundation smoke test — end-to-end wiring

This task adds one integration test that drives the full foundation flow: scaffold a binary, run `vb-add reconstruction`, run `fsm.py state` to confirm the phase recognizes the new artifact state.

**Files:**
- Test: `tests/reconstruct/test_foundation_smoke.py`

- [ ] **Step 1: Write the test**

Create `tests/reconstruct/test_foundation_smoke.py`:

```python
"""End-to-end smoke test for the reconstruct phase foundation.

Drives: vb-add reconstruction -> binary YAML + catalog dir scaffold ->
fsm.py state reports gate evidence for libghidra_alive, no_concurrent_writer,
reachable_named_100pct (fails since coverage.json absent), tail_named_80pct
(fails since coverage.json absent).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_foundation_end_to_end(tmp_path):
    # 1. Set up a fake repo layout under tmp_path.
    (tmp_path / "scripts").mkdir()
    (tmp_path / "engagements").mkdir()
    (tmp_path / "catalog" / "binaries").mkdir(parents=True)

    # Copy the real pipeline.yml so fsm.py reads the right phase definitions.
    (tmp_path / "pipeline.yml").write_text((REPO_ROOT / "pipeline.yml").read_text())

    # Seed a binary YAML.
    stem = "smoke_target"
    (tmp_path / "catalog" / "binaries" / f"{stem}.yml").write_text(yaml.safe_dump({
        "binary": stem,
        "product": "smoke",
    }))

    # Seed an engagement with the bare minimum to satisfy preparation outputs.
    eng = tmp_path / "engagements" / "smoke-2026-05-11"
    eng.mkdir()
    (eng / "scope.json").write_text(json.dumps({
        "binary": stem,
        "target_type": "binary",
    }))
    (eng / "decomp").mkdir()
    (eng / "decomp" / "function_index.json").write_text('{"functions": []}')

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}

    # 2. Run vb-add reconstruction.
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_add.py"),
         "reconstruction", "--binary", stem, "--version", "vsmoke"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    # Catalog dir + YAML block populated.
    recon_dir = tmp_path / "catalog" / "reconstructed" / f"{stem}_vsmoke"
    assert recon_dir.is_dir()
    assert (recon_dir / "manifest.json").is_file()
    assert (recon_dir / ".lock").is_file()

    yml = yaml.safe_load((tmp_path / "catalog" / "binaries" / f"{stem}.yml").read_text())
    assert yml["reconstruction"]["status"] == "not_started"

    # 3. Run fsm.py state to confirm gate evidence is produced for all four gates.
    # fsm.py computes ROOT relative to its own location, so we drive it
    # against the REAL repo's pipeline.yml but a tmp engagement layout.
    # Patch via env: fsm.py supports neither VULNERABIN_ROOT nor a CLI flag for ENG_ROOT,
    # so we test gate_status in-process instead.
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore
    # Point fsm at our fixture layout.
    fsm.ENG_ROOT = tmp_path / "engagements"
    fsm.CATALOG_BINARIES = tmp_path / "catalog" / "binaries"
    fsm.ROOT = tmp_path
    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "smoke-2026-05-11", eng, "reconstruct", cfg["phases"]["reconstruct"]
    )
    gate_ids = {s["id"] for s in statuses}
    assert gate_ids == {
        "libghidra_alive",
        "no_concurrent_writer",
        "reachable_named_100pct",
        "tail_named_80pct",
    }
    # libghidra_alive must be False (no endpoint configured) but with evidence.
    libg = next(s for s in statuses if s["id"] == "libghidra_alive")
    assert libg["ok"] is False
    assert "libghidra" in libg["evidence"].lower() or "endpoint" in libg["evidence"].lower()
    # no_concurrent_writer: lock file exists but is unheld; should pass.
    ncw = next(s for s in statuses if s["id"] == "no_concurrent_writer")
    assert ncw["ok"] is True
    # post-gates fail because coverage.json is not yet produced.
    hard = next(s for s in statuses if s["id"] == "reachable_named_100pct")
    assert hard["ok"] is False
    assert "coverage.json missing" in hard["evidence"]
```

- [ ] **Step 2: Run the smoke test**

```bash
pytest tests/reconstruct/test_foundation_smoke.py -v
```

Expected: PASSED. If FAILED, debug by reading the diagnostic output and fixing the relevant prior task before proceeding.

- [ ] **Step 3: Run the entire foundation test suite to confirm nothing regressed**

```bash
pytest tests/reconstruct/ -v
```

Expected: All tests PASSED.

- [ ] **Step 4: Commit**

```bash
git add tests/reconstruct/test_foundation_smoke.py
git commit -m "test(reconstruct): foundation smoke test wires vb-add + fsm + scaffold"
```

---

## Task 13: Document the foundation in CLAUDE.md

Foundation is in place; the project's CLAUDE.md should mention the new `vb-add reconstruction` subcommand so future Claude sessions know it exists.

**Files:**
- Modify: `CLAUDE.md` (append to the `## vb-add CLI` section)

- [ ] **Step 1: Locate the existing `## vb-add CLI` section**

```bash
grep -n "vb-add CLI" CLAUDE.md
```

Expected: returns a single line number for the section header.

- [ ] **Step 2: Append the new subcommand documentation**

Read the section to see its current shape:

```bash
sed -n "$(grep -n '## vb-add CLI' CLAUDE.md | cut -d: -f1),+30p" CLAUDE.md
```

Then add the new subcommand under the existing examples block in that section, preserving the existing formatting. Use the Edit tool with the precise existing surrounding text — do not use `>>` redirection. The line to add (formatted to match existing style):

```
vb-add reconstruction --binary <stem> --version <tag>
                                                # Scaffold catalog/reconstructed/<stem>_<tag>/
                                                # and add reconstruction: block to binary YAML.
```

- [ ] **Step 3: Verify the change**

```bash
grep -A2 "vb-add reconstruction" CLAUDE.md
```

Expected: shows the three lines.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document vb-add reconstruction subcommand"
```

---

## Done — Foundation acceptance

When all 13 tasks above are complete:

- [ ] `pytest tests/reconstruct/ -v` reports all tests PASSED
- [ ] `python3 scripts/fsm.py state <some-engagement>` does not crash when the engagement has no `reconstruct` artifacts (gates report "not configured" / "missing", which is correct foundation state)
- [ ] `vb-add reconstruction --binary <existing-stem> --version vtest` creates `catalog/reconstructed/<stem>_vtest/` with `manifest.json` + `.lock`, and updates `catalog/binaries/<stem>.yml` with a `reconstruction:` block whose `status: not_started`
- [ ] `vendor/bootstrap.sh --check` exits non-zero with "MISSING:" messages for each placeholder pin

Next sub-plan: **Pass 0 deterministic** (`docs/superpowers/plans/2026-05-11-reconstruct-pass0.md`, written after this plan's tasks are complete and verified).
