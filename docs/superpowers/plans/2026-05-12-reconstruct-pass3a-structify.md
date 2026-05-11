# Reconstruct Phase — Pass 3a Struct Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Pass 3a struct consolidation. After Pass 2 retype proposes `IPC_REQUEST_HEADER *` across multiple functions, Pass 3a clusters those proposals by candidate struct name and dispatches an LLM worker per cluster to produce a consolidated typedef (named fields with offsets + types). Output lives at `manifest.json#passes[].pass3a.structs[]` (NEW schema). Same batch/apply pattern as Pass 1/2.

**Architecture:** `reconstruct_pass3a_batch.py` reads `manifest.json#passes[].pass2.retypes`, finds struct-pointer `to` values (e.g., `IPC_REQUEST_HEADER *`, `BUFFER_DESC *`), clusters by struct base name (strip leading/trailing `*` and `const`), emits one batch JSON per cluster containing the supporting functions + their retype context. `reconstruct_pass3a_apply.py` validates worker output, merges consolidated typedefs into `manifest.json#passes[].pass3a.structs[]`. No coverage.json changes (structs don't contribute to naming gates; they're enrichment).

**Tech Stack:** Python 3.11, pytest, stdlib. Builds on Pass 1/2 patterns.

---

## File Structure

**Create:**
- `scripts/reconstruct_pass3a_batch.py` — cluster struct hypotheses + emit per-cluster batches
- `scripts/reconstruct_pass3a_apply.py` — validate + merge consolidated typedefs
- `prompts/workers/reconstruct_structify.md` — worker contract
- `tests/reconstruct/fixtures/sample_manifest_pass2_done.json` — manifest after Pass 0+1+2
- `tests/reconstruct/fixtures/sample_pass3a_result_valid.json`
- `tests/reconstruct/fixtures/sample_pass3a_result_malformed.json`
- `tests/reconstruct/test_pass3a_batch.py`
- `tests/reconstruct/test_pass3a_apply.py`

**Modify:**
- `prompts/phases/reconstruct.md` — append Pass 3a section
- `CLAUDE.md` — append `### Pass 3a — LLM struct consolidation` sub-section

**Conventions:**

| Concept | Convention |
|---|---|
| Pass 3a batch dir | `catalog/reconstructed/<stem>_<tag>/pass3a_batches/` |
| Batch file | `batch_<NNN>.json` (one batch per candidate struct cluster) |
| Worker result | `result_<NNN>.json` |
| Pass 3a manifest entry | `passes[]` entry with `pass: "pass3a"`, `structs[]` list, `tools_used: ["llm_structify"]` |
| Candidate struct name extraction | strip leading `const`, then strip ALL trailing `*` and whitespace, then keep `[A-Z_][A-Za-z0-9_]*` prefix. Example: `"const IPC_REQUEST_HEADER *"` → `"IPC_REQUEST_HEADER"` |
| Cluster minimum support | 1 function (single-occurrence structs are still useful — defer dedup to a future pass) |

**Pass 3a struct record schema:**

```json
{
  "name": "IPC_REQUEST_HEADER",
  "supporting_functions": ["0x140012a0", "0x140034b0"],
  "fields": [
    {"offset": 0, "type": "uint32_t", "name": "size", "rationale": "..."},
    {"offset": 4, "type": "uint32_t", "name": "type_tag", "rationale": "..."}
  ],
  "confidence": "medium",
  "source": "llm_structify",
  "rationale": "Three callers all use the same offset pattern"
}
```

---

## Task 1: Fixtures — Pass-2-done manifest + worker result examples

**Files:**
- Create: `tests/reconstruct/fixtures/sample_manifest_pass2_done.json`
- Create: `tests/reconstruct/fixtures/sample_pass3a_result_valid.json`
- Create: `tests/reconstruct/fixtures/sample_pass3a_result_malformed.json`

- [ ] **Step 1: Create Pass-2-done manifest**

Create `tests/reconstruct/fixtures/sample_manifest_pass2_done.json`:

```json
{
  "binary": {"stem": "samplebin", "version_tag": "v1_2_3", "status": "partial"},
  "passes": [
    {
      "pass": "pass0",
      "proposed_renames": [],
      "tools_used": ["iat_wrapper_detection"]
    },
    {
      "pass": "pass1",
      "proposed_renames": [
        {"addr": "0x140003000", "from": "FUN_140003000", "to": "DispatchCommand",
         "confidence": "high", "source": "llm_rename", "rationale": "..."},
        {"addr": "0x140005000", "from": "FUN_140005000", "to": "ParseHeader",
         "confidence": "medium", "source": "llm_rename", "rationale": "..."}
      ],
      "tools_used": ["llm_rename"]
    },
    {
      "pass": "pass2",
      "retypes": [
        {
          "addr": "0x140003000",
          "params": [
            {"index": 0, "from": "undefined4 *", "to": "IPC_REQUEST_HEADER *",
             "confidence": "high", "source": "llm_retype",
             "rationale": "Name DispatchCommand + caller pattern"}
          ],
          "locals": []
        },
        {
          "addr": "0x140005000",
          "params": [
            {"index": 0, "from": "undefined4 *", "to": "IPC_REQUEST_HEADER *",
             "confidence": "medium", "source": "llm_retype",
             "rationale": "Calls match header parse pattern"}
          ],
          "locals": []
        },
        {
          "addr": "0x140007000",
          "params": [
            {"index": 0, "from": "char *", "to": "LPCWSTR",
             "confidence": "high", "source": "llm_retype",
             "rationale": "CreateFileW wrapper"}
          ],
          "locals": [
            {"name": "local_18", "from": "DWORD", "to": "NTSTATUS",
             "confidence": "medium", "source": "llm_retype",
             "rationale": "Compared with STATUS_* constants"}
          ]
        }
      ],
      "tools_used": ["llm_retype"]
    }
  ],
  "project_discovery": {
    "reachable_user_defined": ["0x140003000", "0x140005000", "0x140007000"]
  }
}
```

This manifest has two retype proposals citing `IPC_REQUEST_HEADER *` (across `0x140003000` and `0x140005000`) and one citing `LPCWSTR` (Windows builtin — won't cluster as a custom struct). The cluster should produce a single `IPC_REQUEST_HEADER` consolidation candidate with 2 supporting functions.

- [ ] **Step 2: Create valid worker result**

Create `tests/reconstruct/fixtures/sample_pass3a_result_valid.json`:

```json
{
  "pass": "pass3a",
  "batch_id": "batch_000",
  "structs": [
    {
      "name": "IPC_REQUEST_HEADER",
      "supporting_functions": ["0x140003000", "0x140005000"],
      "fields": [
        {"offset": 0, "type": "uint32_t", "name": "size", "rationale": "First 4 bytes consistently read as length"},
        {"offset": 4, "type": "uint32_t", "name": "type_tag", "rationale": "Used as switch discriminator in DispatchCommand"},
        {"offset": 8, "type": "uint8_t[24]", "name": "payload", "rationale": "Variable-length payload, 24 byte slot"}
      ],
      "confidence": "medium",
      "rationale": "Two callers use identical offset pattern; field types inferred from access width"
    }
  ]
}
```

- [ ] **Step 3: Create malformed worker result**

Create `tests/reconstruct/fixtures/sample_pass3a_result_malformed.json`:

```json
{
  "pass": "pass3a",
  "batch_id": "batch_001",
  "structs": [
    {
      "name": "",
      "supporting_functions": [],
      "fields": [
        {"offset": 0, "type": "uint32_t", "name": "size", "rationale": "r"}
      ],
      "confidence": "high",
      "rationale": "Empty struct name"
    },
    {
      "name": "BAD_STRUCT",
      "supporting_functions": ["0x100"],
      "fields": [
        {"type": "uint32_t", "name": "size", "rationale": "missing offset"},
        {"offset": "not-int", "type": "uint32_t", "name": "x", "rationale": "non-int offset"}
      ],
      "confidence": "ultra",
      "rationale": "Bogus confidence"
    }
  ]
}
```

- [ ] **Step 4: Verify**

```bash
python3 -c "
import json
for p in ['sample_manifest_pass2_done.json', 'sample_pass3a_result_valid.json', 'sample_pass3a_result_malformed.json']:
    json.load(open('tests/reconstruct/fixtures/' + p))
print('OK')
"
```

Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add tests/reconstruct/fixtures/sample_manifest_pass2_done.json tests/reconstruct/fixtures/sample_pass3a_result_valid.json tests/reconstruct/fixtures/sample_pass3a_result_malformed.json
git commit -m "test(reconstruct): fixtures for Pass 3a structify"
```

---

## Task 2: `reconstruct_pass3a_batch.py` — cluster + emit batches

**Files:**
- Create: `scripts/reconstruct_pass3a_batch.py`
- Test: `tests/reconstruct/test_pass3a_batch.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_pass3a_batch.py`:

```python
"""Tests for reconstruct_pass3a_batch — cluster Pass 2 struct hypotheses."""
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

import reconstruct_pass3a_batch as batch  # type: ignore


def _manifest_pass2_done() -> dict:
    return json.loads((FIXTURES / "sample_manifest_pass2_done.json").read_text())


def test_extract_struct_name_strips_pointer_decorations():
    assert batch.extract_struct_name("IPC_REQUEST_HEADER *") == "IPC_REQUEST_HEADER"
    assert batch.extract_struct_name("const IPC_REQUEST_HEADER *") == "IPC_REQUEST_HEADER"
    assert batch.extract_struct_name("IPC_REQUEST_HEADER **") == "IPC_REQUEST_HEADER"
    assert batch.extract_struct_name("  IPC_REQUEST_HEADER  *  ") == "IPC_REQUEST_HEADER"


def test_extract_struct_name_returns_none_for_non_struct_types():
    """Windows builtin types like LPCWSTR, HANDLE, NTSTATUS, DWORD are NOT
    struct names. They're scalars/typedefs that shouldn't trigger clustering.
    """
    assert batch.extract_struct_name("LPCWSTR") is None
    assert batch.extract_struct_name("HANDLE") is None
    assert batch.extract_struct_name("NTSTATUS") is None
    assert batch.extract_struct_name("DWORD") is None
    assert batch.extract_struct_name("uint32_t") is None
    assert batch.extract_struct_name("char *") is None
    assert batch.extract_struct_name("void *") is None


def test_extract_struct_name_accepts_uppercase_underscore_identifier():
    """Struct names are UPPERCASE_WITH_UNDERSCORES followed by * suffix."""
    assert batch.extract_struct_name("MY_STRUCT *") == "MY_STRUCT"
    assert batch.extract_struct_name("FOO_BAR_BAZ *") == "FOO_BAR_BAZ"


def test_extract_struct_name_rejects_lowercase_typedefs():
    """`some_struct *` is unlikely to be a custom struct in our binaries."""
    assert batch.extract_struct_name("some_struct *") is None


def test_cluster_struct_hypotheses_finds_ipc_request_header():
    manifest = _manifest_pass2_done()
    clusters = batch.cluster_struct_hypotheses(manifest)
    by_name = {c["name"]: c for c in clusters}
    assert "IPC_REQUEST_HEADER" in by_name
    cluster = by_name["IPC_REQUEST_HEADER"]
    assert set(cluster["supporting_functions"]) == {"0x140003000", "0x140005000"}


def test_cluster_struct_hypotheses_skips_non_struct_types():
    """LPCWSTR appears in pass2 retypes but is not a struct."""
    manifest = _manifest_pass2_done()
    clusters = batch.cluster_struct_hypotheses(manifest)
    names = {c["name"] for c in clusters}
    assert "LPCWSTR" not in names


def test_cluster_struct_hypotheses_returns_empty_when_no_pass2():
    manifest = {"binary": {"stem": "t"}, "passes": [
        {"pass": "pass0", "proposed_renames": []},
    ]}
    clusters = batch.cluster_struct_hypotheses(manifest)
    assert clusters == []


def test_cluster_struct_hypotheses_collects_retype_record_per_function():
    """Each cluster entry should include the retype rationale + confidence for each supporting function."""
    manifest = _manifest_pass2_done()
    clusters = batch.cluster_struct_hypotheses(manifest)
    cluster = next(c for c in clusters if c["name"] == "IPC_REQUEST_HEADER")
    # Cluster should record per-function retype contexts.
    assert "occurrences" in cluster
    occs = {o["addr"]: o for o in cluster["occurrences"]}
    assert "0x140003000" in occs
    assert "0x140005000" in occs
    for o in cluster["occurrences"]:
        assert "param_index" in o
        assert "from_type" in o
        assert "confidence" in o
        assert "rationale" in o


def test_make_batches_one_per_cluster():
    """Each cluster gets its own batch (no further chunking)."""
    clusters = [
        {"name": "A", "supporting_functions": ["0x1"], "occurrences": []},
        {"name": "B", "supporting_functions": ["0x2"], "occurrences": []},
    ]
    batches = batch.make_batches(clusters)
    assert len(batches) == 2
    assert batches[0][0]["name"] == "A"
    assert batches[1][0]["name"] == "B"


def test_write_batches_emits_files_and_index(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass2_done.json", recon_dir / "manifest.json")
    summary = batch.write_batches(recon_dir, _manifest_pass2_done())
    bdir = recon_dir / "pass3a_batches"
    assert (bdir / "batch_000.json").is_file()
    assert (bdir / "index.json").is_file()
    idx = json.loads((bdir / "index.json").read_text())
    assert idx["cluster_count"] == summary["cluster_count"]
    assert len(idx["batches"]) == summary["batch_count"]
    assert all(b["status"] == "pending" for b in idx["batches"])


def test_cli_writes_batches_end_to_end(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass2_done.json", recon_dir / "manifest.json")
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass3a_batch.py"),
         "--binary", "samplebin", "--version", "v1_2_3"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert (recon_dir / "pass3a_batches" / "batch_000.json").is_file()


def test_cli_refuses_missing_catalog_dir(tmp_path):
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass3a_batch.py"),
         "--binary", "missing", "--version", "v0"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "not found" in (result.stdout + result.stderr).lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass3a_batch.py -v
```

Expected: 11 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/reconstruct_pass3a_batch.py`** with EXACT content:

```python
"""Pass 3a batch emission — cluster struct hypotheses from Pass 2 retypes.

Reads `manifest.json#passes[].pass2.retypes` and finds parameter retypes
whose `to` value is a custom struct pointer type (e.g., `IPC_REQUEST_HEADER *`).
Groups occurrences by struct base name and writes one batch JSON per cluster
under <reconstruction.ref>/pass3a_batches/.

A struct base name is UPPERCASE_WITH_UNDERSCORES that becomes a type when
suffixed with `*`. Windows builtin types (LPCWSTR, HANDLE, NTSTATUS, DWORD,
etc.) and lowercase typedefs are intentionally NOT treated as struct
candidates.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)

# Windows scalar/typedef names that must NOT be clustered as structs.
_WIN_BUILTIN_TYPES = {
    "LPCWSTR", "LPWSTR", "LPCSTR", "LPSTR",
    "HANDLE", "HMODULE", "HWND", "HKEY",
    "NTSTATUS", "HRESULT", "WINBOOL", "BOOL", "BOOLEAN",
    "DWORD", "WORD", "BYTE", "LONG", "ULONG", "ULONGLONG", "LONGLONG",
    "QWORD", "DWORDLONG", "INT", "UINT", "UINT8", "UINT16", "UINT32", "UINT64",
    "INT8", "INT16", "INT32", "INT64",
    "SIZE_T", "PSIZE_T", "PVOID", "LPVOID", "LPCVOID",
    "PWSTR", "PSTR", "PWCHAR", "PCHAR",
    "FILETIME", "SYSTEMTIME", "GUID", "UUID",
    "VOID", "NULL", "TRUE", "FALSE",
}
# Common C scalar types.
_C_BUILTIN_TYPES = {
    "char", "short", "int", "long", "float", "double",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "size_t", "ptrdiff_t", "intptr_t", "uintptr_t",
    "bool", "void",
}

_STRUCT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def extract_struct_name(type_str: str) -> str | None:
    """Return the candidate struct base name from a type string, or None
    if the type is not a custom struct pointer."""
    s = (type_str or "").strip()
    if not s:
        return None
    # Strip leading `const` qualifier.
    if s.lower().startswith("const "):
        s = s[6:].strip()
    # Must end in `*` (one or more).
    if "*" not in s:
        return None
    s = s.rstrip().rstrip("*").strip()
    # Remaining must be an identifier.
    if not s:
        return None
    # Reject Windows builtins and C scalars.
    if s in _WIN_BUILTIN_TYPES or s in _C_BUILTIN_TYPES:
        return None
    # Must match UPPERCASE_WITH_UNDERSCORES.
    if not _STRUCT_NAME_RE.match(s):
        return None
    return s


def cluster_struct_hypotheses(manifest: dict) -> list[dict]:
    """Walk all pass2 retypes and group params with matching struct base names.

    Returns a list of cluster dicts:
        {
          "name": "IPC_REQUEST_HEADER",
          "supporting_functions": ["0x...", "0x..."],
          "occurrences": [{addr, param_index, from_type, confidence, rationale}, ...]
        }
    """
    clusters: dict[str, dict] = {}
    for p in manifest.get("passes", []):
        if p.get("pass") != "pass2":
            continue
        for retype in p.get("retypes", []) or []:
            addr = retype.get("addr")
            if not addr:
                continue
            for param in retype.get("params", []) or []:
                struct_name = extract_struct_name(param.get("to", ""))
                if not struct_name:
                    continue
                cluster = clusters.setdefault(struct_name, {
                    "name": struct_name,
                    "supporting_functions": [],
                    "occurrences": [],
                })
                if addr not in cluster["supporting_functions"]:
                    cluster["supporting_functions"].append(addr)
                cluster["occurrences"].append({
                    "addr": addr,
                    "param_index": param.get("index"),
                    "from_type": param.get("from", ""),
                    "confidence": param.get("confidence", ""),
                    "rationale": param.get("rationale", ""),
                })
    return sorted(clusters.values(), key=lambda c: c["name"])


def make_batches(clusters: list[dict]) -> list[list[dict]]:
    """One cluster per batch. (Workers handle one struct at a time.)"""
    return [[c] for c in clusters]


def write_batches(recon_dir: Path, manifest: dict) -> dict:
    clusters = cluster_struct_hypotheses(manifest)
    batches = make_batches(clusters)
    bdir = recon_dir / "pass3a_batches"
    bdir.mkdir(parents=True, exist_ok=True)

    index_entries: list[dict] = []
    for i, b in enumerate(batches):
        batch_id = f"batch_{i:03d}"
        payload = {"batch_id": batch_id, "clusters": b}
        (bdir / f"{batch_id}.json").write_text(json.dumps(payload, indent=2))
        index_entries.append({
            "batch_id": batch_id,
            "cluster_name": b[0]["name"] if b else "",
            "status": "pending",
        })

    (bdir / "index.json").write_text(json.dumps({
        "batches": index_entries,
        "cluster_count": len(clusters),
    }, indent=2))

    return {
        "batch_count": len(batches),
        "cluster_count": len(clusters),
        "batches_dir": str(bdir),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--version", required=True)
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

    summary = write_batches(recon_dir, manifest)
    print(
        f"wrote {summary['batch_count']} pass3a batch(es) covering "
        f"{summary['cluster_count']} struct cluster(s) under "
        f"{Path(summary['batches_dir']).relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass3a_batch.py -v
```

Expected: 11 PASSED.

- [ ] **Step 5: Run ALL reconstruct tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: 164 PASSED (153 prior + 11 new).

- [ ] **Step 6: Commit**

```bash
git add scripts/reconstruct_pass3a_batch.py tests/reconstruct/test_pass3a_batch.py
git commit -m "feat(reconstruct): pass 3a struct hypothesis clustering"
```

---

## Task 3: `reconstruct_pass3a_apply.py` — validator

**Files:**
- Create: `scripts/reconstruct_pass3a_apply.py`
- Test: `tests/reconstruct/test_pass3a_apply.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_pass3a_apply.py`:

```python
"""Tests for reconstruct_pass3a_apply — worker result validation + merge."""
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

import reconstruct_pass3a_apply as apply_mod  # type: ignore


def test_validate_accepts_well_formed_result():
    result = json.loads((FIXTURES / "sample_pass3a_result_valid.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    assert errors == []


def test_validate_rejects_missing_pass_field():
    result = {"batch_id": "x", "structs": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass" in e.lower() for e in errors)


def test_validate_rejects_wrong_pass_value():
    result = {"pass": "pass2", "batch_id": "x", "structs": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass3a" in e.lower() for e in errors)


def test_validate_rejects_structs_not_a_list():
    result = {"pass": "pass3a", "batch_id": "x", "structs": "x"}
    errors = apply_mod.validate_worker_result(result)
    assert any("structs" in e.lower() for e in errors)


def test_validate_rejects_empty_struct_name():
    result = {
        "pass": "pass3a", "batch_id": "x",
        "structs": [{
            "name": "",
            "supporting_functions": ["0x1"],
            "fields": [{"offset": 0, "type": "uint32_t", "name": "x", "rationale": "r"}],
            "confidence": "high",
            "rationale": "r",
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("name" in e.lower() for e in errors)


def test_validate_rejects_unknown_confidence():
    result = {
        "pass": "pass3a", "batch_id": "x",
        "structs": [{
            "name": "OK", "supporting_functions": ["0x1"],
            "fields": [{"offset": 0, "type": "uint32_t", "name": "x", "rationale": "r"}],
            "confidence": "ultra",
            "rationale": "r",
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("confidence" in e.lower() for e in errors)


def test_validate_rejects_field_with_non_int_offset():
    result = {
        "pass": "pass3a", "batch_id": "x",
        "structs": [{
            "name": "OK", "supporting_functions": ["0x1"],
            "fields": [{"offset": "x", "type": "uint32_t", "name": "x", "rationale": "r"}],
            "confidence": "high",
            "rationale": "r",
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("offset" in e.lower() for e in errors)


def test_validate_rejects_field_missing_offset():
    result = {
        "pass": "pass3a", "batch_id": "x",
        "structs": [{
            "name": "OK", "supporting_functions": ["0x1"],
            "fields": [{"type": "uint32_t", "name": "x", "rationale": "r"}],
            "confidence": "high",
            "rationale": "r",
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("offset" in e.lower() for e in errors)


def test_validate_rejects_malformed_fixture():
    result = json.loads((FIXTURES / "sample_pass3a_result_malformed.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    joined = " ".join(errors).lower()
    assert "name" in joined
    assert "offset" in joined
    assert "confidence" in joined
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_pass3a_apply.py -v
```

Expected: 9 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/reconstruct_pass3a_apply.py`** with EXACT content:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_pass3a_apply.py -v
```

Expected: 9 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconstruct_pass3a_apply.py tests/reconstruct/test_pass3a_apply.py
git commit -m "feat(reconstruct): pass 3a apply — worker result validator"
```

---

## Task 4: `reconstruct_pass3a_apply.py` — merge + CLI tests

**Files:**
- Test: `tests/reconstruct/test_pass3a_apply.py` (append)

- [ ] **Step 1: Append the tests**

Append to `tests/reconstruct/test_pass3a_apply.py`:

```python
def test_merge_creates_pass3a_entry_when_absent():
    manifest = json.loads((FIXTURES / "sample_manifest_pass2_done.json").read_text())
    assert not any(p["pass"] == "pass3a" for p in manifest["passes"])
    result = json.loads((FIXTURES / "sample_pass3a_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result)
    pass3a = next(p for p in out["passes"] if p["pass"] == "pass3a")
    names = {s["name"] for s in pass3a["structs"]}
    assert "IPC_REQUEST_HEADER" in names


def test_merge_attaches_source_llm_structify():
    manifest = json.loads((FIXTURES / "sample_manifest_pass2_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass3a_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result)
    pass3a = next(p for p in out["passes"] if p["pass"] == "pass3a")
    for s in pass3a["structs"]:
        assert s["source"] == "llm_structify"


def test_merge_is_idempotent_when_same_result_re_applied():
    manifest = json.loads((FIXTURES / "sample_manifest_pass2_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass3a_result_valid.json").read_text())
    first = apply_mod.merge_into_manifest(manifest, result)
    second = apply_mod.merge_into_manifest(first, result)
    pass3a = next(p for p in second["passes"] if p["pass"] == "pass3a")
    names = [s["name"] for s in pass3a["structs"]]
    assert len(names) == len(set(names))


def test_merge_later_result_overrides_earlier_for_same_struct_name():
    manifest = json.loads((FIXTURES / "sample_manifest_pass2_done.json").read_text())
    first = {
        "pass": "pass3a", "batch_id": "b0",
        "structs": [{
            "name": "IPC_REQUEST_HEADER",
            "supporting_functions": ["0x1"],
            "fields": [{"offset": 0, "type": "uint8_t", "name": "old", "rationale": "..."}],
            "confidence": "low",
            "rationale": "first try",
        }],
    }
    second = {
        "pass": "pass3a", "batch_id": "b1",
        "structs": [{
            "name": "IPC_REQUEST_HEADER",
            "supporting_functions": ["0x1", "0x2"],
            "fields": [{"offset": 0, "type": "uint32_t", "name": "new", "rationale": "..."}],
            "confidence": "high",
            "rationale": "refined",
        }],
    }
    after_first = apply_mod.merge_into_manifest(manifest, first)
    after_second = apply_mod.merge_into_manifest(after_first, second)
    pass3a = next(p for p in after_second["passes"] if p["pass"] == "pass3a")
    rec = next(s for s in pass3a["structs"] if s["name"] == "IPC_REQUEST_HEADER")
    assert rec["confidence"] == "high"
    assert rec["fields"][0]["name"] == "new"


def test_cli_end_to_end(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass3a_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass2_done.json",
                recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_pass3a_result_valid.json",
                recon_dir / "pass3a_batches" / "result_000.json")
    (recon_dir / "pass3a_batches" / "index.json").write_text(json.dumps({
        "batches": [{"batch_id": "batch_000", "cluster_name": "IPC_REQUEST_HEADER", "status": "pending"}],
        "cluster_count": 1,
    }, indent=2))

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass3a_apply.py"),
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass3a_batches" / "result_000.json")],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    manifest = json.loads((recon_dir / "manifest.json").read_text())
    assert any(p["pass"] == "pass3a" for p in manifest["passes"])
    idx = json.loads((recon_dir / "pass3a_batches" / "index.json").read_text())
    assert idx["batches"][0]["status"] == "applied"


def test_cli_refuses_malformed(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass3a_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass2_done.json",
                recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_pass3a_result_malformed.json",
                recon_dir / "pass3a_batches" / "result_999.json")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass3a_apply.py"),
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass3a_batches" / "result_999.json")],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "validation failed" in (r.stdout + r.stderr).lower()
```

- [ ] **Step 2: Run the new tests**

```bash
pytest tests/reconstruct/test_pass3a_apply.py -v
```

Expected: 15 PASSED (9 from Task 3 + 6 new).

- [ ] **Step 3: Run ALL reconstruct tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: 179 PASSED (164 prior + 15 new).

- [ ] **Step 4: Commit**

```bash
git add tests/reconstruct/test_pass3a_apply.py
git commit -m "test(reconstruct): pass 3a apply — merge + CLI"
```

---

## Task 5: Worker prompt + docs

**Files:**
- Create: `prompts/workers/reconstruct_structify.md`
- Modify: `prompts/phases/reconstruct.md` (append Pass 3a section)
- Modify: `CLAUDE.md` (append Pass 3a sub-section)

- [ ] **Step 1: Create `prompts/workers/reconstruct_structify.md`**

```markdown
# Worker: reconstruct_structify (Pass 3a)

You are a reverse-engineering worker tasked with consolidating struct hypotheses produced by Pass 2. The strategist has clustered all Pass 2 retypes that proposed the same struct base name (e.g., `IPC_REQUEST_HEADER`) and is asking you to propose a single consolidated typedef with named fields, offsets, and types.

## Input

You receive ONE JSON document:

```json
{
  "batch_id": "batch_000",
  "clusters": [
    {
      "name": "IPC_REQUEST_HEADER",
      "supporting_functions": ["0x140003000", "0x140005000"],
      "occurrences": [
        {"addr": "0x140003000", "param_index": 0, "from_type": "undefined4 *",
         "confidence": "high", "rationale": "Name DispatchCommand + caller pattern"},
        {"addr": "0x140005000", "param_index": 0, "from_type": "undefined4 *",
         "confidence": "medium", "rationale": "Calls match header parse pattern"}
      ]
    }
  ]
}
```

Each cluster contains one candidate struct + the occurrences where Pass 2 proposed it. You must read the per-occurrence rationale strings to infer plausible field offsets and types.

## Output

Return EXACTLY ONE JSON document (no prose, no markdown fences):

```json
{
  "pass": "pass3a",
  "batch_id": "<same as input>",
  "structs": [
    {
      "name": "IPC_REQUEST_HEADER",
      "supporting_functions": ["0x140003000", "0x140005000"],
      "fields": [
        {"offset": 0, "type": "uint32_t", "name": "size", "rationale": "First 4 bytes consistently read as length"},
        {"offset": 4, "type": "uint32_t", "name": "type_tag", "rationale": "Used as switch discriminator in DispatchCommand"}
      ],
      "confidence": "medium",
      "rationale": "Two callers use identical offset pattern"
    }
  ]
}
```

## Rules

1. **One struct definition per input cluster.** Don't split or merge across clusters.
2. **Fields must have integer offsets.** Sort ascending by offset.
3. **Each field needs a name, type, and rationale.** No placeholders.
4. **`supporting_functions` carries through unchanged** from the input cluster.
5. **Skip a cluster** by omitting it from the output if the input occurrences don't give you enough signal to propose any fields. Better than guessing.

## Confidence rules

- `high`: 3+ supporting functions with consistent access patterns described in the rationales.
- `medium`: 2 supporting functions with plausible alignment.
- `low`: single function or weak signal — use sparingly.

## Caveat: no decompiled bodies

You see the per-occurrence rationale strings produced by Pass 2 retype workers; you do NOT see the actual function bodies. Field-level inference comes from the words those rationales use (e.g., "first 4 bytes read as length" → `uint32_t size`). When in doubt, skip fields rather than guess.
```

- [ ] **Step 2: Append Pass 3a section to `prompts/phases/reconstruct.md`**

Use Edit to insert BEFORE the existing `## What this phase does NOT do (yet)` heading. New content:

````markdown

## Pass 3a sequence

### Step 1 — emit batches

```
python3 scripts/reconstruct_pass3a_batch.py \
    --binary <stem> --version <tag>
```

Reads `manifest.json#passes[].pass2.retypes`, clusters by candidate struct base name (UPPERCASE_WITH_UNDERSCORES, stripping `*` and `const`; Windows builtins like LPCWSTR/HANDLE/NTSTATUS are NOT clustered as structs), writes one batch per cluster.

### Step 2 — dispatch one worker per cluster

For each pending batch, dispatch a worker using `prompts/workers/reconstruct_structify.md`. Save the result to `pass3a_batches/result_NNN.json`.

### Step 3 — apply

```
python3 scripts/reconstruct_pass3a_apply.py \
    --binary <stem> --version <tag> \
    --result catalog/reconstructed/<stem>_<tag>/pass3a_batches/result_NNN.json
```

Each apply call validates the result and merges the consolidated typedef into `manifest.json#passes[].pass3a.structs[]`. Pass 3a does NOT add to `proposed_renames` or `retypes`; it adds a new `structs[]` schema. Coverage gates are unaffected (structs are enrichment, not naming).

````

- [ ] **Step 3: Append Pass 3a section to CLAUDE.md**

Use Edit to insert BEFORE the next `^## ` heading after the existing `### Reachability gates` sub-section. New content:

````markdown

### Pass 3a — LLM struct consolidation

After Pass 2 proposes per-function struct-pointer retypes (e.g., `IPC_REQUEST_HEADER *` across multiple functions), Pass 3a clusters those proposals by candidate struct base name and produces a single consolidated typedef with named fields.

```bash
# 1. Emit one batch per struct cluster.
python3 scripts/reconstruct_pass3a_batch.py --binary <stem> --version <tag>

# 2. Strategist dispatches one Agent per batch using prompts/workers/reconstruct_structify.md,
#    writing each worker's JSON output to pass3a_batches/result_<NNN>.json.

# 3. Apply each result to manifest.json.
python3 scripts/reconstruct_pass3a_apply.py --binary <stem> --version <tag> \
    --result catalog/reconstructed/<stem>_<tag>/pass3a_batches/result_000.json
```

Pass 3a produces:
- `manifest.json#passes[]` gains a `pass3a` entry with `structs[]` (NEW schema; not in proposed_renames or retypes).
- Each struct has `name`, `supporting_functions`, `fields[{offset, type, name, rationale}]`, `confidence`, `source: "llm_structify"`, `rationale`.
- Apply is idempotent (re-running same result is no-op); later results for the same struct name override earlier (full-replace, no per-field merge).

Pass 3a does NOT affect coverage gates — structs are enrichment, not naming. Windows builtin types (`LPCWSTR`, `HANDLE`, `NTSTATUS`, `DWORD`, …) are intentionally NOT clustered as candidate structs.

````

- [ ] **Step 4: Verify**

```bash
grep -c "## Pass 3a sequence" prompts/phases/reconstruct.md
grep -c "### Pass 3a — LLM struct consolidation" CLAUDE.md
```

Both should return `1`.

- [ ] **Step 5: Commit**

```bash
git add prompts/workers/reconstruct_structify.md prompts/phases/reconstruct.md CLAUDE.md
git commit -m "docs(reconstruct): Pass 3a worker contract + strategist + CLAUDE.md"
```

---

## Done — Pass 3a acceptance

When all 5 tasks above are complete:

- [ ] `pytest tests/reconstruct/ -v` reports ~179 PASSED (153 prior + 26 new)
- [ ] `reconstruct_pass3a_batch.py` clusters Pass 2 struct-pointer retypes into per-struct batches
- [ ] `reconstruct_pass3a_apply.py` validates worker output and merges typedefs into `manifest.json#passes[].pass3a.structs[]`
- [ ] Worker prompt at `prompts/workers/reconstruct_structify.md`
- [ ] Strategist + CLAUDE.md document Pass 3a workflow

**Next sub-plan candidates** (each independent):
- Pass 3b commenting / Pass 3c globals / Pass 4 cleanup
- Sub-plan 2.5 Pass 0 expansion (Rich header / string-xref / equates)
- Sub-plan 2-libghidra (real Ghidra integration)
- Comprehend phase
- Acceptance test against `bdservicehost.exe`
