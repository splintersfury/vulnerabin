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
    assert batch.extract_struct_name("LPCWSTR") is None
    assert batch.extract_struct_name("HANDLE") is None
    assert batch.extract_struct_name("NTSTATUS") is None
    assert batch.extract_struct_name("DWORD") is None
    assert batch.extract_struct_name("uint32_t") is None
    assert batch.extract_struct_name("char *") is None
    assert batch.extract_struct_name("void *") is None


def test_extract_struct_name_accepts_uppercase_underscore_identifier():
    assert batch.extract_struct_name("MY_STRUCT *") == "MY_STRUCT"
    assert batch.extract_struct_name("FOO_BAR_BAZ *") == "FOO_BAR_BAZ"


def test_extract_struct_name_rejects_lowercase_typedefs():
    assert batch.extract_struct_name("some_struct *") is None


def test_cluster_struct_hypotheses_finds_ipc_request_header():
    manifest = _manifest_pass2_done()
    clusters = batch.cluster_struct_hypotheses(manifest)
    by_name = {c["name"]: c for c in clusters}
    assert "IPC_REQUEST_HEADER" in by_name
    cluster = by_name["IPC_REQUEST_HEADER"]
    assert set(cluster["supporting_functions"]) == {"0x140003000", "0x140005000"}


def test_cluster_struct_hypotheses_skips_non_struct_types():
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
    manifest = _manifest_pass2_done()
    clusters = batch.cluster_struct_hypotheses(manifest)
    cluster = next(c for c in clusters if c["name"] == "IPC_REQUEST_HEADER")
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
