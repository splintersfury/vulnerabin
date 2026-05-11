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
    # named_total includes: entry (1) + 0x140002000 (1) + 0x140003000 (1) + 0x140004000 (1) = 4
    assert cov["totals"]["user_defined_functions"] == 4
    assert cov["named"]["from_pass0"] == 1
    assert cov["named"]["from_pass1"] == 3
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


def test_pass1_apply_recompute_coverage_uses_real_gates():
    """When pass1 renames cover all reachable functions, gates should flip true."""
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
