"""Tests for comprehend_binary_apply (validation + merge)."""
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
APPLY_PY = REPO_ROOT / "scripts" / "comprehend_binary_apply.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import comprehend_binary_apply as apply_mod  # type: ignore


def _valid_result():
    return {
        "stem": "samplebin",
        "summary": "SYSTEM-context Windows service that receives commands over a named pipe and dispatches to subsystem handlers (process spawn, registry writes, kernel IOCTLs).",
        "full_picture": {
            "loaded_by": ["service manager (auto-start)"],
            "start_trigger": ["boot"],
            "ipc_peers": [
                {"name": "BdNTwrk.dll", "transport": "named pipe \\\\.\\pipe\\BdAg", "direction": "in"}
            ],
            "accepted_inputs": ["IPC messages over \\\\.\\pipe\\BdAg (typed dispatch)"],
            "dangerous_operations_reachable": ["CreateProcessAsUserW", "ChangeServiceConfig2W"],
            "defense_gaps_observed": [],
        },
    }


def test_validate_accepts_valid():
    assert apply_mod.validate_worker_result(_valid_result()) == []


def test_validate_rejects_missing_summary():
    r = _valid_result()
    del r["summary"]
    errors = apply_mod.validate_worker_result(r)
    assert any("summary" in e.lower() for e in errors)


def test_validate_rejects_missing_stem():
    r = _valid_result()
    del r["stem"]
    errors = apply_mod.validate_worker_result(r)
    assert any("stem" in e.lower() for e in errors)


def test_validate_rejects_long_summary():
    r = _valid_result()
    r["summary"] = "x" * 300
    errors = apply_mod.validate_worker_result(r)
    assert any("240" in e for e in errors)


def test_validate_rejects_missing_full_picture_keys():
    r = _valid_result()
    del r["full_picture"]["loaded_by"]
    errors = apply_mod.validate_worker_result(r)
    assert any("loaded_by" in e for e in errors)


def test_validate_rejects_ipc_peer_without_direction():
    r = _valid_result()
    r["full_picture"]["ipc_peers"] = [{"name": "x", "transport": "y"}]
    errors = apply_mod.validate_worker_result(r)
    assert any("direction" in e.lower() for e in errors)


def test_validate_rejects_invalid_direction():
    r = _valid_result()
    r["full_picture"]["ipc_peers"] = [{"name": "x", "transport": "y", "direction": "sideways"}]
    errors = apply_mod.validate_worker_result(r)
    assert any("direction" in e.lower() for e in errors)


def test_validate_accepts_empty_arrays():
    """Empty arrays in full_picture are explicitly allowed (per spec)."""
    r = _valid_result()
    r["full_picture"]["accepted_inputs"] = []
    r["full_picture"]["dangerous_operations_reachable"] = []
    r["full_picture"]["defense_gaps_observed"] = []
    r["full_picture"]["ipc_peers"] = []
    assert apply_mod.validate_worker_result(r) == []


def test_merge_writes_summary_and_full_picture():
    binary_yaml = {"binary": "samplebin", "product": "test"}
    out = apply_mod.merge_into_binary_yaml(binary_yaml, _valid_result())
    assert out["summary"] == _valid_result()["summary"]
    assert "full_picture" in out
    assert out["full_picture"]["loaded_by"] == ["service manager (auto-start)"]


def test_merge_writes_fingerprint_and_timestamp():
    binary_yaml = {"binary": "samplebin", "product": "test"}
    out = apply_mod.merge_into_binary_yaml(binary_yaml, _valid_result())
    assert "summary_fingerprint" in out
    assert len(out["summary_fingerprint"]) == 64   # sha256 hex
    assert "last_comprehended" in out


def test_merge_preserves_existing_yaml_fields():
    binary_yaml = {
        "binary": "samplebin", "product": "test",
        "sources": [{"id": "SRC-001"}],
        "sinks": [{"id": "SNK-001"}],
    }
    out = apply_mod.merge_into_binary_yaml(binary_yaml, _valid_result())
    assert out["sources"] == [{"id": "SRC-001"}]
    assert out["sinks"] == [{"id": "SNK-001"}]


def test_cli_end_to_end(tmp_path):
    # Set up tmp catalog layout
    bdir = tmp_path / "catalog" / "binaries"
    bdir.mkdir(parents=True)
    yml_path = bdir / "samplebin.yml"
    yml_path.write_text(yaml.safe_dump({"binary": "samplebin", "product": "test"}))
    res_path = tmp_path / "result.json"
    res_path.write_text(json.dumps(_valid_result()))

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(APPLY_PY), "--binary", "samplebin", "--result", str(res_path)],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    after = yaml.safe_load(yml_path.read_text())
    assert "summary" in after
    assert "full_picture" in after
    assert "summary_fingerprint" in after


def test_cli_refuses_invalid_result(tmp_path):
    bdir = tmp_path / "catalog" / "binaries"
    bdir.mkdir(parents=True)
    (bdir / "samplebin.yml").write_text(yaml.safe_dump({"binary": "samplebin"}))
    res_path = tmp_path / "result.json"
    res_path.write_text(json.dumps({"stem": "samplebin"}))   # missing summary

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(APPLY_PY), "--binary", "samplebin", "--result", str(res_path)],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "validation failed" in (result.stdout + result.stderr).lower()
