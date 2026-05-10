"""Test vb walk CLI subcommands."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WALK_PY = REPO_ROOT / "scripts" / "catalog_walk.py"


def _make_binary_yaml(tmp_path: Path, name: str, contents: dict) -> Path:
    """Drop a binary YAML into a fresh catalog/binaries dir under tmp_path."""
    bdir = tmp_path / "catalog" / "binaries"
    bdir.mkdir(parents=True, exist_ok=True)
    f = bdir / f"{name}.yml"
    f.write_text(yaml.safe_dump(contents))
    return f


def _run_walk(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(WALK_PY)] + args,
        cwd=cwd, capture_output=True, text=True,
    )


def test_status_empty_binary_reports_not_started(tmp_path):
    _make_binary_yaml(tmp_path, "test_dll", {
        "binary": "test.dll",
        "platform": "windows",
        "binary_kind": "dll",
    })
    r = _run_walk(["status", "test_dll", "--json"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["current_stage"] == "not_started"
    assert out["pending_counts"]["features_unconfirmed"] == 0


def test_status_open_2a_reports_pending_inputs(tmp_path):
    _make_binary_yaml(tmp_path, "test_dll", {
        "binary": "test.dll",
        "platform": "windows",
        "binary_kind": "dll",
        "reverse_engineering": {
            "inputs": [
                {"id": "INP-001", "kind": "ioctl", "confirmed": False},
                {"id": "INP-002", "kind": "ipc_pipe", "confirmed": True},
            ],
        },
        "walk_state": {
            "stages": {
                "2a-inputs": {"status": "open", "opened_at": "2026-05-10T00:00:00Z"},
                "2b-sinks": {"status": "not_started"},
                "2c-features": {"status": "not_started"},
            },
        },
    })
    r = _run_walk(["status", "test_dll", "--json"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["current_stage"] == "2a-inputs"
    assert out["pending_counts"]["inputs_unconfirmed"] == 1


def test_pending_lists_unconfirmed_features(tmp_path):
    _make_binary_yaml(tmp_path, "t", {
        "binary": "t.dll", "platform": "windows", "binary_kind": "dll",
        "features": [
            {"id": "FEAT-001", "slug": "a", "name": "A", "confirmed": False, "rejected": False,
             "signal_sources": [{"detector": "exports", "evidence_type": "export_prefix",
                                  "evidence_value": "A_", "weight": 2}]},
            {"id": "FEAT-002", "slug": "b", "name": "B", "confirmed": True, "rejected": False,
             "signal_sources": []},
        ],
        "walk_state": {"stages": {
            "2a-inputs": {"status": "closed"},
            "2b-sinks": {"status": "closed"},
            "2c-features": {"status": "open"},
        }},
    })
    r = _run_walk(["pending", "t", "--stage", "2c-features", "--json"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert len(out) == 1
    assert out[0]["id"] == "FEAT-001"


def test_reject_writes_rejection(tmp_path):
    yaml_path = _make_binary_yaml(tmp_path, "t", {
        "binary": "t.dll", "platform": "windows", "binary_kind": "dll",
        "features": [{"id": "FEAT-001", "slug": "a", "confirmed": False, "rejected": False,
                      "signal_sources": [{"detector": "exports", "evidence_type": "export_prefix",
                                           "evidence_value": "A_"}]}],
        "walk_state": {"stages": {
            "2a-inputs": {"status": "closed"},
            "2b-sinks": {"status": "closed"},
            "2c-features": {"status": "open"},
        }},
    })
    r = _run_walk(["reject", "t", "FEAT-001", "--reason", "internal dispatcher only"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    after = yaml.safe_load(yaml_path.read_text())
    f = after["features"][0]
    assert f["rejected"] is True
    assert f["rejection_reason"] == "internal dispatcher only"
    assert f["rejected_at"]


def test_close_stage_refuses_with_pending(tmp_path):
    _make_binary_yaml(tmp_path, "t", {
        "binary": "t.dll", "platform": "windows", "binary_kind": "dll",
        "features": [{"id": "FEAT-001", "confirmed": False, "rejected": False,
                      "signal_sources": []}],
        "walk_state": {"stages": {
            "2a-inputs": {"status": "closed"},
            "2b-sinks": {"status": "closed"},
            "2c-features": {"status": "open"},
        }},
    })
    r = _run_walk(["close-stage", "t", "--stage", "2c-features"], cwd=tmp_path)
    assert r.returncode != 0
    assert "pending" in (r.stderr + r.stdout).lower()


def test_close_stage_succeeds_when_clean(tmp_path):
    yaml_path = _make_binary_yaml(tmp_path, "t", {
        "binary": "t.dll", "platform": "windows", "binary_kind": "dll",
        "features": [{"id": "FEAT-001", "confirmed": True, "rejected": False,
                      "signal_sources": []}],
        "walk_state": {"stages": {
            "2a-inputs": {"status": "closed"},
            "2b-sinks": {"status": "closed"},
            "2c-features": {"status": "open"},
        }},
    })
    r = _run_walk(["close-stage", "t", "--stage", "2c-features"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    after = yaml.safe_load(yaml_path.read_text())
    assert after["walk_state"]["stages"]["2c-features"]["status"] == "closed"
    assert after["walk_state"]["stages"]["2c-features"]["closed_at"]


def test_confirm_low_stakes_writes_directly(tmp_path):
    yaml_path = _make_binary_yaml(tmp_path, "t", {
        "binary": "t.dll", "platform": "windows", "binary_kind": "dll",
        "features": [{"id": "FEAT-001", "slug": "a", "confirmed": False, "rejected": False,
                      "signal_sources": []}],
        "walk_state": {"stages": {
            "2a-inputs": {"status": "closed"}, "2b-sinks": {"status": "closed"},
            "2c-features": {"status": "open"},
        }},
    })
    r = _run_walk(["confirm", "t", "FEAT-001",
                   "--description", "auto update orchestrator",
                   "--confidence", "high",
                   "--inspect-worker", "agent-abc"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    after = yaml.safe_load(yaml_path.read_text())
    f = after["features"][0]
    assert f["confirmed"] is True
    assert f["description"] == "auto update orchestrator"
    assert f["confirmation_review"]["verdict"] == "auto-confirm"
    assert f["confirmation_review"]["agent_id"] == "agent-abc"


def test_confirm_high_severity_requires_review(tmp_path):
    _make_binary_yaml(tmp_path, "t", {
        "binary": "t.dll", "platform": "windows", "binary_kind": "dll",
        "features": [{"id": "FEAT-001", "slug": "a", "confirmed": False, "rejected": False,
                      "signal_sources": []}],
        "walk_state": {"stages": {
            "2a-inputs": {"status": "closed"}, "2b-sinks": {"status": "closed"},
            "2c-features": {"status": "open"},
        }},
    })
    r = _run_walk(["confirm", "t", "FEAT-001",
                   "--description", "kernel ioctl spawn",
                   "--severity-ceiling", "High",
                   "--inspect-worker", "agent-abc"], cwd=tmp_path)
    assert r.returncode != 0
    assert "review" in (r.stderr + r.stdout).lower()


def test_confirm_with_review_artifact(tmp_path):
    yaml_path = _make_binary_yaml(tmp_path, "t", {
        "binary": "t.dll", "platform": "windows", "binary_kind": "dll",
        "features": [{"id": "FEAT-001", "slug": "a", "confirmed": False, "rejected": False,
                      "signal_sources": []}],
        "walk_state": {"stages": {
            "2a-inputs": {"status": "closed"}, "2b-sinks": {"status": "closed"},
            "2c-features": {"status": "open"},
        }},
    })
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps({
        "agent_id": "skeptic-xyz",
        "binary": "t.dll",
        "candidate_id": "FEAT-001",
        "verdict": "ship",
        "confidence": "high",
        "rationale": "anchors honest, signals match",
    }))
    r = _run_walk(["confirm", "t", "FEAT-001",
                   "--description", "kernel ioctl spawn",
                   "--severity-ceiling", "High",
                   "--inspect-worker", "agent-abc",
                   "--review-verdict", str(review_path)], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    after = yaml.safe_load(yaml_path.read_text())
    f = after["features"][0]
    assert f["confirmed"] is True
    assert f["confirmation_review"]["verdict"] == "ship"
    assert f["confirmation_review"]["reviewed_by"] == "skeptic-xyz"
