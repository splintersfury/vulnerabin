"""Tests for comprehend_fingerprint."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import comprehend_fingerprint as cfp  # type: ignore


def test_binary_fingerprint_is_deterministic():
    y = {
        "binary": "x",
        "product": "p",
        "reconstruction": {"ref": "catalog/reconstructed/x_v1", "version_tag": "v1", "status": "complete"},
    }
    assert cfp.binary_fingerprint(y) == cfp.binary_fingerprint(y)


def test_binary_fingerprint_changes_when_status_changes():
    y1 = {"binary": "x", "reconstruction": {"ref": "r", "version_tag": "v1", "status": "partial"}}
    y2 = {"binary": "x", "reconstruction": {"ref": "r", "version_tag": "v1", "status": "complete"}}
    assert cfp.binary_fingerprint(y1) != cfp.binary_fingerprint(y2)


def test_binary_fingerprint_ignores_irrelevant_fields():
    y1 = {"binary": "x", "reconstruction": {"ref": "r", "version_tag": "v1", "status": "partial"}}
    y2 = dict(y1, some_unrelated_tag="ignore_me")
    assert cfp.binary_fingerprint(y1) == cfp.binary_fingerprint(y2)


def test_binary_fingerprint_changes_when_chains_change():
    y1 = {"binary": "x", "chains": [{"id": "CHAIN-1", "status": "hypothesised"}]}
    y2 = {"binary": "x", "chains": [{"id": "CHAIN-1", "status": "confirmed"}]}
    assert cfp.binary_fingerprint(y1) != cfp.binary_fingerprint(y2)


def test_product_fingerprint_is_order_independent_in_binary_fps():
    p = {"product": "p", "binaries": ["a", "b"]}
    fps_ab = {"a": "h1", "b": "h2"}
    fps_ba = {"b": "h2", "a": "h1"}
    assert cfp.product_fingerprint(p, fps_ab) == cfp.product_fingerprint(p, fps_ba)


def test_product_fingerprint_changes_when_binary_fp_changes():
    p = {"product": "p", "binaries": ["a"]}
    assert cfp.product_fingerprint(p, {"a": "h1"}) != cfp.product_fingerprint(p, {"a": "h2"})


def test_is_binary_summary_stale_when_no_summary():
    y = {"binary": "x", "reconstruction": {"ref": "r", "version_tag": "v1", "status": "partial"}}
    assert cfp.is_binary_summary_stale(y) is True


def test_is_binary_summary_stale_when_fingerprint_matches():
    y = {
        "binary": "x", "full_picture": {"loaded_by": []}, "summary": "ELI5",
        "reconstruction": {"ref": "r", "version_tag": "v1", "status": "partial"},
    }
    y["summary_fingerprint"] = cfp.binary_fingerprint(y)
    assert cfp.is_binary_summary_stale(y) is False


def test_is_binary_summary_stale_when_binary_changed_after_apply():
    y = {
        "binary": "x", "full_picture": {"loaded_by": []}, "summary": "ELI5",
        "reconstruction": {"ref": "r", "version_tag": "v1", "status": "partial"},
    }
    y["summary_fingerprint"] = cfp.binary_fingerprint(y)
    # Mutate something that affects the fingerprint after apply.
    y["reconstruction"]["status"] = "complete"
    assert cfp.is_binary_summary_stale(y) is True


def test_is_product_narrative_stale_when_no_narrative():
    p = {"product": "p", "binaries": ["a"]}
    assert cfp.is_product_narrative_stale(p, {"a": "h1"}) is True


def test_is_product_narrative_stale_when_fingerprint_matches():
    p = {"product": "p", "binaries": ["a"]}
    fp = cfp.product_fingerprint(p, {"a": "h1"})
    p["architecture_narrative"] = {"summary": "...", "fingerprint": fp}
    assert cfp.is_product_narrative_stale(p, {"a": "h1"}) is False


def test_is_product_narrative_stale_when_binary_fp_changed():
    p = {"product": "p", "binaries": ["a"]}
    fp = cfp.product_fingerprint(p, {"a": "h1"})
    p["architecture_narrative"] = {"summary": "...", "fingerprint": fp}
    assert cfp.is_product_narrative_stale(p, {"a": "h2"}) is True
