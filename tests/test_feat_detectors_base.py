"""Test the detector framework base classes and registry."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"


def _import_pkg():
    """Add scripts/ to sys.path so feat_detectors imports cleanly."""
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import feat_detectors
    import feat_detectors.base as base
    return feat_detectors, base


def test_feature_candidate_dataclass_has_required_fields():
    _, base = _import_pkg()
    c = base.FeatureCandidate(
        slug="auto-update",
        name="Auto-update",
        description="",
        detector="exports",
        detector_version="1.0",
        evidence_type="export",
        evidence_value="Bd_Update_Run",
        weight=2,
        user_observable="",
        capability_hints=[],
        source_hints=[],
        input_hints=[],
        anchor_hints=[],
        ux_string_hints=[],
    )
    assert c.slug == "auto-update"
    assert c.weight == 2


def test_detector_abc_cannot_instantiate_without_detect():
    _, base = _import_pkg()
    with pytest.raises(TypeError):
        base.Detector()  # type: ignore[abstract]


def test_load_detectors_filters_by_platform():
    pkg, base = _import_pkg()

    class StubWindowsDetector(base.Detector):
        name = "stub_windows"
        version = "1.0"
        platforms = {"windows"}
        binary_kinds = {"exe", "dll"}
        representative_cve = "CVE-0000-0000"

        def detect(self, ctx):
            return []

    pkg._REGISTRY = [StubWindowsDetector()]  # type: ignore[attr-defined]
    assert len(pkg.load_detectors("windows", "exe")) == 1
    assert len(pkg.load_detectors("linux", "elf")) == 0


def test_load_detectors_filters_by_binary_kind():
    pkg, base = _import_pkg()

    class StubKernelDetector(base.Detector):
        name = "stub_kernel"
        version = "1.0"
        platforms = {"windows"}
        binary_kinds = {"sys"}
        representative_cve = "CVE-0000-0001"

        def detect(self, ctx):
            return []

    pkg._REGISTRY = [StubKernelDetector()]  # type: ignore[attr-defined]
    assert len(pkg.load_detectors("windows", "exe")) == 0
    assert len(pkg.load_detectors("windows", "sys")) == 1
