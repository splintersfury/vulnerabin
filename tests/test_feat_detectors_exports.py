"""Test the Tier 1 exports detector."""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "feat_detectors"


def _import():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    from feat_detectors.tier1_universal import exports as ex
    from feat_detectors.base import DetectorContext
    return ex, DetectorContext


def _ctx_from_fixture(name: str):
    _, DetectorContext = _import()
    fi = json.loads((FIXTURES / name).read_text())
    return DetectorContext(
        binary_path=Path("/dev/null"),
        decomp_dir=None,
        function_index=fi,
        chains=None,
        re_block={},
        existing_yaml={},
    )


def test_exports_detector_groups_by_prefix():
    ex, _ = _import()
    ctx = _ctx_from_fixture("exports_function_index.json")
    candidates = ex.ExportsDetector().detect(ctx)
    slugs = {c.slug for c in candidates}
    # 3 Bd_Update_* exports → one feature; 2 Bd_Policy_* → one feature.
    # Generic_Init (singleton) → no feature emitted.
    assert "bd-update" in slugs
    assert "bd-policy" in slugs
    assert "generic-init" not in slugs


def test_exports_detector_records_anchors():
    ex, _ = _import()
    ctx = _ctx_from_fixture("exports_function_index.json")
    candidates = ex.ExportsDetector().detect(ctx)
    update = next(c for c in candidates if c.slug == "bd-update")
    rvas = {a["rva"] for a in update.anchor_hints}
    assert rvas == {"0x10001000", "0x10001100", "0x10001200"}


def test_exports_detector_evidence_value_is_prefix():
    ex, _ = _import()
    ctx = _ctx_from_fixture("exports_function_index.json")
    candidates = ex.ExportsDetector().detect(ctx)
    update = next(c for c in candidates if c.slug == "bd-update")
    assert update.evidence_type == "export_prefix"
    assert update.evidence_value == "Bd_Update_"
    assert update.detector == "exports"
    assert update.weight == 2  # exported-prefix is medium-strength signal
