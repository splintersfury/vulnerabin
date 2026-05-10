# FEAT layer v1 implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the FEAT layer end-to-end on a canary binary (`safeelevatedrun_dll`) — schema, one detector (`exports.py`), `vb walk` CLI, worker prompts, web UI features section, override endpoints. v1.1 will add the remaining detectors and Cytoscape Layer 4.

**Architecture:** Approach A from the design spec. Auto-extracted candidates land directly in `catalog/binaries/<binary>.yml` with `confirmed: false`. CLI is canonical for stage gating; web UI is read-mostly with override buttons. One detector framework module per signal source. Skeptic agent fires inline only on stake-gated confirms (severity High+, attached CWE, `product_feature_id` set, or low-confidence inspect verdict).

**Tech stack:** Python 3 + argparse + pyyaml + pefile (new dep) + pytest. Jinja2 + Tailwind for HTML. FastAPI for live server. Markdown via existing renderer.

**Spec reference:** `docs/superpowers/specs/2026-05-10-feat-layer-design.md`

---

## File structure

### New files
- `scripts/feat_detectors/__init__.py` — registry + `load_detectors(platform, binary_kind)`
- `scripts/feat_detectors/base.py` — `Detector` ABC + `FeatureCandidate` dataclass + `DetectorContext`
- `scripts/feat_detectors/tier1_universal/__init__.py` — empty package marker
- `scripts/feat_detectors/tier1_universal/exports.py` — first detector
- `scripts/catalog_walk.py` — `vb walk` CLI
- `scripts/catalog_migrate.py` — tier classifier
- `prompts/workers/walk_inspect_candidate.md` — inspect-worker
- `prompts/workers/walk_confirm_review.md` — skeptic
- `prompts/phases/walk_strategist.md` — strategist loop
- `tests/test_feat_detectors_base.py`
- `tests/test_feat_detectors_exports.py`
- `tests/test_catalog_walk.py`
- `tests/test_catalog_migrate.py`
- `tests/fixtures/feat_detectors/` — synthetic binary fixtures + golden YAMLs

### Modified files
- `catalog/schema.yml` — add `features:`, `walk_state:`, `confirmation_review:`, reverse pointers
- `scripts/catalog_re_extract.py` — wire detector framework dispatch
- `scripts/catalog_render.py` — render features section, walk header, gap panel additions
- `scripts/catalog_site_render.py` — same Jinja additions for static HTML
- `scripts/catalog_serve.py` — override endpoints + same Jinja additions
- `scripts/catalog_add.py` — `vb-add feature` and `vb-add unreachable` subcommands
- `catalog/site/_templates/binary.html.j2` — features section + walk status header + L6 matrix CSS-grid
- `pipeline.yml` — new `walk` phase + `walk_state_started` / `walk_state_done` gates
- `scripts/fsm.py` — recognise new walk phase
- `catalog/README.md` — document FEAT layer + walk_state
- `CLAUDE.md` — document new walk phase + `vb walk` + new `vb-add` subcommands

---

## Task 1: Schema additions

**Files:**
- Modify: `catalog/schema.yml` — add `features:`, `walk_state:`, `confirmation_review:` blocks; add reverse-pointer fields on existing blocks

- [ ] **Step 1: Open `catalog/schema.yml` and locate the `# ----- Capabilities` block (around line 104)**

- [ ] **Step 2: After the `capabilities:` block, before `# ----- Chains -----`, insert the `features:` block:**

```yaml
# ----- Features (NEW — the user-facing layer above capabilities) -----
# What the binary actually DOES from a user's point of view. One feature
# typically aggregates multiple capabilities (e.g. "Auto-update product"
# uses CAP-001 spawn-process + CAP-007 file-write + CAP-012 network-fetch).
# Auto-suggested by detectors in scripts/feat_detectors/; researcher
# confirms via `vb walk <binary>` (stage 2c).
features:
  - id: FEAT-001
    slug: ""                            # human-stable, e.g. "auto-update" — survives renames
    product_feature_id: ""              # canonical across binaries in same product (PFEAT-*)
    name: ""                            # human-readable
    description: ""                     # 1-3 sentences
    status: ""                          # active | deprecated | mitigated | hypothesised | unexplored
    first_seen_version: ""
    last_confirmed_version: ""
    deprecated_in_version: ""
    deprecation_note: ""
    capabilities: []                    # CAP-* IDs
    sources: []                         # SRC-* IDs
    inputs: []                          # INP-* IDs
    implementation_anchors:
      - function: ""
        rva: ""
        role: ""                        # orchestrator | source | sink | helper | dispatcher
    cwe: []
    severity_ceiling: ""                # High | Critical | Medium | Low
    ux_strings: []                      # literal UI strings proving the feature exists user-side
    disabled_by_default: false
    signal_sources:
      - detector: ""
        detector_version: ""
        evidence_type: ""               # rpc_uuid|com_clsid|service_name|string|rva|registry_key|export|symbol|task_xml|systemd_unit|dbus_interface
        evidence_value: ""
        weight: 0                       # 1=weak, 2=medium, 3=strong
        last_detected_at: ""
    confidence: ""                      # high | medium | low (auto from sum-of-weights)
    confirmed: false
    rejected: false
    rejection_reason: ""
    rejected_at: ""
    user_observable: ""
    notes: ""
    confirmation_review:
      required: false
      agent_id: ""
      reviewed_by: ""
      verdict: ""                       # auto-confirm | ship | hedge-then-applied | human-override
      reviewed_at: ""
      artifact_path: ""
      trigger_reason: ""
```

- [ ] **Step 3: After the `chains:` block (around line 149), add reverse-pointer documentation comment + the `walk_state:` block:**

```yaml
# Reverse pointers: every chain MAY carry feature_ids: [] back to the FEATs
# it implements. Same for sinks[].feature_ids, sources[].feature_ids,
# capabilities[].feature_ids, reverse_engineering.inputs[].feature_ids.
# These are written by `vb walk confirm` automatically and never by hand.

# ----- Walk state (NEW — drives `vb walk` stage gating) -----
walk_state:
  stages:
    "2a-inputs":
      status: ""                        # not_started | open | closed
      opened_at: ""
      closed_at: ""
      reopened_at: ""
    "2b-sinks":
      status: ""
      opened_at: ""
      closed_at: ""
      reopened_at: ""
    "2c-features":
      status: ""
      opened_at: ""
      closed_at: ""
      reopened_at: ""
  pending_counts:
    inputs_unconfirmed: 0
    sinks_unconfirmed: 0
    features_unconfirmed: 0
  history:
    - stage: ""
      action: ""                        # opened | closed | reopened | human-override-reject | human-override-confirm
      at: ""
      actor: ""                         # claude | human | inspect-worker-<id> | skeptic-<id>
      target: ""                        # FEAT-* | INP-* | SNK-*
      reason: ""
      confirmed: 0
      rejected: 0
```

- [ ] **Step 4: Verify schema parses by re-running the existing render check:**

Run: `python3 scripts/catalog_render.py --check`
Expected: exits 0, prints "OK" or no errors. The schema is documentation-only YAML and `--check` only parses canonical binary YAMLs, so this confirms nothing else broke.

- [ ] **Step 5: Commit**

```bash
git add catalog/schema.yml
git commit -m "$(cat <<'EOF'
feat(catalog): add features and walk_state schema blocks

Adds optional top-level features[] and walk_state blocks per FEAT layer
design spec. Both are optional; absence renders as legacy
inputs × capabilities matrix. No behaviour change yet.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Detector base classes and registry

**Files:**
- Create: `scripts/feat_detectors/__init__.py`
- Create: `scripts/feat_detectors/base.py`
- Create: `scripts/feat_detectors/tier1_universal/__init__.py`
- Create: `tests/test_feat_detectors_base.py`

- [ ] **Step 1: Write the failing test at `tests/test_feat_detectors_base.py`:**

```python
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
```

- [ ] **Step 2: Run the test to verify it fails:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_feat_detectors_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'feat_detectors'`

- [ ] **Step 3: Create `scripts/feat_detectors/base.py`:**

```python
"""Detector framework base classes."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FeatureCandidate:
    """One auto-detected FEAT candidate emitted by a detector."""
    slug: str
    name: str
    description: str
    detector: str
    detector_version: str
    evidence_type: str
    evidence_value: str
    weight: int
    user_observable: str
    capability_hints: list[str] = field(default_factory=list)
    source_hints: list[str] = field(default_factory=list)
    input_hints: list[str] = field(default_factory=list)
    anchor_hints: list[dict] = field(default_factory=list)
    ux_string_hints: list[str] = field(default_factory=list)


@dataclass
class DetectorContext:
    """Per-detector input bundle."""
    binary_path: Path
    decomp_dir: Path | None
    function_index: dict[str, Any]
    chains: dict[str, Any] | None
    re_block: dict[str, Any]
    existing_yaml: dict[str, Any]


class Detector(ABC):
    """Each detector parses one signal source and emits FeatureCandidate(s)."""
    name: str = ""
    version: str = "0"
    platforms: set[str] = set()
    binary_kinds: set[str] = set()
    representative_cve: str = ""

    @abstractmethod
    def detect(self, ctx: DetectorContext) -> list[FeatureCandidate]:
        """Return zero or more candidates extracted from ctx."""
```

- [ ] **Step 4: Create `scripts/feat_detectors/__init__.py`:**

```python
"""FEAT detector framework + registry.

Detectors register themselves at import time. Use load_detectors() to get
the subset relevant to a given (platform, binary_kind) tuple.
"""
from __future__ import annotations

from .base import Detector, DetectorContext, FeatureCandidate

# Populated at module import time when concrete detectors are loaded.
_REGISTRY: list[Detector] = []


def register(detector: Detector) -> None:
    """Add a detector to the global registry."""
    _REGISTRY.append(detector)


def load_detectors(platform: str, binary_kind: str) -> list[Detector]:
    """Return detectors that apply to (platform, binary_kind)."""
    return [
        d for d in _REGISTRY
        if platform in d.platforms and binary_kind in d.binary_kinds
    ]


__all__ = [
    "Detector",
    "DetectorContext",
    "FeatureCandidate",
    "register",
    "load_detectors",
]
```

- [ ] **Step 5: Create empty package marker `scripts/feat_detectors/tier1_universal/__init__.py`:**

```python
"""Tier 1 detectors — universal PE/ELF signals."""
```

- [ ] **Step 6: Run the tests to verify they pass:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_feat_detectors_base.py -v`
Expected: 4 tests PASS

- [ ] **Step 7: Commit**

```bash
git add scripts/feat_detectors/__init__.py scripts/feat_detectors/base.py \
        scripts/feat_detectors/tier1_universal/__init__.py \
        tests/test_feat_detectors_base.py
git commit -m "$(cat <<'EOF'
feat(detectors): add detector framework base + registry

Detector ABC + FeatureCandidate dataclass + load_detectors filter
by (platform, binary_kind). Registry is populated at import time when
concrete detectors are loaded.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: First detector — `exports.py` (Tier 1 universal)

**Files:**
- Create: `scripts/feat_detectors/tier1_universal/exports.py`
- Create: `tests/fixtures/feat_detectors/exports_function_index.json`
- Create: `tests/test_feat_detectors_exports.py`

- [ ] **Step 1: Create the fixture `tests/fixtures/feat_detectors/exports_function_index.json`. Make the parent directory first:**

```bash
mkdir -p tests/fixtures/feat_detectors
```

Then write:

```json
{
  "binary": "test.dll",
  "platform": "windows",
  "exports": [
    {"name": "Bd_Update_Run", "rva": "0x10001000"},
    {"name": "Bd_Update_Cancel", "rva": "0x10001100"},
    {"name": "Bd_Update_Status", "rva": "0x10001200"},
    {"name": "Bd_Policy_Apply", "rva": "0x10002000"},
    {"name": "Bd_Policy_Refresh", "rva": "0x10002100"},
    {"name": "Generic_Init", "rva": "0x10003000"}
  ]
}
```

- [ ] **Step 2: Write the failing test at `tests/test_feat_detectors_exports.py`:**

```python
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
```

- [ ] **Step 3: Run the test to verify it fails:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_feat_detectors_exports.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'feat_detectors.tier1_universal.exports'`

- [ ] **Step 4: Implement `scripts/feat_detectors/tier1_universal/exports.py`:**

```python
"""Detect features by clustering exported function names by prefix.

Signal: PE/ELF exports table. When ≥2 exports share a non-trivial prefix
(matching `<Prefix>_<Word>`), emit one FEAT candidate per cluster.

Representative CVE: not bug-class-specific — exported function clusters
are how vendor SDKs surface features (BdUpdate*, McsScan*, AvgPolicy*).
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .. import register
from ..base import Detector, DetectorContext, FeatureCandidate


# Capture the prefix portion of `<Prefix>_<Word>` (case-sensitive, ≥3 chars).
PREFIX_RE = re.compile(r"^([A-Z][A-Za-z0-9]{2,})_[A-Za-z0-9]+")


def _slug(prefix: str) -> str:
    """Convert e.g. `Bd_Update_` → `bd-update`."""
    bare = prefix.rstrip("_")
    # Insert a dash between camel transitions and downcase.
    out = re.sub(r"(?<=[a-z0-9])([A-Z])", r"-\1", bare)
    out = re.sub(r"_+", "-", out).lower()
    return out


class ExportsDetector(Detector):
    name = "exports"
    version = "1.0"
    platforms = {"windows", "linux", "macos"}
    binary_kinds = {"exe", "dll", "sys", "so", "dylib"}
    representative_cve = "n/a — generic feature surface"

    def detect(self, ctx: DetectorContext) -> list[FeatureCandidate]:
        exports: list[dict[str, Any]] = ctx.function_index.get("exports") or []
        clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in exports:
            name = e.get("name", "")
            m = PREFIX_RE.match(name)
            if not m:
                continue
            prefix = m.group(1) + "_"
            clusters[prefix].append(e)

        candidates: list[FeatureCandidate] = []
        for prefix, members in clusters.items():
            if len(members) < 2:
                continue
            slug = _slug(prefix)
            anchors = [
                {"function": m["name"], "rva": m.get("rva", ""), "role": "source"}
                for m in members
            ]
            candidates.append(FeatureCandidate(
                slug=slug,
                name=f"Exported {prefix}* surface",
                description=f"Cluster of {len(members)} exported functions sharing prefix `{prefix}`.",
                detector=self.name,
                detector_version=self.version,
                evidence_type="export_prefix",
                evidence_value=prefix,
                weight=2,
                user_observable=f"Callable via DLL export — any process with the right import declaration",
                capability_hints=[],
                source_hints=[],
                input_hints=[],
                anchor_hints=anchors,
                ux_string_hints=[],
            ))
        return candidates


register(ExportsDetector())
```

- [ ] **Step 5: Run the tests to verify they pass:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_feat_detectors_exports.py -v`
Expected: 3 tests PASS

- [ ] **Step 6: Run BOTH detector test suites together to confirm no cross-contamination:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_feat_detectors_base.py tests/test_feat_detectors_exports.py -v`
Expected: 7 tests PASS

- [ ] **Step 7: Commit**

```bash
git add scripts/feat_detectors/tier1_universal/exports.py \
        tests/fixtures/feat_detectors/exports_function_index.json \
        tests/test_feat_detectors_exports.py
git commit -m "$(cat <<'EOF'
feat(detectors): add Tier 1 exports detector

Clusters exported function names by prefix. Emits one FEAT candidate per
cluster of ≥2 exports sharing the same `<Prefix>_<Word>` shape.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Wire detector framework into `catalog_re_extract.py`

**Files:**
- Modify: `scripts/catalog_re_extract.py` — add `process_features(binary_yaml, ctx)` function and call it from the main `process_one` flow

- [ ] **Step 1: Read `scripts/catalog_re_extract.py` to find the `process_one` function and the YAML-write section.** Locate where `inputs[]`, `sources[]`, `sinks[]`, `capabilities[]` are merged into the binary YAML.

Run: `grep -n "def process_one\|def merge_\|capabilities" scripts/catalog_re_extract.py | head -20`

- [ ] **Step 2: Add the `process_features` function near the existing `merge_*` helpers. Insert AFTER the existing `merge_capabilities` function. Code:**

```python
def process_features(binary_yaml: dict, ctx) -> dict:
    """Run the FEAT detector framework against ctx and merge results into binary_yaml.

    Idempotent. Existing FEATs are matched by (detector, evidence_type, evidence_value)
    and updated in place; new candidates are appended with the next free FEAT-* ID.
    Hand-edited fields (description, user_observable, cwe, severity_ceiling,
    confirmed/rejected flags, confirmation_review block) are never overwritten.

    Returns the modified binary_yaml.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    import feat_detectors

    platform = (binary_yaml.get("platform") or "").lower()
    binary_kind = (binary_yaml.get("binary_kind") or "").lower()
    detectors = feat_detectors.load_detectors(platform, binary_kind)
    if not detectors:
        return binary_yaml

    existing = binary_yaml.setdefault("features", []) or []
    by_evidence = {
        (f.get("signal_sources", [{}])[0].get("detector"),
         f.get("signal_sources", [{}])[0].get("evidence_type"),
         f.get("signal_sources", [{}])[0].get("evidence_value")): f
        for f in existing
        if f.get("signal_sources")
    }
    rejected_evidence = {
        (f.get("signal_sources", [{}])[0].get("detector"),
         f.get("signal_sources", [{}])[0].get("evidence_type"),
         f.get("signal_sources", [{}])[0].get("evidence_value"))
        for f in existing if f.get("rejected")
    }

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    next_id = max(
        (int(f["id"].split("-")[1]) for f in existing if f.get("id", "").startswith("FEAT-")),
        default=0,
    ) + 1

    new_candidates = []
    for d in detectors:
        for cand in d.detect(ctx):
            key = (cand.detector, cand.evidence_type, cand.evidence_value)
            if key in rejected_evidence:
                continue
            if key in by_evidence:
                # Update last_detected_at on existing entry.
                feat = by_evidence[key]
                for sig in feat.get("signal_sources", []):
                    if (sig.get("detector"), sig.get("evidence_type"),
                            sig.get("evidence_value")) == key:
                        sig["last_detected_at"] = now
                continue
            # Append new candidate as confirmed=false.
            feat_id = f"FEAT-{next_id:03d}"
            next_id += 1
            new_candidates.append({
                "id": feat_id,
                "slug": cand.slug,
                "product_feature_id": "",
                "name": cand.name,
                "description": cand.description,
                "status": "unexplored",
                "first_seen_version": "",
                "last_confirmed_version": "",
                "deprecated_in_version": "",
                "deprecation_note": "",
                "capabilities": list(cand.capability_hints),
                "sources": list(cand.source_hints),
                "inputs": list(cand.input_hints),
                "implementation_anchors": list(cand.anchor_hints),
                "cwe": [],
                "severity_ceiling": "",
                "ux_strings": list(cand.ux_string_hints),
                "disabled_by_default": False,
                "signal_sources": [{
                    "detector": cand.detector,
                    "detector_version": cand.detector_version,
                    "evidence_type": cand.evidence_type,
                    "evidence_value": cand.evidence_value,
                    "weight": cand.weight,
                    "last_detected_at": now,
                }],
                "confidence": "low" if cand.weight < 3 else "medium",
                "confirmed": False,
                "rejected": False,
                "rejection_reason": "",
                "rejected_at": "",
                "user_observable": cand.user_observable,
                "notes": "",
                "confirmation_review": {
                    "required": False,
                    "agent_id": "",
                    "reviewed_by": "",
                    "verdict": "",
                    "reviewed_at": "",
                    "artifact_path": "",
                    "trigger_reason": "",
                },
            })

    if new_candidates:
        existing.extend(new_candidates)
        binary_yaml["features"] = existing

    return binary_yaml
```

- [ ] **Step 3: In `process_one` (the main entry), find where the binary YAML is finalized before being written. Add a call to `process_features` after `merge_capabilities` and before the file write. Locate by searching:**

Run: `grep -n "def process_one\|merge_capabilities" scripts/catalog_re_extract.py`

Expected: shows where `merge_capabilities` is called inside `process_one`. Add directly after that call:

```python
    binary_yaml = process_features(binary_yaml, ctx)
```

(Replace `ctx` with whatever local variable holds the `DetectorContext` — see existing code for the variable name.)

- [ ] **Step 4: If `DetectorContext` is not yet constructed in `process_one`, build it next to the existing variables. Insert before the call to `process_features`:**

```python
    from feat_detectors.base import DetectorContext
    ctx = DetectorContext(
        binary_path=Path(binary_yaml.get("canonical_path") or ""),
        decomp_dir=decomp_dir,  # already in scope
        function_index=function_index,  # already in scope
        chains=chains_data if 'chains_data' in dir() else None,
        re_block=binary_yaml.get("reverse_engineering", {}) or {},
        existing_yaml=binary_yaml,
    )
```

(If the variable names differ in the actual codebase, adapt — the test in step 6 will confirm correctness.)

- [ ] **Step 5: Add a smoke test for the integration. Create `tests/test_catalog_re_extract_features.py`:**

```python
"""Smoke test: catalog_re_extract calls feat_detectors and merges into YAML."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
RE_EXTRACT = SCRIPTS / "catalog_re_extract.py"


def _import():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("catalog_re_extract", RE_EXTRACT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["catalog_re_extract"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_process_features_idempotent_on_empty_yaml(tmp_path):
    mod = _import()
    fi = {
        "binary": "test.dll",
        "exports": [
            {"name": "Bd_Update_Run", "rva": "0x10001000"},
            {"name": "Bd_Update_Cancel", "rva": "0x10001100"},
        ],
    }
    binary_yaml = {
        "binary": "test.dll",
        "platform": "windows",
        "binary_kind": "dll",
    }
    from feat_detectors.base import DetectorContext
    ctx = DetectorContext(
        binary_path=Path("/dev/null"),
        decomp_dir=None,
        function_index=fi,
        chains=None,
        re_block={},
        existing_yaml=binary_yaml,
    )
    out1 = mod.process_features(binary_yaml, ctx)
    out2 = mod.process_features(out1, ctx)
    assert len(out1["features"]) == len(out2["features"]) == 1
    assert out1["features"][0]["slug"] == "bd-update"


def test_process_features_skips_rejected(tmp_path):
    mod = _import()
    binary_yaml = {
        "binary": "test.dll",
        "platform": "windows",
        "binary_kind": "dll",
        "features": [{
            "id": "FEAT-001",
            "slug": "bd-update",
            "rejected": True,
            "rejection_reason": "internal-only",
            "signal_sources": [{
                "detector": "exports",
                "evidence_type": "export_prefix",
                "evidence_value": "Bd_Update_",
            }],
        }],
    }
    fi = {
        "exports": [
            {"name": "Bd_Update_Run", "rva": "0x10001000"},
            {"name": "Bd_Update_Cancel", "rva": "0x10001100"},
        ],
    }
    from feat_detectors.base import DetectorContext
    ctx = DetectorContext(
        binary_path=Path("/dev/null"),
        decomp_dir=None,
        function_index=fi,
        chains=None,
        re_block={},
        existing_yaml=binary_yaml,
    )
    out = mod.process_features(binary_yaml, ctx)
    # Rejection prevents resurfacing — feature count stays at 1.
    assert len(out["features"]) == 1
    assert out["features"][0]["rejected"] is True
```

- [ ] **Step 6: Run the smoke test:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_re_extract_features.py -v`
Expected: 2 tests PASS

- [ ] **Step 7: Commit**

```bash
git add scripts/catalog_re_extract.py tests/test_catalog_re_extract_features.py
git commit -m "$(cat <<'EOF'
feat(catalog): integrate FEAT detector framework into re-extract

Adds process_features() that runs the detector registry, dedups by
(detector, evidence_type, evidence_value), and skips rejected entries.
Idempotent: re-running updates last_detected_at without duplicating.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `vb walk` CLI — `status` subcommand

**Files:**
- Create: `scripts/catalog_walk.py`
- Create: `tests/test_catalog_walk.py`

- [ ] **Step 1: Write the failing test:**

```python
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
```

- [ ] **Step 2: Run the test to verify it fails:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_walk.py -v`
Expected: FAIL with `FileNotFoundError` or non-zero exit (script doesn't exist)

- [ ] **Step 3: Create `scripts/catalog_walk.py` with the `status` subcommand:**

```python
#!/usr/bin/env python3
"""vb walk — drive the FEAT walk pipeline (stages 2a → 2b → 2c).

Subcommands:
  status      <binary>             — current stage + pending counts (JSON-friendly)
  pending     <binary> --stage S   — list pending candidates for a stage
  inspect     <binary> <id>        — full context for one candidate
  confirm     <binary> <id> ...    — apply a confirm decision (gate-checked)
  reject      <binary> <id> --reason ...  — apply a reject decision
  close-stage <binary> --stage S   — close a stage (refuses if pending > 0)
  refresh     <binary>             — re-run detectors mid-walk

CWD must contain catalog/binaries/<binary>.yml. Falls back to the global
catalog under the script's repo root if `./catalog/` is absent.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml


def _catalog_dir() -> Path:
    """Resolve catalog/binaries — local CWD wins, repo root is fallback."""
    here = Path.cwd() / "catalog" / "binaries"
    if here.is_dir():
        return here
    return Path(__file__).resolve().parent.parent / "catalog" / "binaries"


def _load_binary(name: str) -> tuple[Path, dict[str, Any]]:
    cdir = _catalog_dir()
    p = cdir / f"{name}.yml"
    if not p.exists():
        raise SystemExit(f"binary YAML not found: {p}")
    return p, yaml.safe_load(p.read_text()) or {}


def _current_stage(walk_state: dict) -> str:
    stages = walk_state.get("stages") or {}
    for sname in ("2a-inputs", "2b-sinks", "2c-features"):
        s = stages.get(sname) or {}
        st = (s.get("status") or "").lower()
        if st == "open":
            return sname
    # If any stage is closed but the next is not_started, the next is the
    # implicit current. If all are closed, return done.
    closed = sum(
        1 for sname in ("2a-inputs", "2b-sinks", "2c-features")
        if ((stages.get(sname) or {}).get("status") or "").lower() == "closed"
    )
    if closed == 3:
        return "done"
    return "not_started"


def _pending_counts(yaml_data: dict) -> dict[str, int]:
    re_block = yaml_data.get("reverse_engineering") or {}
    inputs = re_block.get("inputs") or []
    sinks = yaml_data.get("sinks") or []
    features = yaml_data.get("features") or []

    def _unconfirmed(items: list) -> int:
        return sum(1 for it in items if not it.get("confirmed") and not it.get("rejected"))

    return {
        "inputs_unconfirmed": _unconfirmed(inputs),
        "sinks_unconfirmed": _unconfirmed(sinks),
        "features_unconfirmed": _unconfirmed(features),
    }


def cmd_status(args) -> int:
    _, data = _load_binary(args.binary)
    ws = data.get("walk_state") or {}
    out = {
        "binary": args.binary,
        "current_stage": _current_stage(ws),
        "pending_counts": _pending_counts(data),
    }
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"binary: {args.binary}")
        print(f"current stage: {out['current_stage']}")
        print(f"pending: {out['pending_counts']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vb walk", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("status", help="show current stage + pending counts")
    sp.add_argument("binary")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_status)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Make it executable:**

```bash
chmod +x scripts/catalog_walk.py
```

- [ ] **Step 5: Run the tests to verify they pass:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_walk.py -v`
Expected: 2 tests PASS

- [ ] **Step 6: Commit**

```bash
git add scripts/catalog_walk.py tests/test_catalog_walk.py
git commit -m "$(cat <<'EOF'
feat(walk): add vb walk CLI with status subcommand

First subcommand of the vb walk driver. Reports current stage + pending
candidate counts as JSON or human-readable text.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `vb walk` — `pending`, `reject`, `close-stage` subcommands

**Files:**
- Modify: `scripts/catalog_walk.py`
- Modify: `tests/test_catalog_walk.py`

- [ ] **Step 1: Add failing tests at the end of `tests/test_catalog_walk.py`:**

```python
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
```

- [ ] **Step 2: Run the tests to confirm they fail:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_walk.py -v -k "pending or reject or close"`
Expected: 4 tests FAIL with subparser error or argument error

- [ ] **Step 3: Add subcommand implementations to `scripts/catalog_walk.py`. Insert before the `main()` function:**

```python
STAGE_KEY_MAP = {
    "2a-inputs":   ("reverse_engineering", "inputs"),
    "2b-sinks":    (None, "sinks"),
    "2c-features": (None, "features"),
}


def _stage_items(data: dict, stage: str) -> list:
    container, key = STAGE_KEY_MAP[stage]
    parent = data.get(container) if container else data
    if not isinstance(parent, dict):
        parent = {}
    return parent.get(key) or []


def _save_binary(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False))


def cmd_pending(args) -> int:
    _, data = _load_binary(args.binary)
    items = _stage_items(data, args.stage)
    pending = [it for it in items if not it.get("confirmed") and not it.get("rejected")]
    if args.json:
        print(json.dumps(pending, indent=2))
    else:
        for it in pending:
            print(f"{it.get('id', '?')}: {it.get('slug') or it.get('name') or ''}")
    return 0


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def cmd_reject(args) -> int:
    p, data = _load_binary(args.binary)
    if not args.reason or len(args.reason.strip()) < 5:
        print("--reason must be at least 5 chars", file=sys.stderr)
        return 1
    found = False
    for stage in STAGE_KEY_MAP:
        items = _stage_items(data, stage)
        for it in items:
            if it.get("id") == args.id:
                it["rejected"] = True
                it["confirmed"] = False
                it["rejection_reason"] = args.reason.strip()
                it["rejected_at"] = _now()
                found = True
                break
        if found:
            break
    if not found:
        print(f"id not found: {args.id}", file=sys.stderr)
        return 1
    _save_binary(p, data)
    return 0


def cmd_close_stage(args) -> int:
    p, data = _load_binary(args.binary)
    items = _stage_items(data, args.stage)
    pending = [it for it in items if not it.get("confirmed") and not it.get("rejected")]
    if pending:
        print(f"refusing to close: {len(pending)} pending entries in {args.stage}",
              file=sys.stderr)
        return 1
    ws = data.setdefault("walk_state", {}).setdefault("stages", {})
    s = ws.setdefault(args.stage, {})
    s["status"] = "closed"
    s["closed_at"] = _now()
    history = data["walk_state"].setdefault("history", [])
    history.append({
        "stage": args.stage,
        "action": "closed",
        "at": s["closed_at"],
        "actor": "claude",
        "target": "",
        "reason": "",
        "confirmed": sum(1 for it in items if it.get("confirmed")),
        "rejected": sum(1 for it in items if it.get("rejected")),
    })
    _save_binary(p, data)
    return 0
```

- [ ] **Step 4: Wire the new subcommands into `main()`. Replace the existing `main()` body to add three new subparsers:**

```python
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vb walk", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("status", help="show current stage + pending counts")
    sp.add_argument("binary")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("pending", help="list pending candidates for a stage")
    sp.add_argument("binary")
    sp.add_argument("--stage", required=True, choices=list(STAGE_KEY_MAP))
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_pending)

    sp = sub.add_parser("reject", help="reject a candidate")
    sp.add_argument("binary")
    sp.add_argument("id")
    sp.add_argument("--reason", required=True)
    sp.set_defaults(func=cmd_reject)

    sp = sub.add_parser("close-stage", help="close a stage (refuses with pending entries)")
    sp.add_argument("binary")
    sp.add_argument("--stage", required=True, choices=list(STAGE_KEY_MAP))
    sp.set_defaults(func=cmd_close_stage)

    args = p.parse_args(argv)
    return args.func(args)
```

- [ ] **Step 5: Run all walk tests:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_walk.py -v`
Expected: 6 tests PASS

- [ ] **Step 6: Commit**

```bash
git add scripts/catalog_walk.py tests/test_catalog_walk.py
git commit -m "$(cat <<'EOF'
feat(walk): add pending, reject, close-stage subcommands

`vb walk pending` lists unconfirmed candidates per stage. `reject`
applies a reason-tagged rejection. `close-stage` refuses while pending
entries exist, otherwise stamps closed_at + appends to history.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `vb walk confirm` — with stake-gating

**Files:**
- Modify: `scripts/catalog_walk.py`
- Modify: `tests/test_catalog_walk.py`

- [ ] **Step 1: Add failing tests:**

```python
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
```

- [ ] **Step 2: Run the tests to confirm failure:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_walk.py -v -k "confirm"`
Expected: 3 tests FAIL

- [ ] **Step 3: Add `cmd_confirm` to `scripts/catalog_walk.py`. Insert before `main()`:**

```python
def _stake_gated(payload: dict) -> tuple[bool, str]:
    reasons = []
    sev = (payload.get("severity_ceiling") or "").lower()
    if sev in ("high", "critical"):
        reasons.append(f"severity={payload['severity_ceiling']}")
    if payload.get("cwe"):
        reasons.append(f"cwe={','.join(payload['cwe'])}")
    if payload.get("product_feature_id"):
        reasons.append("product_feature_id-set")
    if (payload.get("confidence") or "").lower() == "low":
        reasons.append("confidence=low")
    return (bool(reasons), ",".join(reasons))


def cmd_confirm(args) -> int:
    p, data = _load_binary(args.binary)
    feat = None
    items = _stage_items(data, "2c-features")
    for it in items:
        if it.get("id") == args.id:
            feat = it
            break
    if feat is None:
        print(f"id not found in features: {args.id}", file=sys.stderr)
        return 1

    payload = {
        "description": args.description,
        "cwe": [c.strip() for c in (args.cwe or "").split(",") if c.strip()],
        "severity_ceiling": args.severity_ceiling or "",
        "product_feature_id": args.product_feature_id or "",
        "confidence": args.confidence or "",
        "user_observable": args.user_observable or "",
        "capabilities": [c.strip() for c in (args.capabilities or "").split(",") if c.strip()],
        "sources": [c.strip() for c in (args.sources or "").split(",") if c.strip()],
        "inputs": [c.strip() for c in (args.inputs or "").split(",") if c.strip()],
    }

    needs_review, trigger = _stake_gated(payload)
    review_data = None
    if needs_review:
        if not args.review_verdict:
            print(f"stake-gated confirm requires --review-verdict (triggers: {trigger})",
                  file=sys.stderr)
            return 1
        rp = Path(args.review_verdict)
        if not rp.exists():
            print(f"review verdict file not found: {rp}", file=sys.stderr)
            return 1
        try:
            review_data = json.loads(rp.read_text())
        except json.JSONDecodeError as e:
            print(f"review verdict not valid JSON: {e}", file=sys.stderr)
            return 1
        if review_data.get("verdict") != "ship":
            print(f"review verdict is {review_data.get('verdict')!r}; not confirming",
                  file=sys.stderr)
            return 1
        if review_data.get("candidate_id") and review_data["candidate_id"] != args.id:
            print(f"review verdict is for {review_data.get('candidate_id')}, not {args.id}",
                  file=sys.stderr)
            return 1

    feat["confirmed"] = True
    feat["rejected"] = False
    if payload["description"]:
        feat["description"] = payload["description"]
    for k in ("severity_ceiling", "product_feature_id", "user_observable", "confidence"):
        if payload[k]:
            feat[k] = payload[k]
    if payload["cwe"]:
        feat["cwe"] = payload["cwe"]
    for k in ("capabilities", "sources", "inputs"):
        if payload[k]:
            feat[k] = payload[k]

    cr = feat.setdefault("confirmation_review", {})
    cr["required"] = needs_review
    cr["agent_id"] = args.inspect_worker
    cr["reviewed_at"] = _now()
    cr["trigger_reason"] = trigger
    if review_data:
        cr["reviewed_by"] = review_data.get("agent_id", "")
        cr["verdict"] = "ship"
        cr["artifact_path"] = str(rp)
    else:
        cr["reviewed_by"] = ""
        cr["verdict"] = "auto-confirm"
        cr["artifact_path"] = ""

    # Reverse-pointer backfill: append FEAT-id to capabilities[].feature_ids etc.
    for cap_id in payload["capabilities"]:
        for cap in data.get("capabilities") or []:
            if cap.get("id") == cap_id:
                fids = cap.setdefault("feature_ids", [])
                if args.id not in fids:
                    fids.append(args.id)
    for src_id in payload["sources"]:
        for src in data.get("sources") or []:
            if src.get("id") == src_id:
                fids = src.setdefault("feature_ids", [])
                if args.id not in fids:
                    fids.append(args.id)
    for inp_id in payload["inputs"]:
        re_block = data.setdefault("reverse_engineering", {})
        for inp in re_block.get("inputs") or []:
            if inp.get("id") == inp_id:
                fids = inp.setdefault("feature_ids", [])
                if args.id not in fids:
                    fids.append(args.id)

    _save_binary(p, data)
    return 0
```

- [ ] **Step 4: Wire `confirm` into `main()`. Add the subparser inside `main()`:**

```python
    sp = sub.add_parser("confirm", help="confirm a feature (gate-checked)")
    sp.add_argument("binary")
    sp.add_argument("id")
    sp.add_argument("--description", default="")
    sp.add_argument("--cwe", default="")
    sp.add_argument("--severity-ceiling", default="")
    sp.add_argument("--product-feature-id", default="")
    sp.add_argument("--confidence", default="")
    sp.add_argument("--user-observable", default="")
    sp.add_argument("--capabilities", default="")
    sp.add_argument("--sources", default="")
    sp.add_argument("--inputs", default="")
    sp.add_argument("--inspect-worker", required=True)
    sp.add_argument("--review-verdict", default="")
    sp.set_defaults(func=cmd_confirm)
```

- [ ] **Step 5: Run all walk tests:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_walk.py -v`
Expected: 9 tests PASS

- [ ] **Step 6: Commit**

```bash
git add scripts/catalog_walk.py tests/test_catalog_walk.py
git commit -m "$(cat <<'EOF'
feat(walk): add stake-gated confirm subcommand

confirm refuses without --review-verdict when stakes are high (severity
High/Critical, attached CWE, product_feature_id set, or confidence low).
Otherwise writes confirmation_review.verdict=auto-confirm. Backfills
feature_ids reverse pointers on linked capabilities/sources/inputs.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `vb walk` — `inspect` and `refresh` subcommands

**Files:**
- Modify: `scripts/catalog_walk.py`
- Modify: `tests/test_catalog_walk.py`

- [ ] **Step 1: Add failing tests:**

```python
def test_inspect_returns_full_candidate(tmp_path):
    _make_binary_yaml(tmp_path, "t", {
        "binary": "t.dll", "platform": "windows", "binary_kind": "dll",
        "features": [{
            "id": "FEAT-001", "slug": "auto-update", "name": "Auto-update",
            "description": "the description",
            "implementation_anchors": [{"function": "FUN_1", "rva": "0x10001000", "role": "source"}],
            "signal_sources": [{"detector": "exports", "evidence_type": "export_prefix",
                                 "evidence_value": "Bd_Update_", "weight": 2}],
            "confirmed": False, "rejected": False,
        }],
    })
    r = _run_walk(["inspect", "t", "FEAT-001", "--json"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["id"] == "FEAT-001"
    assert out["slug"] == "auto-update"
    assert len(out["implementation_anchors"]) == 1


def test_refresh_runs_re_extract(tmp_path, monkeypatch):
    # Light-touch: just check the subcommand exists and exits 0 when YAML is
    # readable. Full re-extract integration is covered in test_catalog_re_extract_features.
    _make_binary_yaml(tmp_path, "t", {
        "binary": "t.dll", "platform": "windows", "binary_kind": "dll",
    })
    r = _run_walk(["refresh", "t", "--dry-run"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
```

- [ ] **Step 2: Run tests to confirm failure:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_walk.py -v -k "inspect or refresh"`
Expected: 2 tests FAIL

- [ ] **Step 3: Add `cmd_inspect` and `cmd_refresh` to `scripts/catalog_walk.py`. Insert before `main()`:**

```python
def cmd_inspect(args) -> int:
    _, data = _load_binary(args.binary)
    for stage in STAGE_KEY_MAP:
        for it in _stage_items(data, stage):
            if it.get("id") == args.id:
                if args.json:
                    print(json.dumps(it, indent=2))
                else:
                    print(yaml.safe_dump(it, sort_keys=False))
                return 0
    print(f"id not found: {args.id}", file=sys.stderr)
    return 1


def cmd_refresh(args) -> int:
    if args.dry_run:
        print(f"(dry-run) would re-run detector framework against {args.binary}")
        return 0
    # Real run: import process_features and apply.
    sys.path.insert(0, str(Path(__file__).parent))
    import importlib.util
    re_path = Path(__file__).parent / "catalog_re_extract.py"
    spec = importlib.util.spec_from_file_location("catalog_re_extract", re_path)
    if spec is None or spec.loader is None:
        print("could not import catalog_re_extract", file=sys.stderr)
        return 1
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    p, data = _load_binary(args.binary)
    # Build a minimal DetectorContext: function_index from existing
    # reverse_engineering, decomp_dir from coverage[].decomp_dirs[0] if any.
    from feat_detectors.base import DetectorContext  # type: ignore
    fi = data.get("reverse_engineering", {}) or {}
    coverage = data.get("coverage") or {}
    decomp_dirs = coverage.get("decomp_dirs") or []
    decomp_dir = Path(decomp_dirs[0]) if decomp_dirs else None
    ctx = DetectorContext(
        binary_path=Path(data.get("canonical_path") or ""),
        decomp_dir=decomp_dir,
        function_index=fi,
        chains=None,
        re_block=fi,
        existing_yaml=data,
    )
    out = mod.process_features(data, ctx)
    _save_binary(p, out)
    print(f"refreshed; features now: {len(out.get('features', []))}")
    return 0
```

- [ ] **Step 4: Wire `inspect` and `refresh` into `main()`. Add inside `main()`:**

```python
    sp = sub.add_parser("inspect", help="full context for one candidate")
    sp.add_argument("binary")
    sp.add_argument("id")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_inspect)

    sp = sub.add_parser("refresh", help="re-run detectors against this binary")
    sp.add_argument("binary")
    sp.add_argument("--dry-run", action="store_true")
    sp.set_defaults(func=cmd_refresh)
```

- [ ] **Step 5: Run all walk tests:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_walk.py -v`
Expected: 11 tests PASS

- [ ] **Step 6: Symlink for shell convenience:**

```bash
ln -sf "$PWD/scripts/catalog_walk.py" ~/.local/bin/vb-walk
chmod +x scripts/catalog_walk.py
```

- [ ] **Step 7: Commit**

```bash
git add scripts/catalog_walk.py tests/test_catalog_walk.py
git commit -m "$(cat <<'EOF'
feat(walk): add inspect and refresh subcommands

inspect dumps a single candidate as JSON or YAML. refresh runs the
detector framework against the binary in place.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Worker prompts

**Files:**
- Create: `prompts/workers/walk_inspect_candidate.md`
- Create: `prompts/workers/walk_confirm_review.md`
- Create: `prompts/phases/walk_strategist.md`

- [ ] **Step 1: Write `prompts/workers/walk_inspect_candidate.md`:**

```markdown
# Worker: walk_inspect_candidate

You are deciding whether a single auto-detected FEAT/INP/SNK candidate is real, false-positive, or needs deeper inspection. Output ONE structured JSON verdict per invocation.

## Your input

You will receive:
- `candidate_json` — the full candidate record from `vb walk inspect <binary> <id> --json`
- `engagement_root` — path to `engagements/<eng>/`
- `binary_yaml_path` — path to `catalog/binaries/<name>.yml`

## What to do

1. Read `candidate_json.implementation_anchors[]`. For each anchor `rva`, read the corresponding decompiled function from `<engagement_root>/decomp/functions/FUN_<rva-without-0x>.c`. If the file does not exist, fall back to grepping `function_index.json` for the address.
2. Verify the candidate's claim:
   - For an `exports` candidate: do the exported symbols actually exist in the function index?
   - For an `rpc_interface` candidate: does an `RpcServerRegisterIf*` call appear in any of the anchor functions?
   - For a `string_table` candidate: do the literal `evidence_value` strings appear in `function_index.json.strings[]` or in the decomp output?
   - For others, apply the analogous "evidence verifies" check.
3. If headless decomp shows an indirect call (function pointer, vtable lookup, or `(*foo)(...)` syntax) that is critical to the verification, escalate to Ghidra MCP: call `mcp__ghidra__decompile_function_by_address(<rva>)`, `mcp__ghidra__get_xrefs_to(<address>)`, or `mcp__ghidra__get_xrefs_from(<address>)` as needed. Otherwise, do not use MCP — headless is sufficient.
4. Decide verdict: `confirm`, `reject`, or `defer`.

## Output format (JSON only, one line)

```json
{
  "decision": "confirm | reject | defer",
  "candidate_id": "FEAT-001",
  "rationale": "one paragraph explaining the call",
  "proposed_payload": {
    "description": "fill if confirming",
    "capabilities": ["CAP-001"],
    "sources": ["SRC-002"],
    "inputs": ["INP-003"],
    "cwe": ["CWE-78"],
    "severity_ceiling": "High",
    "user_observable": "Settings -> ...",
    "confidence": "high"
  },
  "rejection_reason": "fill if rejecting",
  "defer_reason": "fill if deferring; what extra context is needed"
}
```

## Discipline

- Never confirm without verifying at least one anchor decompilation matches the claim.
- If you used MCP, mention which calls in `rationale`.
- `confidence: high` means three or more independent signals agreed; `medium` is two; `low` is one.
- If you choose `defer`, be specific about what additional context would change your mind (e.g., "need to see callers of FUN_140012a0 to know if RPC interface is server-side or client-stub").
```

- [ ] **Step 2: Write `prompts/workers/walk_confirm_review.md`:**

```markdown
# Worker: walk_confirm_review (skeptic)

You are an independent fresh-context reviewer of a proposed FEAT confirmation. The inspect-worker has already decided to confirm; your job is to audit that decision against evidence and decide `ship`, `hedge`, or `block`.

You see ONLY:
- `candidate_json` — the candidate record
- `proposed_payload` — what the inspect-worker wants to write
- `engagement_root` — engagement directory
- Ghidra MCP access if needed for verification

You do NOT see the inspect-worker's rationale. That is the point — you re-derive the verdict independently.

## Checks (in order)

1. **Anchor honesty.** For each `implementation_anchors[].rva`, read the decompiled function. Does the function actually do what `proposed_payload.description` claims?
2. **Signal-source corroboration.** For each `signal_sources[]` entry, verify the `evidence_value` is present in the binary's strings table, decompilation, or function index.
3. **Capability/source/input plausibility.** Are the linked CAP-*/SRC-*/INP-* IDs reachable from the anchors (forward-trace)? An RCE-claiming FEAT that lists no spawn-process or unsafe-deserialization CAP is suspicious.
4. **CWE/severity inflation.** Does the worst chain reaching the anchors actually justify `severity_ceiling`? `High` requires a chain to a sink with attacker control.
5. **UX strings exist.** If `ux_strings[]` is non-empty, do those literal strings appear in the binary?

## Output format (JSON only)

```json
{
  "agent_id": "auto-populated by Task tool",
  "binary": "from input",
  "candidate_id": "FEAT-001",
  "verdict": "ship | hedge | block",
  "confidence": "high | medium | low",
  "anchor_audit": [
    {"rva": "0x140012a0", "claim": "orchestrator", "verified": true, "note": "..."}
  ],
  "signal_audit": [
    {"detector": "rpc_interface", "evidence_value": "1234-...", "found_in_binary": true}
  ],
  "specific_corrections": [
    "severity_ceiling claims High but no chain reaches CWE-78; cap at Medium"
  ],
  "rationale": "one paragraph"
}
```

Save the JSON to `engagements/<eng>/walk_reviews/<candidate_id>.json`. Print the path on stdout.

## Verdict rules

- `ship` = anchors honest, signals corroborate, severity defensible, payload accurate
- `hedge` = real candidate but payload needs corrections (spelled out in `specific_corrections`); inspect-worker should re-propose with corrections applied
- `block` = candidate is false-positive OR proposal is so far from evidence that fixing means rewriting the FEAT
```

- [ ] **Step 3: Write `prompts/phases/walk_strategist.md`:**

```markdown
# Phase: walk strategist

You are the strategist for the FEAT walk. Drive `vb walk` to populate auto-detected candidates, dispatch workers per candidate, and apply confirm/reject decisions.

## Loop

```
loop:
    status = run_cmd("vb walk status <binary> --json")
    stage = status.current_stage
    if stage == "done":
        break
    pending = run_cmd(f"vb walk pending <binary> --stage {stage} --json")
    if not pending:
        run_cmd(f"vb walk close-stage <binary> --stage {stage}")
        continue

    # Dispatch up to 5 inspect-workers in parallel (single message, multiple Task calls).
    results = []
    for cand in pending[:5]:
        results.append(Task(prompts/workers/walk_inspect_candidate, candidate_json=cand, ...))

    # Process worker verdicts.
    for verdict in results:
        if verdict.decision == "reject":
            run_cmd(f'vb walk reject <binary> {verdict.candidate_id} --reason "{verdict.rejection_reason}"')
            continue
        if verdict.decision == "defer":
            note_journal_event("defer", verdict.candidate_id, verdict.defer_reason)
            continue
        # confirm path
        if stake_gated(verdict.proposed_payload):
            review = Task(prompts/workers/walk_confirm_review,
                          candidate_json=cand, proposed_payload=verdict.proposed_payload, ...)
            if review.verdict != "ship":
                handle_hedge_or_block(review)
                continue
            run_cmd(build_confirm_cmd(verdict, review_artifact_path))
        else:
            run_cmd(build_confirm_cmd(verdict))
```

## stake_gated rule

Returns true if any of:
- `severity_ceiling` ∈ {High, Critical}
- `cwe` is non-empty
- `product_feature_id` is set
- `confidence` == "low"

## Discipline

- Never call `vb walk confirm` without an `--inspect-worker` argument carrying the worker's agent ID.
- Never call `vb walk confirm` on a stake-gated payload without `--review-verdict <path>`.
- Always run `vb walk close-stage` when the pending list is empty for the current stage.
- If a worker returns `defer`, leave the candidate alone and re-evaluate next loop iteration; if it defers twice in a row with the same reason, escalate to a journal note for human review.
```

- [ ] **Step 4: Verify the prompts read correctly:**

Run: `head -3 prompts/workers/walk_inspect_candidate.md prompts/workers/walk_confirm_review.md prompts/phases/walk_strategist.md`
Expected: each file's first three lines visible

- [ ] **Step 5: Commit**

```bash
git add prompts/workers/walk_inspect_candidate.md \
        prompts/workers/walk_confirm_review.md \
        prompts/phases/walk_strategist.md
git commit -m "$(cat <<'EOF'
feat(walk): add inspect, skeptic, and strategist prompts

walk_inspect_candidate: per-candidate verifier with headless-first /
MCP-on-demand depth routing. walk_confirm_review: independent skeptic
with anchor honesty + signal corroboration checks. walk_strategist:
the loop that drives `vb walk` end-to-end.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Web UI — features section + walk status header

**Files:**
- Modify: `catalog/site/_templates/binary.html.j2`
- Modify: `scripts/catalog_render.py` — add `render_features_section()` and `render_walk_header()`
- Modify: `scripts/catalog_site_render.py` — same Jinja additions

- [ ] **Step 1: Read the existing `binary.html.j2` to find where capabilities are rendered. Look for `{% if data.capabilities %}`:**

Run: `grep -n "capabilities\|features\|walk_state" catalog/site/_templates/binary.html.j2 | head -20`

- [ ] **Step 2: Open `catalog/site/_templates/binary.html.j2`. After the existing block that renders `data.capabilities` and before the `chains` block, add the walk status header at the top of the page (find the `<h1>` for the binary name and insert immediately after):**

```jinja
{% set ws = data.walk_state or {} %}
{% if ws.stages %}
<div class="vbn-walk-header bg-base-200 rounded p-3 mb-4 text-sm">
  <strong>Walk:</strong>
  {% set stage_2a = (ws.stages['2a-inputs'] or {}).status or 'not_started' %}
  {% set stage_2b = (ws.stages['2b-sinks'] or {}).status or 'not_started' %}
  {% set stage_2c = (ws.stages['2c-features'] or {}).status or 'not_started' %}
  <span class="vbn-walk-stage stage-{{ stage_2a }}">2a-inputs: {{ stage_2a }}</span>
  &middot;
  <span class="vbn-walk-stage stage-{{ stage_2b }}">2b-sinks: {{ stage_2b }}</span>
  &middot;
  <span class="vbn-walk-stage stage-{{ stage_2c }}">2c-features: {{ stage_2c }}</span>
  {% set pc = ws.pending_counts or {} %}
  &middot; pending:
  inputs={{ pc.inputs_unconfirmed or 0 }},
  sinks={{ pc.sinks_unconfirmed or 0 }},
  features={{ pc.features_unconfirmed or 0 }}
</div>
{% endif %}
```

- [ ] **Step 3: Add the features section. Insert AFTER the existing capabilities block (`{% endif %}` for capabilities) and BEFORE the chains block:**

```jinja
{% if data.features %}
<section class="vbn-features mt-8">
  <h2 class="text-2xl font-bold">Features</h2>
  <p class="text-sm opacity-70 mb-3">User-facing behaviours; clusters of capabilities that together implement what the user perceives as one feature.</p>
  {% for f in data.features %}
  {% if not f.rejected %}
  <article class="vbn-feature-card border rounded p-3 mb-3 bg-base-100"
           data-feat-id="{{ f.id }}" data-confirmed="{{ f.confirmed }}">
    <header class="flex items-baseline gap-2">
      <span class="font-mono text-xs opacity-60">{{ f.id }}</span>
      <span class="font-bold">{{ f.name or f.slug }}</span>
      {% if f.status %}<span class="badge badge-{{ f.status }}">{{ f.status }}</span>{% endif %}
      {% if f.confidence %}<span class="badge badge-confidence-{{ f.confidence }}">{{ f.confidence }}</span>{% endif %}
      {% if not f.confirmed %}<span class="badge badge-warning">unconfirmed</span>{% endif %}
    </header>
    {% if f.description %}<p class="mt-2">{{ f.description }}</p>{% endif %}
    {% if f.user_observable %}
    <p class="text-sm opacity-80 mt-1"><em>User observes:</em> {{ f.user_observable }}</p>
    {% endif %}
    {% if f.ux_strings %}
    <p class="text-sm mt-1"><em>UX strings:</em>
      {% for s in f.ux_strings %}<code>{{ s }}</code>{% if not loop.last %}, {% endif %}{% endfor %}
    </p>
    {% endif %}
    {% if f.cwe %}
    <p class="text-sm mt-1"><em>CWE:</em>
      {% for c in f.cwe %}<code>{{ c }}</code>{% if not loop.last %}, {% endif %}{% endfor %}
      {% if f.severity_ceiling %} &middot; ceiling: <strong>{{ f.severity_ceiling }}</strong>{% endif %}
    </p>
    {% endif %}
    {% if f.implementation_anchors %}
    <details class="mt-2">
      <summary class="text-sm cursor-pointer">Implementation anchors ({{ f.implementation_anchors|length }})</summary>
      <table class="text-xs mt-1">
        <thead><tr><th>Function</th><th>RVA</th><th>Role</th></tr></thead>
        <tbody>
          {% for a in f.implementation_anchors %}
          <tr><td><code>{{ a.function }}</code></td><td><code>{{ a.rva }}</code></td><td>{{ a.role }}</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </details>
    {% endif %}
    {% if f.signal_sources %}
    <details class="mt-2">
      <summary class="text-sm cursor-pointer">Signal sources ({{ f.signal_sources|length }})</summary>
      <ul class="text-xs mt-1">
        {% for s in f.signal_sources %}
        <li><code>{{ s.detector }}@{{ s.detector_version }}</code> — {{ s.evidence_type }}=<code>{{ s.evidence_value }}</code> (weight {{ s.weight }}; last seen {{ s.last_detected_at }})</li>
        {% endfor %}
      </ul>
    </details>
    {% endif %}
    {% if f.confirmation_review and f.confirmation_review.verdict %}
    <details class="mt-2 text-xs opacity-80">
      <summary class="cursor-pointer">Confirmation review ({{ f.confirmation_review.verdict }})</summary>
      <p>Inspect agent: <code>{{ f.confirmation_review.agent_id }}</code></p>
      {% if f.confirmation_review.reviewed_by %}
      <p>Skeptic agent: <code>{{ f.confirmation_review.reviewed_by }}</code></p>
      {% endif %}
      {% if f.confirmation_review.trigger_reason %}
      <p>Trigger: {{ f.confirmation_review.trigger_reason }}</p>
      {% endif %}
      {% if f.confirmation_review.artifact_path %}
      <p>Artifact: <code>{{ f.confirmation_review.artifact_path }}</code></p>
      {% endif %}
    </details>
    {% endif %}
  </article>
  {% endif %}
  {% endfor %}

  {% set rejected_features = data.features|selectattr("rejected")|list %}
  {% if rejected_features %}
  <details class="mt-3">
    <summary class="cursor-pointer text-sm opacity-70">Rejected features ({{ rejected_features|length }})</summary>
    <ul class="text-xs mt-1">
      {% for f in rejected_features %}
      <li><code>{{ f.id }}</code> {{ f.slug }} — <em>{{ f.rejection_reason }}</em></li>
      {% endfor %}
    </ul>
  </details>
  {% endif %}
</section>
{% endif %}
```

- [ ] **Step 4: Run the static-site renderer and verify it produces output without errors:**

Run: `cd ~/vulnerabin && python3 scripts/catalog_site_render.py 2>&1 | tail -20`
Expected: completes without `UndefinedError` or `TemplateSyntaxError`

- [ ] **Step 5: Inspect one rendered binary page to confirm features section appears (or is absent if no features yet):**

Run: `grep -c "vbn-walk-header\|vbn-feature-card" catalog/site/safeelevatedrun_dll.html 2>&1 || echo "no html yet"`
Expected: `0` or counts of how many cards rendered. Either is fine — the binary may not have features yet.

- [ ] **Step 6: Commit**

```bash
git add catalog/site/_templates/binary.html.j2
git commit -m "$(cat <<'EOF'
feat(site): add walk header + features section to binary template

Walk status banner shows 2a/2b/2c stage states + pending counts.
Features section renders unconfirmed and confirmed FEATs as cards
with anchors, signal sources, and confirmation_review collapsibles.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Web UI — `inputs × features` matrix (CSS-grid v0)

**Files:**
- Modify: `catalog/site/_templates/binary.html.j2`

The full ECharts heatmap for matrices >200 cells ships in v1.1; v1 ships the CSS-grid version that handles up to ~250 cells.

- [ ] **Step 1: Open `catalog/site/_templates/binary.html.j2`. Find the existing `inputs × capabilities` matrix (search for "Coverage matrix" or "inputs × capabilities"):**

Run: `grep -n "Coverage matrix\|inputs.*capabilities\|matrix" catalog/site/_templates/binary.html.j2`

- [ ] **Step 2: Wrap the existing capabilities-matrix block in a fallback condition. Find the matrix block and prefix it with:**

```jinja
{% if not data.features %}
{# fall back to legacy inputs × capabilities matrix when no features defined #}
```

Then close with `{% endif %}` after the existing block.

- [ ] **Step 3: After the legacy matrix's `{% endif %}`, add the new `inputs × features` matrix:**

```jinja
{% if data.features %}
<section class="vbn-matrix-features mt-6">
  <h2 class="text-xl font-bold">Coverage matrix — inputs × features</h2>
  {% set inputs = (data.reverse_engineering or {}).get('inputs') or [] %}
  {% set features = data.features|rejectattr('rejected')|list %}
  {% if inputs and features %}
  <div class="vbn-feature-grid"
       style="display:grid;grid-template-columns: 8em repeat({{ features|length }}, minmax(4em, 1fr));gap:1px;background:#ddd;font-size:11px;">
    <div class="vbn-cell vbn-corner" style="background:white;">&nbsp;</div>
    {% for f in features %}
    <div class="vbn-cell vbn-feat-header" style="background:white;text-align:center;padding:2px;">
      <code>{{ f.id }}</code><br>{{ f.slug }}
    </div>
    {% endfor %}
    {% for inp in inputs %}
    <div class="vbn-cell vbn-input-header" style="background:white;padding:2px;">
      <code>{{ inp.id }}</code><br>{{ inp.kind }}
    </div>
    {% for f in features %}
      {% set in_f_inputs = inp.id in (f.inputs or []) %}
      {% set chain_exists = data.chains|selectattr('inputs', 'defined')|selectattr('feature_ids', 'defined')|selectattr('feature_ids', 'contains', f.id)|list|length > 0 if data.chains else false %}
      {% if in_f_inputs and chain_exists %}
      <div class="vbn-cell" style="background:#16a34a;color:white;text-align:center;" title="chain exists">●</div>
      {% elif in_f_inputs %}
      <div class="vbn-cell" style="background:#fb923c;color:white;text-align:center;" title="reachable, no chain">≈</div>
      {% else %}
      <div class="vbn-cell" style="background:#f3f4f6;text-align:center;" title="unexplored">?</div>
      {% endif %}
    {% endfor %}
    {% endfor %}
  </div>
  <p class="text-xs mt-1 opacity-70">● chain exists &middot; ≈ reachable, no chain &middot; ? unexplored &middot; ⊘ unreachable</p>
  {% else %}
  <p class="text-sm opacity-70">No inputs or features defined yet.</p>
  {% endif %}
</section>
{% endif %}
```

- [ ] **Step 4: Re-render the static site:**

Run: `cd ~/vulnerabin && python3 scripts/catalog_site_render.py 2>&1 | tail -10`
Expected: completes without errors

- [ ] **Step 5: Verify by looking at one binary HTML output:**

Run: `grep -c "vbn-matrix-features\|vbn-feature-grid" catalog/site/safeelevatedrun_dll.html 2>&1 || echo "no html yet"`
Expected: 0 (the canary doesn't have features yet) or a positive count if it does

- [ ] **Step 6: Commit**

```bash
git add catalog/site/_templates/binary.html.j2
git commit -m "$(cat <<'EOF'
feat(site): add inputs × features coverage matrix (CSS-grid v0)

CSS-grid based heatmap, falls back to legacy inputs × capabilities
matrix when binary has no features. ECharts upgrade for >200-cell
matrices comes in v1.1.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Live override endpoints in `catalog_serve.py`

**Files:**
- Modify: `scripts/catalog_serve.py` — add `/api/walk/<binary>/override/<feat-id>` POST handler

- [ ] **Step 1: Read `catalog_serve.py` to find where existing routes are defined:**

Run: `grep -n "@app\.\|app\.add_api_route\|FastAPI\|Router" scripts/catalog_serve.py | head -20`

- [ ] **Step 2: Locate the `app = FastAPI(...)` declaration. After existing routes (or at the file's end before `if __name__`), add:**

```python
from pydantic import BaseModel


class OverrideRequest(BaseModel):
    direction: str  # "reject" | "confirm"
    reason: str = ""
    actor: str = "human"


@app.post("/api/walk/{binary}/override/{feat_id}")
def override_feature(binary: str, feat_id: str, req: OverrideRequest):
    from datetime import datetime, timezone
    cdir = Path(__file__).resolve().parent.parent / "catalog" / "binaries"
    p = cdir / f"{binary}.yml"
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"binary not found: {binary}")
    data = yaml.safe_load(p.read_text()) or {}
    target = None
    for f in data.get("features") or []:
        if f.get("id") == feat_id:
            target = f
            break
    if target is None:
        raise HTTPException(status_code=404, detail=f"feature not found: {feat_id}")

    if req.direction == "reject":
        target["confirmed"] = False
        target["rejected"] = True
        target["rejection_reason"] = req.reason or "human override"
        target["rejected_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        action = "human-override-reject"
    elif req.direction == "confirm":
        target["confirmed"] = True
        target["rejected"] = False
        cr = target.setdefault("confirmation_review", {})
        cr["verdict"] = "human-override"
        cr["agent_id"] = "human"
        cr["reviewed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        action = "human-override-confirm"
    else:
        raise HTTPException(status_code=400, detail="direction must be 'reject' or 'confirm'")

    history = data.setdefault("walk_state", {}).setdefault("history", [])
    history.append({
        "stage": "2c-features",
        "action": action,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "actor": req.actor,
        "target": feat_id,
        "reason": req.reason,
    })
    p.write_text(yaml.safe_dump(data, sort_keys=False))
    return {"ok": True, "feat_id": feat_id, "new_state": req.direction}
```

(If `HTTPException` is not yet imported, add `from fastapi import FastAPI, HTTPException` at the top of the file. If `Path` and `yaml` are missing, add them.)

- [ ] **Step 3: Smoke-test the route by booting the server and curling:**

```bash
cd ~/vulnerabin && python3 scripts/catalog_serve.py --port 8089 &
SERVER_PID=$!
sleep 1
# Should 404 (no such feature on canary yet, but route should respond)
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"direction":"reject","reason":"smoke test"}' \
  http://127.0.0.1:8089/api/walk/safeelevatedrun_dll/override/FEAT-999
kill $SERVER_PID
```

Expected: returns 404 JSON `{"detail":"feature not found: FEAT-999"}` — that's correct; it proves the route exists and only fails because the test FEAT doesn't exist yet.

- [ ] **Step 4: Commit**

```bash
git add scripts/catalog_serve.py
git commit -m "$(cat <<'EOF'
feat(serve): add /api/walk/<binary>/override/<feat-id> endpoint

Lets the human reviewer override a Claude confirm/reject from the web
UI. Appends an entry to walk_state.history with actor: human-override.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Pipeline FSM updates

**Files:**
- Modify: `pipeline.yml` — add `walk` phase + gates
- Modify: `scripts/fsm.py` — recognise the new phase

- [ ] **Step 1: Read `pipeline.yml` to see the existing phase structure:**

Run: `grep -n "phases\|^\s\s-\|name:" pipeline.yml | head -30`

- [ ] **Step 2: Add the `walk` phase between `preparation` and `triage`. Locate the `triage` phase definition in `pipeline.yml` and insert before it:**

```yaml
  - name: walk
    description: |
      Three-stage gated walk over auto-detected candidates: 2a-inputs →
      2b-sinks → 2c-features. Strategist dispatches inspect-workers per
      candidate; stake-gated confirms get an inline skeptic agent.
    entry_artifacts:
      - catalog/binaries/<binary>.yml      # must exist with reverse_engineering populated
    exit_artifacts:
      - catalog/binaries/<binary>.yml      # walk_state.stages all closed
    gates:
      - name: walk_state_started
        when: pre
        check: walk_state.stages.2a-inputs.opened_at_set
        rationale: |
          Walk cannot begin until at least the inputs stage is opened.
      - name: walk_state_done
        when: post
        check: walk_state.stages.all_closed
        rationale: |
          Walk is complete only when 2a, 2b, and 2c are all closed.
    next_phases: [triage]
```

- [ ] **Step 3: Update the `preparation` phase's `next_phases:` to point to `walk` instead of (or in addition to) `triage`:**

Find the existing line (something like `next_phases: [triage]` under `preparation`) and change to:

```yaml
    next_phases: [walk]
```

- [ ] **Step 4: Open `scripts/fsm.py` and find where phases are read. Look for where gates are evaluated:**

Run: `grep -n "gates\|check\|walk_state" scripts/fsm.py | head -20`

- [ ] **Step 5: Add gate checkers for the two new gate names. Insert into the gate-resolver function:**

```python
def _check_walk_state_started(eng_path: Path) -> bool:
    binary_yamls = list((Path(eng_path).parent.parent / "catalog" / "binaries").glob("*.yml"))
    # Permissive: at least one binary in catalog has 2a-inputs opened.
    import yaml as _y
    for p in binary_yamls:
        d = _y.safe_load(p.read_text()) or {}
        s = (d.get("walk_state", {}).get("stages", {}).get("2a-inputs", {}) or {})
        if s.get("opened_at"):
            return True
    return False


def _check_walk_state_done(eng_path: Path) -> bool:
    binary_yamls = list((Path(eng_path).parent.parent / "catalog" / "binaries").glob("*.yml"))
    import yaml as _y
    for p in binary_yamls:
        d = _y.safe_load(p.read_text()) or {}
        stages = d.get("walk_state", {}).get("stages", {}) or {}
        if not all(((stages.get(k) or {}).get("status") == "closed")
                   for k in ("2a-inputs", "2b-sinks", "2c-features")):
            return False
    return True if binary_yamls else False
```

Wire these into the gate-name → callable map (find the existing dict of gate handlers and add):

```python
"walk_state.stages.2a-inputs.opened_at_set": _check_walk_state_started,
"walk_state.stages.all_closed": _check_walk_state_done,
```

- [ ] **Step 6: Smoke-test the FSM:**

```bash
cd ~/vulnerabin && python3 scripts/fsm.py --help
```

Expected: prints help without import errors. If a smoke `--check` or `state` subcommand exists in the existing fsm.py, run it against any engagement directory to confirm no regression.

- [ ] **Step 7: Commit**

```bash
git add pipeline.yml scripts/fsm.py
git commit -m "$(cat <<'EOF'
feat(fsm): add walk phase between preparation and triage

walk phase is gated by walk_state_started (pre) and walk_state_done
(post). Permissive: walk gates evaluate against any binary in
catalog/binaries/ with the required walk_state markers.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: `vb-add` — `feature` and `unreachable` subcommands

**Files:**
- Modify: `scripts/catalog_add.py`

- [ ] **Step 1: Read `catalog_add.py` to understand the existing pattern (`sink`, `input`, `capability`, `chain`, `source` subcommands):**

Run: `grep -n "def cmd_\|sub\.add_parser" scripts/catalog_add.py | head -20`

- [ ] **Step 2: Add `cmd_feature` and `cmd_unreachable` functions following the existing pattern. Insert before `main()`:**

```python
def cmd_feature(args):
    """Append a new FEAT-* entry."""
    from datetime import datetime, timezone
    p, data = _load_or_init(args.binary)  # use existing helper
    feats = data.setdefault("features", [])
    next_id = max(
        (int(f["id"].split("-")[1]) for f in feats if f.get("id", "").startswith("FEAT-")),
        default=0,
    ) + 1
    fid = f"FEAT-{next_id:03d}"
    entry = {
        "id": fid,
        "slug": args.slug or "",
        "name": args.name or "",
        "description": args.description or "",
        "status": args.status or "hypothesised",
        "capabilities": [c.strip() for c in (args.capabilities or "").split(",") if c.strip()],
        "sources": [c.strip() for c in (args.sources or "").split(",") if c.strip()],
        "inputs": [c.strip() for c in (args.inputs or "").split(",") if c.strip()],
        "implementation_anchors": [],
        "cwe": [c.strip() for c in (args.cwe or "").split(",") if c.strip()],
        "severity_ceiling": args.severity_ceiling or "",
        "ux_strings": [],
        "disabled_by_default": False,
        "signal_sources": [{
            "detector": "manual",
            "detector_version": "1.0",
            "evidence_type": "human",
            "evidence_value": "vb-add feature",
            "weight": 3,
            "last_detected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }],
        "confidence": "medium",
        "confirmed": True,
        "rejected": False,
        "user_observable": args.user_observable or "",
        "notes": "",
        "confirmation_review": {
            "required": False, "agent_id": "human", "reviewed_by": "",
            "verdict": "human-override", "reviewed_at": "",
            "artifact_path": "", "trigger_reason": "manual-add",
        },
    }
    feats.append(entry)
    _save(p, data)
    print(fid)


def cmd_unreachable(args):
    """Mark an (input, feature) cell as explicitly unreachable in the matrix."""
    p, data = _load_or_init(args.binary)
    cells = data.setdefault("matrix_overrides", [])
    cells.append({
        "input_id": args.input,
        "feature_id": args.feature,
        "state": "unreachable",
        "reason": args.reason or "",
    })
    _save(p, data)
    print(f"marked {args.input} × {args.feature} unreachable")
```

- [ ] **Step 3: Wire the new subcommands into `main()`:**

```python
    sp = sub.add_parser("feature", help="add a FEAT-* entry by hand")
    sp.add_argument("--binary", required=True)
    sp.add_argument("--slug", default="")
    sp.add_argument("--name", default="")
    sp.add_argument("--description", default="")
    sp.add_argument("--status", default="")
    sp.add_argument("--capabilities", default="")
    sp.add_argument("--sources", default="")
    sp.add_argument("--inputs", default="")
    sp.add_argument("--cwe", default="")
    sp.add_argument("--severity-ceiling", default="")
    sp.add_argument("--user-observable", default="")
    sp.set_defaults(func=cmd_feature)

    sp = sub.add_parser("unreachable", help="mark an inputs × features cell unreachable")
    sp.add_argument("--binary", required=True)
    sp.add_argument("--input", required=True)
    sp.add_argument("--feature", required=True)
    sp.add_argument("--reason", default="")
    sp.set_defaults(func=cmd_unreachable)
```

- [ ] **Step 4: Smoke-test on the canary:**

```bash
cd ~/vulnerabin && vb-add feature --binary safeelevatedrun_dll --slug test-feat \
  --name "Smoke test feature" --description "delete me" --status hypothesised
```

Expected: prints something like `FEAT-001` (or higher if features exist). Verify by checking the YAML:

```bash
yq '.features[-1]' catalog/binaries/safeelevatedrun_dll.yml | head -20
```

Then **delete the smoke entry** to avoid polluting the canary:

```bash
python3 -c "
import yaml
from pathlib import Path
p = Path('catalog/binaries/safeelevatedrun_dll.yml')
d = yaml.safe_load(p.read_text())
if d.get('features') and d['features'][-1].get('slug') == 'test-feat':
    d['features'].pop()
    p.write_text(yaml.safe_dump(d, sort_keys=False))
    print('removed smoke entry')
"
```

- [ ] **Step 5: Commit**

```bash
git add scripts/catalog_add.py
git commit -m "$(cat <<'EOF'
feat(catalog): add `vb-add feature` and `vb-add unreachable` subcommands

`vb-add feature` creates a FEAT-* entry by hand (researcher-driven path,
distinct from the auto-detector path). `vb-add unreachable` marks an
inputs × features matrix cell as explicitly out-of-reach.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: Migration tier classifier

**Files:**
- Create: `scripts/catalog_migrate.py`
- Create: `tests/test_catalog_migrate.py`

- [ ] **Step 1: Write the failing test:**

```python
"""Test catalog_migrate.py tier classifier."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
MIGRATE_PY = SCRIPTS / "catalog_migrate.py"


def _import():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("catalog_migrate", MIGRATE_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _yaml(tmp_path: Path, name: str, contents: dict) -> Path:
    bdir = tmp_path / "catalog" / "binaries"
    bdir.mkdir(parents=True, exist_ok=True)
    p = bdir / f"{name}.yml"
    p.write_text(yaml.safe_dump(contents))
    return p


def test_classify_frozen_when_lifecycle_submitted(tmp_path):
    mod = _import()
    p = _yaml(tmp_path, "x", {"binary": "x.dll", "engagements": [
        {"slug": "x-2026-01-01", "lifecycle": "submitted"}]})
    assert mod.classify_path(p) == "frozen"


def test_classify_active_when_recent_engagement(tmp_path):
    from datetime import datetime, timedelta, timezone
    mod = _import()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    p = _yaml(tmp_path, "x", {"binary": "x.dll", "engagements": [
        {"slug": f"x-{today}", "lifecycle": "active"}]})
    assert mod.classify_path(p) == "active"


def test_classify_catalog_only_when_no_recent_activity(tmp_path):
    mod = _import()
    p = _yaml(tmp_path, "x", {"binary": "x.dll", "engagements": [
        {"slug": "x-2024-01-01", "lifecycle": "open"}]})
    assert mod.classify_path(p) == "catalog_only"


def test_classify_respects_override(tmp_path):
    mod = _import()
    p = _yaml(tmp_path, "x", {"binary": "x.dll",
                              "migration_tier_override": "frozen",
                              "engagements": [{"slug": "x-2026-05-01"}]})
    assert mod.classify_path(p) == "frozen"
```

- [ ] **Step 2: Run the test to confirm failure:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_migrate.py -v`
Expected: FAIL with `FileNotFoundError: catalog_migrate.py`

- [ ] **Step 3: Create `scripts/catalog_migrate.py`:**

```python
#!/usr/bin/env python3
"""Migration tier classifier for the FEAT layer rollout.

Reads each catalog/binaries/<name>.yml and classifies the binary as
'active' (recently engaged → walk in full), 'catalog_only' (auto-extract
only), or 'frozen' (skip, render with legacy matrix). Output is written
to catalog/_migration_plan.yml for hand-review before any walks run.

Override per-binary by setting `migration_tier_override:` to one of
{active, catalog_only, frozen} in the YAML.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalog" / "binaries"
PLAN_OUT = REPO_ROOT / "catalog" / "_migration_plan.yml"


def _eng_date(slug: str) -> datetime | None:
    """Engagement slugs end with -YYYY-MM-DD; extract that."""
    try:
        return datetime.strptime(slug[-10:], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def classify(data: dict) -> str:
    if (data.get("migration_tier_override") or "").strip():
        return data["migration_tier_override"].strip()
    engagements = data.get("engagements") or []
    for eng in engagements:
        if (eng.get("lifecycle") or "") in ("submitted", "frozen", "mitigated"):
            return "frozen"
    horizon = datetime.now(timezone.utc) - timedelta(days=30)
    for eng in engagements:
        d = _eng_date(eng.get("slug", ""))
        if d and d >= horizon:
            return "active"
    return "catalog_only"


def classify_path(p: Path) -> str:
    return classify(yaml.safe_load(p.read_text()) or {})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="print plan to stdout without writing _migration_plan.yml")
    args = ap.parse_args(argv)

    plan = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "binaries": []}
    for p in sorted(CATALOG_DIR.glob("*.yml")):
        tier = classify_path(p)
        plan["binaries"].append({
            "binary": p.stem,
            "tier": tier,
            "yaml": str(p.relative_to(REPO_ROOT)),
        })

    if args.dry_run:
        print(yaml.safe_dump(plan, sort_keys=False))
    else:
        PLAN_OUT.write_text(yaml.safe_dump(plan, sort_keys=False))
        print(f"wrote {PLAN_OUT.relative_to(REPO_ROOT)} ({len(plan['binaries'])} binaries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the tests to verify they pass:**

Run: `cd ~/vulnerabin && python3 -m pytest tests/test_catalog_migrate.py -v`
Expected: 4 tests PASS

- [ ] **Step 5: Smoke-test on the real catalog:**

```bash
cd ~/vulnerabin && python3 scripts/catalog_migrate.py --dry-run | head -30
```

Expected: prints YAML with 87 binaries categorised. Spot-check a handful.

- [ ] **Step 6: Commit**

```bash
git add scripts/catalog_migrate.py tests/test_catalog_migrate.py
git commit -m "$(cat <<'EOF'
feat(catalog): add migration tier classifier

catalog_migrate.py classifies each binary in catalog/binaries/ as
active, catalog_only, or frozen. Active = engagement within last 30
days. Frozen = lifecycle ∈ {submitted, frozen, mitigated}. Override
per-binary via migration_tier_override.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: Canary smoke-test — full pipeline on `safeelevatedrun_dll`

**Files:**
- No new files; this is an integration test of everything built in Tasks 1–15

- [ ] **Step 1: Confirm the canary YAML parses post-schema-additions:**

```bash
cd ~/vulnerabin && python3 -c "
import yaml; d = yaml.safe_load(open('catalog/binaries/safeelevatedrun_dll.yml').read())
print('binary:', d.get('binary'))
print('platform:', d.get('platform'), 'kind:', d.get('binary_kind'))
print('has features:', 'features' in d)
print('has walk_state:', 'walk_state' in d)
"
```

Expected: prints non-error output; both `has features` and `has walk_state` may be `False` (canary not yet migrated, that's the point).

- [ ] **Step 2: Run `vb walk status` on the canary:**

```bash
cd ~/vulnerabin && python3 scripts/catalog_walk.py status safeelevatedrun_dll --json
```

Expected: JSON output `{"binary": "safeelevatedrun_dll", "current_stage": "not_started", "pending_counts": {...}}`.

- [ ] **Step 3: Initialise the canary's walk_state and run refresh to get FEATs:**

```bash
cd ~/vulnerabin && python3 -c "
import yaml
from datetime import datetime, timezone
p = 'catalog/binaries/safeelevatedrun_dll.yml'
d = yaml.safe_load(open(p).read()) or {}
d['walk_state'] = {
    'stages': {
        '2a-inputs':   {'status': 'open', 'opened_at': datetime.now(timezone.utc).isoformat(timespec='seconds')},
        '2b-sinks':    {'status': 'not_started'},
        '2c-features': {'status': 'not_started'},
    },
    'pending_counts': {'inputs_unconfirmed': 0, 'sinks_unconfirmed': 0, 'features_unconfirmed': 0},
    'history': [],
}
open(p, 'w').write(yaml.safe_dump(d, sort_keys=False))
print('initialised walk_state')
"
python3 scripts/catalog_walk.py refresh safeelevatedrun_dll
```

Expected: `refresh` prints `refreshed; features now: N` where N depends on how many export-prefix clusters exist in the canary's function index. May be 0 if the canary has no exports — in that case, the refresh is a no-op and that's a valid outcome.

- [ ] **Step 4: Re-render the static site and visually inspect the canary:**

```bash
cd ~/vulnerabin && python3 scripts/catalog_site_render.py
```

Open `catalog/site/safeelevatedrun_dll.html` in a browser. Confirm:
- Walk header banner appears at the top with "2a-inputs: open · 2b-sinks: not_started · 2c-features: not_started"
- If features exist: a `Features` section appears with cards
- If no features: section is absent (no empty-state shim — that's the design)
- The legacy `inputs × capabilities` matrix is still visible (FEAT layer is empty, fallback engaged)

- [ ] **Step 5: Test override endpoint round-trip:**

```bash
cd ~/vulnerabin && python3 scripts/catalog_serve.py --port 8089 &
SERVER_PID=$!
sleep 2
# Boot the live server, then if features exist, exercise the route. Otherwise just smoke-test 404.
curl -s http://127.0.0.1:8089/binary/safeelevatedrun_dll | head -5
kill $SERVER_PID
```

Expected: HTML output that contains the walk header banner.

- [ ] **Step 6: Roll back the canary's walk_state initialisation so it stays clean for production walks:**

```bash
cd ~/vulnerabin && git checkout catalog/binaries/safeelevatedrun_dll.yml
```

Verify:
```bash
git status catalog/binaries/safeelevatedrun_dll.yml
```

Expected: `working tree clean` for that file (rolled back).

- [ ] **Step 7: Commit nothing — this task is a smoke test. If anything failed, file the failure as a follow-up task and stop here.**

If everything passed, mark the canary smoke test complete in your notes.

---

## Task 17: Documentation updates

**Files:**
- Modify: `catalog/README.md` — document FEAT layer, walk_state, detector framework
- Modify: `CLAUDE.md` — document new walk phase, `vb walk` subcommands, new `vb-add` subcommands

- [ ] **Step 1: Open `catalog/README.md` and find the section that lists the schema layers (e.g. "INP-* (interaction surfaces) → SRC-* ..."). Update the layered model description to:**

```markdown
The catalog uses a six-layer model:

- **INP-*** — interaction surfaces (the things attackers physically poke: IOCTLs, pipes, files, registry)
- **SRC-*** — source code entries (where each input lands in the binary's code)
- **chains/conditions** — what must hold for an input to reach a sink
- **SNK-*** — atomic dangerous API calls (CreateProcess, WriteFile, RpcServerRegisterIf*)
- **CAP-*** — capability groupings of sinks ("what the binary CAN do")
- **FEAT-*** — user-facing features ("what the binary actually DOES" — Auto-update, Apply policy, Authenticate)

FEAT-* sits one level above CAP-*; one feature typically aggregates several
capabilities. Auto-detected by `scripts/feat_detectors/` and walked via
`vb walk <binary>`. See `docs/superpowers/specs/2026-05-10-feat-layer-design.md`
for the full design.
```

- [ ] **Step 2: Add a `## Walk pipeline` section to `catalog/README.md`:**

```markdown
## Walk pipeline (`vb walk`)

After `catalog_re_extract.py` populates auto-detected candidates (inputs,
sinks, features), researchers (or Claude) walk through them in three
gated stages:

| Stage | Walks | Closes when |
|---|---|---|
| `2a-inputs` | `reverse_engineering.inputs[]` | every input is confirmed or rejected |
| `2b-sinks` | `sinks[]` | every sink is confirmed or rejected |
| `2c-features` | `features[]` | every feature is confirmed or rejected |

CLI primitives:

```bash
vb walk status      <binary> --json
vb walk pending     <binary> --stage 2c-features --json
vb walk inspect     <binary> FEAT-001 --json
vb walk confirm     <binary> FEAT-001 --description "..." --inspect-worker <id>
vb walk reject      <binary> FEAT-001 --reason "..."
vb walk close-stage <binary> --stage 2a-inputs
vb walk refresh     <binary>
```

`confirm` is **stake-gated**: if the proposed payload has
`severity_ceiling >= High`, attached `cwe[]`, `product_feature_id` set,
or `confidence: low`, the CLI refuses without `--review-verdict <path>`
pointing at a skeptic-agent verdict file.
```

- [ ] **Step 3: Open `CLAUDE.md` and find the `## Pipeline FSM` section. Update the phase order:**

Change the phase order line from:
```
preparation → triage → deep → ...
```
to:
```
preparation → walk → triage → deep → ...
```

And add a new sub-section `### Walk phase` near the existing phase descriptions:

```markdown
### Walk phase (NEW)

Between `preparation` and `triage`, the walk phase populates and confirms
auto-detected candidates (inputs, sinks, features) for the binary.
Strategist drives `vb walk` (see `prompts/phases/walk_strategist.md`),
dispatching `walk_inspect_candidate` workers per candidate. Stake-gated
confirms (severity High+, attached CWE, product_feature_id set, or
low-confidence) get an inline `walk_confirm_review` skeptic.

Gates:
- `walk_state_started` (pre): `walk_state.stages.2a-inputs.opened_at` set
- `walk_state_done` (post): all three stages closed

CLI: see `catalog/README.md` for full `vb walk` reference.
```

- [ ] **Step 4: In `CLAUDE.md`'s `## Tool Invocation` section, add the new `vb-add` subcommands. Find the existing `vb-add` block and append:**

```bash
vb-add feature      --binary <stem> --slug "..." --name "..." --description "..." \
                    --capabilities CAP-001 --sources SRC-001 --inputs INP-001 \
                    --cwe CWE-78 --severity-ceiling High --user-observable "..."
vb-add unreachable  --binary <stem> --input INP-001 --feature FEAT-001 \
                    --reason "Input INP-001 is admin-only; feature is for low-priv attackers"
```

- [ ] **Step 5: Verify the docs render cleanly:**

```bash
cd ~/vulnerabin && head -30 catalog/README.md && head -30 CLAUDE.md
```

Expected: human-readable markdown, no obvious syntax errors

- [ ] **Step 6: Commit**

```bash
git add catalog/README.md CLAUDE.md
git commit -m "$(cat <<'EOF'
docs: add FEAT layer, walk pipeline, vb walk reference

catalog/README.md: documents six-layer model (INP/SRC/chains/SNK/CAP/FEAT),
walk pipeline three-stage gate, and CLI primitives. CLAUDE.md: adds walk
phase between preparation and triage, new vb-add subcommands.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## End of v1 plan

After Task 17, the FEAT layer ships v1:

- Schema additions are live (Tasks 1)
- Detector framework + ONE detector (`exports.py`) end-to-end (Tasks 2-3)
- `catalog_re_extract.py` integrated (Task 4)
- `vb walk` CLI complete with all 7 subcommands (Tasks 5-8)
- Worker prompts (Task 9)
- Web UI features section + walk header + `inputs × features` matrix (Tasks 10-11)
- Override endpoint (Task 12)
- Pipeline FSM updated (Task 13)
- `vb-add` extended (Task 14)
- Migration tier classifier (Task 15)
- Canary smoke-test passes (Task 16)
- Docs updated (Task 17)

## Self-review

Spec coverage:
- Section 1 (Schema): Task 1 ✓
- Section 2 (Detector framework): Tasks 2 (framework), 3 (one detector). Remaining ~30 detectors deferred to v1.1+ — explicitly noted as scope.
- Section 3 (Walk pipeline): Tasks 4-9 ✓
- Section 4 (Render pipeline): Tasks 10-11 (features section + matrix v0). Cytoscape + ECharts upgrades deferred to v1.1.
- Section 5 (Migration): Task 15 (classifier), Task 16 (canary smoke). Active-tier rollout on the remaining ~14 binaries deferred to v1.1.
- Section 6 (Sequencing): Task ordering matches spec Day 1-7 + Day 12-20 vertical-slice subset.

Placeholder scan: no TBD/TODO/handwaving. Every step has the actual command or code an engineer would run.

Type consistency: `FeatureCandidate`, `Detector`, `DetectorContext` defined in Task 2; used identically in Tasks 3, 4, 8. `STAGE_KEY_MAP` defined in Task 6; used in 7, 8. `_now()`, `_save_binary()`, `_load_binary()` defined in Task 5/6 and reused.

Scope check: this is the v1 vertical slice. Detectors beyond `exports.py`, Cytoscape Layer 4, ECharts Layer 6, full migration of all active binaries, L3/L5 heatmap conversion, and Graphviz-replaces-mermaid all ship in v1.1+ as separate plans. v1 produces working software end-to-end on the canary binary.
