# Reconstruct Phase — Layer 8 + Status Banner (Sub-Plan 4/5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Pass 0's reconstruction data visible in the catalog. A new "Layer 8 — Reconstruction detail" page per binary (`catalog/pages/reconstructed/<stem>_<tag>.md` + `catalog/site/reconstructed/<stem>_<tag>.html`) renders coverage stats, pass log, project_discovery summary, and the proposed-renames table. The existing per-binary page (`catalog/site/binaries/<stem>.html`) gains a reconstruction status banner linking to Layer 8. After this plan, `vb-add reconstruction + reconstruct.py` produces immediately visible artifacts in the catalog UI.

**Architecture:** A single `catalog_reconstruct_render.py` module owns Layer 8 rendering — it reads `manifest.json` + `coverage.json` from the catalog dir and emits both a markdown page and a Jinja2 context dict for the HTML template. `catalog_site_render.py` calls it for any binary whose YAML has a `reconstruction.ref`. The binary page template gets a small inline banner section keyed off the same data. No changes to `catalog_render.py` (markdown-only existing renderer) in this sub-plan — Layer 8 markdown lives in its own file at `catalog/pages/reconstructed/`, separate from the existing `catalog/pages/<binary>.md` pages.

**Tech Stack:** Python 3.11, pytest, PyYAML, Jinja2 (already used by `catalog_site_render.py`). All build artifacts are read-time computed; no new persistent storage.

---

## File Structure

**Create:**
- `scripts/catalog_reconstruct_render.py` — Layer 8 data extraction + markdown render + Jinja2 context builder
- `catalog/site/_templates/reconstructed.html.j2` — full-page Jinja2 template for the Layer 8 HTML page
- `tests/reconstruct/test_catalog_reconstruct_render.py`
- `tests/reconstruct/fixtures/sample_manifest_complete.json` — populated manifest for render tests
- `tests/reconstruct/fixtures/sample_coverage_complete.json` — populated coverage for render tests

**Modify:**
- `scripts/catalog_site_render.py` — add `render_reconstructed_pages()` function, call from `main()`, append to top-nav if any binary has reconstruction.ref
- `catalog/site/_templates/binary.html.j2` — add reconstruction status banner section near the top of the page body
- `CLAUDE.md` — append note describing the Layer 8 page

**Read but do not modify (this sub-plan):**
- `scripts/catalog_render.py` — Layer 8 markdown render lives in `catalog_reconstruct_render.py`, not here; the existing per-binary `catalog/pages/<stem>.md` is unrelated
- `scripts/catalog_serve.py` — picks up new pages from disk automatically on next render; live route registration is a follow-up plan

---

## Task 1: Layer 8 fixture data — manifest + coverage

Two synthetic fixtures that look like real Pass 0 output. Used by every Layer 8 render test.

**Files:**
- Create: `tests/reconstruct/fixtures/sample_manifest_complete.json`
- Create: `tests/reconstruct/fixtures/sample_coverage_complete.json`

- [ ] **Step 1: Create the manifest fixture**

Create `tests/reconstruct/fixtures/sample_manifest_complete.json`:

```json
{
  "binary": {
    "stem": "samplebin",
    "version_tag": "v1_2_3",
    "status": "partial"
  },
  "passes": [
    {
      "pass": "pass0",
      "started_at": "2026-05-11T16:00:00Z",
      "ended_at": "2026-05-11T16:00:42Z",
      "tools_used": ["project_discovery", "iat_wrapper_detection", "pcode_hash_carryforward"],
      "renames_applied": 0,
      "proposed_renames": [
        {
          "addr": "0x140002000",
          "from": "FUN_140002000",
          "to": "RtlAllocateHeap_wrapper",
          "confidence": "medium",
          "source": "iat_wrapper_detection",
          "rationale": "2-instruction function with single external callee RtlAllocateHeap"
        },
        {
          "addr": "0x140004000",
          "from": "FUN_140004000",
          "to": "CreateFileW_wrapper",
          "confidence": "medium",
          "source": "iat_wrapper_detection",
          "rationale": "1-instruction function with single external callee CreateFileW"
        },
        {
          "addr": "0x140003000",
          "from": "FUN_140003000",
          "to": "DispatchCommand",
          "confidence": "high",
          "source": "pcode_hash_carryforward",
          "rationale": "pcode_hash match with prior version v1_2_2 at 0x140003000 (previously named DispatchCommand)"
        }
      ],
      "renames_by_source": {
        "iat_wrapper_detection": 2,
        "pcode_hash_carryforward": 1
      },
      "tokens_spent": 0,
      "snapshot": null,
      "prior_version_consulted": "samplebin_v1_2_2"
    }
  ],
  "project_discovery": {
    "binary": "samplebin.exe",
    "arch": "x86_64",
    "format": "PE",
    "address_size": 64,
    "function_counts": {"total": 12, "user_defined": 8, "external": 3, "thunk": 1},
    "exports": [
      {"name": "DllMain", "address": "0x140006000"},
      {"name": "Ordinal_42", "address": "0x140007000"},
      {"name": "entry", "address": "0x140001000"}
    ],
    "entrypoints": ["0x140001000"],
    "reachable_user_defined": [
      "0x140001000", "0x140002000", "0x140003000", "0x140004000",
      "0x140005000", "0x140006000", "0x140007000"
    ],
    "strings_by_function": {
      "0x140040000": ["Initializing config", "C:\\ProgramData\\sample\\config.json"]
    }
  },
  "pcode_hashes_by_addr": {
    "0x140001000": "hash_entry",
    "0x140002000": "hash_2000",
    "0x140003000": "hash_3000",
    "0x140004000": "hash_4000",
    "0x140005000": "hash_5000",
    "0x140006000": "hash_6000",
    "0x140007000": "hash_7000",
    "0x140040000": "hash_orphan"
  }
}
```

- [ ] **Step 2: Create the coverage fixture**

Create `tests/reconstruct/fixtures/sample_coverage_complete.json`:

```json
{
  "hard_gate_pass": false,
  "soft_gate_pass": false,
  "totals": {
    "user_defined_functions": 8,
    "external_imports_skipped": 3,
    "thunks_skipped": 1
  },
  "named": {
    "total_named": 6,
    "from_pass0": 3
  },
  "low_confidence_named_addresses": []
}
```

- [ ] **Step 3: Verify JSON parseable**

```bash
python3 -c "import json; json.load(open('tests/reconstruct/fixtures/sample_manifest_complete.json'))"
python3 -c "import json; json.load(open('tests/reconstruct/fixtures/sample_coverage_complete.json'))"
```

Expected: no output for either (silent success).

- [ ] **Step 4: Commit**

```bash
git add tests/reconstruct/fixtures/sample_manifest_complete.json tests/reconstruct/fixtures/sample_coverage_complete.json
git commit -m "test(reconstruct): manifest + coverage fixtures for Layer 8 render"
```

---

## Task 2: `catalog_reconstruct_render.py` — data extraction

The `build_context()` function takes a catalog reconstruct dir path and returns a Jinja2 context dict / data dict suitable for both markdown and HTML render. This is the data shape consumed by all downstream rendering.

**Files:**
- Create: `scripts/catalog_reconstruct_render.py`
- Test: `tests/reconstruct/test_catalog_reconstruct_render.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/reconstruct/test_catalog_reconstruct_render.py`:

```python
"""Tests for catalog_reconstruct_render — Layer 8 page generation."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import catalog_reconstruct_render as r  # type: ignore


def _seed_recon_dir(tmp_path: Path, stem: str = "samplebin", tag: str = "v1_2_3") -> Path:
    """Materialize a catalog/reconstructed/<stem>_<tag>/ dir with the fixtures."""
    d = tmp_path / "catalog" / "reconstructed" / f"{stem}_{tag}"
    d.mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_complete.json", d / "manifest.json")
    shutil.copy(FIXTURES / "sample_coverage_complete.json", d / "coverage.json")
    return d


def test_build_context_returns_required_top_level_keys(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    assert set(ctx.keys()) >= {
        "stem",
        "version_tag",
        "status",
        "coverage",
        "pass_log",
        "project_discovery",
        "proposed_renames",
        "renames_by_source_totals",
        "carryforward",
    }
    assert ctx["stem"] == "samplebin"
    assert ctx["version_tag"] == "v1_2_3"
    assert ctx["status"] == "partial"


def test_build_context_coverage_summary(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    cov = ctx["coverage"]
    assert cov["hard_gate_pass"] is False
    assert cov["soft_gate_pass"] is False
    assert cov["totals"]["user_defined_functions"] == 8
    assert cov["named_total"] == 6
    assert cov["named_pct"] == pytest.approx(75.0)  # 6/8 = 75%


def test_build_context_pass_log_lists_pass0(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    log = ctx["pass_log"]
    assert len(log) == 1
    entry = log[0]
    assert entry["pass"] == "pass0"
    assert entry["tools_used"] == [
        "project_discovery", "iat_wrapper_detection", "pcode_hash_carryforward"
    ]
    assert entry["renames_proposed"] == 3
    # Duration field should be derived from started_at + ended_at.
    assert "duration_seconds" in entry
    assert entry["duration_seconds"] == 42


def test_build_context_proposed_renames_sorted_and_complete(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    renames = ctx["proposed_renames"]
    assert len(renames) == 3
    # Sorted by addr (matches reconstruct_pass0 sort).
    addrs = [p["addr"] for p in renames]
    assert addrs == sorted(addrs)
    for p in renames:
        assert {"addr", "from", "to", "confidence", "source", "rationale"} <= set(p.keys())


def test_build_context_renames_by_source_totals(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    totals = ctx["renames_by_source_totals"]
    assert totals["iat_wrapper_detection"] == 2
    assert totals["pcode_hash_carryforward"] == 1


def test_build_context_carryforward_summary(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    cf = ctx["carryforward"]
    assert cf["prior_version_consulted"] == "samplebin_v1_2_2"
    assert cf["renames_ported"] == 1  # one pcode_hash_carryforward rename


def test_build_context_handles_missing_coverage_json(tmp_path):
    """If coverage.json is absent, still produce a context (just empty coverage)."""
    d = tmp_path / "catalog" / "reconstructed" / "samplebin_vfresh"
    d.mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_complete.json", d / "manifest.json")
    ctx = r.build_context(d)
    assert ctx["coverage"] is None or ctx["coverage"] == {} or "hard_gate_pass" not in (ctx["coverage"] or {})


def test_build_context_handles_no_carryforward(tmp_path):
    """If pass0 has no prior_version_consulted, carryforward block reflects that."""
    d = tmp_path / "catalog" / "reconstructed" / "fresh_v1"
    d.mkdir(parents=True)
    manifest = json.loads((FIXTURES / "sample_manifest_complete.json").read_text())
    manifest["passes"][0]["prior_version_consulted"] = None
    manifest["passes"][0]["renames_by_source"] = {"iat_wrapper_detection": 2}
    manifest["passes"][0]["proposed_renames"] = [
        p for p in manifest["passes"][0]["proposed_renames"]
        if p["source"] != "pcode_hash_carryforward"
    ]
    (d / "manifest.json").write_text(json.dumps(manifest))
    (d / "coverage.json").write_text(json.dumps({
        "hard_gate_pass": False, "soft_gate_pass": False,
        "totals": {"user_defined_functions": 8, "external_imports_skipped": 3, "thunks_skipped": 1},
        "named": {"total_named": 5, "from_pass0": 2},
        "low_confidence_named_addresses": [],
    }))
    ctx = r.build_context(d)
    cf = ctx["carryforward"]
    assert cf["prior_version_consulted"] is None
    assert cf["renames_ported"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/reconstruct/test_catalog_reconstruct_render.py -v
```

Expected: 8 FAILED — `ModuleNotFoundError`.

- [ ] **Step 3: Create `scripts/catalog_reconstruct_render.py`** with EXACT content:

```python
"""Layer 8 — Reconstruction detail page renderer.

Reads `catalog/reconstructed/<stem>_<tag>/manifest.json` (and `coverage.json`
if present) and produces:

- `build_context()` — a dict suitable for both Jinja2 HTML rendering
  (catalog_site_render.py) and a markdown render entry point.
- `render_markdown()` — Layer 8 page as a markdown string.
- CLI entry (`if __name__ == "__main__"`) — writes
  `catalog/pages/reconstructed/<stem>_<tag>.md` for one or all binaries.

This module does NOT modify `manifest.json` or `coverage.json`. Read-only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)


def _iso_to_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    s2 = s.rstrip("Z")
    try:
        return datetime.fromisoformat(s2)
    except ValueError:
        return None


def _duration_seconds(start: str | None, end: str | None) -> int | None:
    sdt = _iso_to_dt(start)
    edt = _iso_to_dt(end)
    if sdt and edt:
        return int((edt - sdt).total_seconds())
    return None


def _summarize_passes(manifest: dict) -> list[dict]:
    out: list[dict] = []
    for p in manifest.get("passes", []):
        out.append({
            "pass": p.get("pass"),
            "started_at": p.get("started_at"),
            "ended_at": p.get("ended_at"),
            "duration_seconds": _duration_seconds(p.get("started_at"), p.get("ended_at")),
            "tools_used": p.get("tools_used", []),
            "renames_proposed": len(p.get("proposed_renames", [])),
            "renames_applied": p.get("renames_applied", 0),
            "renames_by_source": p.get("renames_by_source", {}),
            "tokens_spent": p.get("tokens_spent", 0),
            "snapshot": p.get("snapshot"),
            "prior_version_consulted": p.get("prior_version_consulted"),
        })
    return out


def _summarize_coverage(cov: dict | None) -> dict:
    if not cov:
        return {}
    totals = cov.get("totals", {})
    user_defined = totals.get("user_defined_functions", 0) or 0
    named = (cov.get("named") or {}).get("total_named", 0) or 0
    named_pct = (named / user_defined * 100.0) if user_defined else 0.0
    return {
        "hard_gate_pass": bool(cov.get("hard_gate_pass")),
        "soft_gate_pass": bool(cov.get("soft_gate_pass")),
        "totals": totals,
        "named_total": named,
        "from_pass0": (cov.get("named") or {}).get("from_pass0", 0),
        "named_pct": round(named_pct, 1),
        "low_confidence_named_addresses": cov.get("low_confidence_named_addresses", []),
    }


def _aggregate_proposed_renames(passes: list[dict]) -> list[dict]:
    """Flatten across all passes; sorted by addr for stable rendering."""
    out: list[dict] = []
    for p in passes:
        for rec in p.get("proposed_renames", []):
            out.append(rec)
    return sorted(out, key=lambda r: r.get("addr", ""))


def _aggregate_renames_by_source(passes: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for p in passes:
        for src, n in (p.get("renames_by_source") or {}).items():
            out[src] = out.get(src, 0) + n
    return out


def _carryforward_summary(passes: list[dict]) -> dict:
    """First pass that has a prior_version_consulted wins; count of
    carryforward-sourced renames across all passes is the renames_ported.
    """
    prior = None
    for p in passes:
        if p.get("prior_version_consulted"):
            prior = p["prior_version_consulted"]
            break
    ported = 0
    for p in passes:
        for rec in p.get("proposed_renames", []):
            if rec.get("source") == "pcode_hash_carryforward":
                ported += 1
    return {"prior_version_consulted": prior, "renames_ported": ported}


def build_context(recon_dir: Path) -> dict:
    """Read manifest + coverage from `recon_dir` and return a render context.

    `recon_dir` must be a path like `catalog/reconstructed/<stem>_<tag>/`.
    `manifest.json` is required; `coverage.json` is optional.
    """
    manifest_path = recon_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"manifest.json missing at {manifest_path}")
    manifest = json.loads(manifest_path.read_text())

    cov_path = recon_dir / "coverage.json"
    cov = json.loads(cov_path.read_text()) if cov_path.is_file() else None

    bin_meta = manifest.get("binary", {})
    return {
        "stem": bin_meta.get("stem"),
        "version_tag": bin_meta.get("version_tag"),
        "status": bin_meta.get("status"),
        "coverage": _summarize_coverage(cov),
        "pass_log": _summarize_passes(manifest),
        "project_discovery": manifest.get("project_discovery", {}),
        "proposed_renames": _aggregate_proposed_renames(manifest.get("passes", [])),
        "renames_by_source_totals": _aggregate_renames_by_source(manifest.get("passes", [])),
        "carryforward": _carryforward_summary(manifest.get("passes", [])),
        "recon_dir_relative": str(recon_dir.relative_to(ROOT)) if recon_dir.is_relative_to(ROOT) else str(recon_dir),
    }


def render_markdown(ctx: dict) -> str:
    """Produce the Layer 8 markdown page for one reconstruction context."""
    out: list[str] = []
    out.append(f"# Reconstruction detail — {ctx['stem']} @ {ctx['version_tag']}\n")
    out.append(f"**Status:** `{ctx['status']}`\n")
    out.append(f"**Catalog path:** `{ctx['recon_dir_relative']}`\n")

    cov = ctx["coverage"] or {}
    if cov:
        out.append("\n## Coverage\n")
        out.append(f"- Hard gate (reachable_named_100pct): **{'pass' if cov['hard_gate_pass'] else 'fail'}**")
        out.append(f"- Soft gate (tail_named_80pct): **{'pass' if cov['soft_gate_pass'] else 'fail'}**")
        out.append(f"- User-defined functions: {cov['totals'].get('user_defined_functions', 0)}")
        out.append(f"- Named: {cov['named_total']} ({cov['named_pct']}%)")
        out.append(f"- Named via Pass 0: {cov['from_pass0']}")
        ext = cov['totals'].get('external_imports_skipped', 0)
        thunk = cov['totals'].get('thunks_skipped', 0)
        out.append(f"- Skipped: {ext} externals, {thunk} thunks")

    cf = ctx["carryforward"]
    if cf.get("prior_version_consulted"):
        out.append("\n## Carryforward\n")
        out.append(f"- Prior version consulted: `{cf['prior_version_consulted']}`")
        out.append(f"- Renames ported: {cf['renames_ported']}")
    else:
        out.append("\n## Carryforward\n")
        out.append("- No prior version found; this is the first reconstruction of this binary.")

    out.append("\n## Pass log\n")
    out.append("| Pass | Started | Duration | Tools | Renames proposed | Tokens |")
    out.append("|---|---|---|---|---|---|")
    for p in ctx["pass_log"]:
        dur = f"{p['duration_seconds']}s" if p["duration_seconds"] is not None else "—"
        tools = ", ".join(p["tools_used"]) if p["tools_used"] else "—"
        out.append(
            f"| `{p['pass']}` | {p['started_at'] or '—'} | {dur} | {tools} | "
            f"{p['renames_proposed']} | {p['tokens_spent']} |"
        )

    pd = ctx["project_discovery"] or {}
    if pd:
        out.append("\n## Project discovery\n")
        fc = pd.get("function_counts", {})
        out.append(f"- Binary: `{pd.get('binary', '?')}` ({pd.get('arch', '?')}, {pd.get('format', '?')})")
        out.append(f"- Function counts: total={fc.get('total', 0)}, "
                   f"user-defined={fc.get('user_defined', 0)}, "
                   f"external={fc.get('external', 0)}, thunk={fc.get('thunk', 0)}")
        entries = pd.get("entrypoints", [])
        exports = pd.get("exports", [])
        reach = pd.get("reachable_user_defined", [])
        out.append(f"- Entrypoints: {len(entries)} ({', '.join(entries[:5])}{'...' if len(entries) > 5 else ''})")
        out.append(f"- Exports: {len(exports)} ({', '.join(e.get('name', '?') for e in exports[:5])}"
                   f"{'...' if len(exports) > 5 else ''})")
        out.append(f"- Reachable user-defined functions: {len(reach)}")

    rn = ctx["proposed_renames"]
    if rn:
        out.append("\n## Proposed renames\n")
        out.append("| Addr | From | To | Confidence | Source | Rationale |")
        out.append("|---|---|---|---|---|---|")
        for p in rn:
            out.append(
                f"| `{p['addr']}` | `{p['from']}` | `{p['to']}` | {p['confidence']} | "
                f"{p['source']} | {p['rationale']} |"
            )
    else:
        out.append("\n## Proposed renames\n")
        out.append("(none yet)")

    rbs = ctx["renames_by_source_totals"]
    if rbs:
        out.append("\n## Renames by source\n")
        for src, n in sorted(rbs.items()):
            out.append(f"- `{src}`: {n}")

    return "\n".join(out) + "\n"


def _discover_reconstructions() -> list[Path]:
    """Walk catalog/reconstructed/ and return every dir that has a manifest.json."""
    base = ROOT / "catalog" / "reconstructed"
    if not base.is_dir():
        return []
    out: list[Path] = []
    for d in sorted(base.iterdir()):
        if d.is_dir() and (d / "manifest.json").is_file():
            out.append(d)
    return out


def _write_markdown_page(recon_dir: Path) -> Path:
    ctx = build_context(recon_dir)
    pages_dir = ROOT / "catalog" / "pages" / "reconstructed"
    pages_dir.mkdir(parents=True, exist_ok=True)
    out_path = pages_dir / f"{recon_dir.name}.md"
    out_path.write_text(render_markdown(ctx))
    return out_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", nargs="?",
                    help="Specific <stem>_<tag> to render, or omit for all")
    args = ap.parse_args(argv)

    if args.target:
        recon_dir = ROOT / "catalog" / "reconstructed" / args.target
        if not recon_dir.is_dir():
            print(f"error: {recon_dir} not found", file=sys.stderr)
            return 2
        out = _write_markdown_page(recon_dir)
        print(f"wrote {out.relative_to(ROOT)}")
    else:
        dirs = _discover_reconstructions()
        if not dirs:
            print("no reconstructions found under catalog/reconstructed/")
            return 0
        for d in dirs:
            out = _write_markdown_page(d)
            print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_catalog_reconstruct_render.py -v
```

Expected: 8 PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/catalog_reconstruct_render.py tests/reconstruct/test_catalog_reconstruct_render.py
git commit -m "feat(catalog): Layer 8 reconstruction render — context builder + markdown"
```

---

## Task 3: Markdown render CLI smoke test

End-to-end: run `python3 scripts/catalog_reconstruct_render.py` with the env override and verify it writes pages.

**Files:**
- Test: `tests/reconstruct/test_catalog_reconstruct_render.py` (append)

- [ ] **Step 1: Add the failing test**

Append to `tests/reconstruct/test_catalog_reconstruct_render.py`:

```python
import os
import subprocess


def test_cli_writes_markdown_for_specific_target(tmp_path):
    _seed_recon_dir(tmp_path, stem="samplebin", tag="v1_2_3")
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_reconstruct_render.py"),
         "samplebin_v1_2_3"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    out = tmp_path / "catalog" / "pages" / "reconstructed" / "samplebin_v1_2_3.md"
    assert out.is_file()
    text = out.read_text()
    assert "Reconstruction detail — samplebin @ v1_2_3" in text
    assert "RtlAllocateHeap_wrapper" in text
    assert "Carryforward" in text


def test_cli_writes_markdown_for_all_targets_when_no_arg(tmp_path):
    _seed_recon_dir(tmp_path, stem="bin_a", tag="v1")
    _seed_recon_dir(tmp_path, stem="bin_b", tag="v2")
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_reconstruct_render.py")],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    pages = tmp_path / "catalog" / "pages" / "reconstructed"
    assert (pages / "bin_a_v1.md").is_file()
    assert (pages / "bin_b_v2.md").is_file()


def test_cli_refuses_unknown_target(tmp_path):
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_reconstruct_render.py"),
         "does_not_exist_vfoo"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "not found" in (result.stderr + result.stdout).lower()
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
pytest tests/reconstruct/test_catalog_reconstruct_render.py -v
```

Expected: 11 PASSED (8 prior + 3 new).

- [ ] **Step 3: Commit**

```bash
git add tests/reconstruct/test_catalog_reconstruct_render.py
git commit -m "test(catalog): Layer 8 render CLI smoke tests"
```

---

## Task 4: Layer 8 Jinja2 HTML template

The HTML template extends `_base.html.j2` (already used by the site renderer) and renders the same data the markdown shows, with Tailwind styling consistent with the existing site.

**Files:**
- Create: `catalog/site/_templates/reconstructed.html.j2`

- [ ] **Step 1: Inspect the existing base template**

Read `catalog/site/_templates/_base.html.j2` to understand the block structure. Look for `{% block content %}` or similar — that's where the new template extends.

```bash
grep -n "block " catalog/site/_templates/_base.html.j2
```

Note which block names exist (typically `title`, `content`, possibly `breadcrumbs`).

- [ ] **Step 2: Create the template**

Create `catalog/site/_templates/reconstructed.html.j2` with this content. **Note the {% raw %} guard** — copy literally including the `{% raw %}` blocks if your platform's template tooling renders Jinja2-in-Jinja2; otherwise paste as-is:

```jinja2
{% extends "_base.html.j2" %}

{% block title %}Reconstruction — {{ stem }} @ {{ version_tag }}{% endblock %}

{% block content %}
<div class="container mx-auto px-md py-lg max-w-5xl">
  <nav class="text-ui-sans-sm text-on-surface-variant mb-md">
    <a href="../index.html" class="hover:underline">Catalog</a>
    <span class="mx-1">/</span>
    <a href="../binaries/{{ stem }}.html" class="hover:underline">{{ stem }}</a>
    <span class="mx-1">/</span>
    <span>Reconstruction @ {{ version_tag }}</span>
  </nav>

  <h1 class="text-display-md mb-sm">Reconstruction — {{ stem }} @ {{ version_tag }}</h1>

  {% set status_classes = {
    "complete":    "bg-success/10 text-success border-success",
    "partial":     "bg-warning/10 text-warning border-warning",
    "in_progress": "bg-info/10 text-info border-info",
    "not_started": "bg-danger/10 text-danger border-danger",
    "opt_out":     "bg-surface-variant text-on-surface-variant border-on-surface-variant"
  } %}
  <div class="inline-block border rounded px-sm py-1 text-ui-sans-sm font-medium mb-lg
              {{ status_classes.get(status, 'bg-surface-variant text-on-surface-variant border-on-surface-variant') }}">
    Status: {{ status or 'unknown' }}
  </div>

  {% if coverage %}
  <section class="mb-xl">
    <h2 class="text-headline-sm mb-md">Coverage</h2>
    <div class="grid grid-cols-2 gap-md md:grid-cols-4">
      <div class="bg-surface-variant rounded p-md">
        <div class="text-ui-sans-xs text-on-surface-variant uppercase">Hard gate</div>
        <div class="text-headline-sm">{{ "pass" if coverage.hard_gate_pass else "fail" }}</div>
      </div>
      <div class="bg-surface-variant rounded p-md">
        <div class="text-ui-sans-xs text-on-surface-variant uppercase">Soft gate</div>
        <div class="text-headline-sm">{{ "pass" if coverage.soft_gate_pass else "fail" }}</div>
      </div>
      <div class="bg-surface-variant rounded p-md">
        <div class="text-ui-sans-xs text-on-surface-variant uppercase">Named</div>
        <div class="text-headline-sm">{{ coverage.named_total }}/{{ coverage.totals.user_defined_functions }} ({{ coverage.named_pct }}%)</div>
      </div>
      <div class="bg-surface-variant rounded p-md">
        <div class="text-ui-sans-xs text-on-surface-variant uppercase">From Pass 0</div>
        <div class="text-headline-sm">{{ coverage.from_pass0 }}</div>
      </div>
    </div>
  </section>
  {% endif %}

  <section class="mb-xl">
    <h2 class="text-headline-sm mb-md">Carryforward</h2>
    {% if carryforward.prior_version_consulted %}
      <p>Prior version: <code>{{ carryforward.prior_version_consulted }}</code> — {{ carryforward.renames_ported }} renames ported.</p>
    {% else %}
      <p>No prior version found; this is the first reconstruction of this binary.</p>
    {% endif %}
  </section>

  <section class="mb-xl">
    <h2 class="text-headline-sm mb-md">Pass log</h2>
    <table class="w-full text-ui-sans-sm">
      <thead class="text-on-surface-variant">
        <tr>
          <th class="text-left p-2">Pass</th>
          <th class="text-left p-2">Started</th>
          <th class="text-left p-2">Duration</th>
          <th class="text-left p-2">Tools</th>
          <th class="text-right p-2">Renames</th>
          <th class="text-right p-2">Tokens</th>
        </tr>
      </thead>
      <tbody>
        {% for p in pass_log %}
        <tr class="border-t border-surface-variant">
          <td class="p-2"><code>{{ p['pass'] }}</code></td>
          <td class="p-2">{{ p.started_at or '—' }}</td>
          <td class="p-2">{{ (p.duration_seconds|string + 's') if p.duration_seconds is not none else '—' }}</td>
          <td class="p-2">{{ p.tools_used | join(', ') if p.tools_used else '—' }}</td>
          <td class="p-2 text-right">{{ p.renames_proposed }}</td>
          <td class="p-2 text-right">{{ p.tokens_spent }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>

  {% if project_discovery %}
  <section class="mb-xl">
    <h2 class="text-headline-sm mb-md">Project discovery</h2>
    {% set fc = project_discovery.function_counts or {} %}
    <ul class="list-disc list-inside text-ui-sans-sm">
      <li>Binary: <code>{{ project_discovery.binary or '?' }}</code> ({{ project_discovery.arch or '?' }}, {{ project_discovery.format or '?' }})</li>
      <li>Function counts: total={{ fc.get('total', 0) }}, user-defined={{ fc.get('user_defined', 0) }}, external={{ fc.get('external', 0) }}, thunk={{ fc.get('thunk', 0) }}</li>
      <li>Entrypoints: {{ project_discovery.entrypoints | length }} ({{ project_discovery.entrypoints[:5] | join(', ') }}{% if project_discovery.entrypoints | length > 5 %}…{% endif %})</li>
      <li>Exports: {{ project_discovery.exports | length }} ({{ project_discovery.exports[:5] | map(attribute='name') | join(', ') }}{% if project_discovery.exports | length > 5 %}…{% endif %})</li>
      <li>Reachable user-defined: {{ project_discovery.reachable_user_defined | length }}</li>
    </ul>
  </section>
  {% endif %}

  <section class="mb-xl">
    <h2 class="text-headline-sm mb-md">Proposed renames ({{ proposed_renames | length }})</h2>
    {% if proposed_renames %}
    <table class="w-full text-ui-sans-sm">
      <thead class="text-on-surface-variant">
        <tr>
          <th class="text-left p-2">Addr</th>
          <th class="text-left p-2">From</th>
          <th class="text-left p-2">To</th>
          <th class="text-left p-2">Conf</th>
          <th class="text-left p-2">Source</th>
          <th class="text-left p-2">Rationale</th>
        </tr>
      </thead>
      <tbody>
        {% for r in proposed_renames %}
        <tr class="border-t border-surface-variant">
          <td class="p-2"><code>{{ r.addr }}</code></td>
          <td class="p-2"><code>{{ r['from'] }}</code></td>
          <td class="p-2"><code>{{ r.to }}</code></td>
          <td class="p-2">{{ r.confidence }}</td>
          <td class="p-2">{{ r.source }}</td>
          <td class="p-2">{{ r.rationale }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p class="text-on-surface-variant">(none yet)</p>
    {% endif %}
  </section>

  {% if renames_by_source_totals %}
  <section class="mb-xl">
    <h2 class="text-headline-sm mb-md">Renames by source</h2>
    <ul class="list-disc list-inside text-ui-sans-sm">
      {% for src, n in renames_by_source_totals | dictsort %}
      <li><code>{{ src }}</code>: {{ n }}</li>
      {% endfor %}
    </ul>
  </section>
  {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 3: Verify Jinja2 syntax**

```bash
python3 -c "
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('catalog/site/_templates'))
env.get_template('reconstructed.html.j2')
print('OK: template parses')
"
```

Expected: `OK: template parses`. If a parse error fires, fix it before committing.

- [ ] **Step 4: Commit**

```bash
git add catalog/site/_templates/reconstructed.html.j2
git commit -m "feat(catalog): Layer 8 HTML template (reconstructed.html.j2)"
```

---

## Task 5: Wire Layer 8 HTML rendering into `catalog_site_render.py`

Add a `render_reconstructed_pages()` function. Call from `main()`.

**Files:**
- Modify: `scripts/catalog_site_render.py`

- [ ] **Step 1: Inspect existing render flow**

```bash
grep -n "^def render_\|def main" scripts/catalog_site_render.py
```

Identify (a) how existing render functions are structured, (b) where main calls them. Read main() so you know where to insert the new call.

- [ ] **Step 2: Add the new render function**

In `scripts/catalog_site_render.py`, add this function just before `def main():` (it sits alongside the other `render_*` functions):

```python
def render_reconstructed_pages(env: Environment) -> int:
    """Render the Layer 8 reconstruction detail page for every catalog
    reconstruct dir that has a manifest.json. Returns the count rendered.
    """
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "scripts"))
    import catalog_reconstruct_render as crr  # type: ignore
    base = ROOT / "catalog" / "reconstructed"
    if not base.is_dir():
        return 0
    out_dir = SITE_DIR / "reconstructed"
    out_dir.mkdir(parents=True, exist_ok=True)
    tmpl = env.get_template("reconstructed.html.j2")
    count = 0
    for d in sorted(base.iterdir()):
        if not d.is_dir() or not (d / "manifest.json").is_file():
            continue
        ctx = crr.build_context(d)
        html = tmpl.render(**ctx)
        (out_dir / f"{d.name}.html").write_text(html)
        count += 1
    return count
```

The references to `ROOT`, `SITE_DIR`, and `Environment` are already in scope at the top of the file. If they aren't, find their current names (search for `ROOT =` and `SITE_DIR =` or similar) and adapt.

- [ ] **Step 3: Call from `main()`**

Inside `main()`, after the existing render calls (e.g. `render_binaries`, `render_products`), add:

```python
    n_recon = render_reconstructed_pages(env)
    if n_recon:
        print(f"rendered {n_recon} reconstructed page(s)")
```

- [ ] **Step 4: Smoke-run the renderer**

```bash
python3 scripts/catalog_site_render.py
```

Expected: existing pages still render correctly, plus (if any catalog reconstructions exist) "rendered N reconstructed page(s)". If no reconstructions exist in the real `catalog/reconstructed/`, the line will not print — that is correct.

- [ ] **Step 5: Add an integration test**

Append to `tests/reconstruct/test_catalog_reconstruct_render.py`:

```python
def test_site_render_emits_reconstruction_html(tmp_path):
    """Drive catalog_site_render.py via subprocess and verify it writes the
    Layer 8 HTML for a seeded reconstruction.
    """
    # Mirror the bare-minimum repo layout that catalog_site_render expects.
    (tmp_path / "catalog" / "binaries").mkdir(parents=True)
    (tmp_path / "catalog" / "products").mkdir(parents=True)
    (tmp_path / "taxonomy" / "binary").mkdir(parents=True)
    # Copy the real defense_library.json + templates so the existing render
    # functions don't crash for lack of inputs.
    shutil.copy(
        REPO_ROOT / "taxonomy" / "binary" / "defense_library.json",
        tmp_path / "taxonomy" / "binary" / "defense_library.json",
    )
    shutil.copytree(REPO_ROOT / "catalog" / "site" / "_templates",
                    tmp_path / "catalog" / "site" / "_templates")

    # Seed a binary YAML that references our reconstruction.
    (tmp_path / "catalog" / "binaries" / "samplebin.yml").write_text(yaml.safe_dump({
        "binary": "samplebin",
        "product": "test",
        "reconstruction": {
            "ref": "catalog/reconstructed/samplebin_v1_2_3",
            "version_tag": "v1_2_3",
            "status": "partial",
        },
    }))
    _seed_recon_dir(tmp_path, stem="samplebin", tag="v1_2_3")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    # Some downstream rendering reads other source data; let it fail
    # gracefully but require that reconstructed/ specifically is emitted.
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_site_render.py")],
        env=env, capture_output=True, text=True,
    )
    # Non-zero exit is acceptable here as long as the reconstructed HTML
    # was produced — the renderer may bail on missing product YAMLs etc.
    html = tmp_path / "catalog" / "site" / "reconstructed" / "samplebin_v1_2_3.html"
    assert html.is_file(), (
        f"reconstructed HTML not emitted. stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    text = html.read_text()
    assert "samplebin" in text
    assert "v1_2_3" in text
    assert "Reconstruction" in text
```

- [ ] **Step 6: Run the new test**

```bash
pytest tests/reconstruct/test_catalog_reconstruct_render.py::test_site_render_emits_reconstruction_html -v
```

Expected: PASSED. If FAILED with a Jinja2 template error, fix the template (Task 4) and re-run. If FAILED because some other renderer crashes the process before we get to render_reconstructed_pages, move the new render call EARLIER in main() so it runs before the crash-prone ones.

- [ ] **Step 7: Commit**

```bash
git add scripts/catalog_site_render.py tests/reconstruct/test_catalog_reconstruct_render.py
git commit -m "feat(catalog): emit Layer 8 HTML via catalog_site_render"
```

---

## Task 6: Reconstruction status banner on the binary page

Add a small banner section near the top of `catalog/site/_templates/binary.html.j2` that displays the reconstruction status (green/amber/red/etc.) with a link to the Layer 8 page.

**Files:**
- Modify: `catalog/site/_templates/binary.html.j2`
- Modify: `scripts/catalog_site_render.py` (extend the context passed to the binary template with `reconstruction` block)

- [ ] **Step 1: Identify how the existing binary template renders**

```bash
grep -n "binary.html.j2\|render_binaries\b" scripts/catalog_site_render.py
```

Find the function that calls `env.get_template("binary.html.j2")` (or equivalent) and renders for each binary. Note what context dict it currently passes. You'll add a `reconstruction` key to that dict.

- [ ] **Step 2: Add reconstruction context to the binary render**

Inside `render_binaries` (or whichever function renders per-binary pages), where the context dict is built per binary, add the `reconstruction` block:

```python
        # Reconstruction status — None if the binary has no reconstruction.ref.
        recon_block = (b.get("reconstruction") or {})
        ctx_reconstruction = None
        if recon_block.get("ref"):
            ctx_reconstruction = {
                "version_tag": recon_block.get("version_tag", ""),
                "status": recon_block.get("status", "not_started"),
                "ref": recon_block.get("ref"),
                "page": f"reconstructed/{recon_block.get('version_tag', '').replace(' ', '_')}.html",
                "page_relative": f"../reconstructed/{Path(recon_block.get('ref', '')).name}.html",
            }
        # ... wherever the existing context dict is being assembled:
        # ctx = { ..., "reconstruction": ctx_reconstruction }
```

You may need to inspect `Path` import; if not present, add `from pathlib import Path` at the top (it likely already is).

- [ ] **Step 3: Modify `catalog/site/_templates/binary.html.j2`**

Find a stable anchor near the top of the body block. A common spot is just below the page title `<h1>` and above the existing first section. Insert this banner block:

```jinja2
{% if reconstruction %}
{% set _rs = reconstruction.status %}
{% set _classes = {
  "complete":    "bg-success/10 text-success border-success",
  "partial":     "bg-warning/10 text-warning border-warning",
  "in_progress": "bg-info/10 text-info border-info",
  "not_started": "bg-danger/10 text-danger border-danger",
  "opt_out":     "bg-surface-variant text-on-surface-variant border-on-surface-variant"
} %}
{% set _msgs = {
  "complete":    "Reconstructed " ~ reconstruction.version_tag,
  "partial":     "Partial reconstruction " ~ reconstruction.version_tag,
  "in_progress": "Reconstruction in progress (" ~ reconstruction.version_tag ~ ")",
  "not_started": "Reconstruction scaffolded but not run (" ~ reconstruction.version_tag ~ ")",
  "opt_out":     "Reconstruction skipped (" ~ reconstruction.version_tag ~ ")"
} %}
<div class="border rounded px-md py-sm mb-lg flex items-center gap-md
            {{ _classes.get(_rs, 'bg-surface-variant text-on-surface-variant border-on-surface-variant') }}">
  <span class="font-medium">{{ _msgs.get(_rs, 'Reconstruction status: ' ~ _rs) }}</span>
  {% if _rs != 'opt_out' %}
  <a href="{{ reconstruction.page_relative }}" class="text-ui-sans-sm hover:underline">View Layer 8 detail →</a>
  {% endif %}
</div>
{% endif %}
```

If the existing template uses a different style for buttons/banners, adapt the Tailwind classes — read 5-10 lines of existing markup around your insertion point and match its style.

- [ ] **Step 4: Run the integration test from Task 5**

```bash
pytest tests/reconstruct/test_catalog_reconstruct_render.py -k site_render -v
```

(This test already seeds a binary with `reconstruction.ref` and runs the renderer. The new test below verifies the banner text.)

- [ ] **Step 5: Add a banner-content test**

Append to `tests/reconstruct/test_catalog_reconstruct_render.py`:

```python
def test_binary_page_includes_reconstruction_banner(tmp_path):
    """The per-binary HTML page must contain the reconstruction banner
    when the binary YAML has reconstruction.ref.
    """
    (tmp_path / "catalog" / "binaries").mkdir(parents=True)
    (tmp_path / "catalog" / "products").mkdir(parents=True)
    (tmp_path / "taxonomy" / "binary").mkdir(parents=True)
    shutil.copy(
        REPO_ROOT / "taxonomy" / "binary" / "defense_library.json",
        tmp_path / "taxonomy" / "binary" / "defense_library.json",
    )
    shutil.copytree(REPO_ROOT / "catalog" / "site" / "_templates",
                    tmp_path / "catalog" / "site" / "_templates")

    (tmp_path / "catalog" / "binaries" / "samplebin.yml").write_text(yaml.safe_dump({
        "binary": "samplebin",
        "product": "test",
        "reconstruction": {
            "ref": "catalog/reconstructed/samplebin_v1_2_3",
            "version_tag": "v1_2_3",
            "status": "partial",
        },
    }))
    _seed_recon_dir(tmp_path, stem="samplebin", tag="v1_2_3")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_site_render.py")],
        env=env, capture_output=True, text=True,
    )
    bin_html = tmp_path / "catalog" / "site" / "binaries" / "samplebin.html"
    assert bin_html.is_file(), "binary HTML page not emitted"
    text = bin_html.read_text()
    assert "Partial reconstruction" in text or "v1_2_3" in text
    assert "Layer 8" in text or "reconstructed/" in text
```

- [ ] **Step 6: Run all tests**

```bash
pytest tests/reconstruct/ -v
```

Expected: All previous tests + the new banner test = approximately 80 PASSED.

- [ ] **Step 7: Commit**

```bash
git add catalog/site/_templates/binary.html.j2 scripts/catalog_site_render.py tests/reconstruct/test_catalog_reconstruct_render.py
git commit -m "feat(catalog): reconstruction status banner on binary page"
```

---

## Task 7: Document Layer 8 in CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Find the existing "## Reconstruct phase (Pass 0 MVP)" section**

```bash
grep -n "## Reconstruct phase (Pass 0 MVP)" CLAUDE.md
```

The new content goes inside or immediately after that section.

- [ ] **Step 2: Append a Layer 8 sub-section**

Using Edit (NOT redirection), append the following at the end of the `## Reconstruct phase (Pass 0 MVP)` section (just before the next `## ` heading):

```markdown

### Layer 8 reconstruction detail page

The reconstructed `manifest.json` + `coverage.json` are surfaced in the catalog UI as a Layer 8 page per binary version:

```bash
# Render the markdown version (catalog/pages/reconstructed/<stem>_<tag>.md)
python3 scripts/catalog_reconstruct_render.py                 # all
python3 scripts/catalog_reconstruct_render.py samplebin_v1_2_3  # one

# Render the full site (Layer 8 HTML + reconstruction banner on binary page)
python3 scripts/catalog_site_render.py
```

Layer 8 surfaces:
- Coverage stats (hard/soft gate state, named-vs-total, Pass 0 contribution)
- Pass log timeline (one row per pass: started_at, duration, tools, renames, tokens)
- Carryforward summary (prior version consulted, renames ported)
- Project discovery snapshot (function counts, entrypoints, exports, reachable set)
- Proposed renames table (addr / from / to / confidence / source / rationale)
- Renames-by-source totals

The per-binary catalog page (`catalog/site/binaries/<stem>.html`) gains a status banner near the top with a link to Layer 8: green for `complete`, amber for `partial`, info for `in_progress`, red for `not_started`, gray for `opt_out`.
```

- [ ] **Step 3: Verify**

```bash
grep -A2 "Layer 8 reconstruction detail page" CLAUDE.md
```

Expected: shows the new sub-heading.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document Layer 8 reconstruction page + status banner"
```

---

## Done — Layer 8 acceptance

When all 7 tasks are complete:

- [ ] `pytest tests/reconstruct/ -v` reports all tests PASSED (~80 total: 68 from sub-plans 1-2 + ~12 new)
- [ ] `python3 scripts/catalog_reconstruct_render.py` writes `catalog/pages/reconstructed/<stem>_<tag>.md` for every reconstruction
- [ ] `python3 scripts/catalog_site_render.py` writes `catalog/site/reconstructed/<stem>_<tag>.html` AND a status banner appears on the binary page
- [ ] CLAUDE.md documents the new invocations

**Next sub-plan candidates:**
- **Sub-plan 2.5 — Pass 0 expansion** (Rich header, string-xref naming, IOCTL/NTSTATUS constant equates) — adds ~10-15% deterministic naming yield
- **Sub-plan 3 — LLM Passes 1-4** — adds rename/retype/structify/comment workers producing the bulk of reconstruction; output is still proposed_renames data, applied to Ghidra only after LibGhidra integration ships
- **Sub-plan 2-libghidra — LibGhidra integration** — `vendor/bootstrap.sh --install`, FID + BSim, real `.gpr` snapshots, `.c` re-emit. Heaviest sub-plan; defer until you have a concrete Ghidra project to apply against.
