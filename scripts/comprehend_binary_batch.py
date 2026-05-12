"""Bundle a comprehend_binary worker input from existing catalog state.

Reads:
- catalog/binaries/<stem>.yml (descriptive metadata + sources/sinks/chains)
- catalog/reconstructed/<stem>_<tag>/manifest.json (post-Pass-1 state)
- catalog/reconstructed/<stem>_<tag>/vuln_surface.json (if present — output of
  scripts/reconstruct_vuln_surface.py)
- catalog/reconstructed/<stem>_<tag>/notes/*.md (subsystem notes if present)

Writes a bundle JSON to:
- catalog/reconstructed/<stem>_<tag>/comprehend_input.json

The strategist then dispatches a worker with that bundle as input,
saves the worker's result to comprehend_result.json, and runs
comprehend_binary_apply.py to merge it.

If the binary has NOT been reconstructed, this script can still emit a
sparse bundle (just the catalog YAML) — the worker prompt can produce
a minimal summary from that, marking unknowns explicitly.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)


# Vuln-surface categories whose example function names are most useful for
# the worker's mental model. Skip noisy categories like file_source/crypto
# that often surface MSVC scaffolding.
_USEFUL_CATEGORIES = (
    "trust_boundary", "ipc_source", "privilege_sink", "process_sink",
    "dll_load_sink", "path_handling", "file_write_sink", "registry_write_sink",
)


def _load_yaml(path: Path) -> dict:
    import yaml as _y  # type: ignore
    return _y.safe_load(path.read_text()) or {}


def _trim_yaml_excerpt(binary_yaml: dict) -> dict:
    """Keep only the security-relevant blocks the worker should see."""
    return {
        k: binary_yaml.get(k)
        for k in ("sources", "sinks", "capabilities", "chains", "inputs",
                  "features", "process_model", "defenses")
        if binary_yaml.get(k)
    }


def _vuln_surface_examples(surface: dict, max_per_category: int = 5) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for cat, recs in (surface.get("classified") or {}).items():
        if cat not in _USEFUL_CATEGORIES:
            continue
        if not recs:
            continue
        out[cat] = [r.get("name", "") for r in recs[:max_per_category]]
    return out


def _vuln_surface_summary(surface: dict) -> dict[str, int]:
    return {k: v for k, v in (surface.get("summary") or {}).items() if v}


def _notes_subsystems(notes_dir: Path) -> dict[str, str]:
    if not notes_dir.is_dir():
        return {}
    out: dict[str, str] = {}
    for p in sorted(notes_dir.glob("*.md")):
        out[p.stem] = p.read_text(errors="replace")
    return out


def _reconstruction_summary(manifest: dict, coverage: dict) -> dict:
    bin_block = manifest.get("binary", {})
    cov_named = (coverage.get("named") or {})
    cov_totals = (coverage.get("totals") or {})
    return {
        "status": bin_block.get("status", "not_started"),
        "version_tag": bin_block.get("version_tag", ""),
        "named_total": cov_named.get("total_named", 0),
        "user_defined_functions": cov_totals.get("user_defined_functions", 0),
        "named_pct": (
            round(100.0 * cov_named.get("total_named", 0) / cov_totals.get("user_defined_functions", 0), 1)
            if cov_totals.get("user_defined_functions") else 0.0
        ),
    }


def build_bundle(stem: str, version_tag: str | None = None) -> dict:
    """Build the worker input bundle for one binary."""
    yml_path = ROOT / "catalog" / "binaries" / f"{stem}.yml"
    if not yml_path.is_file():
        raise SystemExit(f"catalog/binaries/{stem}.yml not found")
    binary_yaml = _load_yaml(yml_path)

    recon = binary_yaml.get("reconstruction") or {}
    if not version_tag:
        version_tag = recon.get("version_tag", "")

    bundle: dict = {
        "binary": {
            "stem": binary_yaml.get("binary", stem),
            "binary_kind": binary_yaml.get("binary_kind", ""),
            "platform": binary_yaml.get("platform", ""),
            "product": binary_yaml.get("product", ""),
            "description": (binary_yaml.get("description") or "").strip(),
            "principal": (binary_yaml.get("process_model") or {}).get("principal", ""),
        },
        "catalog_yaml_excerpt": _trim_yaml_excerpt(binary_yaml),
    }

    if version_tag:
        recon_dir = ROOT / "catalog" / "reconstructed" / f"{stem}_{version_tag}"
        manifest_path = recon_dir / "manifest.json"
        coverage_path = recon_dir / "coverage.json"
        surface_path = recon_dir / "vuln_surface.json"
        notes_dir = recon_dir / "notes"

        if manifest_path.is_file() and coverage_path.is_file():
            manifest = json.loads(manifest_path.read_text())
            coverage = json.loads(coverage_path.read_text())
            bundle["reconstruction"] = _reconstruction_summary(manifest, coverage)
        if surface_path.is_file():
            surface = json.loads(surface_path.read_text())
            bundle["vuln_surface_summary"] = _vuln_surface_summary(surface)
            bundle["vuln_surface_examples"] = _vuln_surface_examples(surface)
        notes = _notes_subsystems(notes_dir)
        if notes:
            bundle["notes_subsystems"] = notes

    return bundle


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, help="Binary stem")
    ap.add_argument("--version", default=None,
                    help="Reconstruction version tag (default: read from binary YAML)")
    ap.add_argument("--out", default=None,
                    help="Output bundle path (default: catalog/reconstructed/<stem>_<tag>/comprehend_input.json)")
    args = ap.parse_args(argv)

    bundle = build_bundle(args.binary, args.version)
    if args.out:
        out_path = Path(args.out)
    else:
        version_tag = bundle["binary"].get("stem")
        recon_block = (
            (_load_yaml(ROOT / "catalog" / "binaries" / f"{args.binary}.yml")
             .get("reconstruction") or {})
        )
        version_tag = args.version or recon_block.get("version_tag", "")
        if version_tag:
            out_path = (
                ROOT / "catalog" / "reconstructed" / f"{args.binary}_{version_tag}"
                / "comprehend_input.json"
            )
        else:
            out_path = ROOT / "catalog" / "binaries" / f"{args.binary}.comprehend_input.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2))
    print(f"wrote {out_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
