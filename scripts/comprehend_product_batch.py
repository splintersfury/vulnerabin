"""Bundle a comprehend_narrative worker input from a product YAML.

Reads:
- catalog/products/<slug>.yml
- For every binary listed in product.binaries:
  - catalog/binaries/<stem>.yml — pulls summary + full_picture if present

Splits binaries into two groups:
- `binaries_comprehended`: those with a non-empty summary in their YAML
- `binaries_pending`: those without (still awaiting per-binary comprehend)

Writes a bundle JSON to:
- catalog/products/<slug>.comprehend_input.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)


def _load_yaml(path: Path) -> dict:
    import yaml as _y  # type: ignore
    return _y.safe_load(path.read_text()) or {}


def _resolve_binary_yaml(name: str) -> Path | None:
    """Find catalog/binaries/<stem>.yml.

    Product YAML may list binaries as:
    - 'bdservicehost'         -> tries bdservicehost.yml, bdservicehost_exe.yml, ...
    - 'bdservicehost.exe'     -> tries bdservicehost_exe.yml (.->_), then plain
    - 'bdservicehost_exe'     -> tries bdservicehost_exe.yml directly
    Returns None if no match.
    """
    bdir = ROOT / "catalog" / "binaries"
    candidates: list[str] = []
    # Direct match.
    candidates.append(name)
    # If name has a dot extension, convert to underscore form.
    if "." in name:
        candidates.append(name.replace(".", "_"))
    # If name is a bare stem, try with common suffixes.
    if "." not in name and "_" not in name:
        for ext in ("exe", "dll", "sys"):
            candidates.append(f"{name}_{ext}")
    for cand in candidates:
        p = bdir / f"{cand}.yml"
        if p.is_file():
            return p
    return None


def build_bundle(product_slug: str) -> dict:
    yml_path = ROOT / "catalog" / "products" / f"{product_slug}.yml"
    if not yml_path.is_file():
        raise SystemExit(f"catalog/products/{product_slug}.yml not found")
    product_yaml = _load_yaml(yml_path)

    listed = product_yaml.get("binaries") or []
    comprehended: list[dict] = []
    pending: list[str] = []

    for entry in listed:
        # Entry may be plain stem string OR dict with `stem` key.
        if isinstance(entry, dict):
            name = entry.get("stem") or entry.get("name") or ""
        else:
            name = str(entry).split("#")[0].strip()
            # Strip trailing comments / whitespace.
        if not name:
            continue
        bin_path = _resolve_binary_yaml(name)
        if bin_path is None:
            pending.append(name)
            continue
        bin_yaml = _load_yaml(bin_path)
        if not bin_yaml.get("summary") or not bin_yaml.get("full_picture"):
            pending.append(name)
            continue
        comprehended.append({
            "stem": bin_yaml.get("binary", name),
            "summary": bin_yaml["summary"],
            "full_picture": bin_yaml["full_picture"],
        })

    return {
        "product": {
            "slug": product_yaml.get("product", product_slug),
            "display_name": product_yaml.get("display_name", product_slug),
            "vendor": product_yaml.get("vendor", ""),
            "description": (product_yaml.get("description") or "").strip(),
            "binaries_listed": [
                (e.get("stem") if isinstance(e, dict) else str(e).split("#")[0].strip())
                for e in listed
            ],
        },
        "binaries_comprehended": comprehended,
        "binaries_pending": pending,
        "process_model": product_yaml.get("process_model") or {},
        "ipc_edges": product_yaml.get("ipc_edges") or [],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--product", required=True, help="Product slug (matches catalog/products/<slug>.yml)")
    ap.add_argument("--out", default=None,
                    help="Output bundle path (default: catalog/products/<slug>.comprehend_input.json)")
    args = ap.parse_args(argv)

    bundle = build_bundle(args.product)
    if args.out:
        out_path = Path(args.out)
    else:
        out_path = ROOT / "catalog" / "products" / f"{args.product}.comprehend_input.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2))
    print(
        f"wrote {out_path.relative_to(ROOT)}: "
        f"{len(bundle['binaries_comprehended'])} comprehended, "
        f"{len(bundle['binaries_pending'])} pending"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
