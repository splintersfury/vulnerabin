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
            "proposed_renames": p.get("proposed_renames", []),
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
    passes = _summarize_passes(manifest)
    return {
        "stem": bin_meta.get("stem"),
        "version_tag": bin_meta.get("version_tag"),
        "status": bin_meta.get("status"),
        "coverage": _summarize_coverage(cov),
        "pass_log": passes,
        "project_discovery": manifest.get("project_discovery", {}),
        "proposed_renames": _aggregate_proposed_renames(passes),
        "renames_by_source_totals": _aggregate_renames_by_source(passes),
        "carryforward": _carryforward_summary(passes),
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
