#!/usr/bin/env python3
"""
Render `catalog/products/<product>.yml` to a `catalog/pages/products/<product>.md`
page that gives the aerial view of a product spanning multiple binaries.

Layer 4 of the visualization stack (per-binary layers 1-3 are in catalog_render.py).

Outputs:
  - process / IPC topology mermaid diagram (binaries clustered by trust zone)
  - vulnerabilities ledger (cross-binary findings table with submission status)
  - defense distribution (per-defense-component table)
  - source-class heatmap across the product

Usage:
    python3 scripts/catalog_product_render.py                                  # render all
    python3 scripts/catalog_product_render.py bitdefender-total-security       # render one
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PRODUCTS_DIR = ROOT / "catalog" / "products"
PAGES_DIR = ROOT / "catalog" / "pages" / "products"
BINARIES_DIR = ROOT / "catalog" / "binaries"


def _safe(v) -> str:
    if v is None or v == "":
        return "—"
    return str(v).replace("\n", " ").replace("|", "\\|")


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_") or "node"


def _mer(s: str) -> str:
    if not s:
        return ""
    return s.replace('"', "&quot;").replace("|", "/").replace("(", "&#40;").replace(")", "&#41;").replace("[", "&#91;").replace("]", "&#93;")


def load_yaml(p: Path) -> dict:
    return yaml.safe_load(p.read_text()) or {}


def load_binary_meta(binary_token: str) -> dict | None:
    """Try to locate a catalog/binaries/<...>.yml that matches the binary token
    from the product YAML's binaries list. Token may be a filename or a stem."""
    for cand in BINARIES_DIR.glob("*.yml"):
        d = yaml.safe_load(cand.read_text()) or {}
        if d.get("binary") == binary_token or cand.stem == _slug(binary_token).lower():
            return d
    return None


def render_topology_mermaid(data: dict) -> str:
    out = ["## Topology (Layer 4)", ""]
    out.append("Process and IPC topology of the product. Binaries clustered by trust zone; "
               "edges are observed IPC connections; dotted edges from the attacker zone are "
               "speculative injection paths.")
    out.append("")

    topo = data.get("topology") or {}
    zones = topo.get("trust_zones") or {}

    out.append("```mermaid")
    out.append("flowchart TB")

    # Node-id map for edges
    node_id = {}
    for principal, items in zones.items():
        sg = "Z" + _slug(principal)[:24]
        out.append(f'    subgraph {sg}["{_mer(principal)}"]')
        for entry in items:
            n = entry if isinstance(entry, str) else entry.get("name", "?")
            nid = "N" + _slug(n)[:32]
            node_id[n] = nid
            # Color by zone
            if principal.upper().startswith("SYSTEM") or "SYSTEM" in principal.upper():
                cls = ":::sysz"
            elif principal.lower().startswith("admin"):
                cls = ":::admz"
            elif principal.lower().startswith("loggedinuser"):
                cls = ":::usrz"
            elif "attacker" in principal.lower() or "standard" in principal.lower():
                cls = ":::atkz"
            else:
                cls = ":::neut"
            out.append(f'        {nid}["{_mer(n)}"]{cls}')
        out.append("    end")

    def resolve_node(token: str) -> str | None:
        """Match a token against existing node labels by substring as fallback."""
        if token in node_id:
            return node_id[token]
        # Substring match in either direction
        for name, nid in node_id.items():
            if token in name or name in token:
                return nid
        return None

    # IPC edges (deduped by (src, dst, via))
    seen_ext: set = set()
    seen_edges: set = set()
    for edge in (topo.get("ipc_edges") or []):
        src = edge.get("src","?")
        dst = edge.get("dst","?")
        via = edge.get("via","")
        edge_key = (src, dst, via)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        sid = resolve_node(src)
        did = resolve_node(dst)
        label = _mer((via or "")[:40])
        if sid and did:
            out.append(f'    {sid} -. {label} .-> {did}')
        elif sid and not did:
            # External / sink node not in the zone map (e.g., CreateProcessAsUserW)
            ext_id = "X" + _slug(dst)[:32]
            if ext_id not in seen_ext:
                out.append(f'    {ext_id}([{_mer(dst)}]):::ext')
                seen_ext.add(ext_id)
            out.append(f'    {sid} -. {label} .-> {ext_id}')

    out.append("    classDef sysz fill:#fdd,stroke:#900")
    out.append("    classDef admz fill:#fed,stroke:#a60")
    out.append("    classDef usrz fill:#dfd,stroke:#080")
    out.append("    classDef atkz fill:#222,stroke:#000,color:#fff")
    out.append("    classDef neut fill:#eee,stroke:#666")
    out.append("    classDef ext fill:#ffd,stroke:#aa0")
    out.append("```")
    out.append("")
    return "\n".join(out) + "\n"


def render_vulnerabilities_table(data: dict) -> str:
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return ""
    out = ["## Vulnerabilities surfaced", ""]
    out.append("Cross-binary findings catalog. Status badges: ✅ submitted_paid · 🟢 submitted · ⏳ in_progress · ⚠ submitted_dropped · ⏸ not_submitted.")
    out.append("")
    out.append("| Binary | Finding | Classes | Severity | Status | Submission |")
    out.append("|--------|---------|---------|----------|--------|------------|")
    badge = {
        "submitted_paid":      "✅",
        "submitted":           "🟢",
        "in_progress":         "⏳",
        "submitted_dropped":   "⚠",
        "not_submitted":       "⏸",
        "unknown":             "❔",
    }
    for v in vulns:
        out.append("| `{b}` | [`{f}`](../../engagements/{f}) | {c} | {s} | {st} | {sr} |".format(
            b=_safe(v.get("binary")),
            f=_safe(v.get("finding_ref")),
            c=", ".join(v.get("classes", []) or []),
            s=_safe(v.get("severity")),
            st=f"{badge.get(v.get('status','unknown'), '?')} {_safe(v.get('status'))}",
            sr=_safe(v.get("submission_ref")),
        ))
    out.append("")
    return "\n".join(out) + "\n"


def render_defenses_table(data: dict) -> str:
    topo = data.get("topology") or {}
    defenses = topo.get("defenses") or {}
    if not defenses:
        return ""
    out = ["## Defense distribution across the product", ""]
    out.append("Defenses observed by component. `GAP:` lines flag known weaknesses still open.")
    out.append("")
    for component, items in defenses.items():
        out.append(f"### `{component}`")
        out.append("")
        for it in items:
            out.append(f"- {_safe(it)}")
        out.append("")
    return "\n".join(out) + "\n"


def render_class_heatmap(data: dict) -> str:
    """For each binary in the product, count which source classes appear (via
    catalog/binaries/<binary>.yml `sources[].source_class_id`). Render as a
    table heatmap."""
    bins = data.get("binaries") or []
    rows = []
    all_classes: set = set()
    for b in bins:
        meta = load_binary_meta(b)
        if not meta:
            rows.append((b, {}))
            continue
        cls_count = {}
        for s in meta.get("sources") or []:
            cid = s.get("source_class_id")
            if cid:
                cls_count[cid] = cls_count.get(cid, 0) + 1
                all_classes.add(cid)
            for cid2 in s.get("co_class_ids") or []:
                cls_count[cid2] = cls_count.get(cid2, 0) + 1
                all_classes.add(cid2)
        rows.append((b, cls_count))

    if not all_classes:
        return ""

    cls_sorted = sorted(all_classes)
    out = ["## Source-class coverage across binaries", ""]
    out.append("Heatmap: which v2 source classes are catalogued per binary. Counts are the number of distinct sources tagged with that class.")
    out.append("")
    header = ["Binary"] + cls_sorted
    out.append("| " + " | ".join(header) + " |")
    out.append("|" + "|".join(["---"] * len(header)) + "|")
    for b, cls_count in rows:
        cells = [f"`{b}`"]
        for c in cls_sorted:
            n = cls_count.get(c, 0)
            cells.append(str(n) if n else "·")
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    return "\n".join(out) + "\n"


def render_open_angles(data: dict) -> str:
    angles = data.get("open_angles") or []
    if not angles:
        return ""
    out = ["## Open angles flagged for vendor / future investigation", ""]
    for a in angles:
        out.append(f"- {_safe(a)}")
    out.append("")
    return "\n".join(out) + "\n"


def render_product_page(data: dict) -> str:
    out = []
    out.append(f"# {data.get('display_name') or data.get('product')}")
    out.append("")
    if data.get("vendor"):
        out.append(f"**Vendor**: {data['vendor']}")
        out.append("")
    if data.get("description"):
        out.append(str(data["description"]).strip())
        out.append("")

    # Versions
    vs = data.get("versions_seen") or []
    if vs:
        out.append("## Versions catalogued")
        out.append("")
        out.append("| Version | First seen | Engagement |")
        out.append("|---------|------------|------------|")
        for v in vs:
            out.append(f"| {_safe(v.get('version'))} | {_safe(v.get('seen'))} | `{_safe(v.get('eng'))}` |")
        out.append("")

    # Layer 4 visualizations
    out.append(render_topology_mermaid(data))
    out.append(render_class_heatmap(data))
    out.append(render_defenses_table(data))
    out.append(render_vulnerabilities_table(data))
    out.append(render_open_angles(data))

    # Per-binary index
    bins = data.get("binaries") or []
    if bins:
        out.append("## Binaries in this product")
        out.append("")
        for b in bins:
            meta = load_binary_meta(b)
            if meta:
                # Compute the page filename
                pf = re.sub(r"[^A-Za-z0-9]+", "_", meta.get("binary", b).lower()).strip("_")
                principal = (meta.get("process_model") or {}).get("principal", "?")
                src_count = len(meta.get("sources") or [])
                chain_count = len(meta.get("chains") or [])
                out.append(f"- [`{b}`](../{pf}.md) — {principal}, {src_count} sources, {chain_count} chains")
            else:
                out.append(f"- `{b}` _(no catalog/binaries/ entry yet)_")
        out.append("")

    out.append("---")
    out.append(f"_Auto-generated by `scripts/catalog_product_render.py` at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}._")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("product", nargs="?", help="render only this product (filename without .yml)")
    args = ap.parse_args()

    if not PRODUCTS_DIR.is_dir():
        print(f"no products dir at {PRODUCTS_DIR}", file=sys.stderr)
        return 0

    PAGES_DIR.mkdir(exist_ok=True, parents=True)

    if args.product:
        targets = [PRODUCTS_DIR / f"{args.product}.yml"]
    else:
        # Skip files starting with _ (schemas, drafts)
        targets = sorted(p for p in PRODUCTS_DIR.glob("*.yml") if not p.name.startswith("_"))

    for path in targets:
        if not path.is_file():
            print(f"not found: {path}", file=sys.stderr)
            continue
        data = load_yaml(path)
        if not data.get("product"):
            continue
        out_path = PAGES_DIR / f"{path.stem}.md"
        out_path.write_text(render_product_page(data))
        print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
