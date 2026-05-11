#!/usr/bin/env python3
"""
Render the catalog as a static HTML site under `catalog/site/`.

Consumes:
  catalog/binaries/<name>.yml  — per-binary data
  catalog/products/<slug>.yml  — per-product topology + ledger
  catalog/index.json           — global summary (for the index page)
  taxonomy/binary/defense_library.json — per-class detection checklists / canonical defenses

Outputs:
  catalog/site/index.html                  — catalog browse view
  catalog/site/binaries/<page-stem>.html   — per-binary detail (Layers 1, 2, 3, 5)
  catalog/site/products/<slug>.html        — per-product (Layer 4)
  catalog/site/products/index.html         — product list
  catalog/site/binaries/index.html         — same as catalog index, alt entry

Templates live under `catalog/site/_templates/`. Uses Jinja2 (already installed).

Usage:
    python3 scripts/catalog_site_render.py
    python3 scripts/catalog_site_render.py --serve 8080  # render + spawn http.server
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

import os as _os
ROOT = Path(_os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)
CATALOG = ROOT / "catalog"
SITE = CATALOG / "site"
TEMPLATES = SITE / "_templates"


def load_yaml(p: Path) -> dict:
    return yaml.safe_load(p.read_text()) or {}


def page_stem(binary_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", binary_name.lower()).strip("_")


def load_defense_library() -> dict:
    p = ROOT / "taxonomy" / "binary" / "defense_library.json"
    if not p.is_file():
        return {}
    return json.loads(p.read_text())


def relevant_classes_for(binary: dict, lib: dict) -> list[str]:
    """Mirror the logic in catalog_render.py for class relevance."""
    pr = lib.get("platform_relevance", {})
    platform = (binary.get("platform") or "").lower()
    kind = (binary.get("binary_kind") or "").lower()
    if platform in pr:
        candidates = set(pr[platform])
    else:
        candidates = {c["id"] for c in lib.get("classes", [])}
    bk_map = pr.get("binary_kind", {})
    if kind in bk_map:
        kind_set = set()
        for token in bk_map[kind]:
            if token.endswith("-*"):
                prefix = token[:-2]
                for c in lib.get("classes", []):
                    if c["id"].startswith(prefix + "-"):
                        kind_set.add(c["id"])
            else:
                kind_set.add(token)
        candidates &= kind_set
    return sorted(candidates)


def build_class_coverage_grouped(binary: dict, lib: dict):
    relevant = relevant_classes_for(binary, lib)
    class_meta = {c["id"]: c for c in lib.get("classes", [])}
    cov = {entry.get("class_id"): entry for entry in (binary.get("class_coverage") or [])}

    rows = []
    for cid in relevant:
        meta = class_meta.get(cid, {})
        entry = cov.get(cid, {})
        rows.append({
            "class_id": cid,
            "name": meta.get("name", ""),
            "status": entry.get("status", "unchecked"),
            "rationale": entry.get("rationale", ""),
            "refs": entry.get("refs"),
            "lib": meta if entry.get("status", "unchecked") == "unchecked" else None,
        })

    by_group: dict[str, list] = {}
    for r in rows:
        grp = r["class_id"].split("-")[0]
        by_group.setdefault(grp, []).append(r)
    order = ["F", "I", "N", "K", "U", "T", "UP", "C", "E", "W", "CR"]
    grouped = []
    for grp in [g for g in order if g in by_group] + sorted(g for g in by_group if g not in order):
        grouped.append((grp, by_group[grp]))
    stats = Counter(r["status"] for r in rows)
    coverage_stats = {
        "present": stats.get("present", 0),
        "defense_observed": stats.get("defense_observed", 0),
        "not_present": stats.get("not_present", 0),
        "unchecked": stats.get("unchecked", 0),
    }
    return grouped, coverage_stats


def status_dot_for(binary: dict) -> str:
    """Return tailwind bg-* class for the index-row status dot."""
    chains = binary.get("chains") or []
    statuses = [c.get("status") for c in chains]
    if "confirmed" in statuses:
        return "bg-error"
    if "partial" in statuses:
        return "bg-tertiary"
    if "unexplored" in statuses or "hypothesised" in statuses:
        return "bg-secondary"
    return "bg-outline"


def collect_binaries() -> list[dict]:
    bins = []
    bdir = CATALOG / "binaries"
    if not bdir.is_dir():
        return bins
    for p in sorted(bdir.glob("*.yml")):
        d = load_yaml(p)
        if not d.get("binary"):
            continue
        d["page_stem"] = p.stem
        d["yml_path"] = str(p)
        bins.append(d)
    return bins


def collect_products() -> list[dict]:
    prods = []
    pdir = CATALOG / "products"
    if not pdir.is_dir():
        return prods
    for p in sorted(pdir.glob("*.yml")):
        if p.name.startswith("_"):
            continue
        d = load_yaml(p)
        if not d.get("product"):
            continue
        d["slug"] = p.stem
        prods.append(d)
    return prods


def compute_global_stats(binaries: list[dict], products: list[dict]) -> dict:
    chain_status_counter = Counter()
    for b in binaries:
        for c in b.get("chains") or []:
            chain_status_counter[c.get("status", "unexplored")] += 1
    return {
        "total_binaries": len(binaries),
        "total_products": len(products),
        "total_chains": sum(len(b.get("chains") or []) for b in binaries),
        "confirmed": chain_status_counter.get("confirmed", 0),
        "partial": chain_status_counter.get("partial", 0),
        "unexplored": chain_status_counter.get("unexplored", 0) + chain_status_counter.get("hypothesised", 0),
    }


def render_products_grid(env: Environment, binaries: list[dict], products: list[dict]):
    """Landing page: products grid (the primary entry point)."""
    # Build per-product stats (binary count, chain count, status distribution)
    bins_by_product: dict[str, list[dict]] = {}
    for b in binaries:
        if b.get("product"):
            bins_by_product.setdefault(b["product"], []).append(b)

    rows = []
    for p in products:
        prod_bins = bins_by_product.get(p["slug"], [])
        confirmed = partial = unexplored = chain_count = 0
        for b in prod_bins:
            for c in b.get("chains") or []:
                chain_count += 1
                st = c.get("status", "unexplored")
                if st == "confirmed": confirmed += 1
                elif st == "partial": partial += 1
                elif st in ("unexplored", "hypothesised"): unexplored += 1
        # Latest version from product YAML versions_seen
        versions = p.get("versions_seen") or []
        latest_version = versions[0].get("version") if versions else ""
        rows.append({
            "product": p["product"],
            "slug": p["slug"],
            "display_name": p.get("display_name"),
            "vendor": p.get("vendor"),
            "description": p.get("description", ""),
            "latest_version": latest_version,
            "binary_count": len(prod_bins),
            "chain_count": chain_count,
            "finding_count": len(p.get("vulnerabilities") or []),
            "confirmed_count": confirmed,
            "partial_count": partial,
            "unexplored_count": unexplored,
        })
    rows.sort(key=lambda r: (-r["confirmed_count"], -r["partial_count"], -r["chain_count"], r["product"]))
    unique_vendors = sorted({p["vendor"] for p in rows if p.get("vendor")})

    tpl = env.get_template("products_grid.html.j2")
    out = SITE / "index.html"
    out.write_text(tpl.render(products=rows, stats=compute_global_stats(binaries, products), unique_vendors=unique_vendors, root=""))
    print(f"wrote {out.relative_to(ROOT)}")


def render_binaries_index(env: Environment, binaries: list[dict], products: list[dict]):
    """Secondary cross-cut: flat binaries table (still useful for ad-hoc binary search)."""
    rows = []
    class_counter = Counter()
    chain_status_counter = Counter()
    for b in binaries:
        chains = b.get("chains") or []
        statuses = [c.get("status", "unexplored") for c in chains]
        for s in statuses:
            chain_status_counter[s] += 1
        for src in (b.get("sources") or []):
            cid = src.get("source_class_id")
            if cid:
                class_counter[cid] += 1
            for c2 in src.get("co_class_ids") or []:
                class_counter[c2] += 1
        rows.append({
            "binary": b.get("binary"),
            "display_name": b.get("display_name"),
            "page_stem": b["page_stem"],
            "product": b.get("product"),
            "platform": b.get("platform", "?"),
            "source_count": len(b.get("sources") or []),
            "sink_count": len(b.get("sinks") or []),
            "chain_count": len(chains),
            "confirmed": statuses.count("confirmed"),
            "partial": statuses.count("partial"),
            "unexplored": statuses.count("unexplored") + statuses.count("hypothesised"),
            "status_dot": status_dot_for(b),
        })
    stats = compute_global_stats(binaries, products)
    stats["top_classes"] = class_counter.most_common(8)
    recent = []
    for b in binaries:
        for c in b.get("chains") or []:
            if c.get("submission_ref"):
                recent.append({
                    "id_short": c.get("id"),
                    "title": c.get("title", ""),
                    "platform": b.get("platform", "?"),
                    "icon": "memory" if b.get("binary_kind") == "sys" else "dns",
                    "product_slug": b.get("product", ""),
                    "status_dot": "bg-error" if c.get("status") == "confirmed" else "bg-tertiary" if c.get("status") == "partial" else "bg-secondary",
                    "status_label": (c.get("status") or "").replace("_", " "),
                })
    recent = sorted(recent, key=lambda x: x["id_short"])[:6]
    unique_platforms = sorted({b.get("platform") for b in rows if b.get("platform") and b.get("platform") != "?"})

    tpl = env.get_template("index.html.j2")  # the old binaries-table template
    out = SITE / "binaries.html"
    out.write_text(tpl.render(binaries=rows, recent_findings=recent, stats=stats, unique_platforms=unique_platforms, root=""))
    print(f"wrote {out.relative_to(ROOT)}")


def render_chains_index(env: Environment, binaries: list[dict]):
    """Cross-binary chain index — every chain across every binary, filterable."""
    chains = []
    for b in binaries:
        for c in (b.get("chains") or []):
            chains.append({
                "id": c.get("id"),
                "title": c.get("title", ""),
                "binary": b.get("binary"),
                "binary_page_stem": b["page_stem"],
                "product": b.get("product"),
                "status": c.get("status", "unexplored"),
                "severity": c.get("severity", ""),
                "cwe": c.get("cwe", []),
                "submission_ref": c.get("submission_ref", ""),
            })
    chains.sort(key=lambda c: ({"confirmed": 0, "partial": 1, "hypothesised": 2, "unexplored": 3, "mitigated": 4}.get(c["status"], 5), c["id"]))
    out = SITE / "chains.html"
    wrapper = env.from_string("""{% extends "_base.html.j2" %}
{% set active = 'chain' %}
{% block title %}Vulnerabin · Chains{% endblock %}
{% block content %}
<div class="px-lg py-md border-b border-outline-variant bg-surface">
  <div class="max-w-[1600px] mx-auto w-full">
    <h1 class="font-h1 text-h1 text-primary">Chains across all binaries</h1>
    <p class="text-ui-sans-sm text-on-surface-variant mt-xs max-w-3xl">{{ chains|length }} chains catalogued. Each row is a source → conditions → sink path; click to see the full chain detail with all conditions.</p>
  </div>
</div>
<div class="p-lg max-w-[1600px] mx-auto w-full">
  <table class="w-full text-left text-data-mono-sm bg-surface border border-outline-variant rounded">
    <thead><tr class="bg-surface-container border-b border-outline-variant">
      <th class="p-2 font-normal text-on-surface-variant uppercase">ID</th>
      <th class="p-2 font-normal text-on-surface-variant uppercase">Title</th>
      <th class="p-2 font-normal text-on-surface-variant uppercase">Binary</th>
      <th class="p-2 font-normal text-on-surface-variant uppercase">Product</th>
      <th class="p-2 font-normal text-on-surface-variant uppercase">Status</th>
      <th class="p-2 font-normal text-on-surface-variant uppercase">Severity</th>
      <th class="p-2 font-normal text-on-surface-variant uppercase">CWE</th>
    </tr></thead>
    <tbody>
      {% for c in chains %}
      <tr class="border-b border-outline-variant hover:bg-surface-container cursor-pointer" onclick="location.href='{{ root }}binaries/{{ c.binary_page_stem }}/chains/{{ c.id }}.html'">
        <td class="p-2 text-primary font-bold">{{ c.id }}</td>
        <td class="p-2 text-on-surface">{{ c.title | truncate(80) }}</td>
        <td class="p-2 text-on-surface-variant">{{ c.binary }}</td>
        <td class="p-2 text-on-surface-variant">{% if c.product %}<a href="{{ root }}products/{{ c.product }}.html" class="hover:text-primary" onclick="event.stopPropagation()">{{ c.product }}</a>{% else %}—{% endif %}</td>
        <td class="p-2">
          {% if c.status == 'confirmed' %}<span class="bg-error/20 text-error px-1.5 py-0.5 rounded">✅ confirmed</span>
          {% elif c.status == 'partial' %}<span class="bg-tertiary/20 text-tertiary px-1.5 py-0.5 rounded">🟡 partial</span>
          {% elif c.status == 'hypothesised' %}<span class="bg-primary/20 text-primary px-1.5 py-0.5 rounded">❔ hypothesised</span>
          {% elif c.status == 'unexplored' %}<span class="bg-secondary/20 text-secondary px-1.5 py-0.5 rounded">⏳ unexplored</span>
          {% elif c.status == 'mitigated' %}<span class="bg-on-surface-variant/10 text-on-surface-variant px-1.5 py-0.5 rounded">🛡 mitigated</span>{% endif %}
        </td>
        <td class="p-2 text-on-surface-variant">{{ c.severity | default('—') }}</td>
        <td class="p-2 text-on-surface-variant">{{ c.cwe | join(', ') if c.cwe else '—' }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}""")
    out.write_text(wrapper.render(chains=chains, root=""))
    print(f"wrote {out.relative_to(ROOT)}")


def chain_workflow_stage(chain: dict) -> str:
    """Same logic as catalog_serve._chain_workflow_stage."""
    poc = chain.get("poc") or {}
    outcome = chain.get("outcome") or {}
    sub_ref = chain.get("submission_ref") or ""
    if sub_ref:
        return "submitted"
    if outcome.get("boundary_crossed") in ("yes", True):
        return "boundary_crossed"
    if poc.get("status") in ("tested", "executed"):
        return "poc_tested"
    if poc.get("status") in ("built", "drafted"):
        return "poc_built"
    if chain.get("conditions") and len([c for c in chain["conditions"] if "auto-stub" not in c]) > 0:
        return "conditions_enumerated"
    return "input_identified"


def render_chain_pages(env: Environment, binaries: list[dict]):
    """Per-chain detail pages: catalog/site/binaries/<binary_stem>/chains/<chain_id>.html"""
    tpl = env.get_template("chain.html.j2")
    for b in binaries:
        chains = b.get("chains") or []
        if not chains:
            continue
        sibling_lookup = [{"id": c.get("id"), "title": c.get("title", ""), "status": c.get("status", "unexplored"), "severity": c.get("severity", "")} for c in chains]
        sources_lookup = {s["id"]: s for s in (b.get("sources") or [])}
        sinks_lookup = {s["id"]: s for s in (b.get("sinks") or [])}
        root = "../../../"
        outdir = SITE / "binaries" / b["page_stem"] / "chains"
        outdir.mkdir(parents=True, exist_ok=True)
        for c in chains:
            sib = [s for s in sibling_lookup if s["id"] != c.get("id")]
            src = sources_lookup.get(c.get("source_id"))
            snk = sinks_lookup.get(c.get("sink_id"))
            stage = chain_workflow_stage(c)
            out = outdir / f"{c['id']}.html"
            out.write_text(tpl.render(chain=c, binary=b, source=src, sink=snk, sibling_chains=sib, workflow_current_stage=stage, root=root))
        print(f"wrote {len(chains)} chain pages under {outdir.relative_to(ROOT)}")


def render_pipeline_static(env: Environment, binaries: list[dict]):
    """Static-site equivalent of /pipeline."""
    PIPELINE_STAGES = [
        ("input_identified",      "Input identified",      "primary",   "search"),
        ("conditions_enumerated", "Conditions enumerated", "tertiary",  "list_alt"),
        ("poc_built",             "PoC built",             "secondary", "build"),
        ("poc_tested",            "PoC tested",            "secondary", "play_arrow"),
        ("boundary_crossed",      "Boundary crossed",      "error",     "warning"),
        ("submitted",             "Submitted",             "error",     "send"),
    ]
    by_stage = {s[0]: [] for s in PIPELINE_STAGES}
    for b in binaries:
        for c in (b.get("chains") or []):
            stage = chain_workflow_stage(c)
            by_stage.setdefault(stage, []).append({
                "id": c.get("id"), "title": c.get("title", ""),
                "binary": b.get("binary"), "binary_page_stem": b["page_stem"],
                "product": b.get("product"),
                "status": c.get("status", "unexplored"),
                "severity": c.get("severity", ""),
                "submission_ref": c.get("submission_ref", ""),
            })
    wrapper = env.from_string("""{% extends "_base.html.j2" %}
{% set active = 'pipeline' %}
{% block title %}Vulnerabin · Research pipeline{% endblock %}
{% block content %}
<div class="px-lg py-md border-b border-outline-variant bg-surface">
  <div class="max-w-[1800px] mx-auto w-full flex items-end justify-between">
    <div>
      <h1 class="font-h1 text-h1 text-primary">Research pipeline</h1>
      <p class="text-ui-sans-sm text-on-surface-variant mt-xs max-w-3xl">Chains organised by workflow stage. Move left → right as you reverse a binary, identify inputs, trace conditions, build a PoC, test it, observe whether it crosses a security boundary, and ultimately submit.</p>
    </div>
    <div class="text-data-mono-sm text-on-surface-variant">{{ total_chains }} chains across pipeline</div>
  </div>
</div>
<div class="p-lg max-w-[1800px] mx-auto w-full">
  <div class="grid grid-cols-6 gap-md">
    {% for stage_key, stage_label, stage_color, stage_icon in stages %}
    {% set items = by_stage[stage_key] %}
    <div class="bg-surface-container border border-outline-variant rounded flex flex-col">
      <div class="px-sm py-xs border-b border-outline-variant bg-surface-container-low flex items-center justify-between">
        <div class="flex items-center gap-2">
          <span class="material-symbols-outlined text-[14px] text-{{ stage_color }}">{{ stage_icon }}</span>
          <span class="font-data-mono-sm uppercase text-on-surface">{{ stage_label }}</span>
        </div>
        <span class="font-data-mono-sm text-on-surface-variant">{{ items | length }}</span>
      </div>
      <div class="p-sm flex flex-col gap-sm flex-1 min-h-[300px] max-h-[70vh] overflow-y-auto">
        {% for c in items %}
        <a href="{{ root }}binaries/{{ c.binary_page_stem }}/chains/{{ c.id }}.html" class="bg-surface-container-low hover:bg-surface-container-high border border-outline-variant rounded p-sm block transition-colors">
          <div class="flex items-center gap-1 mb-1">
            <span class="font-data-mono-sm text-primary font-bold">{{ c.id }}</span>
            {% if c.status == 'confirmed' %}<span class="text-[10px] bg-error/20 text-error px-1 rounded ml-auto">✅</span>
            {% elif c.status == 'partial' %}<span class="text-[10px] bg-tertiary/20 text-tertiary px-1 rounded ml-auto">🟡</span>{% endif %}
          </div>
          <div class="text-ui-sans-sm text-on-surface mb-1" style="display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">{{ c.title }}</div>
          <div class="text-data-mono-sm text-on-surface-variant truncate">{{ c.binary }}</div>
          {% if c.severity %}<div class="text-data-mono-sm mt-1"><span class="bg-surface-container-lowest text-on-surface px-1 rounded">{{ c.severity }}</span></div>{% endif %}
        </a>
        {% else %}
        <div class="text-data-mono-sm text-on-surface-variant text-center mt-md italic opacity-60">no chains</div>
        {% endfor %}
      </div>
    </div>
    {% endfor %}
  </div>
</div>
{% endblock %}""")
    total = sum(len(v) for v in by_stage.values())
    out = SITE / "pipeline.html"
    out.write_text(wrapper.render(by_stage=by_stage, stages=PIPELINE_STAGES, total_chains=total, root=""))
    print(f"wrote {out.relative_to(ROOT)}")


def build_coverage_matrix(b: dict) -> dict:
    """For each (input, capability) pair, compute the chain coverage.

    Returns dict with:
      - inputs: list of input dicts (from reverse_engineering.inputs)
      - capabilities: list of capability dicts
      - matrix: dict[input_id][capability_id] -> {"chains": [...], "status": "connected|unreachable|unexplored", "note": ""}
      - sinks_by_id: lookup
      - gaps: {"unreached_inputs": [...], "unreached_capabilities": [...], "unmapped_sinks": [...]}
    """
    re_block = b.get("reverse_engineering") or {}
    inputs = re_block.get("inputs") or []
    capabilities = b.get("capabilities") or []
    sinks = b.get("sinks") or []
    chains = b.get("chains") or []
    sources = b.get("sources") or []

    sinks_by_id = {s.get("id"): s for s in sinks}
    sources_by_id = {s.get("id"): s for s in sources}

    # Map source_id -> input_id (via derived_from)
    src_to_input = {s.get("id"): s.get("derived_from") for s in sources if s.get("id") and s.get("derived_from")}
    # Map sink_id -> capability_id (via capabilities[].sinks)
    sink_to_cap: dict[str, list[str]] = {}
    for cap in capabilities:
        for sid in cap.get("sinks") or []:
            sink_to_cap.setdefault(sid, []).append(cap.get("id"))

    # Build matrix
    matrix: dict[str, dict[str, dict]] = {}
    for inp in inputs:
        inp_id = inp.get("id")
        if not inp_id:
            continue
        matrix[inp_id] = {cap.get("id"): {"chains": [], "status": "unexplored", "note": ""}
                          for cap in capabilities if cap.get("id")}

    for ch in chains:
        src_id = ch.get("source_id")
        sink_id = ch.get("sink_id")
        explicit_cap = ch.get("capability_id")
        inp_id = src_to_input.get(src_id)
        if not inp_id:
            continue
        # Determine which capability(ies) this chain reaches
        reached_caps = []
        if explicit_cap:
            reached_caps = [explicit_cap]
        elif sink_id and sink_id in sink_to_cap:
            reached_caps = sink_to_cap[sink_id]
        for cap_id in reached_caps:
            cell = matrix.get(inp_id, {}).get(cap_id)
            if cell is None:
                continue
            cell["chains"].append(ch.get("id"))
            cell["status"] = "connected"

    # Backward-reachability hints from capability.reachable_from.inputs[]
    for cap in capabilities:
        cap_id = cap.get("id")
        for inp_id in (cap.get("reachable_from") or {}).get("inputs") or []:
            cell = matrix.get(inp_id, {}).get(cap_id)
            if cell is None or cell["status"] == "connected":
                continue
            cell["status"] = "hypothesised"
            cell["note"] = "backward-trace says reachable; chain not yet built"

    # Gap analysis
    inputs_with_chain = {ch.get("source_id") and src_to_input.get(ch["source_id"]) for ch in chains}
    inputs_with_chain.discard(None)
    caps_with_chain = set()
    for ch in chains:
        sink_id = ch.get("sink_id")
        if sink_id in sink_to_cap:
            caps_with_chain.update(sink_to_cap[sink_id])
        if ch.get("capability_id"):
            caps_with_chain.add(ch["capability_id"])

    unreached_inputs = [i for i in inputs if i.get("id") and i["id"] not in inputs_with_chain]
    unreached_caps = [c for c in capabilities if c.get("id") and c["id"] not in caps_with_chain]
    sinks_with_cap = set()
    for cap in capabilities:
        for sid in cap.get("sinks") or []:
            sinks_with_cap.add(sid)
    unmapped_sinks = [s for s in sinks if s.get("id") and s["id"] not in sinks_with_cap]

    return {
        "matrix_inputs": inputs,
        "matrix_capabilities": capabilities,
        "matrix": matrix,
        "matrix_sinks_by_id": sinks_by_id,
        "matrix_gaps": {
            "unreached_inputs": unreached_inputs,
            "unreached_capabilities": unreached_caps,
            "unmapped_sinks": unmapped_sinks,
        },
    }


def build_re_context(b: dict) -> dict:
    """Compute derivation links + sidecar markdown for the RE brief.

    Returns dict with:
      - re: the reverse_engineering block (or empty dict)
      - re_inputs_by_id: lookup of INP-* id -> input dict
      - sources_missing_derivation: list of SRC-* ids that lack derived_from (warning)
      - sidecar_html: rendered markdown of <name>.re.md if present
    """
    re_block = b.get("reverse_engineering") or {}
    inputs = re_block.get("inputs") or []
    inputs_by_id = {i.get("id"): i for i in inputs if i.get("id")}

    missing = []
    for s in (b.get("sources") or []):
        df = s.get("derived_from")
        if not df:
            missing.append(s.get("id", "?"))
        elif df not in inputs_by_id and inputs:
            # df points at non-existent INP id when inputs exist
            missing.append(f"{s.get('id', '?')} (broken: {df})")

    # Look for sidecar
    sidecar_path = ROOT / "catalog" / "binaries" / f"{b['page_stem']}.re.md"
    sidecar_html = ""
    if sidecar_path.exists():
        try:
            import markdown
            sidecar_html = markdown.markdown(sidecar_path.read_text(), extensions=["fenced_code", "tables"])
        except ImportError:
            # Fallback: render as <pre> if markdown not available
            sidecar_html = f"<pre class='whitespace-pre-wrap'>{sidecar_path.read_text()}</pre>"

    return {
        "re": re_block,
        "re_inputs_by_id": inputs_by_id,
        "sources_missing_derivation": missing,
        "sidecar_html": sidecar_html,
    }


def render_binaries(env: Environment, binaries: list[dict], lib: dict):
    tpl = env.get_template("binary.html.j2")
    bdir = SITE / "binaries"
    bdir.mkdir(exist_ok=True)
    for b in binaries:
        # Add status_badge per source for the L1 map
        chains = b.get("chains") or []
        src_status: dict[str, str] = {}
        priority = {"confirmed": 4, "partial": 3, "hypothesised": 2, "unexplored": 1, "mitigated": 0}
        for c in chains:
            sid = c.get("source_id")
            st = c.get("status", "unexplored")
            if priority.get(st, 0) > priority.get(src_status.get(sid, "unexplored"), 0):
                src_status[sid] = st
        for s in (b.get("sources") or []):
            badge_map = {"confirmed": "✅", "partial": "🟡", "hypothesised": "❔", "unexplored": "⏳", "mitigated": "🛡"}
            s["status_badge"] = badge_map.get(src_status.get(s.get("id"), "unexplored"), "⏳")
        grouped, cov_stats = build_class_coverage_grouped(b, lib)
        re_ctx = build_re_context(b)
        matrix_ctx = build_coverage_matrix(b)
        out = bdir / f"{b['page_stem']}.html"
        out.write_text(tpl.render(binary=b, class_coverage_grouped=grouped, coverage_stats=cov_stats,
                                  root="../", **re_ctx, **matrix_ctx))
        print(f"wrote {out.relative_to(ROOT)}")


def render_products(env: Environment, products: list[dict], binaries: list[dict]):
    tpl = env.get_template("product.html.j2")
    pdir = SITE / "products"
    pdir.mkdir(exist_ok=True)

    # Map binary-name token -> page_stem for cross-linking
    known_binaries = {b["binary"]: b["page_stem"] for b in binaries}
    for b in binaries:
        # Also key by bare stem (no extension) for fuzzy matches in YAMLs
        bare = b["binary"].split(".")[0]
        if bare and bare not in known_binaries:
            known_binaries[bare] = b["page_stem"]

    for prod in products:
        # Build heatmap: rows = binaries listed in product, columns = source classes seen
        heatmap_rows = []
        all_classes: set = set()
        for b_token in (prod.get("binaries") or []):
            stem = b_token.split(" ")[0]
            target = next((b for b in binaries if b["binary"] == stem or b["binary"].split(".")[0] == stem), None)
            if not target:
                heatmap_rows.append({"binary": b_token, "counts": {}})
                continue
            counts: dict[str, int] = {}
            for s in (target.get("sources") or []):
                cid = s.get("source_class_id")
                if cid:
                    counts[cid] = counts.get(cid, 0) + 1
                    all_classes.add(cid)
                for c2 in s.get("co_class_ids") or []:
                    counts[c2] = counts.get(c2, 0) + 1
                    all_classes.add(c2)
            heatmap_rows.append({"binary": b_token, "counts": counts})
        heatmap_classes = sorted(all_classes)

        out = pdir / f"{prod['slug']}.html"
        out.write_text(tpl.render(
            product=prod,
            heatmap_classes=heatmap_classes,
            heatmap_rows=heatmap_rows,
            known_binaries=known_binaries,
            root="../",
        ))
        print(f"wrote {out.relative_to(ROOT)}")

    # Product index page (lightweight: use the same index template but filtered to products)
    # For now just write a minimal index that lists products
    idx = pdir / "index.html"
    items = []
    for p in products:
        items.append(f'<li class="bg-surface-container border border-outline-variant rounded p-md hover:bg-surface-container-high"><a href="{p["slug"]}.html" class="block"><div class="font-h2 text-primary">{p.get("display_name", p["product"])}</div><div class="text-on-surface-variant text-data-mono-sm">{p.get("vendor", "")}</div><div class="text-on-surface-variant text-ui-sans-sm mt-2">{(p.get("description") or "")[:160].strip()}…</div><div class="text-data-mono-sm text-on-surface-variant mt-2">{len(p.get("binaries") or [])} binaries · {len(p.get("vulnerabilities") or [])} findings</div></a></li>')
    plisting = '<ul class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-md p-lg">' + '\n'.join(items) + '</ul>'

    # Mini-render via the base template using a simple context
    tpl = env.get_template("_base.html.j2")
    # Override block content via a string; simplest: use environment to render a tiny wrapper
    wrapper = env.from_string("""{% extends "_base.html.j2" %}
{% set active = 'product' %}
{% block title %}Vulnerabin · Products{% endblock %}
{% block content %}
<div class="p-lg">
  <h1 class="font-h1 text-h1 text-primary mb-md">Products</h1>
  <p class="text-ui-sans-sm text-on-surface-variant mb-lg max-w-3xl">{{ count }} catalogued products. Each provides a Layer 4 cross-binary topology view, source-class heatmap, defense distribution, and vulnerabilities ledger.</p>
  __ITEMS__
</div>
{% endblock %}""".replace("__ITEMS__", plisting))
    idx.write_text(wrapper.render(count=len(products), root="../"))
    print(f"wrote {idx.relative_to(ROOT)}")


def render_taxonomy_page(env: Environment, lib: dict):
    """Stub for the taxonomy nav link — for now just point at the comprehensive doc."""
    out = SITE / "taxonomy.html"
    wrapper = env.from_string("""{% extends "_base.html.j2" %}
{% set active = 'taxonomy' %}
{% block title %}Vulnerabin · Taxonomy{% endblock %}
{% block content %}
<div class="p-lg max-w-[1200px] mx-auto">
<h1 class="font-h1 text-h1 text-primary mb-md">Source taxonomy v2</h1>
<p class="text-ui-sans-sm text-on-surface-variant mb-lg max-w-3xl">{{ class_count }} source classes across {{ group_count }} groups. The canonical reference is <code class="bg-surface-container px-1 rounded">taxonomy/binary/sources_comprehensive.md</code>; the detection-checklist + defense library is at <code class="bg-surface-container px-1 rounded">taxonomy/binary/defense_library.json</code>.</p>
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-md">
  {% for c in classes %}
  <div class="bg-surface-container border border-outline-variant rounded p-md">
    <div class="flex items-center justify-between mb-1">
      <span class="font-data-mono-md text-primary font-bold">{{ c.id }}</span>
      <span class="text-[10px] uppercase font-data-mono-sm" style="color: {{ group_color[c.id.split('-')[0]] }}">{{ c.id.split('-')[0] }}</span>
    </div>
    <div class="font-ui-sans-md text-on-surface mb-2">{{ c.name }}</div>
    {% if c.canonical_defense %}<div class="text-data-mono-sm text-on-surface-variant"><span class="text-on-surface font-bold">Defense:</span> {{ c.canonical_defense | truncate(160) }}</div>{% endif %}
  </div>
  {% endfor %}
</div>
</div>
{% endblock %}""")
    classes = lib.get("classes", [])
    group_color = {"F": "#fdd6d6", "I": "#fed9a3", "N": "#c5d3ff", "K": "#e0bdf2", "U": "#bfeac6", "T": "#cfd2d8", "UP": "#fff0a3", "C": "#e9d4b8", "E": "#a8d4ff", "W": "#f4c5ff", "CR": "#cccccc"}
    out.write_text(wrapper.render(classes=classes, class_count=len(classes), group_count=len({c["id"].split("-")[0] for c in classes}), group_color=group_color, root=""))
    print(f"wrote {out.relative_to(ROOT)}")


def render_reconstructed_pages(env: Environment) -> int:
    """Render the Layer 8 reconstruction detail page for every catalog
    reconstruct dir that has a manifest.json. Returns the count rendered.
    """
    import importlib.util as _ilu
    import sys as _sys

    # Ensure scripts/ is on sys.path so catalog_reconstruct_render can be imported
    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in _sys.path:
        _sys.path.insert(0, scripts_dir)

    import catalog_reconstruct_render as crr  # type: ignore

    base = ROOT / "catalog" / "reconstructed"
    if not base.is_dir():
        return 0
    out_dir = SITE / "reconstructed"
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", type=int, default=None, help="after rendering, spawn `python3 -m http.server N` on the given port")
    args = ap.parse_args()

    if not TEMPLATES.is_dir():
        raise SystemExit(f"templates not found at {TEMPLATES}")

    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))

    binaries = collect_binaries()
    products = collect_products()
    lib = load_defense_library()

    SITE.mkdir(exist_ok=True)
    # New IA: products grid is the landing
    render_products_grid(env, binaries, products)
    # Secondary cross-cuts
    render_binaries_index(env, binaries, products)
    render_chains_index(env, binaries)
    # Detail pages
    render_binaries(env, binaries, lib)
    n_recon = render_reconstructed_pages(env)
    if n_recon:
        print(f"rendered {n_recon} reconstructed page(s)")
    render_chain_pages(env, binaries)
    render_products(env, products, binaries)
    render_taxonomy_page(env, lib)
    render_pipeline_static(env, binaries)

    print(f"\n✓ Rendered {len(binaries)} binary pages, {len(products)} product pages.")
    print(f"  Open: file://{SITE / 'index.html'}")

    if args.serve is not None:
        import http.server, os
        os.chdir(SITE)
        port = args.serve
        print(f"\nServing on http://127.0.0.1:{port}/  (Ctrl-C to stop)")
        with http.server.ThreadingHTTPServer(("127.0.0.1", port), http.server.SimpleHTTPRequestHandler) as srv:
            srv.serve_forever()

    return 0


if __name__ == "__main__":
    sys.exit(main())
