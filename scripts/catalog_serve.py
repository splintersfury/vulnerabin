#!/usr/bin/env python3
"""
Live web app for the catalog. Reads catalog/binaries/*.yml and
catalog/products/*.yml at request time, so editing a YAML and refreshing the
page shows the change immediately. Same Jinja2 templates as the static site
(catalog/site/_templates/), so visual fidelity is identical.

Endpoints:
  GET  /                                       index page (catalog browse)
  GET  /binaries/<name>                        binary detail
  GET  /products/<slug>                        product detail
  GET  /products/                              product list
  GET  /taxonomy                               taxonomy reference
  GET  /api/binaries                           JSON list of all binaries
  GET  /api/binary/<name>                      JSON for one binary
  GET  /api/products                           JSON list of products
  GET  /api/product/<slug>                     JSON for one product
  GET  /api/search?q=...                       fuzzy search across all data
  GET  /healthz                                liveness check

Usage:
    python3 scripts/catalog_serve.py                    # listen on 127.0.0.1:8088
    python3 scripts/catalog_serve.py --port 9000
    python3 scripts/catalog_serve.py --host 0.0.0.0 --port 8088   # LAN access (careful)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"
SITE = CATALOG / "site"
TEMPLATES = SITE / "_templates"

# Reuse helpers from catalog_site_render
sys.path.insert(0, str(ROOT / "scripts"))
from catalog_site_render import (
    collect_binaries,
    collect_products,
    load_defense_library,
    build_class_coverage_grouped,
    build_coverage_matrix,
    build_re_context,
    page_stem,
    status_dot_for,
)
from collections import Counter

env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))

app = FastAPI(title="Vulnerabin Catalog (live)", description="Live YAML-backed catalog with auto-reload on change.")


# ----- Helpers -----


def _global_stats(binaries, products):
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


def render_products_grid_html(root: str = "/") -> str:
    binaries = collect_binaries()
    products = collect_products()
    bins_by_product: dict = {}
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
        versions = p.get("versions_seen") or []
        latest_version = versions[0].get("version") if versions else ""
        rows.append({
            "product": p["product"], "slug": p["slug"], "display_name": p.get("display_name"),
            "vendor": p.get("vendor"), "description": p.get("description", ""),
            "latest_version": latest_version, "binary_count": len(prod_bins),
            "chain_count": chain_count, "finding_count": len(p.get("vulnerabilities") or []),
            "confirmed_count": confirmed, "partial_count": partial, "unexplored_count": unexplored,
        })
    rows.sort(key=lambda r: (-r["confirmed_count"], -r["partial_count"], -r["chain_count"], r["product"]))
    unique_vendors = sorted({p["vendor"] for p in rows if p.get("vendor")})
    tpl = env.get_template("products_grid.html.j2")
    return tpl.render(products=rows, stats=_global_stats(binaries, products), unique_vendors=unique_vendors, root=root)


def render_binaries_index_html(root: str = "/") -> str:
    binaries = collect_binaries()
    products = collect_products()
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
            "binary": b.get("binary"), "display_name": b.get("display_name"),
            "page_stem": b["page_stem"], "product": b.get("product"),
            "platform": b.get("platform", "?"),
            "source_count": len(b.get("sources") or []),
            "sink_count": len(b.get("sinks") or []),
            "chain_count": len(chains),
            "confirmed": statuses.count("confirmed"),
            "partial": statuses.count("partial"),
            "unexplored": statuses.count("unexplored") + statuses.count("hypothesised"),
            "status_dot": status_dot_for(b),
        })
    stats = _global_stats(binaries, products)
    stats["top_classes"] = class_counter.most_common(8)
    recent = []
    for b in binaries:
        for c in b.get("chains") or []:
            if c.get("submission_ref"):
                recent.append({
                    "id_short": c.get("id"), "title": c.get("title", ""),
                    "platform": b.get("platform", "?"),
                    "icon": "memory" if b.get("binary_kind") == "sys" else "dns",
                    "product_slug": b.get("product", ""),
                    "status_dot": "bg-error" if c.get("status") == "confirmed" else "bg-tertiary" if c.get("status") == "partial" else "bg-secondary",
                    "status_label": (c.get("status") or "").replace("_", " "),
                })
    recent = sorted(recent, key=lambda x: x["id_short"])[:6]
    unique_platforms = sorted({b.get("platform") for b in rows if b.get("platform") and b.get("platform") != "?"})
    tpl = env.get_template("index.html.j2")
    return tpl.render(binaries=rows, recent_findings=recent, stats=stats, unique_platforms=unique_platforms, root=root)


def render_chains_index_html(root: str = "/") -> str:
    binaries = collect_binaries()
    chains = []
    for b in binaries:
        for c in (b.get("chains") or []):
            chains.append({
                "id": c.get("id"), "title": c.get("title", ""),
                "binary": b.get("binary"), "binary_page_stem": b["page_stem"],
                "product": b.get("product"),
                "status": c.get("status", "unexplored"),
                "severity": c.get("severity", ""),
                "cwe": c.get("cwe", []),
                "submission_ref": c.get("submission_ref", ""),
            })
    chains.sort(key=lambda c: ({"confirmed": 0, "partial": 1, "hypothesised": 2, "unexplored": 3, "mitigated": 4}.get(c["status"], 5), c["id"]))
    wrapper = env.from_string("""{% extends "_base.html.j2" %}
{% set active = 'chain' %}
{% block title %}Vulnerabin · Chains{% endblock %}
{% block content %}
<div class="px-lg py-md border-b border-outline-variant bg-surface">
  <div class="max-w-[1600px] mx-auto w-full">
    <h1 class="font-h1 text-h1 text-primary">Chains across all binaries</h1>
    <p class="text-ui-sans-sm text-on-surface-variant mt-xs max-w-3xl">{{ chains|length }} chains catalogued. Each row is a source → conditions → sink path; click to see the full chain detail.</p>
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
      <tr class="border-b border-outline-variant hover:bg-surface-container cursor-pointer" onclick="location.href='{{ root }}binaries/{{ c.binary_page_stem }}/chains/{{ c.id }}'">
        <td class="p-2 text-primary font-bold">{{ c.id }}</td>
        <td class="p-2 text-on-surface">{{ c.title | truncate(80) }}</td>
        <td class="p-2 text-on-surface-variant">{{ c.binary }}</td>
        <td class="p-2 text-on-surface-variant">{% if c.product %}<a href="{{ root }}products/{{ c.product }}" class="hover:text-primary" onclick="event.stopPropagation()">{{ c.product }}</a>{% else %}—{% endif %}</td>
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
    return wrapper.render(chains=chains, root=root)


def _chain_workflow_stage(chain: dict) -> str:
    """Map a chain to its current research-pipeline stage based on the
    progression: input identified → conditions enumerated → PoC built →
    PoC tested → boundary crossed → submitted. Returns the stage label."""
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
    if chain.get("source_id"):
        return "input_identified"
    return "input_identified"


PIPELINE_STAGES = [
    ("input_identified",      "Input identified",      "primary",   "search"),
    ("conditions_enumerated", "Conditions enumerated", "tertiary",  "list_alt"),
    ("poc_built",             "PoC built",             "secondary", "build"),
    ("poc_tested",            "PoC tested",            "secondary", "play_arrow"),
    ("boundary_crossed",      "Boundary crossed",      "error",     "warning"),
    ("submitted",             "Submitted",             "error",     "send"),
]


def render_pipeline_html(root: str = "/") -> str:
    """Kanban: chains organised by their current workflow stage. Mirrors
    the user's actual research flow: identify input → trace → PoC → test →
    submit."""
    binaries = collect_binaries()
    by_stage: dict = {s[0]: [] for s in PIPELINE_STAGES}
    for b in binaries:
        for c in (b.get("chains") or []):
            stage = _chain_workflow_stage(c)
            by_stage.setdefault(stage, []).append({
                "id": c.get("id"),
                "title": c.get("title", ""),
                "binary": b.get("binary"),
                "binary_page_stem": b["page_stem"],
                "product": b.get("product"),
                "status": c.get("status", "unexplored"),
                "severity": c.get("severity", ""),
                "submission_ref": c.get("submission_ref", ""),
                "outcome_boundary": (c.get("outcome") or {}).get("boundary_crossed"),
                "poc_path": (c.get("poc") or {}).get("path"),
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
        <a href="{{ root }}binaries/{{ c.binary_page_stem }}/chains/{{ c.id }}" class="bg-surface-container-low hover:bg-surface-container-high border border-outline-variant rounded p-sm block transition-colors">
          <div class="flex items-center gap-1 mb-1">
            <span class="font-data-mono-sm text-primary font-bold">{{ c.id }}</span>
            {% if c.status == 'confirmed' %}<span class="text-[10px] bg-error/20 text-error px-1 rounded ml-auto">✅</span>
            {% elif c.status == 'partial' %}<span class="text-[10px] bg-tertiary/20 text-tertiary px-1 rounded ml-auto">🟡</span>{% endif %}
          </div>
          <div class="text-ui-sans-sm text-on-surface mb-1" style="display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">{{ c.title }}</div>
          <div class="text-data-mono-sm text-on-surface-variant truncate">{{ c.binary }}</div>
          {% if c.severity %}<div class="text-data-mono-sm mt-1"><span class="bg-surface-container-lowest text-on-surface px-1 rounded">{{ c.severity }}</span></div>{% endif %}
          {% if c.submission_ref %}<div class="text-data-mono-sm text-on-surface-variant mt-1 truncate">{{ c.submission_ref | truncate(40) }}</div>{% endif %}
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
    return wrapper.render(by_stage=by_stage, stages=PIPELINE_STAGES, total_chains=total, root=root)


def render_chain_html(binary_stem: str, chain_id: str, root: str = "/") -> str:
    binaries = collect_binaries()
    target_b = next((b for b in binaries if b["page_stem"] == binary_stem), None)
    if not target_b:
        raise HTTPException(404, f"binary not found: {binary_stem}")
    target_c = next((c for c in (target_b.get("chains") or []) if c.get("id") == chain_id), None)
    if not target_c:
        raise HTTPException(404, f"chain {chain_id} not found in {binary_stem}")
    sources_lookup = {s["id"]: s for s in (target_b.get("sources") or [])}
    sinks_lookup = {s["id"]: s for s in (target_b.get("sinks") or [])}
    sib = [{"id": c.get("id"), "title": c.get("title", ""), "status": c.get("status", "unexplored"), "severity": c.get("severity", "")}
           for c in (target_b.get("chains") or []) if c.get("id") != chain_id]
    src = sources_lookup.get(target_c.get("source_id"))
    snk = sinks_lookup.get(target_c.get("sink_id"))
    tpl = env.get_template("chain.html.j2")
    return tpl.render(chain=target_c, binary=target_b, source=src, sink=snk, sibling_chains=sib, root=root)


def render_binary_html(name: str, root: str = "/") -> str:
    binaries = collect_binaries()
    target = next((b for b in binaries if b["page_stem"] == name or b["binary"] == name), None)
    if not target:
        raise HTTPException(404, f"binary not found: {name}")
    lib = load_defense_library()
    chains = target.get("chains") or []
    src_status: dict[str, str] = {}
    priority = {"confirmed": 4, "partial": 3, "hypothesised": 2, "unexplored": 1, "mitigated": 0}
    for c in chains:
        sid = c.get("source_id")
        st = c.get("status", "unexplored")
        if priority.get(st, 0) > priority.get(src_status.get(sid, "unexplored"), 0):
            src_status[sid] = st
    for s in (target.get("sources") or []):
        badge_map = {"confirmed": "✅", "partial": "🟡", "hypothesised": "❔", "unexplored": "⏳", "mitigated": "🛡"}
        s["status_badge"] = badge_map.get(src_status.get(s.get("id"), "unexplored"), "⏳")
    grouped, cov_stats = build_class_coverage_grouped(target, lib)
    re_ctx = build_re_context(target)
    matrix_ctx = build_coverage_matrix(target)
    tpl = env.get_template("binary.html.j2")
    return tpl.render(binary=target, class_coverage_grouped=grouped, coverage_stats=cov_stats,
                      root=root, **re_ctx, **matrix_ctx)


def render_product_html(slug: str, root: str = "/") -> str:
    products = collect_products()
    binaries = collect_binaries()
    target = next((p for p in products if p["slug"] == slug), None)
    if not target:
        raise HTTPException(404, f"product not found: {slug}")
    known_binaries = {b["binary"]: b["page_stem"] for b in binaries}
    for b in binaries:
        bare = b["binary"].split(".")[0]
        if bare and bare not in known_binaries:
            known_binaries[bare] = b["page_stem"]
    heatmap_rows = []
    all_classes: set = set()
    for b_token in (target.get("binaries") or []):
        stem = b_token.split(" ")[0]
        bin_target = next((b for b in binaries if b["binary"] == stem or b["binary"].split(".")[0] == stem), None)
        if not bin_target:
            heatmap_rows.append({"binary": b_token, "counts": {}})
            continue
        counts: dict[str, int] = {}
        for s in (bin_target.get("sources") or []):
            cid = s.get("source_class_id")
            if cid:
                counts[cid] = counts.get(cid, 0) + 1
                all_classes.add(cid)
            for c2 in s.get("co_class_ids") or []:
                counts[c2] = counts.get(c2, 0) + 1
                all_classes.add(c2)
        heatmap_rows.append({"binary": b_token, "counts": counts})
    tpl = env.get_template("product.html.j2")
    return tpl.render(product=target, heatmap_classes=sorted(all_classes), heatmap_rows=heatmap_rows, known_binaries=known_binaries, root=root)


# ----- Routes -----


@app.get("/", response_class=HTMLResponse)
def index():
    return render_products_grid_html(root="/")


@app.get("/binaries", response_class=HTMLResponse)
def binaries_index():
    return render_binaries_index_html(root="/")


@app.get("/chains", response_class=HTMLResponse)
def chains_index():
    return render_chains_index_html(root="/")


@app.get("/pipeline", response_class=HTMLResponse)
def pipeline_view():
    return render_pipeline_html(root="/")


@app.get("/binaries/{name}", response_class=HTMLResponse)
def binary_detail(name: str):
    if name.endswith(".html"):
        name = name[:-5]
    return render_binary_html(name, root="/")


@app.get("/binaries/{name}/chains/{chain_id}", response_class=HTMLResponse)
def chain_detail(name: str, chain_id: str):
    if chain_id.endswith(".html"):
        chain_id = chain_id[:-5]
    return render_chain_html(name, chain_id, root="/")


@app.get("/products", response_class=HTMLResponse)
def products_index():
    products = collect_products()
    items_html = ""
    for p in products:
        items_html += f'<li class="bg-surface-container border border-outline-variant rounded p-md hover:bg-surface-container-high"><a href="/products/{p["slug"]}" class="block"><div class="font-h2 text-primary">{p.get("display_name", p["product"])}</div><div class="text-on-surface-variant text-data-mono-sm">{p.get("vendor", "")}</div><div class="text-on-surface-variant text-ui-sans-sm mt-2">{(p.get("description") or "")[:160].strip()}…</div><div class="text-data-mono-sm text-on-surface-variant mt-2">{len(p.get("binaries") or [])} binaries · {len(p.get("vulnerabilities") or [])} findings</div></a></li>'
    plisting = '<ul class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-md p-lg">' + items_html + '</ul>'
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
    return wrapper.render(count=len(products), root="/")


@app.get("/products/{slug}", response_class=HTMLResponse)
def product_detail(slug: str):
    if slug.endswith(".html"):
        slug = slug[:-5]
    return render_product_html(slug, root="/")


@app.get("/taxonomy", response_class=HTMLResponse)
def taxonomy_page():
    lib = load_defense_library()
    classes = lib.get("classes", [])
    group_color = {"F": "#fdd6d6", "I": "#fed9a3", "N": "#c5d3ff", "K": "#e0bdf2", "U": "#bfeac6", "T": "#cfd2d8", "UP": "#fff0a3", "C": "#e9d4b8", "E": "#a8d4ff", "W": "#f4c5ff", "CR": "#cccccc"}
    wrapper = env.from_string("""{% extends "_base.html.j2" %}
{% set active = 'taxonomy' %}
{% block title %}Vulnerabin · Taxonomy{% endblock %}
{% block content %}
<div class="p-lg max-w-[1200px] mx-auto">
<h1 class="font-h1 text-h1 text-primary mb-md">Source taxonomy v2</h1>
<p class="text-ui-sans-sm text-on-surface-variant mb-lg max-w-3xl">{{ class_count }} source classes across {{ group_count }} groups.</p>
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
    return wrapper.render(classes=classes, class_count=len(classes), group_count=len({c["id"].split("-")[0] for c in classes}), group_color=group_color, root="/")


# ----- API endpoints (JSON) -----


@app.get("/api/binaries")
def api_binaries():
    binaries = collect_binaries()
    return JSONResponse([{
        "binary": b["binary"],
        "display_name": b.get("display_name"),
        "page_stem": b["page_stem"],
        "product": b.get("product"),
        "platform": b.get("platform"),
        "binary_kind": b.get("binary_kind"),
        "source_count": len(b.get("sources") or []),
        "sink_count": len(b.get("sinks") or []),
        "chain_count": len(b.get("chains") or []),
        "principal": (b.get("process_model") or {}).get("principal"),
    } for b in binaries])


@app.get("/api/binary/{name}")
def api_binary(name: str):
    binaries = collect_binaries()
    target = next((b for b in binaries if b["page_stem"] == name or b["binary"] == name), None)
    if not target:
        raise HTTPException(404, f"binary not found: {name}")
    return JSONResponse(target)


@app.get("/api/products")
def api_products():
    products = collect_products()
    return JSONResponse([{
        "product": p["product"],
        "display_name": p.get("display_name"),
        "slug": p["slug"],
        "vendor": p.get("vendor"),
        "binaries": p.get("binaries") or [],
        "finding_count": len(p.get("vulnerabilities") or []),
    } for p in products])


@app.get("/api/product/{slug}")
def api_product(slug: str):
    products = collect_products()
    target = next((p for p in products if p["slug"] == slug), None)
    if not target:
        raise HTTPException(404, f"product not found: {slug}")
    return JSONResponse(target)


@app.get("/api/search")
def api_search(q: str = ""):
    if not q or len(q) < 2:
        return JSONResponse({"binaries": [], "products": [], "classes": []})
    q_low = q.lower()
    binaries = collect_binaries()
    products = collect_products()
    lib = load_defense_library()
    bin_hits = [b for b in binaries if q_low in (b.get("binary", "") + " " + (b.get("display_name") or "")).lower()]
    prod_hits = [p for p in products if q_low in (p.get("product", "") + " " + (p.get("display_name") or "") + " " + (p.get("vendor") or "")).lower()]
    cls_hits = [c for c in lib.get("classes", []) if q_low in (c.get("id", "") + " " + c.get("name", "")).lower()]
    return JSONResponse({
        "binaries": [{"binary": b["binary"], "page_stem": b["page_stem"], "platform": b.get("platform")} for b in bin_hits[:20]],
        "products": [{"product": p["product"], "slug": p["slug"], "vendor": p.get("vendor")} for p in prod_hits[:20]],
        "classes": [{"id": c["id"], "name": c.get("name")} for c in cls_hits[:20]],
    })


@app.get("/healthz")
def healthz():
    return {"status": "ok", "binaries": len(collect_binaries()), "products": len(collect_products())}


# ----- CLI entry -----


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--reload", action="store_true", help="enable uvicorn auto-reload on .py changes")
    args = ap.parse_args()

    import uvicorn
    print(f"Vulnerabin Catalog (live)  →  http://{args.host}:{args.port}/")
    print(f"  / · /binaries · /products · /taxonomy")
    print(f"  /api/binaries  /api/products  /api/search?q=...  /healthz")
    print(f"  YAML changes are picked up on every request — no restart needed.")
    uvicorn.run(
        "catalog_serve:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
