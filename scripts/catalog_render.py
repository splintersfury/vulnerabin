#!/usr/bin/env python3
"""
Render `catalog/binaries/<name>.yml` into `catalog/pages/<name>.md` with:
  - versions table
  - sources / sinks tables
  - one section per chain, each with a summary table and a mermaid flowchart
Also updates `catalog/index.json` (machine-readable global view) and
`catalog/pages/index.md` (human-readable global view).

Usage:
    python3 scripts/catalog_render.py                        # render all
    python3 scripts/catalog_render.py safeelevatedrun_dll    # render one
    python3 scripts/catalog_render.py --check                # don't write, just verify YAML parses
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
CATALOG = ROOT / "catalog"
BINARIES = CATALOG / "binaries"
PAGES = CATALOG / "pages"


def slug(s: str) -> str:
    """Normalise a string for use in a mermaid node id (no spaces or special chars)."""
    out = re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_")
    return out or "node"


def mermaid_escape(s: str) -> str:
    """Escape characters mermaid would mis-parse inside a node label."""
    if not s:
        return ""
    return s.replace('"', "&quot;").replace("|", "/").replace("(", "&#40;").replace(")", "&#41;").replace("[", "&#91;").replace("]", "&#93;")


def load_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as e:
        raise SystemExit(f"YAML parse error in {p}: {e}")


def _safe(v) -> str:
    """Render any scalar to a markdown-table-safe string."""
    if v is None or v == "":
        return "—"
    s = str(v).replace("\n", " ").replace("|", "\\|")
    return s


def _list_one_line(items) -> str:
    """Render a YAML list of strings as a single markdown-table cell."""
    if not items:
        return "—"
    if isinstance(items, list):
        return "<br>".join(_safe(x) for x in items if x not in ("", None))
    return _safe(items)


def render_versions(versions: list) -> str:
    if not versions:
        return "_No versions catalogued yet._\n"
    rows = ["| Version | First seen | Engagement | SHA256 | Notes |",
            "|---------|------------|------------|--------|-------|"]
    for v in versions:
        rows.append("| {ver} | {seen} | {eng} | {sha} | {notes} |".format(
            ver=_safe(v.get("version")),
            seen=_safe(v.get("seen")),
            eng=_safe(v.get("eng")),
            sha=_safe(v.get("sha256"))[:16] if v.get("sha256") else "—",
            notes=_safe(v.get("notes")),
        ))
    return "\n".join(rows) + "\n"


def render_sources(sources: list) -> str:
    if not sources:
        return "_No sources catalogued yet._\n"
    rows = ["| ID | Name | Via | Type | Attacker-controlled | First seen | Notes |",
            "|----|------|-----|------|---------------------|------------|-------|"]
    for s in sources:
        ac = s.get("attacker_controlled", "?")
        if ac == "yes_with_caveat" and s.get("caveat"):
            ac = f"yes (caveat: {s.get('caveat')})"
        rows.append("| {id} | {name} | {via} | {type} | {ac} | {fsv} | {notes} |".format(
            id=_safe(s.get("id")),
            name=_safe(s.get("name")),
            via=_safe(s.get("via")),
            type=_safe(s.get("type")),
            ac=_safe(ac),
            fsv=_safe(s.get("first_seen_version")),
            notes=_safe(s.get("notes")),
        ))
    return "\n".join(rows) + "\n"


def render_sinks(sinks: list) -> str:
    if not sinks:
        return "_No sinks catalogued yet._\n"
    rows = ["| ID | Name | CWE | Function | Impact | First seen |",
            "|----|------|-----|----------|--------|------------|"]
    for s in sinks:
        rows.append("| {id} | {name} | {cwe} | {fn} | {impact} | {fsv} |".format(
            id=_safe(s.get("id")),
            name=_safe(s.get("name")),
            cwe=_safe(s.get("cwe")),
            fn=_safe(s.get("function")),
            impact=_safe(s.get("impact")),
            fsv=_safe(s.get("first_seen_version")),
        ))
    return "\n".join(rows) + "\n"


def find_source(sources: list, sid: str) -> dict:
    for s in sources or []:
        if s.get("id") == sid:
            return s
    return {}


def find_sink(sinks: list, sid: str) -> dict:
    for s in sinks or []:
        if s.get("id") == sid:
            return s
    return {}


def render_chain(chain: dict, sources: list, sinks: list) -> str:
    src = find_source(sources, chain.get("source_id"))
    snk = find_sink(sinks, chain.get("sink_id"))
    src_name = src.get("name", chain.get("source_id") or "?")
    snk_name = snk.get("name", chain.get("sink_id") or "?")

    title = chain.get("title") or chain.get("id") or "(untitled chain)"
    status = chain.get("status", "unexplored")

    # Status badge for the heading
    status_badge = {
        "confirmed": "✅ confirmed",
        "partial": "🟡 partial",
        "hypothesised": "❔ hypothesised",
        "unexplored": "⏳ unexplored",
        "mitigated": "🛡 mitigated",
    }.get(status, status)

    out = []
    out.append(f"### {chain.get('id', 'CHAIN-?')} — {title}")
    out.append("")
    out.append(f"**Status:** {status_badge}  ")
    if chain.get("severity"):
        out.append(f"**Severity:** {_safe(chain.get('severity'))}  ")
    if chain.get("cvss"):
        out.append(f"**CVSS:** `{_safe(chain.get('cvss'))}`  ")
    if chain.get("cwe"):
        out.append(f"**CWE:** {_list_one_line(chain.get('cwe'))}  ")
    if chain.get("confirmed_in_version"):
        out.append(f"**Confirmed in version:** {_safe(chain.get('confirmed_in_version'))}  ")
    if chain.get("finding_ref"):
        out.append(f"**Finding:** [`{chain['finding_ref']}`](../../engagements/{chain['finding_ref']})  ")
    if chain.get("submission_ref"):
        out.append(f"**Submission:** `{_safe(chain.get('submission_ref'))}`")
    out.append("")

    # Summary table
    out.append("| Source | Conditions | Sink | Impact |")
    out.append("|--------|------------|------|--------|")
    out.append("| `{s}` | {c} | `{k}` | {i} |".format(
        s=_safe(src_name),
        c=_list_one_line(chain.get("conditions")),
        k=_safe(snk_name),
        i=_safe(chain.get("impact")),
    ))
    out.append("")

    # Mermaid graph
    out.append("```mermaid")
    out.append("flowchart LR")
    out.append(f'    SRC["{mermaid_escape(src_name)}"]:::src')
    prev = "SRC"
    for i, cond in enumerate(chain.get("conditions") or []):
        nid = f"C{i+1}"
        out.append(f'    {nid}["{mermaid_escape(cond)}"]:::cond')
        out.append(f"    {prev} --> {nid}")
        prev = nid
    out.append(f'    SNK["{mermaid_escape(snk_name)}"]:::sink')
    out.append(f"    {prev} --> SNK")
    out.append("    classDef src fill:#dff,stroke:#069")
    out.append("    classDef cond fill:#ffd,stroke:#960")
    out.append("    classDef sink fill:#fdd,stroke:#900")
    out.append("```")
    out.append("")

    # Bypasses & notes
    if chain.get("bypasses_required"):
        out.append("**Bypasses required to fire this chain:**")
        for b in chain["bypasses_required"]:
            if b:
                out.append(f"- {b}")
        out.append("")
    if chain.get("notes"):
        out.append("**Notes:**")
        out.append("")
        out.append(str(chain["notes"]).strip())
        out.append("")

    return "\n".join(out)


# Source-class group → mermaid color mapping (Layer 1 attack-surface map)
CLASS_GROUP_STYLE = {
    "F":  ("#fdd", "#c00"),  # filesystem — red
    "I":  ("#fed", "#c80"),  # IPC — orange
    "N":  ("#ddf", "#06c"),  # network — blue
    "K":  ("#e9d", "#909"),  # kernel — purple
    "U":  ("#dfd", "#080"),  # user-input — green
    "T":  ("#ddd", "#555"),  # trust — gray
    "UP": ("#ffd", "#aa0"),  # update — yellow
    "C":  ("#edc", "#862"),  # config — brown
    "E":  ("#bdf", "#069"),  # electron — teal
    "W":  ("#fdf", "#909"),  # web — lavender
    "CR": ("#eee", "#333"),  # crypto — neutral
}

EXPLOITABILITY_BADGE = {
    "confirmed":     "✅",
    "partial":       "🟡",
    "hypothesised":  "❔",
    "unexplored":    "⏳",
    "mitigated":     "🛡",
}


def _class_group(class_id: str) -> str:
    """Return the group prefix from a class id like 'I-002' -> 'I'."""
    if not class_id:
        return ""
    return class_id.split("-")[0]


def render_attack_surface_map(data: dict) -> str:
    """Layer 1 — every source as a colored node feeding the binary;
    binary's sinks on the other side."""
    out = []
    sources = data.get("sources") or []
    sinks = data.get("sinks") or []
    if not sources and not sinks:
        return "_No attack-surface map: no sources or sinks catalogued._\n"

    out.append("## Attack-surface map (Layer 1)")
    out.append("")
    out.append("Every entry point that reaches this binary, colored by source-class group "
               "(per `taxonomy/binary/sources_v2.json`). Status badges: ✅ confirmed · 🟡 partial · ❔ hypothesised · ⏳ unexplored · 🛡 mitigated.")
    out.append("")

    # Determine status per source from the chains that reference it
    chains = data.get("chains") or []
    src_status = {}
    for ch in chains:
        sid = ch.get("source_id")
        st = ch.get("status", "unexplored")
        # Take the worst status: confirmed > partial > hypothesised > unexplored > mitigated
        priority = {"confirmed": 4, "partial": 3, "hypothesised": 2, "unexplored": 1, "mitigated": 0}
        prev = src_status.get(sid, "unexplored")
        if priority.get(st, 0) > priority.get(prev, 0):
            src_status[sid] = st

    out.append("```mermaid")
    out.append("flowchart LR")

    # Source nodes
    used_groups = set()
    for s in sources:
        sid = s.get("id")
        cls = s.get("source_class_id") or "?"
        co_cls = s.get("co_class_ids") or []
        cls_label = cls if not co_cls else f"{cls} + {'+'.join(co_cls)}"
        grp = _class_group(cls)
        used_groups.add(grp)
        st = src_status.get(sid, "unexplored")
        badge = EXPLOITABILITY_BADGE.get(st, "")
        ac = s.get("attacker_controlled", "?")
        ac_short = "ac=" + {"yes": "y", "yes_with_caveat": "y+caveat", "no": "n", "unclear": "?"}.get(ac, "?")
        label = f"{mermaid_escape(s.get('name','?')[:60])}<br/>{cls_label} · {ac_short} · {badge} {st}"
        out.append(f'    {sid}["{label}"]:::grp{grp}')

    # Binary node (center)
    bin_label = f"{mermaid_escape(data.get('binary','?'))}<br/>{data.get('process_model',{}).get('principal','principal?')}"
    out.append(f'    BIN([{bin_label}]):::binary')

    # Sink nodes
    for s in sinks:
        out.append(f'    {s.get("id")}["{mermaid_escape(s.get("name","?")[:80])}<br/>{_safe(s.get("cwe",""))}"]:::sink')

    # Edges: each source -> binary, binary -> each sink
    for s in sources:
        out.append(f'    {s.get("id")} --> BIN')
    for s in sinks:
        out.append(f'    BIN --> {s.get("id")}')

    # ClassDefs
    for grp in sorted(used_groups):
        if grp in CLASS_GROUP_STYLE:
            fill, stroke = CLASS_GROUP_STYLE[grp]
            out.append(f"    classDef grp{grp} fill:{fill},stroke:{stroke}")
    out.append("    classDef binary fill:#222,stroke:#000,color:#fff")
    out.append("    classDef sink fill:#fcc,stroke:#900")
    out.append("```")
    out.append("")
    return "\n".join(out) + "\n"


def render_trust_boundary(data: dict) -> str:
    """Layer 2 — process model + IPC topology around this binary."""
    pm = data.get("process_model") or {}
    if not pm:
        return ""

    out = []
    out.append("## Trust boundary & process model (Layer 2)")
    out.append("")
    out.append("Privilege ladder around this binary, with IPC peers and impersonation status.")
    out.append("")

    # Quick-facts
    out.append(f"- **Loaded by**: `{_safe(pm.get('loaded_by',''))}`")
    out.append(f"- **Principal**: {_safe(pm.get('principal',''))}")
    out.append(f"- **Start trigger**: {_safe(pm.get('start_trigger',''))}")
    out.append(f"- **Impersonation seen**: {pm.get('impersonation_seen', '?')}")
    out.append(f"- **PPL protected**: {pm.get('ppl_protected', '?')}")
    out.append("")

    out.append("```mermaid")
    out.append("flowchart TB")

    # Group peers by principal for subgraph rendering
    by_principal: dict = {}
    binary_principal = pm.get("principal", "?")
    by_principal.setdefault(binary_principal, []).append({"name": data.get("binary","?"), "is_self": True})

    for parent in pm.get("parent_processes") or []:
        by_principal.setdefault(parent.get("principal","?"), []).append(parent)
    for peer in pm.get("ipc_peers") or []:
        by_principal.setdefault(peer.get("principal","?"), []).append(peer)

    # Add an attacker zone
    by_principal.setdefault("Standard user (attacker)", []).append({"name": "(any standard-user process)", "is_attacker": True})

    # Render subgraphs in priority order: SYSTEM, Admin, LoggedInUser, Standard user
    order_keys = ["SYSTEM", "Admin (no PPL)", "Admin", "LocalService", "NetworkService", "loggedInUser", "Standard user (attacker)"]
    rendered_keys = list(by_principal.keys())
    rendered_keys.sort(key=lambda k: order_keys.index(k) if k in order_keys else 100)

    node_id_map = {}
    for principal in rendered_keys:
        sg_id = "Z" + slug(principal)[:20]
        out.append(f'    subgraph {sg_id}["{mermaid_escape(principal)}"]')
        for entry in by_principal[principal]:
            n = entry.get("name","?")
            nid = "N" + slug(n)[:24]
            node_id_map[(principal, n)] = nid
            if entry.get("is_self"):
                out.append(f'        {nid}["**{mermaid_escape(n)}**<br/>(this binary)"]:::self')
            elif entry.get("is_attacker"):
                out.append(f'        {nid}(({mermaid_escape(n)})):::attacker')
            else:
                role = entry.get("role") or entry.get("via") or ""
                role_short = mermaid_escape(role[:50]) if role else ""
                out.append(f'        {nid}["{mermaid_escape(n)}<br/><i>{role_short}</i>"]:::peer')
        out.append("    end")

    # IPC edges from peers to self
    self_principal = binary_principal
    self_name = data.get("binary","?")
    self_node = node_id_map.get((self_principal, self_name))
    if self_node:
        for peer in pm.get("ipc_peers") or []:
            peer_node = node_id_map.get((peer.get("principal","?"), peer.get("name","?")))
            if peer_node:
                via = mermaid_escape(peer.get("via","")[:60])
                out.append(f'    {peer_node} -. {via} .-> {self_node}')

        # Attacker speculative edges (dotted to peers, suggesting injection vector)
        attacker_node = node_id_map.get(("Standard user (attacker)", "(any standard-user process)"))
        if attacker_node:
            for peer in pm.get("ipc_peers") or []:
                peer_node = node_id_map.get((peer.get("principal","?"), peer.get("name","?")))
                if peer_node and peer.get("principal") in ("loggedInUser", "Admin (no PPL)"):
                    out.append(f'    {attacker_node} -. inject .-> {peer_node}')

    out.append("    classDef self fill:#222,stroke:#000,color:#fff")
    out.append("    classDef peer fill:#eef,stroke:#039")
    out.append("    classDef attacker fill:#fdd,stroke:#c00,color:#600")
    out.append("```")
    out.append("")
    return "\n".join(out) + "\n"


def render_defense_matrix(data: dict) -> str:
    """Layer 3 — per-source-class defense table."""
    defenses = data.get("defenses") or []
    if not defenses:
        return ""
    out = []
    out.append("## Defense matrix (Layer 3)")
    out.append("")
    out.append("For each source class touching this binary: what defense is expected, what's observed in the binary, where the gap is, and any bypass attempts we've tried.")
    out.append("")
    out.append("| Class | Defense expected | Observed in binary | Gap | Bypass attempts |")
    out.append("|-------|------------------|---------------------|-----|-----------------|")
    for d in defenses:
        out.append("| `{c}` | {e} | {o} | {g} | {b} |".format(
            c=_safe(d.get("class_id")),
            e=_safe(d.get("defense_expected"))[:200],
            o=_safe(d.get("observed"))[:200],
            g=_safe(d.get("gap"))[:120],
            b=_safe(d.get("bypass_attempts"))[:200],
        ))
    out.append("")
    return "\n".join(out) + "\n"


_DEFENSE_LIBRARY_CACHE = None


def load_defense_library() -> dict:
    """Lazy-load taxonomy/binary/defense_library.json."""
    global _DEFENSE_LIBRARY_CACHE
    if _DEFENSE_LIBRARY_CACHE is not None:
        return _DEFENSE_LIBRARY_CACHE
    p = ROOT / "taxonomy" / "binary" / "defense_library.json"
    if not p.is_file():
        _DEFENSE_LIBRARY_CACHE = {}
        return _DEFENSE_LIBRARY_CACHE
    _DEFENSE_LIBRARY_CACHE = json.loads(p.read_text())
    return _DEFENSE_LIBRARY_CACHE


def relevant_classes(data: dict) -> list[str]:
    """Compute the list of taxonomy class IDs relevant to this binary, based on
    platform and binary_kind, per the defense_library platform_relevance map."""
    lib = load_defense_library()
    pr = lib.get("platform_relevance", {})
    platform = (data.get("platform") or "").lower()
    kind = (data.get("binary_kind") or "").lower()

    # Start from platform-relevant set
    if platform in pr:
        candidates = set(pr[platform])
    else:
        # No platform: include the union of all class IDs present in the library
        candidates = {c["id"] for c in lib.get("classes", [])}

    # Intersect with binary-kind set if available
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


def coverage_status_badge(status: str) -> str:
    return {
        "present": "🔴 present",
        "defense_observed": "🟢 defense observed",
        "not_present": "⚪ not present",
        "unchecked": "⏳ unchecked",
    }.get(status, "❔ " + (status or "unknown"))


def render_class_coverage_matrix(data: dict) -> str:
    """The comprehensive forcing-function. Lists every taxonomy class relevant
    to this binary's platform/kind, with status badge and inline detection
    checklist for unchecked classes."""
    relevant = relevant_classes(data)
    if not relevant:
        return ""

    lib = load_defense_library()
    class_meta = {c["id"]: c for c in lib.get("classes", [])}

    cov = {entry.get("class_id"): entry for entry in (data.get("class_coverage") or [])}

    out = []
    out.append("## Class coverage matrix (comprehensive)")
    out.append("")
    out.append("Every taxonomy class relevant to this binary's platform + kind. **Goal: zero `unchecked` rows.** Unchecked rows show the inline detection checklist; walk through, then update `class_coverage[]` in the YAML.")
    out.append("")
    out.append(f"_{len(relevant)} relevant classes; "
               f"{sum(1 for c in relevant if cov.get(c, {}).get('status') == 'present')} present · "
               f"{sum(1 for c in relevant if cov.get(c, {}).get('status') == 'defense_observed')} defense observed · "
               f"{sum(1 for c in relevant if cov.get(c, {}).get('status') == 'not_present')} not present · "
               f"{sum(1 for c in relevant if cov.get(c, {}).get('status', 'unchecked') == 'unchecked')} unchecked_"
               )
    out.append("")

    # Group by class-group prefix for readability (F, I, N, K, U, T, UP, C, E, W, CR)
    by_group: dict[str, list[str]] = {}
    for cid in relevant:
        grp = cid.split("-")[0]
        by_group.setdefault(grp, []).append(cid)

    group_order = ["F", "I", "N", "K", "U", "T", "UP", "C", "E", "W", "CR"]
    for grp in [g for g in group_order if g in by_group] + sorted(g for g in by_group if g not in group_order):
        out.append(f"### Group {grp}")
        out.append("")
        out.append("| Class | Status | Rationale / refs |")
        out.append("|-------|--------|-------------------|")
        for cid in by_group[grp]:
            meta = class_meta.get(cid, {})
            entry = cov.get(cid, {})
            status = entry.get("status", "unchecked")
            badge = coverage_status_badge(status)
            cls_label = f"`{cid}` {meta.get('name', '')[:60]}"
            cell = ""
            if status == "present":
                refs = entry.get("refs") or {}
                src_refs = refs.get("sources") or []
                chain_refs = refs.get("chains") or []
                parts = []
                if src_refs: parts.append("sources: " + ", ".join(f"`{x}`" for x in src_refs))
                if chain_refs: parts.append("chains: " + ", ".join(f"`{x}`" for x in chain_refs))
                cell = "; ".join(parts) or "(no refs given)"
            elif status in ("defense_observed", "not_present"):
                cell = entry.get("rationale", "") or "(no rationale given)"
            elif status == "unchecked":
                cell = "_walk the detection checklist below_"
            out.append("| {c} | {b} | {r} |".format(c=cls_label, b=badge, r=_safe(cell)[:200]))
        out.append("")

        # Inline detection checklists for unchecked classes in this group
        unchecked_in_group = [cid for cid in by_group[grp] if cov.get(cid, {}).get("status", "unchecked") == "unchecked"]
        for cid in unchecked_in_group:
            meta = class_meta.get(cid, {})
            checklist = meta.get("detection_checklist") or []
            if not checklist:
                continue
            out.append(f"<details><summary>Detection checklist for <code>{cid}</code> — {_safe(meta.get('name','')[:80])}</summary>")
            out.append("")
            out.append(f"**Canonical defense:** {_safe(meta.get('canonical_defense',''))[:300]}")
            out.append("")
            if meta.get("common_bypasses"):
                out.append("**Common bypasses:**")
                for b in meta["common_bypasses"]:
                    out.append(f"- {_safe(b)}")
                out.append("")
            out.append("**Detection checklist:**")
            for q in checklist:
                out.append(f"- [ ] {_safe(q)}")
            if meta.get("tools"):
                out.append("")
                out.append("**Tools:** " + ", ".join(f"`{t}`" for t in meta["tools"]))
            out.append("")
            out.append("</details>")
            out.append("")

    return "\n".join(out) + "\n"


def render_coverage(data: dict) -> str:
    """Sub-section: what's been analyzed vs not."""
    cov = data.get("coverage") or {}
    if not cov:
        return ""
    out = []
    out.append("## Analysis coverage")
    out.append("")
    if cov.get("decomp_dirs"):
        out.append("**Decomp dirs**: " + ", ".join(f"`{d}`" for d in cov["decomp_dirs"]))
        out.append("")
    if cov.get("function_count"):
        out.append(f"**Function count**: {cov['function_count']}")
        out.append("")
    if cov.get("functions_analyzed"):
        out.append("**Functions analyzed**:")
        for f in cov["functions_analyzed"]:
            out.append(f"- `{_safe(f)}`")
        out.append("")
    if cov.get("unanalyzed_high_priority"):
        out.append("**Unanalyzed but high-priority**:")
        for f in cov["unanalyzed_high_priority"]:
            out.append(f"- {_safe(f)}")
        out.append("")
    if cov.get("recon_gaps"):
        out.append("**Recon gaps**:")
        for f in cov["recon_gaps"]:
            out.append(f"- {_safe(f)}")
        out.append("")
    return "\n".join(out) + "\n"


def render_binary(data: dict) -> str:
    out = []
    out.append(f"# {data.get('display_name') or data.get('binary')}")
    out.append("")
    if data.get("product"):
        out.append(f"**Product**: [`{data['product']}`](../products/{data['product']}.md)")
        out.append("")
    if data.get("description"):
        out.append(str(data["description"]).strip())
        out.append("")

    # Quick-facts box
    facts = []
    for k in ("binary", "canonical_path", "platform", "binary_kind", "arch", "trust_boundary"):
        if data.get(k):
            facts.append(f"- **{k.replace('_',' ').title()}**: `{_safe(data[k])}`" if k in ("binary", "canonical_path") else f"- **{k.replace('_',' ').title()}**: {_safe(data[k])}")
    if facts:
        out.append("## At a glance")
        out.append("")
        out.extend(facts)
        out.append("")

    # === LAYERED VISUALIZATIONS ===
    out.append(render_attack_surface_map(data))
    out.append(render_trust_boundary(data))
    out.append(render_defense_matrix(data))
    out.append(render_class_coverage_matrix(data))
    out.append(render_coverage(data))

    out.append("## Versions catalogued")
    out.append("")
    out.append(render_versions(data.get("versions") or []))
    out.append("")

    out.append(f"## Sources ({len(data.get('sources') or [])})")
    out.append("")
    out.append(render_sources(data.get("sources") or []))
    out.append("")

    out.append(f"## Sinks ({len(data.get('sinks') or [])})")
    out.append("")
    out.append(render_sinks(data.get("sinks") or []))
    out.append("")

    chains = data.get("chains") or []
    out.append(f"## Chains ({len(chains)})")
    out.append("")
    if not chains:
        out.append("_No chains catalogued yet._")
        out.append("")
    else:
        # Index table at the top
        out.append("| ID | Title | Source → Sink | Status | Severity |")
        out.append("|----|-------|---------------|--------|----------|")
        for ch in chains:
            src = find_source(data.get("sources") or [], ch.get("source_id"))
            snk = find_sink(data.get("sinks") or [], ch.get("sink_id"))
            out.append("| [{id}](#{anchor}) | {title} | `{s}` → `{k}` | {status} | {sev} |".format(
                id=_safe(ch.get("id")),
                anchor=_safe(ch.get("id", "")).lower().replace("-", "-"),
                title=_safe(ch.get("title")),
                s=_safe(src.get("name") or ch.get("source_id")),
                k=_safe(snk.get("name") or ch.get("sink_id")),
                status=_safe(ch.get("status", "unexplored")),
                sev=_safe(ch.get("severity")),
            ))
        out.append("")
        for ch in chains:
            out.append(render_chain(ch, data.get("sources") or [], data.get("sinks") or []))
            out.append("")

    out.append("---")
    out.append(f"_Auto-generated by `scripts/catalog_render.py` at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}. Edit `catalog/binaries/{slug(data.get('binary',''))}.yml` then re-run the renderer._")
    return "\n".join(out) + "\n"


def render_index(all_data: list[tuple[Path, dict]]) -> str:
    out = ["# Vulnerabin binary catalog index", ""]
    out.append(f"{len(all_data)} binaries catalogued.")
    out.append("")
    out.append("| Binary | Display name | Versions | Sources | Sinks | Chains | Confirmed | Partial | Unexplored |")
    out.append("|--------|--------------|----------|---------|-------|--------|-----------|---------|------------|")
    for path, data in sorted(all_data, key=lambda x: x[1].get("binary", "")):
        chains = data.get("chains") or []
        statuses = [c.get("status", "unexplored") for c in chains]
        page_name = path.stem  # binaries/foo.yml -> foo
        out.append("| [`{b}`](./{page}.md) | {dn} | {vers} | {ns} | {nk} | {nc} | {confirmed} | {partial} | {unexp} |".format(
            b=_safe(data.get("binary")),
            page=page_name,
            dn=_safe(data.get("display_name")),
            vers=len(data.get("versions") or []),
            ns=len(data.get("sources") or []),
            nk=len(data.get("sinks") or []),
            nc=len(chains),
            confirmed=statuses.count("confirmed"),
            partial=statuses.count("partial"),
            unexp=statuses.count("unexplored") + statuses.count("hypothesised"),
        ))
    out.append("")
    out.append(f"_Auto-generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}._")
    return "\n".join(out) + "\n"


def write_index_json(all_data: list[tuple[Path, dict]]):
    idx = []
    for path, data in all_data:
        chains = data.get("chains") or []
        idx.append({
            "binary": data.get("binary"),
            "display_name": data.get("display_name"),
            "yml_path": str(path.relative_to(ROOT)),
            "page_path": str((PAGES / f"{path.stem}.md").relative_to(ROOT)),
            "platform": data.get("platform"),
            "binary_kind": data.get("binary_kind"),
            "version_count": len(data.get("versions") or []),
            "source_count": len(data.get("sources") or []),
            "sink_count": len(data.get("sinks") or []),
            "chain_count": len(chains),
            "status_counts": {
                "confirmed": sum(1 for c in chains if c.get("status") == "confirmed"),
                "partial": sum(1 for c in chains if c.get("status") == "partial"),
                "hypothesised": sum(1 for c in chains if c.get("status") == "hypothesised"),
                "unexplored": sum(1 for c in chains if c.get("status") == "unexplored"),
                "mitigated": sum(1 for c in chains if c.get("status") == "mitigated"),
            },
            "engagements": sorted({v.get("eng") for v in (data.get("versions") or []) if v.get("eng")}),
        })
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "binary_count": len(idx),
        "binaries": idx,
    }
    (CATALOG / "index.json").write_text(json.dumps(out, indent=2))


def collect_targets(args) -> list[Path]:
    if not BINARIES.is_dir():
        raise SystemExit(f"catalog/binaries/ not found at {BINARIES}")
    if args.binary:
        path = BINARIES / f"{args.binary}.yml"
        if not path.is_file():
            raise SystemExit(f"not found: {path}")
        return [path]
    return sorted(BINARIES.glob("*.yml"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?", help="render only this binary (filename without .yml)")
    ap.add_argument("--check", action="store_true", help="parse YAML but don't write any files")
    ap.add_argument("--quiet", action="store_true", help="only print errors")
    args = ap.parse_args()

    targets = collect_targets(args)
    if not targets:
        print("no catalog/binaries/*.yml files found", file=sys.stderr)
        return 0

    PAGES.mkdir(exist_ok=True)
    all_data: list[tuple[Path, dict]] = []

    for path in targets:
        data = load_yaml(path)
        if not data.get("binary"):
            print(f"warning: {path} has no `binary` key, skipping", file=sys.stderr)
            continue
        all_data.append((path, data))
        if args.check:
            if not args.quiet:
                print(f"ok: {path}")
            continue
        page = render_binary(data)
        out_path = PAGES / f"{path.stem}.md"
        out_path.write_text(page)
        if not args.quiet:
            print(f"wrote {out_path}")

    if not args.check:
        # Always re-render the global index when we touch any page
        all_data_full = []
        for p in sorted(BINARIES.glob("*.yml")):
            d = load_yaml(p)
            if d.get("binary"):
                all_data_full.append((p, d))
        index_md = render_index(all_data_full)
        (PAGES / "index.md").write_text(index_md)
        write_index_json(all_data_full)
        if not args.quiet:
            print(f"wrote {PAGES / 'index.md'} and {CATALOG / 'index.json'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
