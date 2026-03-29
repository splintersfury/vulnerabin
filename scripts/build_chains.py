#!/usr/bin/env python3
"""Build source-to-sink chains by tracing imports/call graphs.

For Electron apps: parses require()/import statements to build a module
dependency graph, then links source patterns to sink patterns via that graph.

For binaries: reads function_index.json (from Ghidra) and links source
functions to sink functions via the call graph.

No LLM involved — pure deterministic graph traversal.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


def load_taxonomy(taxonomy_dir):
    """Load source/sink/sanitizer taxonomy files."""
    taxonomy = {}
    for name in ("sources", "sinks", "sanitizers"):
        path = os.path.join(taxonomy_dir, f"{name}.json")
        if os.path.isfile(path):
            with open(path) as f:
                taxonomy[name] = json.load(f)
    return taxonomy


# ─── Electron / JavaScript chain building ───


def parse_js_imports(filepath, app_dir):
    """Extract import/require dependencies from a JS file."""
    deps = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except IOError:
        return deps

    # CommonJS: require('./foo'), require('../bar'), require('module')
    for m in re.finditer(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", content):
        deps.append(m.group(1))

    # ES modules: import ... from './foo'
    for m in re.finditer(r"""import\s+.*?\s+from\s+['"]([^'"]+)['"]""", content):
        deps.append(m.group(1))

    # Dynamic import: import('./foo')
    for m in re.finditer(r"""import\s*\(\s*['"]([^'"]+)['"]""", content):
        deps.append(m.group(1))

    # Resolve relative paths
    resolved = []
    file_dir = os.path.dirname(filepath)
    for dep in deps:
        if dep.startswith("."):
            # Relative import
            candidate = os.path.normpath(os.path.join(file_dir, dep))
            rel = os.path.relpath(candidate, app_dir)
            # Try common extensions
            for ext in ("", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", "/index.js", "/index.ts"):
                full = candidate + ext
                if os.path.isfile(full):
                    resolved.append(os.path.relpath(full, app_dir))
                    break
            else:
                resolved.append(rel)  # Keep unresolved for tracking
        else:
            resolved.append(dep)  # node_modules or built-in

    return resolved


def build_js_module_graph(app_dir, js_files):
    """Build a module dependency graph from JS imports."""
    graph = defaultdict(set)       # file -> set of files it imports
    reverse_graph = defaultdict(set)  # file -> set of files that import it

    for js_file in js_files:
        full_path = os.path.join(app_dir, js_file)
        deps = parse_js_imports(full_path, app_dir)
        for dep in deps:
            if dep in js_files or any(dep.startswith(f.rsplit(".", 1)[0]) for f in js_files):
                # Find the actual file
                matched = None
                for candidate in js_files:
                    if candidate == dep or candidate.startswith(dep.rstrip("/") + ".") or candidate.startswith(dep.rstrip("/") + "/index."):
                        matched = candidate
                        break
                if matched:
                    graph[js_file].add(matched)
                    reverse_graph[matched].add(js_file)

    return dict(graph), dict(reverse_graph)


def scan_js_patterns(filepath, taxonomy):
    """Scan a JS file for source/sink/sanitizer patterns."""
    results = {"sources": [], "sinks": [], "sanitizers": []}

    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except IOError:
        return results

    for line_num, line in enumerate(lines, 1):
        for category_name in ("sources", "sinks", "sanitizers"):
            cat = taxonomy.get(category_name, {})
            for pattern_group, info in cat.items():
                patterns = info.get("patterns", []) if isinstance(info, dict) else info
                if isinstance(patterns, dict):
                    patterns = patterns.get("patterns", [])
                if not isinstance(patterns, list):
                    continue
                for p in patterns:
                    if p and p in line:
                        results[category_name].append({
                            "group": pattern_group,
                            "pattern": p,
                            "line": line_num,
                            "context": line.strip()[:200],
                        })

    return results


def find_chains_bfs(source_files, sink_files, graph, max_depth=5):
    """BFS from each source file to find paths to sink files."""
    chains = []

    for src_file, src_info in source_files.items():
        # BFS
        queue = [(src_file, [src_file])]
        visited = {src_file}

        while queue:
            current, path = queue.pop(0)

            if len(path) > max_depth:
                continue

            # Check if current file has sinks
            if current in sink_files and current != src_file:
                chains.append({
                    "source_file": src_file,
                    "source_patterns": src_info,
                    "sink_file": current,
                    "sink_patterns": sink_files[current],
                    "path": list(path),
                    "depth": len(path) - 1,
                })

            # Also check if source and sink are in same file
            if current == src_file and src_file in sink_files:
                chains.append({
                    "source_file": src_file,
                    "source_patterns": src_info,
                    "sink_file": src_file,
                    "sink_patterns": sink_files[src_file],
                    "path": [src_file],
                    "depth": 0,
                })

            # Expand neighbors
            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

    return chains


def build_electron_chains(app_dir, taxonomy_dir):
    """Build source-to-sink chains for an Electron app."""
    taxonomy = load_taxonomy(taxonomy_dir)

    # Find all JS files
    js_files = []
    skip_dirs = {"node_modules", ".git", ".cache", "__pycache__"}
    for root, dirs, files in os.walk(app_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
                js_files.append(os.path.relpath(os.path.join(root, f), app_dir))

    # Build module graph
    graph, reverse_graph = build_js_module_graph(app_dir, js_files)

    # Scan all files for patterns
    source_files = {}
    sink_files = {}
    sanitizer_files = {}
    all_scan_results = {}

    for js_file in js_files:
        full_path = os.path.join(app_dir, js_file)
        scan = scan_js_patterns(full_path, taxonomy)
        all_scan_results[js_file] = scan

        if scan["sources"]:
            source_files[js_file] = scan["sources"]
        if scan["sinks"]:
            sink_files[js_file] = scan["sinks"]
        if scan["sanitizers"]:
            sanitizer_files[js_file] = scan["sanitizers"]

    # Find chains via BFS through import graph
    chains = find_chains_bfs(source_files, sink_files, graph)

    # Score chains
    for chain in chains:
        score = 0.0

        # Shorter chains = higher confidence
        if chain["depth"] == 0:
            score += 3.0  # Same file = strong signal
        elif chain["depth"] == 1:
            score += 2.0
        elif chain["depth"] <= 3:
            score += 1.0

        # Critical sink types boost score
        for sp in chain["sink_patterns"]:
            group = sp["group"]
            if group in ("command_execution", "code_evaluation", "execute_javascript"):
                score += 2.0
            elif group in ("shell_open", "html_injection", "file_write"):
                score += 1.5
            elif group in ("sql_query", "navigation"):
                score += 1.0

        # High-risk source types boost score
        for sp in chain["source_patterns"]:
            group = sp["group"]
            if group in ("protocol_handler", "deep_link", "ipc_main"):
                score += 1.5
            elif group in ("dom_input", "network_response"):
                score += 1.0

        # Check if any sanitizer is in the path
        sanitizers_in_path = []
        for path_file in chain["path"]:
            if path_file in sanitizer_files:
                sanitizers_in_path.extend(sanitizer_files[path_file])
                score -= 1.0  # Reduce score if sanitizer present

        chain["sanitizers_in_path"] = sanitizers_in_path
        chain["score"] = round(max(score, 0.0), 1)

    # Sort by score descending
    chains.sort(key=lambda c: c["score"], reverse=True)

    # Deduplicate (same source file + sink file = keep highest scored)
    seen = set()
    unique_chains = []
    for chain in chains:
        key = (chain["source_file"], chain["sink_file"])
        if key not in seen:
            seen.add(key)
            unique_chains.append(chain)

    return {
        "type": "electron",
        "app_dir": app_dir,
        "total_files": len(js_files),
        "source_files": len(source_files),
        "sink_files": len(sink_files),
        "sanitizer_files": len(sanitizer_files),
        "total_chains": len(unique_chains),
        "chains": unique_chains,
        "module_graph": {k: list(v) for k, v in graph.items()},
    }


# ─── Binary chain building (from Ghidra function index) ───


def build_binary_chains(function_index_path, taxonomy_dir):
    """Build source-to-sink chains for a decompiled binary."""
    taxonomy = load_taxonomy(taxonomy_dir)

    with open(function_index_path) as f:
        index = json.load(f)

    functions = index.get("functions", [])
    call_graph = index.get("call_graph", {})

    # Build reverse call graph
    reverse_graph = defaultdict(list)
    for caller, callees in call_graph.items():
        for callee in callees:
            reverse_graph[callee].append(caller)

    # Identify source and sink functions
    source_funcs = {}
    sink_funcs = {}

    source_symbols = set()
    sink_symbols = set()

    for group_name, info in taxonomy.get("sources", {}).items():
        symbols = info.get("symbols", []) if isinstance(info, dict) else []
        for s in symbols:
            source_symbols.add(s)

    for group_name, info in taxonomy.get("sinks", {}).items():
        symbols = info.get("symbols", []) if isinstance(info, dict) else []
        for s in symbols:
            sink_symbols.add(s)

    for func in functions:
        name = func.get("name", "")
        addr = func.get("address", "")
        callees = call_graph.get(addr, [])

        # Check if this function calls any source/sink
        calls_sources = [c for c in callees if c in source_symbols or any(c.endswith(s) for s in source_symbols)]
        calls_sinks = [c for c in callees if c in sink_symbols or any(c.endswith(s) for s in sink_symbols)]

        if calls_sources:
            source_funcs[addr] = {"name": name, "sources": calls_sources}
        if calls_sinks:
            sink_funcs[addr] = {"name": name, "sinks": calls_sinks}

    # BFS from sources to sinks through call graph
    chains = []
    for src_addr, src_info in source_funcs.items():
        queue = [(src_addr, [src_addr])]
        visited = {src_addr}

        while queue:
            current, path = queue.pop(0)
            if len(path) > 6:
                continue

            if current in sink_funcs:
                chains.append({
                    "source_addr": src_addr,
                    "source_name": src_info["name"],
                    "source_calls": src_info["sources"],
                    "sink_addr": current,
                    "sink_name": sink_funcs[current]["name"],
                    "sink_calls": sink_funcs[current]["sinks"],
                    "path": path,
                    "depth": len(path) - 1,
                })

            for callee in call_graph.get(current, []):
                if callee not in visited and callee in {f.get("address", "") for f in functions}:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))

    # Score and sort
    for chain in chains:
        score = 3.0 - (chain["depth"] * 0.5)
        for s in chain["sink_calls"]:
            if s in ("system", "popen", "execve"):
                score += 2.0
            elif s in ("strcpy", "sprintf", "strcat"):
                score += 1.5
        chain["score"] = round(max(score, 0.0), 1)

    chains.sort(key=lambda c: c["score"], reverse=True)

    return {
        "type": "binary",
        "total_functions": len(functions),
        "source_functions": len(source_funcs),
        "sink_functions": len(sink_funcs),
        "total_chains": len(chains),
        "chains": chains,
    }


def main():
    parser = argparse.ArgumentParser(description="Build source-to-sink chains")
    parser.add_argument("path", help="App directory (Electron) or function_index.json (binary)")
    parser.add_argument("--taxonomy", "-t", required=True, help="Path to taxonomy directory")
    parser.add_argument("--type", choices=["electron", "binary", "auto"], default="auto",
                        help="Target type (default: auto-detect)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    args = parser.parse_args()

    path = os.path.abspath(args.path)

    # Auto-detect type
    target_type = args.type
    if target_type == "auto":
        if os.path.isdir(path):
            target_type = "electron"
        elif path.endswith(".json"):
            target_type = "binary"
        else:
            print(json.dumps({"error": "Cannot auto-detect type. Use --type electron|binary"}))
            sys.exit(1)

    if target_type == "electron":
        result = build_electron_chains(path, args.taxonomy)
    else:
        result = build_binary_chains(path, args.taxonomy)

    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Chains written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
