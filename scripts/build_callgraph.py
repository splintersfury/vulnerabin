#!/usr/bin/env python3
"""Build call graph from Ghidra function index for chain analysis.

Reads function_index.json (from ExportFunctionIndex.py) and builds:
- Forward call graph (function → functions it calls)
- Reverse call graph (function → functions that call it)
- Entry point identification (exports, main, CGI handlers)
- Reachability analysis from entry points
"""

import argparse
import json
import os
import sys
from collections import defaultdict, deque


def load_function_index(path):
    """Load the Ghidra-exported function index."""
    with open(path) as f:
        return json.load(f)


def build_graphs(index):
    """Build forward and reverse call graphs."""
    functions = {f["address"]: f for f in index.get("functions", [])}
    call_graph = index.get("call_graph", {})

    forward = defaultdict(list)   # addr → [callee addrs]
    reverse = defaultdict(list)   # addr → [caller addrs]

    for caller_addr, callees in call_graph.items():
        for callee in callees:
            forward[caller_addr].append(callee)
            reverse[callee].append(caller_addr)

    return functions, dict(forward), dict(reverse)


def identify_entry_points(functions, forward_graph):
    """Identify likely entry points in the binary."""
    entries = []

    entry_patterns = [
        "main", "_start", "__libc_start_main",
        # CGI / web server patterns
        "handle_request", "process_request", "do_get", "do_post",
        "cgi_main", "http_handler",
        # IOCTL / driver patterns
        "DriverEntry", "ioctl_handler", "DeviceIoControl",
        "dispatch_ioctl", "IRP_MJ_DEVICE_CONTROL",
        # Network patterns
        "accept_connection", "handle_client", "process_packet",
        # Init patterns
        "init", "initialize", "setup",
    ]

    for addr, func in functions.items():
        name = func.get("name", "").lower()
        is_entry = False

        # Check name patterns
        for pattern in entry_patterns:
            if pattern.lower() in name:
                is_entry = True
                break

        # Check if it's exported
        if func.get("is_exported", False):
            is_entry = True

        # Check if nothing calls it (top of call tree)
        if addr not in {callee for callees in forward_graph.values() for callee in callees}:
            # Only if it calls other things (not a leaf)
            if addr in forward_graph and len(forward_graph[addr]) > 0:
                is_entry = True

        if is_entry:
            entries.append({
                "address": addr,
                "name": func.get("name", "unknown"),
                "reason": "name_match" if any(p.lower() in name for p in entry_patterns)
                          else "exported" if func.get("is_exported") else "unreferenced_caller",
            })

    return entries


def compute_reachability(entry_points, forward_graph):
    """BFS from entry points to find all reachable functions."""
    reachable = set()
    for entry in entry_points:
        addr = entry["address"]
        queue = deque([addr])
        visited = {addr}

        while queue:
            current = queue.popleft()
            reachable.add(current)
            for callee in forward_graph.get(current, []):
                if callee not in visited:
                    visited.add(callee)
                    queue.append(callee)

    return reachable


def compute_function_stats(functions, forward_graph, reverse_graph, reachable):
    """Compute per-function statistics useful for triage."""
    stats = {}
    for addr, func in functions.items():
        callers = reverse_graph.get(addr, [])
        callees = forward_graph.get(addr, [])

        stats[addr] = {
            "address": addr,
            "name": func.get("name", "unknown"),
            "num_callers": len(callers),
            "num_callees": len(callees),
            "is_leaf": len(callees) == 0,
            "is_reachable": addr in reachable,
            "callers": callers[:20],  # Cap for readability
            "callees": callees[:20],
        }

    return stats


def main():
    parser = argparse.ArgumentParser(description="Build call graph from Ghidra function index")
    parser.add_argument("function_index", help="Path to function_index.json")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    args = parser.parse_args()

    if not os.path.isfile(args.function_index):
        print(json.dumps({"error": f"File not found: {args.function_index}"}))
        sys.exit(1)

    index = load_function_index(args.function_index)
    functions, forward, reverse = build_graphs(index)
    entries = identify_entry_points(functions, forward)
    reachable = compute_reachability(entries, forward)
    stats = compute_function_stats(functions, forward, reverse, reachable)

    result = {
        "binary": index.get("binary", "unknown"),
        "total_functions": len(functions),
        "entry_points": entries,
        "reachable_functions": len(reachable),
        "unreachable_functions": len(functions) - len(reachable),
        "leaf_functions": sum(1 for s in stats.values() if s["is_leaf"]),
        "function_stats": stats,
        "forward_graph": forward,
        "reverse_graph": reverse,
    }

    output = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Call graph written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
