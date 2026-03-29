#!/usr/bin/env python3
"""Extract and index an Electron application for vulnerability analysis."""

import argparse
import json
import os
import re
import subprocess
import sys


def find_asar(app_dir):
    """Find app.asar in the application directory."""
    candidates = [
        os.path.join(app_dir, "app.asar"),
        os.path.join(app_dir, "resources", "app.asar"),
    ]

    # Search recursively (max 3 levels)
    for root, dirs, files in os.walk(app_dir):
        depth = root.replace(app_dir, "").count(os.sep)
        if depth > 3:
            dirs.clear()
            continue
        if "app.asar" in files:
            candidates.append(os.path.join(root, "app.asar"))

    for c in candidates:
        if os.path.isfile(c):
            return c

    # Check for unpacked app directory
    unpacked = [
        os.path.join(app_dir, "resources", "app"),
        os.path.join(app_dir, "app"),
    ]
    for u in unpacked:
        if os.path.isdir(u) and os.path.isfile(os.path.join(u, "package.json")):
            return u  # Already extracted

    return None


def extract_asar(asar_path, output_dir):
    """Extract app.asar using npx asar."""
    os.makedirs(output_dir, exist_ok=True)

    # If it's already a directory (unpacked app), just return it
    if os.path.isdir(asar_path):
        return asar_path

    try:
        subprocess.run(
            ["npx", "asar", "extract", asar_path, output_dir],
            check=True, capture_output=True, timeout=120
        )
        print(f"Extracted asar to {output_dir}", file=sys.stderr)
        return output_dir
    except FileNotFoundError:
        print("npx not found. Trying asar directly...", file=sys.stderr)
        try:
            subprocess.run(
                ["asar", "extract", asar_path, output_dir],
                check=True, capture_output=True, timeout=120
            )
            return output_dir
        except FileNotFoundError:
            print("Error: asar tool not found. Install with: npm install -g asar", file=sys.stderr)
            return None
    except subprocess.CalledProcessError as e:
        print(f"asar extract failed: {e.stderr.decode()}", file=sys.stderr)
        return None


def find_js_files(app_dir):
    """Find all JavaScript/TypeScript files."""
    js_files = []
    skip_dirs = {"node_modules", ".git", ".cache", "dist-electron", "__pycache__"}

    for root, dirs, files in os.walk(app_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, app_dir)
                js_files.append(rel_path)

    return sorted(js_files)


def parse_package_json(app_dir):
    """Parse package.json for app metadata."""
    pkg_path = os.path.join(app_dir, "package.json")
    if not os.path.isfile(pkg_path):
        return {}

    try:
        with open(pkg_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def scan_file_for_patterns(filepath, patterns):
    """Scan a file for regex/string patterns. Returns list of matches."""
    matches = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for pattern_name, pattern_list in patterns.items():
                    for p in pattern_list:
                        if p in line:
                            matches.append({
                                "pattern": pattern_name,
                                "match": p,
                                "line": line_num,
                                "context": line.strip()[:200],
                            })
    except IOError:
        pass
    return matches


def index_electron_app(app_dir):
    """Build a comprehensive index of the Electron app."""
    pkg = parse_package_json(app_dir)
    js_files = find_js_files(app_dir)

    result = {
        "app_name": pkg.get("name", "unknown"),
        "version": pkg.get("version", "unknown"),
        "description": pkg.get("description", ""),
        "main_entry": pkg.get("main", "index.js"),
        "total_js_files": len(js_files),
        "file_list": js_files,
        "browser_windows": [],
        "preload_scripts": [],
        "ipc_handlers": [],
        "dangerous_apis": [],
        "misconfigs": [],
        "electron_version": "",
    }

    # Get Electron version from dependencies
    all_deps = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))
    result["electron_version"] = all_deps.get("electron", "unknown")

    # Patterns to search for
    security_patterns = {
        "browser_window": ["new BrowserWindow(", "BrowserWindow({"],
        "preload": ["preload:", "preload ="],
        "ipc_main_on": ["ipcMain.on(", "ipcMain.handle(", "ipcMain.once("],
        "ipc_renderer": ["ipcRenderer.send(", "ipcRenderer.invoke("],
        "shell_open": ["shell.openExternal(", "shell.openPath("],
        "child_process": ["child_process", "exec(", "spawn(", "execFile(", "execSync("],
        "eval": ["eval(", "new Function(", "executeJavaScript("],
        "context_bridge": ["contextBridge.exposeInMainWorld("],
        "protocol_handler": ["protocol.registerHttpProtocol(", "protocol.handle(", "protocol.registerFileProtocol("],
        "deep_link": ["setAsDefaultProtocolClient(", "open-url"],
        "node_integration": ["nodeIntegration"],
        "context_isolation": ["contextIsolation"],
        "web_security": ["webSecurity"],
        "sandbox_setting": ["sandbox:"],
        "inner_html": ["innerHTML", "outerHTML", "insertAdjacentHTML(", "dangerouslySetInnerHTML"],
        "navigate": ["will-navigate", "setWindowOpenHandler", "loadURL(", "loadFile("],
        "file_ops": ["fs.writeFile", "fs.readFile", "fs.unlink", "writeFileSync", "readFileSync"],
    }

    for js_file in js_files:
        full_path = os.path.join(app_dir, js_file)
        matches = scan_file_for_patterns(full_path, security_patterns)

        for m in matches:
            entry = {"file": js_file, "line": m["line"], "pattern": m["pattern"], "match": m["match"], "context": m["context"]}

            if m["pattern"] == "browser_window":
                result["browser_windows"].append(entry)
            elif m["pattern"] == "preload":
                result["preload_scripts"].append(entry)
            elif m["pattern"] in ("ipc_main_on", "ipc_renderer"):
                result["ipc_handlers"].append(entry)
            elif m["pattern"] in ("shell_open", "child_process", "eval", "inner_html", "file_ops"):
                result["dangerous_apis"].append(entry)
            elif m["pattern"] in ("node_integration", "context_isolation", "web_security", "sandbox_setting"):
                # Check if it's a dangerous config
                ctx = m["context"].lower()
                if ("nodeintegration" in ctx and "true" in ctx) or \
                   ("contextisolation" in ctx and "false" in ctx) or \
                   ("websecurity" in ctx and "false" in ctx) or \
                   ("sandbox" in ctx and "false" in ctx and "sandbox:" in ctx):
                    result["misconfigs"].append(entry)

    # Classify files by role
    main_entry = result["main_entry"]
    result["file_roles"] = {}
    for f in js_files:
        if f == main_entry or "main" in f.lower():
            result["file_roles"][f] = "main"
        elif "preload" in f.lower():
            result["file_roles"][f] = "preload"
        elif "renderer" in f.lower() or "render" in f.lower():
            result["file_roles"][f] = "renderer"
        else:
            result["file_roles"][f] = "utility"

    # Summary stats
    result["summary"] = {
        "browser_windows": len(result["browser_windows"]),
        "preload_scripts": len(result["preload_scripts"]),
        "ipc_handlers": len(result["ipc_handlers"]),
        "dangerous_apis": len(result["dangerous_apis"]),
        "misconfigs": len(result["misconfigs"]),
    }

    return result


def main():
    parser = argparse.ArgumentParser(description="Extract and index an Electron application")
    parser.add_argument("path", help="Path to Electron app directory or .asar file")
    parser.add_argument("--output-dir", "-o", help="Output directory for extracted app")
    args = parser.parse_args()

    path = os.path.abspath(args.path)

    if not os.path.exists(path):
        print(json.dumps({"error": f"Path does not exist: {path}"}))
        sys.exit(1)

    # Find the asar
    asar_path = None
    if path.endswith(".asar"):
        asar_path = path
    elif os.path.isdir(path):
        asar_path = find_asar(path)

    if not asar_path:
        # Maybe it's already an extracted app directory with package.json
        if os.path.isfile(os.path.join(path, "package.json")):
            app_dir = path
        else:
            print(json.dumps({"error": "Could not find app.asar or package.json"}))
            sys.exit(1)
    else:
        # Extract asar
        if args.output_dir:
            extract_dir = args.output_dir
        else:
            extract_dir = os.path.join(os.path.dirname(asar_path), "app_extracted")

        if os.path.isdir(asar_path):
            app_dir = asar_path  # Already extracted
        else:
            app_dir = extract_asar(asar_path, extract_dir)
            if not app_dir:
                print(json.dumps({"error": "Failed to extract app.asar"}))
                sys.exit(1)

    # Index the app
    index = index_electron_app(app_dir)
    index["extracted_path"] = app_dir

    print(json.dumps(index, indent=2))


if __name__ == "__main__":
    main()
