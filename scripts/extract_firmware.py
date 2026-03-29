#!/usr/bin/env python3
"""Extract firmware images and identify analysis targets.

Supports:
- SquashFS (unsquashfs)
- JFFS2 (jefferson)
- UBIFS
- Generic (binwalk)
- Raw tar/gzip/xz archives

After extraction, identifies:
- ELF binaries (especially CGI endpoints, daemons, init scripts)
- Web interface files (HTML, JS, PHP, Lua)
- Configuration files with hardcoded credentials
- Shared libraries used by multiple binaries
"""

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from collections import defaultdict


def find_tool(name):
    """Check if a tool is available."""
    try:
        subprocess.run(["which", name], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def extract_with_binwalk(firmware_path, output_dir):
    """Extract using binwalk."""
    if not find_tool("binwalk"):
        return None

    os.makedirs(output_dir, exist_ok=True)
    try:
        subprocess.run(
            ["binwalk", "-e", "-C", output_dir, firmware_path],
            capture_output=True, timeout=300, check=True
        )
        # binwalk creates a subdirectory
        for entry in os.listdir(output_dir):
            subdir = os.path.join(output_dir, entry)
            if os.path.isdir(subdir) and entry.startswith("_"):
                return subdir
        return output_dir
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def extract_squashfs(firmware_path, output_dir, offset=0):
    """Extract SquashFS filesystem."""
    if not find_tool("unsquashfs"):
        return None

    os.makedirs(output_dir, exist_ok=True)

    # If offset > 0, extract the squashfs portion first
    input_path = firmware_path
    if offset > 0:
        temp_path = os.path.join(output_dir, ".squashfs_part")
        with open(firmware_path, "rb") as f_in:
            f_in.seek(offset)
            with open(temp_path, "wb") as f_out:
                f_out.write(f_in.read())
        input_path = temp_path

    try:
        subprocess.run(
            ["unsquashfs", "-d", os.path.join(output_dir, "rootfs"), "-f", input_path],
            capture_output=True, timeout=300
        )
        rootfs = os.path.join(output_dir, "rootfs")
        if os.path.isdir(rootfs):
            return rootfs
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    return None


def is_elf(path):
    """Check if file is an ELF binary."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (IOError, PermissionError):
        return False


def find_targets(rootfs_dir):
    """Find analysis targets in extracted firmware rootfs."""
    targets = {
        "elf_binaries": [],
        "cgi_endpoints": [],
        "web_files": [],
        "config_files": [],
        "init_scripts": [],
        "shared_libs": [],
        "setuid_binaries": [],
    }

    cgi_dirs = {"cgi-bin", "cgi", "www-cgi", "htdocs", "www"}
    web_extensions = {".html", ".htm", ".php", ".lua", ".cgi", ".asp", ".jsp", ".js"}
    config_extensions = {".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml"}

    for root, dirs, files in os.walk(rootfs_dir):
        rel_root = os.path.relpath(root, rootfs_dir)

        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, rootfs_dir)

            try:
                st = os.lstat(full_path)
            except OSError:
                continue

            # Check for ELF
            if is_elf(full_path):
                entry = {
                    "path": rel_path,
                    "size": st.st_size,
                }

                # Classify
                if any(cgi_dir in rel_path.lower() for cgi_dir in cgi_dirs) or f.endswith(".cgi"):
                    entry["type"] = "cgi"
                    targets["cgi_endpoints"].append(entry)
                elif rel_path.startswith("usr/lib/") or rel_path.startswith("lib/") or f.endswith(".so") or ".so." in f:
                    entry["type"] = "shared_lib"
                    targets["shared_libs"].append(entry)
                else:
                    entry["type"] = "binary"

                # Check setuid/setgid
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    entry["setuid"] = True
                    targets["setuid_binaries"].append(entry)

                targets["elf_binaries"].append(entry)

            # Web files
            elif any(f.lower().endswith(ext) for ext in web_extensions):
                targets["web_files"].append({"path": rel_path, "size": st.st_size})

            # Config files
            elif any(f.lower().endswith(ext) for ext in config_extensions):
                targets["config_files"].append({"path": rel_path, "size": st.st_size})

            # Init scripts
            elif rel_path.startswith(("etc/init.d/", "etc/rc.d/", "etc/init/", "etc/systemd/")):
                targets["init_scripts"].append({"path": rel_path})

    return targets


def scan_for_credentials(rootfs_dir, config_files):
    """Quick scan for hardcoded credentials in config files."""
    cred_patterns = [
        (r'password\s*[=:]\s*["\']?(\S+)', "password"),
        (r'passwd\s*[=:]\s*["\']?(\S+)', "password"),
        (r'secret\s*[=:]\s*["\']?(\S+)', "secret"),
        (r'api[_-]?key\s*[=:]\s*["\']?(\S+)', "api_key"),
        (r'token\s*[=:]\s*["\']?(\S+)', "token"),
        (r'private[_-]?key', "private_key"),
    ]

    findings = []
    for cf in config_files[:100]:  # Cap to avoid slow scans
        full_path = os.path.join(rootfs_dir, cf["path"])
        try:
            with open(full_path, encoding="utf-8", errors="ignore") as f:
                content = f.read(50000)  # Read first 50KB

            for pattern, cred_type in cred_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for m in matches:
                    findings.append({
                        "file": cf["path"],
                        "type": cred_type,
                        "line_context": m.group(0)[:100],
                    })
        except IOError:
            continue

    return findings


def main():
    parser = argparse.ArgumentParser(description="Extract and analyze firmware images")
    parser.add_argument("firmware", help="Path to firmware image")
    parser.add_argument("--output", "-o", required=True, help="Output directory")
    parser.add_argument("--skip-binwalk", action="store_true", help="Skip binwalk, use direct extraction only")
    args = parser.parse_args()

    firmware_path = os.path.abspath(args.firmware)
    output_dir = os.path.abspath(args.output)

    if not os.path.isfile(firmware_path):
        print(json.dumps({"error": f"File not found: {firmware_path}"}))
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)
    result = {"firmware": firmware_path, "output_dir": output_dir}

    # Try to detect and extract
    rootfs = None

    # Check for squashfs at start
    with open(firmware_path, "rb") as f:
        magic = f.read(4)
        if magic in (b"hsqs", b"sqsh"):
            print("Detected SquashFS at offset 0", file=sys.stderr)
            rootfs = extract_squashfs(firmware_path, output_dir)

    # If not direct squashfs, try binwalk
    if not rootfs and not args.skip_binwalk:
        print("Trying binwalk extraction...", file=sys.stderr)
        rootfs = extract_with_binwalk(firmware_path, output_dir)

    # If already a directory (pre-extracted rootfs), use directly
    if not rootfs and os.path.isdir(firmware_path):
        rootfs = firmware_path

    if not rootfs:
        result["error"] = "Failed to extract firmware. Install binwalk: pip install binwalk"
        print(json.dumps(result, indent=2))
        sys.exit(1)

    result["rootfs_path"] = rootfs

    # Find targets
    print("Scanning extracted filesystem...", file=sys.stderr)
    targets = find_targets(rootfs)
    result["targets"] = targets

    # Summary
    result["summary"] = {
        "total_elf_binaries": len(targets["elf_binaries"]),
        "cgi_endpoints": len(targets["cgi_endpoints"]),
        "web_files": len(targets["web_files"]),
        "config_files": len(targets["config_files"]),
        "init_scripts": len(targets["init_scripts"]),
        "shared_libs": len(targets["shared_libs"]),
        "setuid_binaries": len(targets["setuid_binaries"]),
    }

    # Quick credential scan
    cred_findings = scan_for_credentials(rootfs, targets["config_files"])
    if cred_findings:
        result["credential_findings"] = cred_findings

    # Prioritized targets for analysis
    priority_targets = []

    # CGI endpoints are highest priority (direct web attack surface)
    for t in targets["cgi_endpoints"]:
        priority_targets.append({**t, "priority": "critical", "reason": "CGI endpoint — direct web attack surface"})

    # Setuid binaries
    for t in targets["setuid_binaries"]:
        if t not in targets["cgi_endpoints"]:
            priority_targets.append({**t, "priority": "high", "reason": "SetUID/SetGID binary — LPE target"})

    # Network daemons (common names)
    daemon_names = {"httpd", "lighttpd", "nginx", "telnetd", "sshd", "ftpd",
                    "udhcpd", "dnsmasq", "miniupnpd", "upnpd", "tr069",
                    "cwmpd", "uhttpd", "goahead", "boa", "thttpd"}
    for t in targets["elf_binaries"]:
        basename = os.path.basename(t["path"]).lower()
        if basename in daemon_names or any(d in basename for d in daemon_names):
            if t not in priority_targets:
                priority_targets.append({**t, "priority": "high", "reason": f"Network daemon — {basename}"})

    result["priority_targets"] = priority_targets[:30]

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
