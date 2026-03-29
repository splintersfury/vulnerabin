#!/usr/bin/env python3
"""Detect target type: Electron app, native binary, or firmware image."""

import json
import os
import struct
import sys


def check_magic(path):
    """Read first bytes to identify file type."""
    try:
        with open(path, "rb") as f:
            magic = f.read(16)
    except (IsADirectoryError, PermissionError):
        return None

    if len(magic) < 4:
        return None

    # ELF
    if magic[:4] == b"\x7fELF":
        bits = {1: 32, 2: 64}.get(magic[4], 0)
        endian = {1: "little", 2: "big"}.get(magic[5], "unknown")
        machine_offset = 18
        if len(magic) > 19:
            fmt = "<H" if endian == "little" else ">H"
            machine = struct.unpack(fmt, magic[machine_offset:machine_offset + 2])[0]
            arch_map = {3: "x86", 62: "x86_64", 40: "arm", 183: "aarch64", 8: "mips"}
            arch = arch_map.get(machine, f"unknown({machine})")
        else:
            arch = "unknown"
        return {"format": "elf", "bits": bits, "endian": endian, "arch": arch}

    # PE (MZ header)
    if magic[:2] == b"MZ":
        return {"format": "pe"}

    # Mach-O
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                      b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return {"format": "macho"}

    # Firmware signatures
    if magic[:4] == b"hsqs":  # squashfs (little-endian)
        return {"format": "squashfs"}
    if magic[:4] == b"sqsh":  # squashfs (big-endian)
        return {"format": "squashfs"}

    return None


def find_asar(path):
    """Search for app.asar in common Electron locations."""
    if os.path.isfile(path) and path.endswith(".asar"):
        return path

    if os.path.isdir(path):
        candidates = [
            os.path.join(path, "app.asar"),
            os.path.join(path, "resources", "app.asar"),
            os.path.join(path, "resources", "app"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c

        # Recursive search (1 level into subdirs)
        for entry in os.listdir(path):
            subdir = os.path.join(path, entry)
            if os.path.isdir(subdir):
                for sub_candidate in ["app.asar", os.path.join("resources", "app.asar")]:
                    full = os.path.join(subdir, sub_candidate)
                    if os.path.exists(full):
                        return full

    return None


def check_electron_source(path):
    """Check if directory is an Electron source project (has package.json with electron dep)."""
    pkg_json = os.path.join(path, "package.json") if os.path.isdir(path) else None
    if pkg_json and os.path.isfile(pkg_json):
        try:
            with open(pkg_json) as f:
                pkg = json.load(f)
            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))
            if "electron" in all_deps:
                return {
                    "name": pkg.get("name", "unknown"),
                    "version": pkg.get("version", "unknown"),
                    "main": pkg.get("main", "index.js"),
                    "electron_version": all_deps.get("electron", "unknown"),
                }
        except (json.JSONDecodeError, KeyError):
            pass
    return None


def check_firmware_signatures(path):
    """Scan file for embedded firmware filesystem signatures."""
    if not os.path.isfile(path):
        return None

    try:
        size = os.path.getsize(path)
        if size > 500 * 1024 * 1024:  # Skip files > 500MB
            return None

        with open(path, "rb") as f:
            data = f.read(min(size, 10 * 1024 * 1024))  # Read first 10MB

        signatures = {
            b"hsqs": "squashfs",
            b"sqsh": "squashfs",
            b"\x85\x19\x01\xe0": "cramfs",
            b"\x19\x85\x20\x03": "jffs2",
            b"UBI#": "ubifs",
        }

        for sig, fs_type in signatures.items():
            offset = data.find(sig)
            if offset >= 0:
                return {"filesystem": fs_type, "offset": offset}

    except PermissionError:
        pass

    return None


def detect(path):
    """Main detection logic. Returns JSON-serializable result."""
    path = os.path.abspath(path)

    if not os.path.exists(path):
        return {"error": f"Path does not exist: {path}"}

    result = {"path": path}

    # Check for Electron app (asar)
    asar = find_asar(path)
    if asar:
        result["type"] = "electron"
        result["evidence"] = f"Found asar at {asar}"
        result["asar_path"] = asar
        return result

    # Check for Electron source project
    if os.path.isdir(path):
        electron_info = check_electron_source(path)
        if electron_info:
            result["type"] = "electron_source"
            result["evidence"] = "package.json has electron dependency"
            result.update(electron_info)
            return result

    # Check file magic bytes
    if os.path.isfile(path):
        magic_info = check_magic(path)
        if magic_info:
            fmt = magic_info["format"]
            if fmt in ("elf", "pe", "macho"):
                result["type"] = "native_binary"
                result["evidence"] = f"{fmt.upper()} binary detected"
                result.update(magic_info)
                return result
            if fmt == "squashfs":
                result["type"] = "firmware"
                result["evidence"] = "SquashFS filesystem detected"
                return result

        # Check for embedded firmware signatures
        fw_info = check_firmware_signatures(path)
        if fw_info:
            result["type"] = "firmware"
            result["evidence"] = f"Embedded {fw_info['filesystem']} at offset {fw_info['offset']}"
            result.update(fw_info)
            return result

    # If directory, check contents
    if os.path.isdir(path):
        files = os.listdir(path)
        # Check for extracted firmware rootfs patterns
        rootfs_indicators = {"bin", "sbin", "usr", "etc", "lib", "var"}
        if len(rootfs_indicators.intersection(set(files))) >= 3:
            result["type"] = "firmware_rootfs"
            result["evidence"] = "Directory contains Linux rootfs structure"
            return result

    result["type"] = "unknown"
    result["evidence"] = "Could not determine target type"
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: detect.py <path>"}))
        sys.exit(1)

    result = detect(sys.argv[1])
    print(json.dumps(result, indent=2))
    sys.exit(0 if "error" not in result else 1)
