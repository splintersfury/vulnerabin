#!/usr/bin/env python3
"""Download and extract target applications for vulnerability analysis."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

# Known targets registry — maps friendly names to download info
KNOWN_TARGETS = {
    "mattermost-desktop": {
        "github": "mattermost/desktop",
        "asset_pattern": "linux-amd64.deb",
        "type": "electron",
    },
    "discord": {
        "url": "https://discord.com/api/download?platform=linux&format=deb",
        "type": "electron",
    },
    "signal-desktop": {
        "github": "nicehash/NiceHashQuickMiner",  # placeholder — Signal uses apt repo
        "apt": "signal-desktop",
        "type": "electron",
        "note": "Signal distributes via apt repo. Install: apt install signal-desktop",
    },
    "slack": {
        "url": "https://downloads.slack-edge.com/desktop-releases/linux/x64/4.41.105/slack-desktop-4.41.105-amd64.deb",
        "type": "electron",
    },
    "telegram-desktop": {
        "github": "nicehash/NiceHashQuickMiner",  # placeholder
        "snap": "telegram-desktop",
        "type": "electron",
        "note": "Telegram distributes via snap/flatpak. Install: snap install telegram-desktop",
    },
    "vscode": {
        "url": "https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64",
        "type": "electron",
    },
    "1password": {
        "url": "https://downloads.1password.com/linux/debian/amd64/stable/1password-latest.deb",
        "type": "electron",
    },
}


def get_github_latest_release(repo, asset_pattern):
    """Get download URL for latest release from GitHub."""
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(api_url, headers={"Accept": "application/vnd.github.v3+json"})

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        return None, None, str(e)

    version = data.get("tag_name", "unknown")

    for asset in data.get("assets", []):
        if asset_pattern in asset["name"]:
            return asset["browser_download_url"], version, None

    # Try all assets if pattern not found
    asset_names = [a["name"] for a in data.get("assets", [])]
    return None, version, f"No asset matching '{asset_pattern}'. Available: {asset_names}"


def download_file(url, dest_dir):
    """Download a file to dest_dir. Returns local path."""
    os.makedirs(dest_dir, exist_ok=True)

    # Try to get filename from URL or Content-Disposition
    filename = url.split("/")[-1].split("?")[0]
    if not filename or filename == "":
        filename = "download"

    dest_path = os.path.join(dest_dir, filename)

    print(f"Downloading: {url}", file=sys.stderr)
    print(f"Destination: {dest_path}", file=sys.stderr)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulneraBin/1.0"})
        with urllib.request.urlopen(req) as resp:
            # Check for Content-Disposition header
            cd = resp.headers.get("Content-Disposition", "")
            if "filename=" in cd:
                fn = cd.split("filename=")[-1].strip('"\'')
                if fn:
                    dest_path = os.path.join(dest_dir, fn)

            with open(dest_path, "wb") as f:
                shutil.copyfileobj(resp, f)

        print(f"Downloaded: {os.path.getsize(dest_path)} bytes", file=sys.stderr)
        return dest_path

    except Exception as e:
        return None


def extract_deb(deb_path, dest_dir):
    """Extract a .deb package."""
    os.makedirs(dest_dir, exist_ok=True)

    # Try dpkg-deb first
    try:
        subprocess.run(
            ["dpkg-deb", "-x", deb_path, dest_dir],
            check=True, capture_output=True
        )
        print(f"Extracted .deb to {dest_dir}", file=sys.stderr)
        return dest_dir
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Fallback to ar + tar
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["ar", "x", deb_path], cwd=tmpdir, check=True, capture_output=True)
            # Find data.tar.*
            for f in os.listdir(tmpdir):
                if f.startswith("data.tar"):
                    subprocess.run(
                        ["tar", "xf", os.path.join(tmpdir, f), "-C", dest_dir],
                        check=True, capture_output=True
                    )
                    print(f"Extracted .deb (via ar+tar) to {dest_dir}", file=sys.stderr)
                    return dest_dir
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return None


def extract_appimage(appimage_path, dest_dir):
    """Extract an AppImage."""
    os.makedirs(dest_dir, exist_ok=True)

    # Make executable and extract
    os.chmod(appimage_path, 0o755)
    try:
        subprocess.run(
            [appimage_path, "--appimage-extract"],
            cwd=dest_dir, check=True, capture_output=True
        )
        squashfs_dir = os.path.join(dest_dir, "squashfs-root")
        if os.path.isdir(squashfs_dir):
            print(f"Extracted AppImage to {squashfs_dir}", file=sys.stderr)
            return squashfs_dir
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return None


def extract_archive(archive_path, dest_dir):
    """Extract common archive formats."""
    os.makedirs(dest_dir, exist_ok=True)

    ext = archive_path.lower()

    try:
        if ext.endswith(".tar.gz") or ext.endswith(".tgz"):
            subprocess.run(["tar", "xzf", archive_path, "-C", dest_dir], check=True, capture_output=True)
        elif ext.endswith(".tar.xz"):
            subprocess.run(["tar", "xJf", archive_path, "-C", dest_dir], check=True, capture_output=True)
        elif ext.endswith(".zip"):
            subprocess.run(["unzip", "-o", archive_path, "-d", dest_dir], check=True, capture_output=True)
        elif ext.endswith(".7z"):
            subprocess.run(["7z", "x", archive_path, f"-o{dest_dir}"], check=True, capture_output=True)
        else:
            return None

        print(f"Extracted archive to {dest_dir}", file=sys.stderr)
        return dest_dir
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def acquire_target(target, output_dir):
    """Main acquisition logic."""
    raw_dir = os.path.join(output_dir, "raw")
    extracted_dir = os.path.join(output_dir, "target")
    os.makedirs(raw_dir, exist_ok=True)

    result = {"target": target, "output_dir": output_dir}

    # Check if target is a local path
    if os.path.exists(target):
        dest = os.path.join(extracted_dir, os.path.basename(target))
        if os.path.isdir(target):
            shutil.copytree(target, dest, dirs_exist_ok=True)
        else:
            os.makedirs(extracted_dir, exist_ok=True)
            shutil.copy2(target, dest)
        result["type"] = "local"
        result["extracted_path"] = dest
        return result

    # Check if target is a URL
    if target.startswith("http://") or target.startswith("https://"):
        dl_path = download_file(target, raw_dir)
        if not dl_path:
            result["error"] = f"Failed to download: {target}"
            return result

        result["download_path"] = dl_path

        # Try to extract
        if dl_path.endswith(".deb"):
            ext_path = extract_deb(dl_path, extracted_dir)
        elif dl_path.lower().endswith(".appimage"):
            ext_path = extract_appimage(dl_path, extracted_dir)
        else:
            ext_path = extract_archive(dl_path, extracted_dir)

        if ext_path:
            result["extracted_path"] = ext_path
        else:
            result["extracted_path"] = dl_path  # Use raw file

        return result

    # Check known targets registry
    target_lower = target.lower().replace(" ", "-")
    info = KNOWN_TARGETS.get(target_lower)
    if not info:
        # Fuzzy match
        for key, val in KNOWN_TARGETS.items():
            if target_lower in key or key in target_lower:
                info = val
                target_lower = key
                break

    if not info:
        result["error"] = f"Unknown target: {target}. Known targets: {', '.join(KNOWN_TARGETS.keys())}"
        result["hint"] = "Provide a direct URL or local file path instead."
        return result

    result["registry_match"] = target_lower

    # Handle special cases
    if info.get("note"):
        print(f"Note: {info['note']}", file=sys.stderr)

    # Check if installed locally (snap/apt)
    if info.get("snap"):
        snap_path = f"/snap/{info['snap']}/current"
        if os.path.isdir(snap_path):
            result["type"] = "snap"
            result["extracted_path"] = snap_path
            result["note"] = f"Using locally installed snap at {snap_path}"
            return result

    if info.get("apt"):
        # Check common install locations
        for prefix in ["/opt", "/usr/lib", "/usr/share"]:
            candidate = os.path.join(prefix, info["apt"])
            if os.path.isdir(candidate):
                result["type"] = "apt"
                result["extracted_path"] = candidate
                return result

    # Download from GitHub releases
    if info.get("github"):
        url, version, err = get_github_latest_release(info["github"], info.get("asset_pattern", ""))
        if url:
            result["version"] = version
            dl_path = download_file(url, raw_dir)
            if dl_path:
                result["download_path"] = dl_path

                if dl_path.endswith(".deb"):
                    ext_path = extract_deb(dl_path, extracted_dir)
                elif dl_path.lower().endswith(".appimage"):
                    ext_path = extract_appimage(dl_path, extracted_dir)
                else:
                    ext_path = extract_archive(dl_path, extracted_dir)

                if ext_path:
                    result["extracted_path"] = ext_path
                else:
                    result["extracted_path"] = dl_path
                return result

        if err:
            print(f"GitHub release error: {err}", file=sys.stderr)

    # Download from direct URL
    if info.get("url"):
        dl_path = download_file(info["url"], raw_dir)
        if dl_path:
            result["download_path"] = dl_path

            if dl_path.endswith(".deb"):
                ext_path = extract_deb(dl_path, extracted_dir)
            elif dl_path.lower().endswith(".appimage"):
                ext_path = extract_appimage(dl_path, extracted_dir)
            else:
                ext_path = extract_archive(dl_path, extracted_dir)

            if ext_path:
                result["extracted_path"] = ext_path
            else:
                result["extracted_path"] = dl_path
            return result

    result["error"] = f"Could not acquire {target}. Try providing a direct URL."
    return result


def main():
    parser = argparse.ArgumentParser(description="Acquire target for vulnerability analysis")
    parser.add_argument("--target", "-t", required=True, help="Target name, URL, or local path")
    parser.add_argument("--output-dir", "-o", required=True, help="Output directory for the engagement")
    parser.add_argument("--list", "-l", action="store_true", help="List known targets")
    args = parser.parse_args()

    if args.list:
        for name, info in KNOWN_TARGETS.items():
            print(f"  {name:25s} [{info['type']}]")
        return

    result = acquire_target(args.target, args.output_dir)
    print(json.dumps(result, indent=2))
    sys.exit(0 if "error" not in result else 1)


if __name__ == "__main__":
    main()
