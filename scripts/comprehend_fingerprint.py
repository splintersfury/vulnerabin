"""Fingerprint computation for the comprehend phase carryforward.

Per spec §1.4:
- binary_fingerprint: sha256 over (stem + reconstruction.ref + version_tag +
  status + relevant binary YAML blocks + reconstruction notes/* dir hash)
- product_fingerprint: sha256 over (product slug + sorted binary fingerprints +
  product YAML structure blocks)

If a binary's fingerprint matches what's already stored in
`catalog/binaries/<stem>.yml#summary_fingerprint`, comprehend skips the
LLM dispatch for that binary. Same for products — `architecture_narrative.fingerprint`.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Iterable

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)


def _stable_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _section_hash(yaml_data: dict, keys: Iterable[str]) -> str:
    """Hash only the listed top-level keys from a YAML dict.

    Missing keys contribute the empty string. Order-stable.
    """
    payload = {k: yaml_data.get(k) for k in sorted(keys)}
    return _hash(_stable_json(payload))


def _notes_dir_hash(notes_dir: Path) -> str:
    """Hash the contents of a notes directory (sorted by relpath).

    Returns empty hash if dir doesn't exist (so it doesn't change the
    fingerprint when notes are absent).
    """
    if not notes_dir.is_dir():
        return ""
    pairs: list[tuple[str, str]] = []
    for p in sorted(notes_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(notes_dir))
        pairs.append((rel, _hash(p.read_text(errors="replace"))))
    return _hash(_stable_json(pairs))


# Binary YAML keys that affect comprehension. Changes to these should
# invalidate the cached summary; changes to other keys (e.g. unrelated
# tags) should not.
_BINARY_FINGERPRINT_YAML_KEYS = (
    "binary", "product", "binary_kind", "platform",
    "sources", "sinks", "capabilities", "chains",
    "inputs", "features",
    "reconstruction",
)

_PRODUCT_FINGERPRINT_YAML_KEYS = (
    "product", "display_name", "vendor", "description",
    "binaries", "trust_zones", "ipc_edges", "process_model",
)


def binary_fingerprint(binary_yaml: dict) -> str:
    """Compute the per-binary fingerprint."""
    stem = binary_yaml.get("binary") or ""
    recon = binary_yaml.get("reconstruction") or {}
    ref = recon.get("ref") or ""
    version_tag = recon.get("version_tag") or ""
    status = recon.get("status") or "not_started"

    notes_hash = ""
    if ref:
        notes_dir = ROOT / ref / "notes"
        notes_hash = _notes_dir_hash(notes_dir)

    yaml_section = _section_hash(binary_yaml, _BINARY_FINGERPRINT_YAML_KEYS)

    payload = {
        "stem": stem,
        "ref": ref,
        "version_tag": version_tag,
        "status": status,
        "yaml_section": yaml_section,
        "notes_hash": notes_hash,
    }
    return _hash(_stable_json(payload))


def product_fingerprint(product_yaml: dict, per_binary_fingerprints: dict[str, str]) -> str:
    """Compute the per-product fingerprint.

    `per_binary_fingerprints` maps binary stem -> binary_fingerprint(stem).
    Order-stable (sorted) so adding/removing binaries changes the hash but
    list reordering does not.
    """
    slug = product_yaml.get("product") or ""
    yaml_section = _section_hash(product_yaml, _PRODUCT_FINGERPRINT_YAML_KEYS)
    sorted_bin_fps = sorted(per_binary_fingerprints.items())
    payload = {
        "slug": slug,
        "yaml_section": yaml_section,
        "binary_fingerprints": sorted_bin_fps,
    }
    return _hash(_stable_json(payload))


def is_binary_summary_stale(binary_yaml: dict) -> bool:
    """Return True if the binary YAML's stored summary_fingerprint disagrees
    with the freshly computed fingerprint (or no summary exists yet)."""
    if "summary" not in binary_yaml or "full_picture" not in binary_yaml:
        return True
    stored = binary_yaml.get("summary_fingerprint")
    if not stored:
        return True
    return stored != binary_fingerprint(binary_yaml)


def is_product_narrative_stale(product_yaml: dict, per_binary_fingerprints: dict[str, str]) -> bool:
    """Return True if the product narrative needs re-synthesis."""
    nar = product_yaml.get("architecture_narrative") or {}
    if not nar:
        return True
    stored = nar.get("fingerprint")
    if not stored:
        return True
    return stored != product_fingerprint(product_yaml, per_binary_fingerprints)
