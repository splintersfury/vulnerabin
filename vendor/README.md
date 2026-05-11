# vendor/ — Third-Party Pinning for the Reconstruct Phase

This directory pins external dependencies used by the `reconstruct` pipeline
phase. The reconstruct phase refuses to run if these pins are inconsistent
with what is actually installed on disk.

## Files

| File | Purpose |
|---|---|
| `libghidra.version` | URL + commit SHA + sha256 of the LibGhidra Java extension (0xeb/libghidra) |
| `ghidrasql_skills.version` | URL + commit SHA + sha256 of the GhidraSQL skill set (0xeb/ghidrasql) |
| `fid_db_versions.json` | Per-FID-DB version + checksum (Ghidra Function ID databases) |
| `bootstrap.sh` | `--check` verifies pins match installed; `--install` (Pass 0 sub-plan) installs from pinned commit |

## Workflow

- After cloning the repo: `vendor/bootstrap.sh --check` reports which
  dependencies are missing.
- Pass 0 sub-plan adds `vendor/bootstrap.sh --install` which downloads
  and builds LibGhidra from the pinned commit, clones the GhidraSQL skill
  set into `.claude/skills/ghidrasql/`, and generates the FID DBs.
- Bumping a pin: edit the relevant `.version` or `.json` file, rerun
  `vendor/bootstrap.sh --install`, run `pytest tests/reconstruct/` to
  ensure tests still pass, commit the updated pin + lockfile.

## Why not check in the binary blobs?

LibGhidra and the FID DBs are large (50-200 MB). Pinning by URL + commit
SHA + checksum keeps the repo light while preserving reproducibility.
A single bootstrap script makes the install a one-shot operation on any
clone.
