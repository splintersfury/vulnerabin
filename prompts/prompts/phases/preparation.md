# Phase 2 — Preparation

See CLAUDE.md "Phase 2: Preparation" for the full workflow per target type.

## Produces (any of)

- `decomp/` (native binaries via `scripts/decomp.py`)
- `extracted/` (Electron via `scripts/extract_electron.py`)
- `firmware/` (firmware via `scripts/extract_firmware.py`)

## Journal

```bash
python3 scripts/journal.py append <eng> --phase preparation --actor script:<name> \
    --event phase_end --ref <produced dir> --summary "Extracted <N> functions/files"
```
