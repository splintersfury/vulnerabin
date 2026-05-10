# Phase 1 — Acquisition

See CLAUDE.md "Phase 1: Acquisition & Detection" for the full workflow. This file is just the gate definition.

## Produces

- `engagements/<eng>/scope.json` (target metadata, bounty program, in/out of scope)
- `engagements/<eng>/scope.md` (RoE if provided)
- `engagements/<eng>/target/` (raw downloaded/provided binary or app)

## Journal

```bash
python3 scripts/journal.py append <eng> --phase acquisition --actor human --event phase_end \
    --ref scope.json --summary "Acquired <target> v<version>"
```
