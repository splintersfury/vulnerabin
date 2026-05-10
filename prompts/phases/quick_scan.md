# Quick Scan Mode

See CLAUDE.md "Quick Scan Mode" for full workflow. This is a fast-pass alternative to full triage — no per-unit enumeration, one comprehensive prompt over the most security-critical files (entry points, IPC handlers, IOCTL dispatchers).

## When to use

- Initial recon before committing to full triage (~30 min spend)
- Confirming a target is worth deeper investment

## Output

Notes only — quick scan does NOT produce `triage.json`. If something interesting surfaces, escalate to `deep` directly OR fall back to full `triage`.

## Journal

```bash
python3 scripts/journal.py append <eng> --phase triage --actor <model> --event note \
    --summary "Quick scan: 3 candidate findings; recommending full triage on IPC layer"
```
