# Phase 6 — Reporting

User-directed. Format CONFIRMED findings for the requested platform (Bugcrowd, HackerOne, ZDI, MSRC, vendor PSIRT).

## Mandatory gate: exec_required_or_justified

For every finding tagged `CONFIRMED`, one of these must hold:
- An `exec_result` event in the journal with `verdict=triggered` or `crashed`, OR
- A `note` event with `meta.waived=true` and a written reason

`scripts/fsm.py validate <eng>` enforces this before `report` is considered started.

## Per-platform shapes

- **Bugcrowd**: title, VRT classification, affected component, steps to reproduce, impact, evidence chain.
- **HackerOne**: same structure; CVSS string mandatory.
- **ZDI**: longer technical write-up, must include the patch suggestion.
- **MSRC**: Microsoft's portal; bug class taxonomy + reproducer + crash dump if applicable.
- **Vendor PSIRT** (Intel, NVIDIA, etc.): vendor-specific template.

Pull the platform's accepted submissions from KB to mimic their shape:
```bash
python3 scripts/kb_query.py --search "bugcrowd accepted" --format context
```

## What every report needs

1. Title (≤80 chars, action-oriented)
2. CWE + CVSS 3.1 vector + score
3. Summary (2-3 sentences — what, where, impact)
4. Affected component + version
5. Steps to reproduce — ordered, copy-pasteable, no prose-only steps
6. Impact assessment with concrete blast radius
7. Evidence chain: source line → intermediate transformations → sink line
8. PoC reference (link to `pocs/<N>/`) and exec evidence (link to `exec/<N>/`)
9. Suggested fix (one paragraph)

## Output

`engagements/<eng>/reports/<platform>-<finding-slug>.md`

## Journal

```bash
python3 scripts/journal.py append <eng> --phase report --actor <model> --event artifact \
    --ref reports/bugcrowd-ipc-rce.md --summary "Drafted Bugcrowd submission for finding 003"
```
