# Phase 3 — Triage

Systematic per-function (binary) or per-file (Electron) labeling. This is the high-volume phase — most engagement tokens are spent here.

## Pre-flight (mandatory gate: kb_prime)

Before any analysis, run:
```bash
python3 scripts/kb_query.py --target-type <type> --format context > /tmp/kb_prime.txt
python3 scripts/kb_query.py --search "<vendor>" --format context >> /tmp/kb_prime.txt
```
Read the output. If similar targets have been triaged before, lean on those patterns. The article's anti-pattern: "discover from first principles every time" wastes tokens we don't need to spend.

## Per-unit triage

If in **Strategist mode**, do NOT read source files yourself. For each unit, dispatch a worker:
- `prompts/workers/inspect_function.md` for binaries (one function per worker call)
- `prompts/workers/inspect_file.md` for Electron/scripting

The worker writes its JSON output to `engagements/<eng>/triage_workers/<unit>.json`. The Strategist then aggregates these into `triage.json`.

If NOT in Strategist mode, read the unit yourself and emit the same JSON shape directly.

Either way: every record MUST conform to `taxonomy/schemas/triage_output.json` and MUST include the `reasoning` field (mandatory per CLAUDE.md).

## Aggregation

Once all units processed, write `engagements/<eng>/triage.json` per CLAUDE.md schema. Append journal:
```bash
python3 scripts/journal.py append <eng> --phase triage --actor <model> --event phase_end \
    --ref triage.json --summary "Triaged <N> units; <M> rated >=4"
```

Then present the top-N table to the user (per CLAUDE.md Phase 3 step 5).

## Anti-patterns

- ❌ Reading the entire decomp directory in one shot. The whole point is per-unit fresh context.
- ❌ Skipping the KB-prime step "to save time" — it costs <1k tokens and prevents repeated mistakes.
- ❌ Making the reasoning field a single sentence. Step-by-step is mandatory; that's what filters FPs.
