# Reconstruct phase strategist

The reconstruct phase turns raw Ghidra decompilation into idiomatic reconstructed source. As of the Pass 1 sub-plan, the strategist drives two passes:

1. **Pass 0 (deterministic)** — `scripts/reconstruct.py` runs project discovery + IAT wrapper detection + pcode-hash carryforward. No LLM involvement.
2. **Pass 1 (LLM rename)** — `scripts/reconstruct_pass1_batch.py` emits per-batch input bundles; the strategist dispatches an Agent (Task tool) per batch with `prompts/workers/reconstruct_rename.md`; `scripts/reconstruct_pass1_apply.py` validates + merges each result.

## Pre-conditions

Before running this phase:

- The engagement has decomp output at `engagements/<eng>/decomp/function_index.json`.
- The binary has a catalog entry at `catalog/binaries/<stem>.yml`.
- The reconstruction dir is scaffolded: `vb-add reconstruction --binary <stem> --version <tag>`.
- (Pass 1 only) `LIBGHIDRA_HEALTHZ_URL` is set OR the user has opted out — the FSM `libghidra_alive` gate is informational at this stage; Pass 1 itself does not call LibGhidra.

## Pass 0 sequence

```
python3 scripts/reconstruct.py \
    --engagement <eng-slug> \
    --binary <stem> \
    --version <tag>
```

After Pass 0 completes:
- `catalog/reconstructed/<stem>_<tag>/manifest.json` has a `pass0` entry with `proposed_renames`, `project_discovery`, `pcode_hashes_by_addr`.
- `catalog/reconstructed/<stem>_<tag>/coverage.json` exists with `hard_gate_pass: false`, `soft_gate_pass: false`.
- `catalog/binaries/<stem>.yml#reconstruction.status` is `partial`.

## Pass 1 sequence

### Step 1 — emit batches

```
python3 scripts/reconstruct_pass1_batch.py \
    --engagement <eng-slug> \
    --binary <stem> \
    --version <tag>
```

This identifies FUN_* survivors (anything Pass 0 did not lock at confidence ≥ medium) and writes `catalog/reconstructed/<stem>_<tag>/pass1_batches/batch_NNN.json` + an `index.json`. Read `index.json` to learn how many batches there are.

### Step 2 — dispatch one worker per batch

For each pending batch in `pass1_batches/index.json`, dispatch a worker:

- Tool: Task (subagent_type: general-purpose, model: opus, temperature 0 if surfaced)
- Prompt: the content of `prompts/workers/reconstruct_rename.md` with the batch JSON appended as the worker's input
- Save the worker's returned JSON to `catalog/reconstructed/<stem>_<tag>/pass1_batches/result_NNN.json`

Dispatch SEQUENTIALLY for the first 2-3 batches to confirm the worker contract behaves as expected; after that, parallel dispatch is allowed (the apply step is idempotent so order does not matter).

### Step 3 — apply each result

```
python3 scripts/reconstruct_pass1_apply.py \
    --engagement <eng-slug> \
    --binary <stem> \
    --version <tag> \
    --result catalog/reconstructed/<stem>_<tag>/pass1_batches/result_NNN.json
```

Each apply call validates the worker result, merges accepted renames into `manifest.json#passes[]`, and recomputes `coverage.json`. The apply step:

- Rejects renames for addresses locked by Pass 0 (medium/high-confidence Pass 0 renames).
- Validates schema (`pass: pass1`, `batch_id`, `renames[].{addr,to,confidence,rationale}`, confidence in `{high, medium, low}`).
- Flips the matching `pass1_batches/index.json` entry's `status` from `pending` to `applied`.

If apply rejects a result, the strategist may either fix the worker prompt and re-dispatch, or skip that batch (the `index.json` entry remains `pending` so it's visible).

## Failure handling

- **Worker returns invalid JSON.** Re-dispatch with an explicit reminder of the schema. If the worker fails twice, mark the batch `failed` in `index.json` manually and skip.
- **Apply rejects renames for locked addresses.** Expected; the worker proposed a rename for a function Pass 0 already locked. Log the rejection and continue.
- **All batches applied but coverage is still low.** This is normal for the MVP — Pass 1 alone targets unnamed FUN_* survivors. Reachability gates (`reachable_named_100pct`) and additional naming sources (Pass 2 retype, Pass 3 structify) live in follow-on sub-plans.

## Post-conditions

- Every batch in `pass1_batches/index.json` has status `applied` or `failed`.
- `manifest.json#passes` contains both `pass0` and `pass1` entries.
- `coverage.json` reflects the cumulative Pass 0 + Pass 1 named count.
- `catalog/binaries/<stem>.yml#reconstruction.status` is still `partial` (hard gate semantics for `complete` status arrive with the reachability sub-plan).

## What this phase does NOT do (yet)

- Apply renames to a Ghidra project (`.gpr` mutation requires LibGhidra integration).
- Retype function parameters / locals (Pass 2 — separate sub-plan).
- Consolidate struct hypotheses (Pass 3a — separate sub-plan).
- Add decompiler comments (Pass 3b — separate sub-plan).
- Name globals (Pass 3c — separate sub-plan).
