# Comprehend phase strategist

The comprehend phase synthesizes a plain-language **mental model** of the product the engagement targets, between `reconstruct` and `walk`. After Pass 0 + Pass 1 give functions semantic names, this phase produces:

1. **Per-binary `summary` + `full_picture`** in `catalog/binaries/<stem>.yml` — TL;DR + structured Full Picture (loaded_by / start_trigger / ipc_peers / accepted_inputs / dangerous_operations_reachable / defense_gaps_observed). Renders as a banner on each binary's catalog page.
2. **Product-level `architecture_narrative`** in `catalog/products/<slug>.yml` — summary + data_flow_prose + binary_roles + trust_boundaries + attack_surface_primary. Renders as the "How this product works" section on the product page (above Layer 4 topology).

A researcher entering an unfamiliar product reads BOTH artifacts before touching source — that's the point.

## Pre-conditions

- The engagement's primary binary has `reconstruction.status` ∈ {`complete`, `partial`} (FSM gate `primary_binary_reconstructed`).
- The catalog product YAML for the binary's `product` exists.

If you opt out (e.g., for a one-shot binary not in any product), pass `--no-comprehend` to skip the phase. Walk-strategist instructions can still be loaded without comprehension; quality of grounding is just lower.

## Sequence

### Step 1 — bundle per-binary worker input

For each binary in the product that has been reconstructed (or is the engagement's primary binary):

```
python3 scripts/comprehend_binary_batch.py --binary <stem> [--version <tag>]
```

Writes `catalog/reconstructed/<stem>_<tag>/comprehend_input.json` containing the catalog YAML excerpt + reconstruction summary + vuln_surface examples + subsystem notes. If the binary has not been reconstructed, the bundle still gets written from catalog metadata alone — the worker prompt acknowledges that case.

### Step 2 — dispatch one worker per binary

Use the Task tool with `subagent_type: general-purpose, model: opus`. Worker prompt: `prompts/workers/comprehend_binary.md`. Pass the binary's bundle path as input. Worker returns `summary` + `full_picture`. Save its result JSON to `catalog/reconstructed/<stem>_<tag>/comprehend_result.json`.

Sequential is fine here — comprehension is one pass per binary. Skip binaries whose `summary_fingerprint` matches the freshly computed `binary_fingerprint(yaml)` (the apply step is idempotent but you save tokens).

### Step 3 — apply per-binary results

```
python3 scripts/comprehend_binary_apply.py \
    --binary <stem> \
    --result catalog/reconstructed/<stem>_<tag>/comprehend_result.json
```

Validates schema, merges `summary` + `full_picture` + `summary_fingerprint` + `last_comprehended` into the binary YAML.

### Step 4 — bundle product worker input

```
python3 scripts/comprehend_product_batch.py --product <slug>
```

Walks the product's binaries list, splits into `binaries_comprehended` (have summary in YAML) vs `binaries_pending` (don't). Writes `catalog/products/<slug>.comprehend_input.json`.

### Step 5 — dispatch the product narrative worker

Use the Task tool. Worker prompt: `prompts/workers/comprehend_narrative.md`. Save result to `catalog/products/<slug>.comprehend_result.json`.

### Step 6 — apply the product result

```
python3 scripts/comprehend_product_apply.py \
    --product <slug> \
    --bundle catalog/products/<slug>.comprehend_input.json \
    --result catalog/products/<slug>.comprehend_result.json
```

Writes `architecture_narrative` block to the product YAML.

### Step 7 — render the catalog site

```
python3 scripts/catalog_site_render.py
```

The TL;DR banner appears on every binary page that has a `summary`. The "How this product works" section appears on every product page that has an `architecture_narrative`.

## Carryforward

If a binary's YAML state hasn't changed since the last comprehension, `comprehend_fingerprint.is_binary_summary_stale(yaml)` returns `False` and you can skip dispatching its worker. Same for the product narrative — `is_product_narrative_stale` compares the stored `architecture_narrative.fingerprint` to the freshly computed one.

In a 30-binary product where one binary was re-reconstructed, the typical incremental run is 1 binary worker dispatch + 1 product worker dispatch instead of 31.

## Failure handling

- **Per-binary worker returns invalid JSON.** Re-dispatch with the same prompt. If it fails twice, mark that binary's apply as failed in the journal and move on — the product synthesis can still run with the remaining comprehended binaries.
- **Product worker returns invalid JSON.** Re-dispatch. If it fails twice, halt the comprehend phase with `narrative_present` gate failing.
- **All binaries pending.** Product worker still runs; output narrative will say "no comprehended binaries yet" and list every binary as pending.

## Post-conditions

- `catalog/binaries/<stem>.yml#summary` and `#full_picture` populated for every reconstructed binary (FSM gate `binary_summaries_present`).
- `catalog/products/<slug>.yml#architecture_narrative` populated (FSM gate `narrative_present`).
- Layer 8 page + product page render the new content on next `catalog_site_render.py`.

## What this phase does NOT do

- Modify reconstruction artifacts (manifest, coverage, proposed_renames). Comprehension reads these, never writes back.
- Mutate Ghidra projects.
- Find vulnerabilities — this is orientation, not analysis. The walk + triage + deep phases use the narrative as grounding context.
