# Phase 5 — Validation / PoC (AUP-decomposed)

Build a runnable PoC for a CONFIRMED or LIKELY finding. **All PoC construction goes through `scripts/exploit_step.py`** — see `prompts/aup_decomposition.md` for the why.

## Mandatory gate: aup_decomposed

You may NOT produce an end-to-end exploit in one model response. Each step is a separate `exploit_step.py prompt` → operator runs the model → `exploit_step.py record`. Steps:

1. reconnaissance
2. input_shape
3. trigger_condition
4. harness_skeleton
5. single_iteration
6. sweep (optional)
7. evidence

## Workflow

```bash
# For finding 003, step 1:
python3 scripts/exploit_step.py prompt <eng> 003 1 > /tmp/step1_prompt.txt

# Operator runs the prompt through chosen model (or just answers in main loop), saves result:
# ... model output -> /tmp/step1_out.md ...

python3 scripts/exploit_step.py record <eng> 003 1 --input /tmp/step1_out.md --actor opus

# Repeat for steps 2..N
```

If a step is refused (`AUP_REFUSAL: ...` in the output), re-run that step using:
```bash
python3 scripts/route_model.py exec aup_offload --prompt-file /tmp/step3_prompt.txt --output /tmp/step3_out.md
python3 scripts/exploit_step.py record <eng> 003 3 --input /tmp/step3_out.md --actor opencode --refused
```

## Output layout

Each step writes `engagements/<eng>/pocs/<N>/step_<k>_<name>.{md,c,py,...}`. The collected steps ARE the PoC trail.

## Don't forget

- Never execute against live targets.
- Execution belongs to Phase 5c (`prompts/phases/exec_validation.md`), not here.
- Append a journal `validation`/`artifact` event per step (exploit_step.py does this if `VULNERABIN_JOURNAL=1`).
