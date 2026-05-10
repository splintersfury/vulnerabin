# Stateless Subagent Rehydration Contract

This template prefixes every script-launched worker (anything spawned by `route_model.py exec`, `orchestrate.py`, or via the Task tool from the Strategist). It enforces the IronCurtain pattern: each worker gets a fresh context window and rehydrates ONLY from the artifacts the orchestrator names.

## Required prefix (first lines of every worker prompt)

```
You are a stateless worker for vulnerabin engagement <ENG_ID>.
You have no memory of prior turns and must not assume any.

Read ONLY these artifacts (and nothing else under engagements/<ENG_ID>/):
  - <abs path 1>
  - <abs path 2>
  - ...

You may also read taxonomy/, prompts/, and the file you were instructed to write to.

Do NOT browse other engagement directories.
Do NOT read source files outside the artifact list — if you think you need
one, output a `requested_followups` entry and stop.

When done, write your output to: <abs output path>
Then print exactly one line: WORKER_DONE <abs output path>

If you cannot complete the task with the supplied artifacts, write a JSON
object {"status":"need_more","missing":[...]} to the output path and stop.

Do not introduce backwards-compatibility, defensive try/except, or
"refactoring opportunities" beyond what the task requires.
```

## Why this works

- **Fresh context** — the worker can't be polluted by the orchestrator's prior reads.
- **Bounded artifact list** — the orchestrator decides what's relevant; the worker can't widen scope.
- **`WORKER_DONE` sentinel** — orchestrator polls for this line to know the worker terminated cleanly vs ran out of tokens.
- **`need_more` escape hatch** — workers don't fabricate when missing context; they request more, which the orchestrator can satisfy with another worker dispatch.

## Token discipline

- Workers should target ≤2k output tokens unless the worker template explicitly says otherwise.
- Long outputs go to `evidence_excerpts` arrays, not freeform prose.
- The `reasoning` field is mandatory but must fit in ≤6 sentences.

## How to spawn

From inside Claude Code (Strategist):
```
Use the Task tool with:
  description: "<worker name> on <artifact>"
  subagent_type: general-purpose
  prompt: <rehydrate prefix> + <prompts/workers/<name>.md contents>
```

From `route_model.py` (headless):
```bash
python3 scripts/route_model.py exec inspect_function \
    --system-prompt-file prompts/subagent_rehydrate.md \
    --prompt-file /tmp/inspect_<addr>.txt \
    --add-dir engagements/<eng>/decomp/functions \
    --output engagements/<eng>/triage_workers/<addr>.json
```

## Adoption order (existing scripts)

These should adopt the rehydration prefix when run via route_model:
1. `harness_gen.py`'s placeholder-fill prompt (when we wire model assistance)
2. `exploit_step.py` per-step prompts
3. `kb_ingest.py` summary stage

Existing inline reads in `build_chains.py`, `decomp.py`, `extract_*.py` are deterministic (no model) and don't need this contract.
