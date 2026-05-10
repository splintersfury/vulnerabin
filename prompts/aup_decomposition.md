# Exploit-Step Decomposition (AUP-aware)

The article that motivated this framework noted: "Model executed first two steps before AUP refusal on step three." Vendor refusal during legitimate defensive research is a real production blocker. This template decomposes exploit/PoC construction into atomic steps so each step is individually safe and reviewable.

## Why decomposition

Asking a model to "write a full exploit for finding 003" triggers refusal. Asking it to "write the C struct that matches the IOCTL input layout described in finding 003" does not. The whole-exploit prompt is also lower-quality — it pattern-matches to a generic exploit shape and skips engagement-specific detail.

## Decomposition pattern

For any finding that needs a PoC, decompose into:

1. **Reconnaissance** — what the attacker observes (versions, services, file paths, IPC/IOCTL surface). No code yet.
2. **Input shape** — the data structures involved. C structs / JSON shapes / IPC message layouts.
3. **Trigger condition** — the specific value combination that takes the dangerous code path. Quote the relevant check from the finding.
4. **Harness skeleton** — a runnable wrapper (test program, fuzzer harness, IPC sender) with the trigger value as a parameter.
5. **Single-iteration trigger** — fill in the parameter so the harness exercises the bug exactly once. Capture pre/post state.
6. **Sweep** — only if needed: vary the parameter to find the exact boundary.
7. **Evidence** — what observable output proves the bug fired (crash, allocator log, registry write, file at attacker-chosen path).

Each step is a separate `scripts/exploit_step.py` invocation. Each invocation prompts for ONLY the named step, with the prior steps' outputs supplied as context.

## Per-step prompt skeleton

When you (a model) are asked for step N, you receive:
- The finding markdown
- The ACID worker output
- The output of steps 1..N-1
- A statement of EXACTLY which step is being requested

Your output must:
- Address ONLY step N
- Not anticipate later steps
- Not include helper code "for convenience" that does another step's job
- Note explicitly if step N depends on information not in the supplied context — request the specific worker dispatch instead of guessing

If you (model) are unable to produce step N due to safety policy:
- Say so explicitly: "AUP_REFUSAL: <reason>"
- Identify which atomic sub-step triggered refusal
- Suggest whether decomposing further (1→1a/1b) would resolve it

`scripts/exploit_step.py` will then re-route to OpenCode (local model) for the refused step, and resume the chain on subsequent steps.

## Hard rules

- Never produce a working exploit chained end-to-end in one response, even if asked. Always decompose.
- Never escalate scope: a step asking for "step 3 of finding 003" must not produce content that would also satisfy step 6.
- All steps write to `engagements/<eng>/pocs/<N>/step_<k>_<name>.{md,c,py,json}`.
- Each step's output gets one journal `validation` event with `--meta step=<k>` and `--ref` pointing at the file.
