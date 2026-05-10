# Phase 5c — Execution Validation (sandboxed)

The IronCurtain article's load-bearing claim: static analysis without execution produces high false-positive volume. This phase forces an exec attempt or an explicit waiver before a finding can move to `report`.

## Mandatory gate: sandbox_declared

The finding's target type must map to a sandbox in `sandboxes.yml`:
- `linux_userland_binary`, `electron_node_module`, `fuzz_harness` → `linux_usermode`
- `firmware_cgi`, `firmware_daemon` → `qemu_user`
- `windows_userland`, `kernel_driver`, `ioctl_handler` → `driver_target_vm`

Anything not declared requires explicit user authorization (per RoE #2).

## Workflow

1. **Generate harness variants** from the PoC trail (steps 4-7 of validation):
   ```bash
   python3 scripts/harness_gen.py <eng> <finding-N>
   ```
   Produces `engagements/<eng>/exec/<N>/harness.{c,py}` plus variants at different memory pressure / heap state — per the article's media-framework lesson, single-shot harnesses miss bugs that need specific allocator state.

2. **Run** in the declared sandbox:
   ```bash
   python3 scripts/exec_validate.py <eng> <finding-N> --sandbox linux_usermode
   ```
   Captures stdout/stderr, sanitizer output, return code. Writes `exec/<N>/result.json`.

3. **Feed back** to ACID: re-run `prompts/workers/acid_check.md` with `exec_result` in the input. The verdict may upgrade (LIKELY → CONFIRMED) or downgrade (CONFIRMED → UNCERTAIN if no_repro).

4. **Journal**:
   ```bash
   python3 scripts/journal.py append <eng> --phase exec --actor script:exec_validate.py \
       --event exec_result --ref exec/<N>/result.json --summary "..." --meta verdict=triggered
   ```

## Gate: evidence_recorded

`exec/<N>/result.json` must contain `verdict` (triggered|crashed|no_repro|inconclusive) and `evidence_hash` (sha256 of the captured artifact). FSM blocks `report` otherwise.

## Waiver

Some findings can't be executed (auth required, hardware unavailable, etc.). To skip:
```bash
python3 scripts/journal.py append <eng> --phase exec --actor human \
    --event note --summary "WAIVER: <reason>" --meta finding=<N> --meta waived=true
```
The report-phase gate will accept the waiver. **Don't abuse this** — every waiver is a future FP risk.
