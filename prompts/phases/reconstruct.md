# Reconstruct Phase — Strategist Prompt

**Status:** Foundation scaffold. Real strategist logic lands in the Pass 0 sub-plan.

## Purpose

The reconstruct phase turns raw Ghidra decompilation into idiomatic reconstructed source (named functions, typed params, consolidated structs, named globals, inline comments) before walk/triage/deep run. The result is binary-keyed under `catalog/reconstructed/<binary-stem>_<version-tag>/` so reconstruction compounds across engagements.

## Entry conditions

- LibGhidra API host responds to healthz (`libghidra_alive` gate)
- No other process holds the catalog dir lock (`no_concurrent_writer` gate)
- Prior `preparation` phase produced `engagements/<eng>/decomp/function_index.json` + `decomp/functions/`

## Exit conditions

- `coverage.json#hard_gate_pass == true` (100% of entrypoint-reachable user-defined functions named + typed)
- `coverage.json#soft_gate_pass == true` (≥80% of remaining user-defined functions named) — warning if below, does not block

## Pass sequence

1. **Pass 0** — deterministic (no LLM): IAT, Function ID, BSim, Rich-header library detection, string-xref heuristic naming, pcode-hash carryforward, constant equates
2. **Pass 1** — LLM rename (batched 20-per-worker by callgraph proximity, temp 0)
3. **Pass 2** — LLM retype (scalar param/local types; struct hypotheses collected)
4. **Pass 3a** — LLM struct consolidation
5. **Pass 3b** — LLM commenting
6. **Pass 3c** — deterministic global naming
7. **Pass 4** — cleanup of unprocessed functions + final gate check

## Implementation status

- **Foundation (sub-plan 1)** — pipeline.yml node, fsm.py gates, vendor pinning, libghidra_connect primitives, pcode_hash stub, vb-add reconstruction subcommand. **SHIPPED.**
- **Pass 0 (sub-plan 2)** — deterministic naming pass. Pending.
- **Passes 1-4 (sub-plan 3)** — LLM-driven reconstruction. Pending.
- **Catalog integration + Layer 8 (sub-plan 4)** — catalog_re_extract integration, reconstruction detail page renderer. Pending.
- **Acceptance (sub-plan 5)** — real-binary validation. Pending.

See `docs/superpowers/specs/2026-05-11-reconstruct-phase-design.md` for the full spec.
