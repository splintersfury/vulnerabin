# Phase 4 — Deep Analysis

User-directed: the user picks 1-3 triage findings to chase. This phase produces `findings/<N>-<slug>.md` with full chain analysis and ACID verdict.

## Pre-flight (mandatory gate: kb_prime)

For each candidate finding, query KB by CWE and technique:
```bash
python3 scripts/kb_query.py --cwe <CWE-id> --format context
python3 scripts/kb_query.py --technique <technique> --format context
```
What worked before? What defenses were bypassed? What FP patterns to avoid?

## Per-finding workflow

1. Gather related code: the flagged unit + its callers + callees + relevant taxonomy.
2. If in Strategist mode: dispatch `inspect_function`/`inspect_file` workers for each related unit. Aggregate summaries.
3. Apply ACID via `prompts/workers/acid_check.md` — even when not in Strategist mode, the JSON output structure forces discipline.
4. Self-critique using `prompts/self_critique.md` — challenge your own reasoning.
5. Write `engagements/<eng>/findings/<N>-<slug>.md` with:
   - Title, CWE, severity guess
   - Source → intermediate → sink chain with file:line refs
   - ACID block (the JSON output of acid_check, embedded as a code block)
   - Confidence
   - Suggested next step
6. Journal:
   ```
   python3 scripts/journal.py append <eng> --phase deep --actor <model> --event finding \
       --ref findings/<N>-<slug>.md --summary "..." --meta cwe=<X> --meta acid=<verdict>
   ```

## Gate: acid_complete

The phase is incomplete until every finding written has a non-empty ACID block. `scripts/fsm.py validate <eng>` will refuse to advance past `deep` otherwise.

## Anti-patterns

- ❌ "Looks bad to me" without a chain. ACID with one bullet per axis is the floor.
- ❌ Skipping self-critique because it might downgrade your own finding. That's exactly when it's needed.
- ❌ Writing the finding with no `requested_followups` — almost every real finding needs one more worker dispatch to nail the chain.
