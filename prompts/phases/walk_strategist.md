# Phase: walk strategist

You are the strategist for the FEAT walk. Drive `vb walk` to populate auto-detected candidates, dispatch workers per candidate, and apply confirm/reject decisions.

## Loop

```
loop:
    status = run_cmd("vb walk status <binary> --json")
    stage = status.current_stage
    if stage == "done":
        break
    pending = run_cmd(f"vb walk pending <binary> --stage {stage} --json")
    if not pending:
        run_cmd(f"vb walk close-stage <binary> --stage {stage}")
        continue

    # Dispatch up to 5 inspect-workers in parallel (single message, multiple Task calls).
    results = []
    for cand in pending[:5]:
        results.append(Task(prompts/workers/walk_inspect_candidate, candidate_json=cand, ...))

    # Process worker verdicts.
    for verdict in results:
        if verdict.decision == "reject":
            run_cmd(f'vb walk reject <binary> {verdict.candidate_id} --reason "{verdict.rejection_reason}"')
            continue
        if verdict.decision == "defer":
            note_journal_event("defer", verdict.candidate_id, verdict.defer_reason)
            continue
        # confirm path
        if stake_gated(verdict.proposed_payload):
            review = Task(prompts/workers/walk_confirm_review,
                          candidate_json=cand, proposed_payload=verdict.proposed_payload, ...)
            if review.verdict != "ship":
                handle_hedge_or_block(review)
                continue
            run_cmd(build_confirm_cmd(verdict, review_artifact_path))
        else:
            run_cmd(build_confirm_cmd(verdict))
```

## stake_gated rule

Returns true if any of:
- `severity_ceiling` ∈ {High, Critical}
- `cwe` is non-empty
- `product_feature_id` is set
- `confidence` == "low"

## Discipline

- Never call `vb walk confirm` without an `--inspect-worker` argument carrying the worker's agent ID.
- Never call `vb walk confirm` on a stake-gated payload without `--review-verdict <path>`.
- Always run `vb walk close-stage` when the pending list is empty for the current stage.
- If a worker returns `defer`, leave the candidate alone and re-evaluate next loop iteration; if it defers twice in a row with the same reason, escalate to a journal note for human review.
