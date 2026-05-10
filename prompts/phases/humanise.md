# Phase: humanise — de-AI-style a writeup before vendor disclosure

A vendor PSIRT engineer who triages 50+ LLM-drafted reports per month can clock the AI tells in 30 seconds. That affects how seriously they take the next submission from the same researcher. Run this pass on every report draft (and on every finding markdown that will be quoted into a vendor portal) before pasting into Bugcrowd / HackerOne / MSRC / direct PSIRT.

Skeptic-review only audits truth and evidence alignment. It does NOT catch prose register. Humanise is a separate, deterministic-then-rewriting pass that runs adjacent to skeptic — typically right before it.

## What you are fixing

Run `scripts/humanise_audit.py <path>` first. It enumerates the issues with line numbers. Your job is to take the audit output and rewrite the prose so the next audit scores at most 3 (marginal). Anything below that is acceptable.

Categories the auditor flags, ordered by severity:

1. **Bold-punchline sentences.** Lines whose entire content is a `**bolded**` declaration ("**The fix is one canonicalization call. The vulnerability is real regardless of how hard the trigger is.**"). Drop them. Vendors don't need rhetorical flourish.
2. **Sentences with 3+ bold spans.** Same family as punchlines but stitched into one sentence. Rewrite as plain prose with at most one bold span per sentence, and only when the bold word is a literal symbol or filename.
3. **Em-dashes in prose** (— and the rare LLM en-dash –). Replace with regular dashes, commas, colons, semicolons, or a period to start a new sentence. Keep them only inside fenced code blocks reproducing real program output, where preserving the verbatim character is part of the evidence.
4. **Formulaic AI-tell phrases.** "supplementary context, not load-bearing evidence", "in the discoverer's testing", "leverage", "robust", "delve", "tapestry", "It is worth noting", "It's important to", "comprehensive", "multifaceted", "Furthermore", "Moreover", "In conclusion", "plethora", "myriad", etc. Replace with first-person prose ("I confirmed X by Y") or just drop. The auditor lists every hit with a per-phrase suggestion.
5. **Repetition tics.** Phrases that are fine once but become tells when repeated 4-5 times in one writeup. The auditor flags every occurrence so you can see the density and vary the phrasing.
6. **Triple-AND lists** ("static decompilation, runtime confirmation, and a self-contained mimicry harness"). Flatten or vary. AI-drafted writeups overuse this rhythm; vary by splitting into separate sentences, dropping the third item, or restructuring as bullets.

## Cardinal rules

1. **Never humanise inside fenced code blocks** (` ``` ... ``` `) that reproduce real program output, decompilation snippets, or PoC source. The verbatim characters are part of the evidence. Lying about what the program prints is worse than any AI tell. The auditor already strips fenced blocks before scanning, so it won't flag em-dashes inside them; you must respect the same boundary.
2. **Don't drop technical claims to score better.** The score is a heuristic for prose register, not for content. If a phrase the auditor flags is the right technical term, leave it (one-time use of "end-to-end" or "load-bearing" in an evidence-scope statement is fine).
3. **Preserve the section structure** (### headers, tables, ordered lists). Humanise targets the prose between them, not the skeleton.
4. **Preserve direct quotations and any text that is itself an evidence sample** (a copy-pasted error message, a vendor email excerpt, etc.).
5. **First-person voice is preferred** over third-person hedging. "I confirmed X by Y" beats "In the discoverer's testing, X was observed."
6. **Concrete beats abstract.** "The check returns TRUE for `c:\program files\bitdefender\..\..\..\windows\system32\cmd.exe`" beats "The check accepts a malicious payload that bypasses the trust boundary."

## Workflow

1. Read the audit output (`scripts/humanise_audit.py <path>`). Note the score and the flagged lines.
2. Read the writeup end-to-end to understand the technical narrative before rewriting.
3. Apply the rewrite, going section by section. Don't try to handle all six categories at once on one paragraph — start with bold-punchlines (delete or restructure), then em-dashes, then formulaic phrases, then repetition.
4. Re-run the auditor. Iterate until the score is ≤3.
5. Read the rewrite end-to-end again. Verify no technical claim was weakened or lost. Verify code blocks match the originals exactly.
6. If you changed any section's load-bearing claim during the rewrite, re-run `/skeptic-review` on the result. (If the rewrite is purely stylistic, the prior skeptic verdict still holds.)

## Output

Overwrite the input file with the humanised version. The auditor's pre-rewrite and post-rewrite scores should both be captured for the journal:

```bash
python3 scripts/journal.py append <eng> --phase report --actor <model> --event note \
    --summary "Humanised <path>: score N → M" --meta humanise_pre=N --meta humanise_post=M
```

## Edge cases

- **Title** (one line, often pasted into a portal's separate title field): can keep one em-dash if it reads cleanly as `subject — predicate`. Repeated em-dashes in a title is still a tell. Prefer colons for the subject/predicate split.
- **Code-fence-adjacent prose** (the sentence right before a code block, often "Running it:" or "Output:"): keep terse. AI-drafted reports often pad these with "The following demonstrates..." — drop the preamble.
- **Tables**: cell contents are prose and ARE audited. Triple-AND inside a "Why blocked" cell is fine (table rows are list-like by nature), but triple-AND inside the prose around a table is a hit.
- **Verbatim program output that legitimately contains an em-dash** (a Python script that prints `→` or `—`): leave it alone, that's evidence. The auditor strips fenced blocks so it won't flag them.

## What success looks like

The humanise pass on BDTS 005 v2-conservative (2026-05-09) dropped the body from 21,277 chars / ~50 em-dashes / 6+ formulaic tics to 14,008 chars / 0 prose em-dashes / 0 formulaic tics, while preserving every technical claim and passing skeptic-review at `ship` (high) on the next pass. That's the empirical baseline.
