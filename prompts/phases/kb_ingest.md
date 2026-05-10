# Phase 6b — KB Ingest

Automatic post-report. Feeds confirmed findings back into the knowledge base so future engagements benefit.

## Run

```bash
python3 scripts/kb_ingest.py engagements/<eng>/
```

## Journal

```bash
python3 scripts/journal.py append <eng> --phase kb --actor script:kb_ingest.py \
    --event phase_end --ref taxonomy/kb/index.json --summary "Ingested <N> findings"
```

## When to skip

If the engagement produced no CONFIRMED findings, skip KB ingest. UNCERTAIN/FALSE_POSITIVE entries pollute the KB.
