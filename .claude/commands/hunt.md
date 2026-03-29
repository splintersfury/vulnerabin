# /hunt — Start a Vulnerability Hunting Engagement

You are starting a new vulnerability hunting engagement. Follow these steps precisely.

## Input: $ARGUMENTS

The user has provided a target: "$ARGUMENTS". This could be:
- An app name (e.g., "Telegram Desktop", "mattermost-desktop", "Discord")
- A URL to download
- A local file/directory path
- A bug bounty scope description

## Step 1: Create Engagement

Create the engagement folder with today's date:
```bash
mkdir -p engagements/<target-slug>-$(date +%Y-%m-%d)/{target,extracted,findings,pocs,reports}
```

If the user provided a bug bounty RoE or scope, save it to `engagements/<folder>/scope.md`.

## Step 2: Acquire Target

If the target is a known app name or URL:
```bash
python3 scripts/acquire.py --target "<target>" --output-dir engagements/<folder>/
```

If the target is a local path, note it and proceed to detection.

Read the acquire.py output to get the extracted path.

## Step 3: Detect Target Type

```bash
python3 scripts/detect.py <extracted-path>
```

Read the output. Branch based on type:
- **electron**: Continue to Step 4a
- **native_binary**: Tell user "Binary support coming in Sprint 3. For now, provide decompiled output in the engagement folder and I'll triage it directly."
- **firmware**: Tell user "Firmware support coming in Sprint 5."
- **unknown**: Ask user for more context about the target.

## Step 4a: Extract Electron App

```bash
python3 scripts/extract_electron.py <path> --output-dir engagements/<folder>/extracted/
```

Read the JSON output. Note:
- Total JS files found
- BrowserWindow configurations
- Preload scripts
- IPC handlers
- Dangerous API usage
- Security misconfigurations

Save the index to `engagements/<folder>/electron_index.json`.

## Step 5: Triage

Load the taxonomy files:
- Read `taxonomy/electron/sources.json`
- Read `taxonomy/electron/sinks.json`
- Read `taxonomy/electron/sanitizers.json`
- Read `taxonomy/electron/misconfigs.json`

Now systematically triage. Start with the highest-signal files:
1. **Preload scripts** — these bridge renderer to main process
2. **Main process entry** — IPC handlers, protocol handlers, BrowserWindow configs
3. **Files with dangerous APIs** (from the index)
4. **Renderer files** that handle user input

For each file:
1. Read the file
2. Check against source patterns from the taxonomy
3. Check against sink patterns
4. Check for misconfigurations
5. Rate exploitability 1-5
6. Label: SOURCE / SINK / PASSTHROUGH / SANITIZER / IRRELEVANT

After triaging all high-signal files, present results as a ranked table:

```
# Triage Results — <app_name> v<version>

**Target type**: Electron
**Files analyzed**: X / Y total
**Misconfigurations found**: [list any]

| # | File | Rating | Label | Key Finding |
|---|------|--------|-------|-------------|
| 1 | ... | 5/5 | SINK | ... |
| 2 | ... | 4/5 | SOURCE | ... |

## Initial Assessment
[Brief summary of the attack surface — what looks promising, what security measures are in place]

Which findings should I investigate deeper? Or say "quick scan" for a fast monolithic pass.
```

## After Triage

The engagement is now interactive. Wait for the user to direct you:

- **"Go deeper on #N"** → Bundle the file + its imports/callers into a chain window. Trace source→sink. Apply ACID framework (read `prompts/acid_check.md`). Apply self-critique (read `prompts/self_critique.md`). Save finding to `engagements/<folder>/findings/`.

- **"Build a PoC"** → Construct a concrete attack payload. Save to `engagements/<folder>/pocs/`. NEVER execute against live targets without explicit permission.

- **"Write the report"** or **"Format for Bugcrowd/HackerOne/ZDI"** → Generate structured submission with CVSS, steps to reproduce, evidence chain, PoC. Save to `engagements/<folder>/reports/`.

- **"Quick scan"** → Skip systematic triage. Load the most critical files (main + preload + IPC handlers) and analyze everything in one pass.

- **"Variant analysis for CVE-XXXX-YYYY"** → Search for the same vulnerability pattern across the codebase. Check git history if available.

- **"What else should we look at?"** → Suggest next areas based on what hasn't been triaged yet.
