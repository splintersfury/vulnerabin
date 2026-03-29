# VulneraBin

AI-powered binary and application vulnerability hunter. Automated source-to-sink analysis on decompiled binaries and Electron apps using LLMs, built for bug bounty hunters.

## What It Does

VulneraBin runs inside [Claude Code](https://claude.ai/code). You point it at a target, it acquires, extracts, and systematically triages every file/function — then helps you trace source-to-sink vulnerability chains and generate PoCs and bug bounty submissions.

```
/hunt mattermost-desktop

# Claude downloads the app, extracts the asar, triages all files,
# and presents ranked findings. You pick where to go deeper.

"go deeper on #1"
"build a PoC"
"write the Bugcrowd report"
```

## Methodology

Built on proven approaches from:
- **XBOW** — short-lived agents with fresh context, deterministic validation
- **Carlini** — systematic per-file enumeration, meta-triage
- **Anthropic** — self-critique, variant analysis
- **Kong** — rich context windows with cross-references and call graphs
- **Penligent** — ACID framework for validating attacker-controlled input

### ACID Framework

Every finding is validated against:
- **A**ttacker-Controlled — is the input genuinely from an attacker?
- **C**hain-Complete — does data flow source→sink without sanitization?
- **I**mpact — what's the concrete security consequence?
- **D**efenses — what mitigations must be bypassed?

## Supported Targets

| Target Type | Status | Method |
|------------|--------|--------|
| Electron apps | Ready | asar extraction → JS analysis |
| Native binaries (ELF/PE) | Sprint 3 | Ghidra decompile → Kong rename → analysis |
| Firmware images | Sprint 5 | binwalk extraction → multi-binary triage |

## Prerequisites

- [Claude Code](https://claude.ai/code) CLI
- Python 3.8+
- Node.js (for `npx asar extract`)
- Optional: Ghidra (for binary analysis, Sprint 3)
- Optional: Kong (for function renaming, Sprint 3)

## Usage

```bash
cd vulnerabin
claude

# Start a hunt
/hunt <target-name-or-url-or-path>

# Examples
/hunt mattermost-desktop
/hunt discord
/hunt https://example.com/app.deb
/hunt /path/to/local/binary
```

After triage, everything is conversational:
- "go deeper on #3"
- "build a PoC for finding 1"
- "write the HackerOne report"
- "do a quick scan instead"
- "variant analysis for CVE-2024-XXXXX"

## Project Structure

```
vulnerabin/
├── CLAUDE.md                    # Core methodology (Claude Code loads this)
├── .claude/commands/hunt.md     # /hunt slash command
├── scripts/
│   ├── acquire.py               # Download & extract targets
│   ├── detect.py                # Identify target type
│   └── extract_electron.py      # Electron app extraction & indexing
├── taxonomy/
│   ├── electron/                # Electron source/sink/sanitizer patterns
│   └── binary/                  # Binary source/sink patterns (Sprint 3)
├── prompts/
│   ├── triage_electron.md       # Per-file triage template
│   ├── acid_check.md            # ACID validation framework
│   └── self_critique.md         # Devil's advocate prompt
└── engagements/                 # Per-target workspaces
    └── <target>-<date>/
        ├── scope.md
        ├── triage.json
        ├── findings/
        ├── pocs/
        └── reports/
```

## License

MIT
