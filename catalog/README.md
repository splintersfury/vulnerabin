# Vulnerabin binary catalog

A per-binary attack-surface catalog. One YAML file per logical binary, auto-rendered to a markdown page that documents every known **source → conditions → sink** chain. Versioned: when a new product release ships, re-seed and the renderer flags new sources / sinks / chains added since the last version.

## Why this exists

Engagement folders capture the work *for one product version at one moment*. They don't tell you "what's the full attack surface of `safeelevatedrun.dll` across the four times we've looked at it?" The catalog answers that:

- **Variant analysis on new releases**: vendor ships a new build, run the seeder again, see which sources/sinks/chains are new vs. previously catalogued.
- **Avoid redoing work**: before opening a new engagement on a product you've touched before, check `catalog/pages/<binary>.md` to see what attack surface is already mapped.
- **Triage prioritisation**: chains marked `unexplored` or `partial` are the obvious next targets when you re-engage.
- **Submission scaffolding**: a confirmed chain in the catalog cross-links to the finding markdown and the disclosure thread.

## Layout

```
catalog/
├── README.md                       this file
├── index.json                      auto-generated; lists all binaries with version + chain counts
├── schema.yml                      reference YAML structure (canonical schema)
├── binaries/
│   ├── safeelevatedrun_dll.yml     one YAML per binary (you edit)
│   ├── bdappsrv_exe.yml
│   └── ...
├── pages/
│   ├── safeelevatedrun_dll.md      auto-generated from .yml (you read)
│   ├── bdappsrv_exe.md
│   └── ...
└── _drafts/                        seeder output that hasn't been promoted yet
    └── ...
```

You edit `binaries/<name>.yml`. You read `pages/<name>.md`. The renderer keeps them in sync.

## Tooling

- `scripts/catalog_render.py` — read `binaries/<name>.yml`, write `pages/<name>.md` and update `index.json`. Run with no args to render all; pass a binary name to render one. Idempotent.
- `scripts/catalog_seed.py` — walk `engagements/`, extract source/sink/chain info from `findings/*.md` + `scope.json` + `chains.json` (when present), produce draft YAML files in `catalog/_drafts/`. You review each draft, then `mv` it to `catalog/binaries/`.
- `scripts/catalog_diff.py` — compare two versions of a binary's catalog entry (e.g., `safeelevatedrun.dll` v27 vs v28), show added/removed/changed sources, sinks, and chains.

## YAML schema (canonical reference: `catalog/schema.yml`)

Every `binaries/<name>.yml` looks like:

```yaml
binary: safeelevatedrun.dll                # canonical binary name
display_name: Bitdefender SafeElevatedRun  # human-readable title
description: >
  Bitdefender helper DLL used by bdappsrv to spawn elevated processes after
  a trust check on the requested executable path.
canonical_path: C:\Program Files\Bitdefender\Bitdefender Security App\safeelevatedrun.dll
arch: x64
platform: windows                         # windows | linux | macos | firmware | other
binary_kind: dll                          # exe | dll | sys (kernel driver) | so | other
trust_boundary: SYSTEM <- bdappsrv (admin) <- bdagent (user-context) <- standard user
                                          # one-line description of the privilege ladder
versions:
  - version: "27"
    sha256: ""                            # optional but recommended
    eng: bitdefender-total-security-2026-04-11
    seen: 2026-04-11
    notes: ""
  - version: "27.1.1.28"
    eng: bitdefender-2026-05-02
    seen: 2026-05-02

# Sources: where attacker input enters this binary. Each gets a stable ID
# referenced by chains[].source_id. Adding a new source bumps `first_seen_version`.
sources:
  - id: SRC-001
    name: msgbus.run_elevated_async.executable_path
    via: msgbus IPC pipe (local\msgbus\bdappsrv)
    type: wide_string
    attacker_controlled: yes               # yes | yes_with_caveat | no
    caveat: "Peer must be BD-Authenticode-signed and live in BD install path"
    function: FUN_18001c460                # decompiler-named or symbol if known
    first_seen_version: "27"
    last_confirmed_version: "27.1.1.28"
    notes: ""

# Sinks: where dangerous operations happen. Each gets a stable ID.
sinks:
  - id: SNK-001
    name: CreateProcessAsUserW(SYSTEM_token, exe_path)
    cwe: CWE-269
    function: bdappservice.dll FUN_18000c290
    impact: SYSTEM process spawn
    first_seen_version: "27"
    notes: ""

# Chains: the real catalog content. Each chain links one source to one sink
# via an ordered list of conditions that must hold for the chain to fire.
chains:
  - id: CHAIN-001
    title: "IsInFolder prefix check accepts .. traversal"
    source_id: SRC-001
    sink_id: SNK-001
    conditions:
      - "ExePath::IsInFolder(exe_path, install_folder) returns TRUE — the wcsncmp prefix check has no canonicalization, so `..` segments slip through"
      - "WinVerifyTrust(exe_path) succeeds — payload `cmd.exe` is Microsoft-Authenticode-signed"
    impact: SYSTEM process spawn
    cwe: [CWE-22, CWE-269]
    severity: P3
    cvss: "5.7 / AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
    status: confirmed                      # confirmed | partial | hypothesised | unexplored | mitigated
    confirmed_in_version: "27"
    finding_ref: bitdefender-total-security-2026-04-11/findings/005-safeelevatedrun-path-traversal.md
    submission_ref: bugcrowd:59aada4c-64d7-4215-851f-03ebde5d0629
    bypasses_required:
      - "Caller must be BD-Authenticode-signed (msgbus same_sign + trusted_client_process rules)"
      - "If injecting from non-BD process, defeat bdprivmon.sys VAD scan"
    notes: ""
```

## Status enum

- `confirmed` — chain demonstrably reachable end-to-end. Has a finding markdown and ideally an exec_result.
- `partial` — primitive or sub-chain proven; full chain not reproduced (e.g., trust check bypassable but call path needs a BD-signed peer).
- `hypothesised` — pattern-match candidate. No PoC yet. Useful for marking surface that smells wrong but hasn't been deep-dived.
- `unexplored` — known source-to-sink edge that hasn't been investigated. Use these to prioritise the next pass.
- `mitigated` — vendor patched or upstream defense closed the chain. Keep it for historical reference and to flag potential patch-bypass research.

## Workflow

### First time cataloguing a binary

```bash
# Auto-seed from existing engagement data (writes to catalog/_drafts/)
python3 scripts/catalog_seed.py --binary safeelevatedrun.dll

# Review the draft YAML, edit it, then promote
mv catalog/_drafts/safeelevatedrun_dll.yml catalog/binaries/

# Render
python3 scripts/catalog_render.py safeelevatedrun_dll
```

### After a new product version drops

```bash
# Drop the new binary into a fresh engagement folder, run preparation/triage as usual
# Then re-seed; new sources/sinks get tagged with the new version
python3 scripts/catalog_seed.py --binary safeelevatedrun.dll --eng bitdefender-2026-05-02

# Diff against the previous version
python3 scripts/catalog_diff.py safeelevatedrun.dll --from "27" --to "27.1.1.28"

# Re-render
python3 scripts/catalog_render.py safeelevatedrun_dll
```

### Rendering everything

```bash
python3 scripts/catalog_render.py            # render every binary
```

The renderer also updates `catalog/index.json` and `catalog/pages/index.md` with a global view of all catalogued binaries.
