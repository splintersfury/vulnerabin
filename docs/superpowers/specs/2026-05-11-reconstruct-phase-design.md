# `reconstruct` Phase Design — Source-Quality RE in the VulneraBin Pipeline

**Status:** Approved (pending implementation plan)
**Date:** 2026-05-11
**Author:** Ahmad Abdillah + Claude (Opus 4.7)
**Driving motivation:** Source→sink pattern matching on raw Ghidra decompilation (`FUN_140012a0(undefined4 *param_1)`) is materially less reliable than matching on idiomatic reconstructed source (`HandleIoctl_QueryRange(IPC_REQUEST_HEADER *req)`). The reconstruct phase fills that gap, treating each catalog binary as a one-time investment whose reconstruction compounds across engagements.

---

## 1. Architecture

### 1.1 Pipeline placement

New phase `reconstruct` inserted between `preparation` and `walk`:

```
acquisition → preparation → reconstruct → walk → triage → deep → validation → exec → skeptic_review → report → kb_ingest
                              ↑ NEW
```

`pipeline.yml` declares:

```yaml
phases:
  reconstruct:
    description: "Reconstruct binary as idiomatic source via deterministic + LLM passes"
    entry_artifacts:
      - "engagements/{eng}/decomp/function_index.json"
      - "engagements/{eng}/decomp/functions/"
    exit_artifacts:
      - "catalog/reconstructed/{stem}_{version_tag}/manifest.json"
      - "catalog/reconstructed/{stem}_{version_tag}/coverage.json"
      - "catalog/binaries/{stem}.yml#reconstruction.ref"
    gates:
      pre:
        - libghidra_alive
        - prior_decomp_present
        - no_concurrent_writer
      post:
        - reachable_named_100pct
        - tail_named_80pct
    transitions:
      from: [preparation]
      to: [walk]
    opt_out_flag: "--no-reconstruct"
```

### 1.2 Tool stack

- **LibGhidra** — Java extension installed in Ghidra, exposes a Protobuf API host (Elias Bachaalany's tool, see `vendor/libghidra.version` for pinned commit). Auto-spawns headless Ghidra when no GUI is attached.
- **GhidraSQL** — skill set loaded into the agent workspace at `.claude/skills/ghidrasql/`, commit-pinned in `vendor/ghidrasql_skills.version`. Skills teach the agent how to drive LibGhidra's Protobuf API for queries, renames, retypes, comments, decompile-on-demand.
- **GhidraMCP** — already installed at port 8089. **Forbidden** during reconstruct phase (lock collision). Stays available for interactive deep-dives on `>=3/5` findings *after* the phase exits.

Run mode: **always headless**. Reconstruct phase never opens a GUI window. The LibGhidra Java extension auto-spawns Ghidra in the background when the phase orchestrator calls into it.

### 1.3 Scope

Reconstruct every **user-defined function**, where the predicate is exactly:

```
is_external == false AND is_thunk == false
```

(both fields already present in `function_index.json` from `decomp.py`'s headless export). External imports, thunks, and CRT functions matched by FID are out of scope for LLM passes but DO count in the named-function totals.

### 1.4 Reachability root (per binary kind)

The hard gate keys on functions transitively reachable from a binary-kind-specific entrypoint set:

| Binary kind | Reachability roots |
|---|---|
| Windows kernel driver (`.sys`) | `DriverEntry` + every `IRP_MJ_*` dispatch arm registered in `DriverObject->MajorFunction[]` + every IOCTL handler reached from `IRP_MJ_DEVICE_CONTROL` dispatch table |
| Windows exe (`.exe`) | PE entrypoint + every export + every thread function passed to `CreateThread`/`RtlCreateUserThread` if statically identifiable + IPC server entrypoints (named-pipe / ALPC / RPC stub registration) |
| Windows dll (`.dll`) | `DllMain` + every export + every callback registered with `LdrRegister*` or `RegisterCallback*` family APIs if statically identifiable |
| Linux ELF executable | `main` + every entry exported in `.dynsym` + every constructor in `.init_array` |
| Linux ELF shared object | Every exported symbol + every constructor in `.init_array` |

The phase orchestrator computes the reachable set as the transitive closure over `callees[]` from the root set, restricted to user-defined functions.

### 1.5 Counted-as-named predicate

A function is "named" for gate purposes iff **all** of:

1. Its name does not match `^(FUN_|sub_)[0-9a-f]+$`
2. Its name was either:
   - Assigned by Pass 0 with confidence `medium` or `high` (FID matches always count as high; IAT-wrapper detection counts as medium; string-xref heuristics count as low and DO NOT pass), OR
   - Assigned/confirmed by any LLM pass (Pass 1, 2, 3)

"Counted-as-named" is recorded as a boolean `named_for_gate` in the per-function record inside `coverage.json`, so the gate is a simple count, not a regex re-derivation.

### 1.6 Coverage gates

- **Hard gate `reachable_named_100pct`**: 100% of functions in the reachability root closure satisfy `named_for_gate == true` AND have non-`undefined*` parameter types. Failure blocks the phase transition. Strategist writes `reconstruct_review.md` listing the unnamed reachable functions for human triage.
- **Soft gate `tail_named_80pct`**: ≥80% of user-defined functions OUTSIDE the reachability closure satisfy `named_for_gate == true`. Failure logs warning, sets `coverage.json#soft_gate_pass: false`, but does NOT block; downstream walk/triage workers see the warning.

---

## 2. Storage

### 2.1 Catalog layout

```
catalog/reconstructed/<binary-stem>_<version-tag>/
├── manifest.json
├── ghidra.gpr                      ← canonical Ghidra project (mutable)
├── ghidra.rep/                     ← Ghidra project repo dir
├── snapshots/
│   ├── pass0_post.gpr.zst          ← pre-LLM baseline (kept on success)
│   ├── pass1_post.gpr.zst          ← (dropped on success)
│   ├── pass2_post.gpr.zst          ← (dropped on success)
│   └── pass3_post.gpr.zst          ← final (kept on success)
├── functions/                      ← re-emitted at pass boundaries; .c is DERIVED
│   ├── DriverEntry.c
│   ├── HandleIoctl_QueryRange.c
│   ├── FUN_140012a0.c              ← surviving FUN_*, logged in coverage
│   └── ...
├── headers/
│   ├── types.h
│   ├── globals.h
│   ├── ioctls.h
│   └── strings.h
├── coverage.json
├── carryforward.json               ← present only if prior version reconstructed
├── cost_report.json
├── pass_log.jsonl                  ← append-only events
├── notes/                          ← per-subsystem markdown memory files (Elias pattern)
│   ├── network.md
│   ├── ipc.md
│   ├── io.md
│   └── ...
└── .lock                           ← flock target for single-writer discipline
```

### 2.2 Version-tag conventions

- `<binary-stem>` matches existing `catalog/binaries/<stem>.yml` stem (single source of truth).
- `<version-tag>` is `v<dotted-version>` with dots replaced by underscores, prefixed `v`. Examples: `v27_1_1_28`, `vdec2025` (date-tagged dumps), `vlatest` (HEAD-of-vendor-channel placeholders).
- Stem aliases (vendor renames) declared in `catalog/binaries/<stem>.yml#aliases: [...]`. Carryforward matching consults aliases.

### 2.3 Single source of truth

The engagement does **not** carry a `reconstructed_ref` field. Resolution path:

1. `engagements/<eng>/scope.json#binary` → `<stem>`
2. `catalog/binaries/<stem>.yml#reconstruction.ref` → `catalog/reconstructed/<stem>_<tag>/`

The binary YAML is canonical. The engagement just knows which binary it's working on.

### 2.4 Atomicity

`catalog/binaries/<stem>.yml#reconstruction.ref` is written **only after** `manifest.json` finalizes. Partial reconstructions never appear as ready in the catalog.

### 2.5 Snapshot retention

- On phase success: keep `pass0_post.gpr.zst` (pre-LLM rollback point) and `pass3_post.gpr.zst` (final). Delete `pass1` and `pass2` snapshots.
- On phase failure: keep all snapshots until next successful run, then evict per the success rule.
- All snapshots compressed with `zstd -19`.
- The orchestrator emits a warning to stderr if total snapshot footprint across `catalog/reconstructed/*/snapshots/` exceeds 50 GB.

---

## 3. Manifest, coverage, carryforward schemas

### 3.1 `manifest.json`

```json
{
  "binary": {
    "stem": "bdservicehost",
    "version": "27.1.1.28",
    "version_tag": "v27_1_1_28",
    "source_engagement": "bitdefender-total-security-2026-04-11",
    "file_sha256": "...",
    "text_section_sha256": "...",
    "pcode_hash_aggregate": "...",
    "size_bytes": 4193280,
    "arch": "x86_64",
    "subsystem": "console",
    "platform": "windows",
    "binary_kind": "exe"
  },
  "tooling": {
    "ghidra_version": "11.3.1",
    "libghidra_commit": "<pinned SHA>",
    "ghidrasql_skills_commit": "<pinned SHA>",
    "reconstruct_phase_version": "1.0.0",
    "fid_db_versions": {
      "msvc_crt_19": "...",
      "winapi_thunks": "..."
    }
  },
  "project_discovery": {
    "entrypoints": ["main", "Ordinal_1", "..."],
    "segments": [...],
    "modules": [...],
    "exports": [...],
    "rich_header_compilers": ["MSVC 19.34"]
  },
  "passes": [
    {
      "pass": "pass0",
      "started_at": "2026-05-11T14:23:00Z",
      "ended_at": "2026-05-11T14:25:00Z",
      "tools_used": ["FunctionID", "BSim", "IAT", "string_xref", "rich_header", "pcode_hash_carryforward"],
      "renames_applied": 1483,
      "types_applied": 902,
      "tokens_spent": 0,
      "snapshot": "snapshots/pass0_post.gpr.zst"
    },
    {"pass": "pass1_rename", "model": "claude-opus-4-7", "renames_applied": 5847, "tokens_spent": 1834201, "snapshot": "..."},
    {"pass": "pass2_retype", "...": "..."},
    {"pass": "pass3a_structify", "...": "..."},
    {"pass": "pass3b_comment", "...": "..."},
    {"pass": "pass3c_global_naming", "...": "..."},
    {"pass": "pass4_cleanup", "...": "..."}
  ],
  "coverage_final": {
    "total_user_defined_functions": 7124,
    "reachability_root_count": 47,
    "reachable_set_size": 1289,
    "reachable_named": 1289,
    "reachable_typed": 1289,
    "reachable_hard_gate_pass": true,
    "tail_function_count": 5835,
    "tail_named": 4920,
    "tail_named_pct": 0.843,
    "tail_soft_gate_pass": true
  }
}
```

### 3.2 `coverage.json`

```json
{
  "hard_gate_pass": true,
  "soft_gate_pass": true,
  "totals": {
    "user_defined_functions": 7124,
    "external_imports_skipped": 1234,
    "thunks_skipped": 542
  },
  "reachable": {
    "root_set": ["main", "Ordinal_1", "..."],
    "function_count": 1289,
    "named": 1289,
    "typed": 1289,
    "struct_recovered": 1101,
    "addresses": ["0x140001000", "..."]
  },
  "tail": {
    "function_count": 5835,
    "named": 4920,
    "typed": 4205,
    "struct_recovered": 2987
  },
  "unnamed_function_addresses": [],
  "low_confidence_named_addresses": ["0x140098e0", "..."]
}
```

### 3.3 `carryforward.json`

```json
{
  "prior_version": "bdservicehost_v27_1_1_19",
  "matches_by_pcode_hash": [
    {"addr": "0x140012a0", "name": "ProcessIPCRequest", "from_prior": true, "confidence": "exact"}
  ],
  "matches_by_bsim": [
    {"addr": "0x140034b0", "name": "validate_caller_token", "from_prior": true, "confidence": "0.92"}
  ],
  "no_match": ["0x140098e0", "..."],
  "stats": {"exact": 4823, "fuzzy": 691, "no_match": 1610},
  "port_rate": 0.773,
  "compiler_flag_drift_warning": false
}
```

A `compiler_flag_drift_warning: true` is set when `port_rate < 0.30`. This is a soft signal, not a gate.

---

## 4. Passes

### 4.1 Pass 0 — deterministic (no LLM)

Sequence, each step a LibGhidra/GhidraSQL call:

1. **Project discovery** (one-time init). Agent reads LibGhidra Protobuf schemas + enumerates binary structure (entrypoints, segments, modules, exports, Rich header). Output cached in `manifest.json#project_discovery`.
2. **IAT enumeration**. Mark single-call forwarders to IAT entries as `<api>_wrapper` (confidence: medium).
3. **Function ID match**. Invoke Ghidra's FID against bundled `fid_db/*.fidb` (msvc_crt_19, winapi_thunks, common OSS lib builds). Matched functions renamed (confidence: high).
4. **BSim fuzzy match**. On surviving `FUN_*`. Threshold 0.85. Annotated in Ghidra comment as `inherited_from_bsim` (confidence: medium).
5. **Rich header parse**. Identify compiler+linker version → choose appropriate fid_db variants; also reveals MFC/ATL/MSVCP presence and the orchestrator skips those subtrees for LLM passes.
6. **String-xref naming**. Heuristic rename for FUN_* with discriminating string xrefs (e.g., `"Failed to open %s"` → `try_open_file_xxx`). Confidence: **low**. These names do NOT count toward gates; they exist so Pass 1 has weak prior signal.
7. **Pcode-hash carryforward**. If prior reconstruction exists, match by pcode_hash → port renames+types+comments; log to `carryforward.json` and set `inherited_from: <prior version_tag>` Ghidra comment. BSim fuzzy match runs as secondary.
8. **Constant equate naming**. Detect IOCTL codes (constants matching `CTL_CODE(DeviceType, Function, Method, Access)`), NTSTATUS, HRESULT, registry hive constants. Apply via ghidrasql `set_equate`. Populate `headers/ioctls.h`.

Pass 0 snapshot: `snapshots/pass0_post.gpr.zst`. Re-emit all touched `.c` files. Write/update `coverage.json`.

Expected yield: 15-25% of original `FUN_*` converted to named functions.

### 4.2 Pass 1 — LLM rename

- Strategist queries via GhidraSQL for all remaining `FUN_*` user-defined functions.
- Groups into batches of **20 functions** by 2-hop callgraph proximity (callees + callers + sibling callees of common parents share batches when possible; hub functions with high fan-out get their own batch). String-xref low-confidence Pass 0 names are passed to the worker as **hints**, not commitments.
- Each worker (Opus 4.7, **temperature 0**) receives: 20 function decompilations + caller/callee name lists (no bodies) + xref'd strings + Pass 0 hints if any. Token budget per call ~30k.
- Worker returns:
  ```json
  [
    {"addr": "0x140012a0", "name": "ProcessConfigRequest", "confidence": "high",
     "rationale": "writes to %ProgramData%\\bd\\config + RtlInitUnicodeString from param_1"},
    ...
  ]
  ```
- Strategist applies via GhidraSQL. Pass 0 high/medium-confidence names are LOCKED (not overridden). Pass 0 low-confidence names CAN be overridden by Pass 1.

After all batches complete, re-emit affected `.c` files in one sweep, snapshot `pass1_post.gpr.zst`, update coverage.

### 4.3 Pass 2 — LLM retype

Same dispatch pattern (batched 20). Worker reads post-rename source and returns:

- Parameter retypes: `param_1 (LPVOID) → IPC_REQUEST_HEADER *req`
- Local var retypes: `local_18 (DWORD) → NTSTATUS status`
- **Struct hypotheses** (offset map + suggested types per offset) — these are NOT written to Ghidra yet; they're collected for Pass 3a consolidation.

Strategist applies scalar retypes immediately via GhidraSQL. Struct hypotheses written to an internal `pass2_struct_hypotheses.json` (transient, not in final artifacts).

Pass 2 snapshot, re-emit, update coverage.

### 4.4 Pass 3a — struct consolidation

- Cluster struct hypotheses from Pass 2 by access-pattern signature (offset set + type-per-offset compatibility).
- For each cluster with ≥3 supporting functions, dispatch one consolidator worker that reads all candidate functions and proposes a single struct definition with member names.
- Strategist applies the consolidated typedef across all sites via GhidraSQL. Writes to `headers/types.h`.

### 4.5 Pass 3b — LLM commenting

- One worker per non-trivial function (≥20 instructions AND has decision branches).
- Worker returns decompiler comments on non-obvious blocks. No body rewrite, no rename, no retype.
- Strategist applies comments via GhidraSQL.

### 4.6 Pass 3c — deterministic global naming

- Walk `DAT_*` references.
- A `DAT_*` written-once in `DllMain`/init and read in N functions → `g_<inferred_type>_<inferred_purpose>` (e.g., `g_service_handle`, `g_device_object`).
- Apply via GhidraSQL. Populate `headers/globals.h`.

### 4.7 Pass 4 — cleanup + final gate

- Identifies any functions left unprocessed by Pass 1-3 (malformed JSON, timeouts, batches that failed twice).
- Retries with batch size 10, single retry only.
- After Pass 4, run final coverage check.
- If hard gate fails: strategist writes `reconstruct_review.md` listing unnamed reachable functions with reasons (e.g., "Pass 1 returned malformed JSON 2x", "function is 4000+ instructions, exceeded worker context"). Phase exits with non-zero status. **Pass 4 IS the hard-gate failure handler** — there is no separate failure flow.
- If hard gate passes: write final manifest, set `catalog/binaries/<stem>.yml#reconstruction.ref`, snapshot `pass3_post.gpr.zst` (and prune intermediate snapshots per §2.5).

### 4.8 Re-emit discipline

`.c` files are **derived** artifacts. Re-emit occurs only at pass boundaries (and during initial Pass 0 if functions were renamed via carryforward). Workers within a pass read live decompilation via GhidraSQL, not `.c` files.

### 4.9 Cost report

After every pass, `cost_report.json` updated with cumulative tokens + USD estimate. Strategist surfaces a warning before each LLM pass if cumulative cost has exceeded `VULNERABIN_RECONSTRUCT_WARN_USD` (default 50). Hard cap only if `VULNERABIN_RECONSTRUCT_MAX_USD` is set.

### 4.10 LLM determinism

- Temperature 0 across all LLM passes.
- System prompts pinned per pass (committed under `prompts/workers/reconstruct_*.md`).
- Name-conflict precedence: Pass 0 (FID, IAT) high/medium > Pass 1+ on FUN_* only. Conflicts logged to `pass_log.jsonl`.

---

## 5. Components

### 5.1 New scripts

| File | Purpose |
|---|---|
| `scripts/reconstruct.py` | Phase orchestrator. Reads `scope.json`, computes reachability roots, runs Pass 0→4, writes coverage/manifest, sets `catalog/binaries/<stem>.yml#reconstruction.ref`, exits with FSM gate state |
| `scripts/reconstruct_pass0.py` | Deterministic pass implementation |
| `scripts/reconstruct_emit.py` | Re-decompile via LibGhidra/GhidraSQL → write `functions/*.c` + `headers/*.h` |
| `scripts/reconstruct_coverage.py` | Walk Ghidra project state, compute per-tier stats, write coverage.json |
| `scripts/reconstruct_carryforward.py` | Given prior reconstruction dir, port renames+types+comments via pcode_hash + BSim |
| `scripts/libghidra_connect.py` | Wraps LibGhidra `/connect` mechanism for non-interactive use; healthz, headless auto-spawn, lock-acquire-or-fail |
| `scripts/pcode_hash.py` | Library: structural hash of normalized PCode per function |
| `scripts/catalog_reconstruct_render.py` | Render Layer 8 reconstruction detail page |

### 5.2 Modified scripts

| File | Change |
|---|---|
| `pipeline.yml` | Insert `reconstruct` phase node, gates, transitions, per-binary-kind reachability roots |
| `scripts/fsm.py` | Add `reconstruct` to phase enum, gate validators (`libghidra_alive`, `no_concurrent_writer`, `reachable_named_100pct`, `tail_named_80pct`) |
| `scripts/journal.py` | Add `reconstruct` to allowed phases |
| `scripts/catalog_re_extract.py` | New optional flag `--reconstructed-dir <path>`; when present, prefers reading `functions/*.c` + `headers/types.h` over raw decomp. Auto-invoked at phase end. Output schema unchanged. |
| `prompts/workers/inspect_function.md` | Source-path resolver: prefer `<reconstruction.ref>/functions/<name>.c` over `decomp/functions/FUN_*.c` |
| `prompts/workers/inspect_function_mcp.md` | Same resolver; MCP deep-dive on reconstructed binary uses `<reconstruction.ref>/ghidra.gpr` |
| `prompts/strategist.md` | Add `reconstruct` phase awareness, journal event types |

### 5.3 New prompts

| File | Purpose |
|---|---|
| `prompts/phases/reconstruct.md` | Strategist-mode prompt for the phase |
| `prompts/workers/reconstruct_rename.md` | One batch (≤20 funcs) → JSON rename array |
| `prompts/workers/reconstruct_retype.md` | One batch → scalar retypes + struct hypotheses |
| `prompts/workers/reconstruct_structify.md` | One struct cluster → consolidated typedef |
| `prompts/workers/reconstruct_comment.md` | One function → decompiler comments |

### 5.4 Vendor + skills

```
vendor/
├── libghidra.version           # URL + commit SHA + sha256 checksum
├── ghidrasql_skills.version    # URL + commit SHA + sha256 checksum
├── fid_db_versions.json        # per-FID-DB version pins
└── bootstrap.sh                # downloads/builds/installs the above

fid_db/
├── msvc_crt_19.fidb
├── winapi_thunks.fidb
└── README.md                   # how to generate/update FID dbs

.claude/skills/ghidrasql/       # repo-local skill files, copied by bootstrap.sh
└── ...
```

The reconstruct phase fails its pre-gate if `vendor/bootstrap.sh` has not been run.

### 5.5 vb-add additions

Single new subcommand:

```bash
vb-add reconstruction --binary <stem> --version <tag>
```

Creates the catalog dir scaffold (`catalog/reconstructed/<stem>_<tag>/` with empty `manifest.json` + `.lock`) and writes a `reconstruction:` block with `status: not_started` to `catalog/binaries/<stem>.yml`. It **does not** flip `status` to `complete`, `partial`, or `in_progress` — only the reconstruct phase orchestrator transitions those, and only after the corresponding pass state is reached and `manifest.json` is finalized. If invoked when the catalog dir already exists, it's a no-op.

(Excluded for YAGNI: `vb-add note --subsystem`, `vb-add reconstruction --status complete`.)

---

## 6. Visualization integration

### 6.1 Binary YAML extension

```yaml
# catalog/binaries/<stem>.yml
reconstruction:
  ref: catalog/reconstructed/bdservicehost_v27_1_1_28
  version_tag: v27_1_1_28
  status: complete            # complete | partial | in_progress | not_started | opt_out
  coverage:
    reachable_named_pct: 100
    tail_named_pct: 84
    hard_gate_pass: true
    soft_gate_pass: true
  last_reconstructed: 2026-05-11T15:23:00Z
  notes_subsystems: [network, ipc, registry]

aliases: []                   # vendor renames, e.g. ["BDProductAgentService"]
```

### 6.2 Layer impact

- **Layer 1 (attack-surface map)**: node labels become semantic (real function names) — no mermaid template changes.
- **Layer 3 (defense matrix)**: "Observed in binary" column populated more reliably from named+typed source.
- **Layer 5 (class coverage matrix)**: new "Reconstruction state" column. A class flagged `unchecked` whose carrier functions aren't reconstructed gets an "audit blocker" badge linking to Layer 8.
- **Layer 6 (attack flow)**: chain visualizations show real names; pipeline progress bar gets a 🔨 reconstructed precondition badge.
- **Layer 8 (NEW — reconstruction detail page)**: per binary, rendered at `catalog/pages/reconstructed/<stem>_<tag>.md` + HTML. **Layer 8 is the canonical surface**; Layer 5 column and binary-page banner are summary links into it.

### 6.3 Layer 8 contents

- Coverage heatmap: function × pass × state (Pass 0 green / Pass 1 LLM blue / Pass 2 typed yellow / Pass 3 struct-recovered purple / untouched gray).
- Unnamed-function list (FUN_* survivors): address, instruction count, xref counts, reason for non-reconstruction.
- Subsystem notes (`notes/*.md`) rendered inline.
- Carryforward summary if `carryforward.json` present: exact / fuzzy / no-match stats; drift warning if any.
- Pass log timeline: durations, token spend, rename/retype counts per pass.

(Excluded for YAGNI: cross-binary BSim similarity links.)

### 6.4 catalog_serve.py + catalog_site_render.py

- New route `GET /reconstructed/<stem>_<tag>` → Layer 8 page (live server) / static HTML (site renderer).
- Binary page (`/binary/<stem>` and `catalog/site/binaries/<stem>.html`) gets a **reconstruction status banner**:
  - 🟢 `status: complete` → "Reconstructed v27.1.1.28 — 100% reachable named, 84% tail" → links to Layer 8
  - 🟡 `status: partial` → "Partial reconstruction — 92% reachable named, soft gate failed" → links to Layer 8
  - 🟠 `status: in_progress` → "Reconstruction in progress (started <T>)" → links to live Layer 8 with pass log streaming
  - 🔴 `status: not_started` → "Not yet reconstructed — class coverage audit will be unreliable" → links to docs on running reconstruct
  - ⚪ `status: opt_out` → "Reconstruction skipped (`--no-reconstruct` opt-out for engagement <slug>)" → no link

### 6.5 vb status integration

- Engagement with no reconstruction for its binary AND no `--no-reconstruct` opt-out → suggested next action: `→ run reconstruct phase`.
- Engagement consuming a stale reconstruction (binary version changed since reconstruct) → suggested next action: `→ re-reconstruct (new version detected)`.
- `vb --eng <slug>` detail view shows linked `reconstruction.ref` + coverage state pulled from binary YAML.

---

## 7. Concurrency and locking

### 7.1 Single-writer `.gpr` discipline

- `.lock` file in catalog reconstruct dir, acquired via `flock(2)` exclusive.
- Reconstruct phase orchestrator acquires the lock at phase entry (pre-gate `no_concurrent_writer`).
- If another writer holds the lock (e.g., MCP attached, or another reconstruct invocation), phase **refuses to start** with a clear error message: "Lock held by PID <X> since <T>. If this is stale, remove `<path>/.lock`. If MCP is attached to this Ghidra project, close it before re-running reconstruct."
- Phase does **not** evict an existing GUI/MCP session.

### 7.2 MCP × LibGhidra coexistence

- During reconstruct phase: MCP attempts to write to the same `.gpr` are detected via the lock and refused at the MCP wrapper layer. Reads are unaffected (MCP can serve read-only queries against the project).
- Outside reconstruct phase: MCP works normally. The `inspect_function_mcp.md` worker uses `<reconstruction.ref>/ghidra.gpr` as its project path.

### 7.3 Parallel reconstruct of different binaries

Out of scope for v1. Each binary gets its own catalog dir + its own LibGhidra Ghidra instance, so parallelism is theoretically free, but `scripts/reconstruct_batch.py` is excluded for YAGNI until a real second-binary-blocking-first scenario shows up.

---

## 8. Error handling & recovery

| Failure | Recovery |
|---|---|
| `libghidra_alive` healthz fails | Halt phase, exit 2, journal `phase_error`, surface install steps from `vendor/bootstrap.sh --check` |
| `no_concurrent_writer` fails | Halt phase, exit 3, surface lock-holder info |
| Ghidra project corruption mid-pass | Restore from prior pass snapshot, retry pass once; on second failure halt with `reconstruct_review.md` |
| LLM worker batch returns malformed JSON | Retry once with batch size 10; if still fails, log as `unprocessed` — Pass 4 cleanup picks them up |
| Worker times out | Same as malformed JSON |
| Pass 4 cleanup leaves reachable functions unnamed | Hard gate fails; phase exits non-zero; `reconstruct_review.md` lists offending functions |
| Soft gate fails | Phase proceeds with warning; `coverage.json#soft_gate_pass: false`; binary page banner amber |
| Lock contention >10min | Abort with stale-lock advice |

### 8.1 Idempotence

- Re-running `reconstruct.py` against a complete reconstruction is a no-op (manifest check).
- `--force-rebuild` wipes the catalog dir and restarts from Pass 0.
- (Excluded for YAGNI: `--force-pass N` surgical mid-pipeline restart.)

---

## 9. Testing

### 9.1 Unit tests under `tests/reconstruct/`

| Test | Asserts |
|---|---|
| `test_pcode_hash.py` | Hash stability across two compilations of same source with `/Brepro`; hash divergence with code changes |
| `test_carryforward.py` | Synthetic prior reconstruction + new version with 70% unchanged → port rate ≥0.65 |
| `test_pass0_string_xref.py` | Golden binary with known string-xref naming opportunities |
| `test_coverage_gate.py` | Manifest scenarios that pass/fail each gate |
| `test_emit_resync.py` | Touched functions re-emitted at pass boundary, .c file written within 5s |
| `test_lock_collision.py` | Concurrent reconstruct invocation refused with clear error |
| `test_reachability_root.py` | Per-binary-kind root computation matches expected set for each fixture |

### 9.2 Integration test

`tests/fixtures/sample_driver/` — purpose-built ~50-function Windows driver checked into the repo. End-to-end reconstruct phase against it, assert manifest matches expected coverage.

### 9.3 No-LLM dry-run mode

`reconstruct.py --skip-llm-passes` runs Pass 0 + coverage only. Used in CI to validate deterministic plumbing without burning tokens.

### 9.4 Acceptance test

One real binary (`bdservicehost.exe`, already in catalog) reconstructed once at design-validation time. Manual baseline of coverage stats + sample reconstructed function quality. Not part of automated CI.

---

## 10. Backfill policy

Existing ~30 catalog binaries (Bitdefender, Dell, Razer, Bind9, etc.) are **not bulk-reconstructed**. They get reconstructed **on-demand on next touch**:

- New engagement scope.json referencing the binary → reconstruct phase runs.
- Catalog-only re-render with stale reconstruction → no action; just renders the binary page with banner showing not_reconstructed state.

This spreads cost across natural workflow. Bulk backfill (`scripts/catalog_reconstruct_all.py`) is excluded for YAGNI.

---

## 11. Open items for implementation plan

These details are intentionally left to the writing-plans phase rather than the spec:

1. Exact GhidraSQL skill files to clone from 0xeb/vibe-re upstream; commit SHA pin.
2. Exact LibGhidra Java extension build/install steps for `vendor/bootstrap.sh`.
3. fid_db source — which `.lib` to ingest for `msvc_crt_19.fidb`, BSim corpus seed strategy.
4. Worker prompt token-budget instrumentation (we log `tokens_spent` per pass but the budget enforcement details are an implementation choice).
5. Exact JSON schema validation library for worker outputs (jsonschema vs pydantic vs custom).
6. The lock-aware MCP wrapper details — whether to ship as a fork of GhidraMCP or a thin proxy.

---

## 12. Out of scope (explicit cuts)

- `scripts/reconstruct_batch.py` multi-binary parallel orchestrator
- `vb-add note --subsystem` CLI for subsystem notes (use `$EDITOR`)
- `vb-add reconstruction --status complete` manual status flip
- Cross-binary BSim similarity links on Layer 8
- `--force-pass N` surgical mid-pipeline restart
- Bulk backfill (`catalog_reconstruct_all.py`)

---

## 13. Acceptance criteria

The reconstruct phase ships when:

1. `pipeline.yml` declares the phase with all gates; `fsm.py state <eng>` returns the new phase in transitions.
2. End-to-end on `tests/fixtures/sample_driver/` produces a complete catalog dir with hard+soft gates passing.
3. On `bdservicehost.exe` (real binary), reconstructed `functions/*.c` are readable and meaningfully named (manual eyeball + spot-check 10 functions for correctness).
4. `catalog_re_extract.py --reconstructed-dir <path>` produces a draft `reverse_engineering:` block in the binary YAML that has materially better SRC/INP/SNK/CAP coverage than the same script run against raw decomp (measured: count of high-confidence INP-* entries with `derived_from` populated).
5. Layer 8 reconstruction detail page renders correctly in both `catalog_site_render.py` and `catalog_serve.py`.
6. Binary page banner shows correct reconstruction status across all 4 states (green/amber/red/gray).
7. MCP refuses to attach to a `.gpr` whose `.lock` is held by the reconstruct phase.
8. Re-running reconstruct on a complete catalog dir is a no-op.
