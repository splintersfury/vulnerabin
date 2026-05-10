# FEAT layer — design

**Date:** 2026-05-10
**Status:** Approved (sections 1–6); pending implementation plan
**Resumes from:** `~/.claude/projects/-home-splintersfury-vulnerabin/memory/project_re_pipeline_feat_layer.md` (paused 2026-05-10)

## Why

The current binary-catalog matrix is `inputs × capabilities`, where capabilities are dangerous-API groupings (Modify Registry, Spawn Process). What we actually want is `inputs × features` — features are user-facing behaviours (Auto-update product, Apply policy from cloud, Authenticate user). Capabilities sit one layer below; features are a NEW aggregation layer above them. Both stay.

The bidirectional model: **forward** (input → conditions → ... → feature) AND **backward** (feature first → reverse-trace what user activates it). Comprehensive coverage when both directions agree.

## Decisions

Four design questions were settled before drafting (see `project_re_pipeline_feat_layer.md`):

1. **Walk staging** — three gated sub-stages: `2a-inputs` → `2b-sinks` → `2c-features`. Researcher walks via `vb walk <binary>`; gates enforced by `walk_state`.
2. **Detector scope** — pluggable detectors covering five tiers (universal PE/ELF, Windows userland, Windows kernel, Unix-like, cross-cutting), plus a tier 4b for macOS and tier 6 for firmware. Detectors filtered by `(platform, binary_kind)` like `defense_library`.
3. **FEAT anchors** — every FEAT carries `implementation_anchors[]` with RVAs (denormalised, full Ghidra-jump support).
4. **Walk UX** — CLI is canonical (gates, stage transitions); web UI is read-mostly with override buttons. Approach A: candidates land directly in `catalog/binaries/<binary>.yml` with `confirmed: false`, mirroring how `capabilities[]` works today. No sidecar files.

## Section 1 — Schema

### `features:` block (new top-level key)

```yaml
features:
  - id: FEAT-001
    slug: ""                            # human-stable, e.g. "auto-update" — survives renames
    product_feature_id: ""              # e.g. "PFEAT-bdts-001"; canonical across binaries in same product
    name: ""                            # human-readable, e.g. "Auto-update product binaries"
    description: ""                     # 1-3 sentence plain-English of what the user perceives
    status: ""                          # active | deprecated | mitigated | hypothesised | unexplored
    first_seen_version: ""
    last_confirmed_version: ""
    deprecated_in_version: ""
    deprecation_note: ""

    # Forward links
    capabilities: []                    # CAP-* IDs this feature exercises
    sources: []                         # SRC-* IDs that activate this feature
    inputs: []                          # INP-* IDs (the user-touchable surface)

    implementation_anchors:
      - function: ""                    # Ghidra function name post-rename
        rva: ""                         # e.g. "0x140012a0"
        role: ""                        # orchestrator | source | sink | helper | dispatcher

    # Risk roll-up
    cwe: []
    severity_ceiling: ""                # worst-case severity any reaching chain could achieve
    ux_strings: []                      # literal UI strings proving the feature exists user-side
    disabled_by_default: false

    # Detector provenance
    signal_sources:
      - detector: ""                    # e.g. "rpc_interface_table"
        detector_version: ""            # invalidate when detector logic changes
        evidence_type: ""               # rpc_uuid|com_clsid|service_name|string|rva|registry_key|export|symbol|task_xml|systemd_unit|dbus_interface
        evidence_value: ""              # the literal value
        weight: 0                       # 1=weak, 2=medium, 3=strong
        last_detected_at: ""            # ISO timestamp of last detector run that fired
    confidence: ""                      # auto-derived from sum-of-weights (≥5 high, ≥3 medium, else low)

    # Walk lifecycle
    confirmed: false
    rejected: false
    rejection_reason: ""
    rejected_at: ""
    user_observable: ""                 # how the user interacts
    notes: ""

    # Confirmation review (added by `vb walk confirm`)
    confirmation_review:
      required: false                   # auto-set by CLI based on stake conditions
      agent_id: ""                      # inspect-worker id (always recorded)
      reviewed_by: ""                   # skeptic agent id (only when required)
      verdict: ""                       # auto-confirm | ship | hedge-then-applied | human-override
      reviewed_at: ""
      artifact_path: ""                 # walk_reviews/<id>.json (only when reviewed)
      trigger_reason: ""                # which stake condition fired, e.g. "severity=High,cwe=CWE-78"
```

### `walk_state:` block (new top-level key)

```yaml
walk_state:
  stages:
    "2a-inputs":
      status: ""                        # not_started | open | closed
      opened_at: ""
      closed_at: ""
      reopened_at: ""
    "2b-sinks":
      status: ""
      opened_at: ""
      closed_at: ""
      reopened_at: ""
    "2c-features":
      status: ""
      opened_at: ""
      closed_at: ""
      reopened_at: ""
  pending_counts:                       # advisory cache, recomputed on render
    inputs_unconfirmed: 0
    sinks_unconfirmed: 0
    features_unconfirmed: 0
  history:
    - stage: ""
      action: ""                        # opened | closed | reopened | human-override-reject | human-override-confirm
      at: ""
      actor: ""                         # claude | human | inspect-worker-<id> | skeptic-<id>
      target: ""                        # FEAT-* | INP-* | SNK-*
      reason: ""
      confirmed: 0
      rejected: 0
```

### Reverse-pointer additions on existing blocks

Consistent plural `feature_ids: []` across all reverse-pointing records:

- `sources[].feature_ids: []`
- `reverse_engineering.inputs[].feature_ids: []`
- `sinks[].feature_ids: []`
- `chains[].feature_ids: []`
- `capabilities[].feature_ids: []`

### ID stability

Detector matches existing FEAT by tuple `(detector, evidence_type, evidence_value)` before assigning a new ID. `slug` is the human-stable handle; `id` is the machine-stable handle. Rejected entries are never resurfaced — auto-extract checks against `(detector, evidence_type, evidence_value)` of all `rejected: true` entries and skips matches.

### Migration story

Both `features:` and `walk_state:` are optional top-level keys. The renderer treats absence as "stage not started", and the binary page falls back to the existing `inputs × capabilities` matrix when `features: []`.

## Section 2 — Detector framework

Layout under `scripts/feat_detectors/`:

```
scripts/feat_detectors/
├── __init__.py                # registry + load_detectors(platform, binary_kind)
├── base.py                    # FeatureCandidate dataclass + Detector ABC
│
├── tier1_universal/
│   ├── exports.py             # PE/ELF exported function names
│   ├── version_info.py        # PE VS_VERSIONINFO FileDescription/ProductName
│   ├── string_table.py        # RT_STRING / .rodata UI + log strings
│   ├── manifest_sxs.py        # embedded sxs Application + Capabilities
│   ├── debug_paths.py         # PDB / DWARF compile-unit paths
│   └── help_urls.py           # help-page URLs in resources
│
├── tier2_windows_userland/
│   ├── rpc_interface.py       # RpcServerRegisterIf* UUIDs + procedure tables
│   ├── com_classes.py         # CLSID/IID + DllRegisterServer + .rgs + vtable
│   ├── wmi_provider.py        # MOF classes + IWbemServices methods
│   ├── named_pipe.py          # CreateNamedPipeW + endpoint name
│   ├── alpc_port.py           # NtCreatePort / NtAlpcCreatePort + name
│   ├── service_trigger.py     # SERVICE_TRIGGER_INFO blobs
│   ├── scheduled_task.py      # Task Scheduler XML harvest
│   ├── winrt_activatable.py   # AppxManifest ActivatableClass
│   ├── msix_appx_targets.py   # AppxManifest protocol/fileTypeAssoc/appService/shareTarget/backgroundTask
│   ├── shell_extension.py     # HKCR\<ext>\ShellEx handlers (context/preview/thumbnail/property)
│   ├── print_provider.py      # HKLM\SYSTEM\…\Print\Monitors\<name>\Driver
│   ├── lsa_provider.py        # LSA Auth/Security/Notification packages + Credential Providers
│   ├── amsi_provider.py       # HKLM\SOFTWARE\Microsoft\AMSI\Providers + IAntimalwareProvider
│   ├── cfapi_provider.py      # CfRegisterSyncRoot + windows.cloudFiles + SyncRootManager
│   ├── cng_ksp_provider.py    # BCryptRegisterProvider/NCryptRegisterProvider
│   ├── ui_automation.py       # IRawElementProviderSimple + Accessibility\ATs
│   ├── dotnet_reflection.py   # [Cmdlet], [ServiceContract], AssemblyDescription
│   ├── powershell_cmdlet.py   # PSModuleManifest CmdletsToExport
│   └── iis_module.py          # applicationHost.config <modules> + ISAPI filters + RegisterModule
│
├── tier3_windows_kernel/
│   ├── irp_dispatch.py        # IRP_MJ_* dispatch table from DriverEntry
│   ├── ioctl_table.py         # IoControlCode switches in IRP_MJ_DEVICE_CONTROL
│   ├── wdf_interface.py       # WdfDriverCreate/WdfDeviceCreate/WdfDeviceCreateDeviceInterface
│   ├── wfp_callout.py         # FwpsCalloutRegister*
│   ├── kernel_callbacks.py    # CmRegisterCallback / PsSet*NotifyRoutine
│   ├── etw_provider.py        # MERGED with telemetry_events: EtwRegister + manifests + format strings
│   ├── minifilter.py          # FltRegisterFilter + altitude
│   └── vmbus_channel.py       # VmbChannelAllocate + VMBus channel GUIDs (Hyper-V guest→host)
│
├── tier4a_linux/
│   ├── systemd_unit.py        # .service Description + ExecStart
│   ├── dbus_interface.py      # introspection XML + Method names
│   ├── udev_rules.py
│   ├── elf_exports.py         # exported symbols + custom section names
│   ├── cli_argparse.py        # argparse/clap/CLI11/getopt --help parser
│   ├── linux_chardev.py       # cdev_init/register_chrdev + file_operations + netlink genl_register_family
│   ├── linux_capabilities.py  # security.capability xattr + cap_set_proc + setuid/setgid + seccomp BPF
│   └── linux_module_param.py  # .modinfo + module_param + sysfs write handlers
│
├── tier4b_macos/
│   └── macos_xpc_service.py   # Info.plist XPCService + Mach-service names + NSXPCConnection + entitlements
│
├── tier5_crosscutting/
│   ├── http_routes.py         # embedded route tables (Mongoose, civetweb)
│   ├── grpc_descriptors.py    # FileDescriptorSet protobufs
│   ├── jsonrpc_methods.py     # method dispatcher tables
│   ├── custom_protocol.py     # vendor-proprietary protocol verbs
│   ├── chrome_native_messaging.py  # NativeMessagingHosts manifest + allowed_origins[]
│   ├── xll_addin.py           # xlAutoOpen/xlAutoClose exports
│   ├── dotnet_deserializer.py # BinaryFormatter/SoapFormatter/LosFormatter/ObjectStateFormatter callsites
│   └── updater_channel.py     # Squirrel.Windows + electron-updater + ClickOnce + MSI patch
│
└── tier6_firmware/
    └── uefi_smi_handler.py    # EFI_DRIVER_TYPE_SMM + SmiHandlerRegister + comm-buffer GUIDs
```

### Common interface (`base.py`)

```python
@dataclass
class FeatureCandidate:
    slug: str
    name: str
    description: str
    detector: str
    detector_version: str
    evidence_type: str               # rpc_uuid|com_clsid|...
    evidence_value: str
    weight: int                      # 1|2|3
    user_observable: str
    capability_hints: list[str]
    source_hints: list[str]
    input_hints: list[str]
    anchor_hints: list[dict]         # [{function, rva, role}]
    ux_string_hints: list[str]

class Detector(ABC):
    name: str
    version: str
    platforms: set[str]
    binary_kinds: set[str]
    representative_cve: str          # the bug class that motivates this detector
    @abstractmethod
    def detect(self, ctx: DetectorContext) -> list[FeatureCandidate]: ...

class DetectorContext:
    binary_path: Path
    decomp_dir: Path | None
    function_index: dict
    chains: dict | None
    re_block: dict
    existing_yaml: dict
```

### Aggregation (in `catalog_re_extract.py`)

1. Load all relevant detectors for `(platform, binary_kind)`
2. Run each → list of `FeatureCandidate`
3. Group candidates by `(detector, evidence_type, evidence_value)`; dedup against `existing_yaml.features[]`
4. Cross-detector convergence: candidates with matching `slug` (or fuzzy-matched `name`) merge into one FEAT with multiple `signal_sources[]`
5. Compute `confidence` from sum of `weight` (≥5 high, ≥3 medium, else low)
6. Write/update YAML, preserving hand-edited fields and `confirmed/rejected` flags
7. Update `last_detected_at` per `signal_sources[]`; stale signals flagged `stale: true`

### Authoring discipline

- Each detector ships its own `version` string. Bumping invalidates that detector's old candidates only.
- Detectors are deterministic and pure — no LLM calls, no network.
- New detector = new file in correct tier folder, register in `__init__.py`. No core code changes.
- Each detector's docstring records a representative CVE (the bug class that motivated the detector).

## Section 3 — `vb walk` pipeline

### Two-actor model

| Actor | Role | Surface |
|---|---|---|
| **Claude (strategist + workers)** | Inspect candidates, decide confirm/reject, write YAML | Scriptable CLI subcommands, JSON-out, structured args |
| **Human reviewer** | Spot-check what Claude decided, override mistakes | Web UI binary page with override buttons on every confirmed/rejected entry |

### CLI primitives

```bash
vb walk pending <binary> --stage 2c --json
vb walk inspect <binary> <feat-id> --json
vb walk confirm <binary> <feat-id> [--review-verdict <path>] [--inspect-worker <id>] ...
vb walk reject  <binary> <feat-id> --reason "..."
vb walk close-stage <binary> --stage 2a
vb walk refresh <binary>
vb walk status  <binary> --json
```

### Strategist + worker pattern

`prompts/phases/walk_strategist.md`:

```
while True:
    status = vb walk status <binary> --json
    if status.current_stage == "done": break
    pending = vb walk pending <binary> --stage <status.current_stage> --json
    if not pending:
        vb walk close-stage <binary> --stage <status.current_stage>; continue
    # Dispatch one inspect-worker per candidate, parallel batch (up to 5)
    for candidate in pending[:5]:
        Task(workers/walk_inspect_candidate, candidate_json=...)
    # Each worker returns: {decision: confirm|reject|defer, ...fields...}
    for verdict in worker_results:
        if verdict.decision == "confirm":
            if stake_gated(verdict.payload):
                review = Task(workers/walk_confirm_review, candidate_json=..., proposal=...)
                if review.verdict != "ship":
                    handle_hedge_or_block(review)
                    continue
            run: vb walk confirm <binary> <feat-id> ...
        elif verdict.decision == "reject":
            run: vb walk reject <binary> <feat-id> --reason ...
```

### Worker depth routing

`prompts/workers/walk_inspect_candidate.md`:

- **Headless first** (cheap, parallelisable): worker reads anchor RVAs' `.c` files from `engagements/<eng>/decomp/functions/`. Sufficient for ~80% of candidates.
- **MCP escalation**: worker calls `mcp__ghidra__decompile_function_by_address`, `mcp__ghidra__get_xrefs_to`, `mcp__ghidra__get_xrefs_from` when headless lacks a concrete callee, or shows a function-pointer indirect call / vtable.
- **Defer**: worker can't decide even with MCP. Returns `defer`; strategist re-queues with broader context.

### Stake-gated skeptic

The skeptic (`prompts/workers/walk_confirm_review.md`) fires inline only when ANY of:

1. `severity_ceiling` ∈ {High, Critical}
2. `cwe[]` is non-empty
3. `product_feature_id` is set (cross-binary)
4. Inspect-worker self-rated `confidence: low`

Everything else: inspect-worker decides, `vb walk confirm` writes immediately. Cost: ~30-candidate binary → ~35 dispatches (vs ~60 with per-candidate skeptic).

Skeptic checks (skeptic prompt):
1. Anchor honesty — does decompilation at each anchor RVA actually do what `description` claims?
2. Signal-source corroboration — do `evidence_value`s appear in the binary's strings/.rdata?
3. Capability/source/input plausibility — are linked IDs reachable from the anchors?
4. CWE/severity inflation — does the worst chain reaching this FEAT justify the proposed `severity_ceiling`?
5. UX strings exist — do `ux_strings[]` appear in the binary's resource section/.rdata?

Skeptic outputs structured JSON to `engagements/<eng>/walk_reviews/<feat-id>.json` with verdict `ship | hedge | block`.

### CLI gate on confirm

```bash
# Stake-gated path — review required
vb walk confirm <binary> <feat-id> \
  --review-verdict engagements/<eng>/walk_reviews/<feat-id>.json \
  --description "..." --cwe CWE-78 --severity-ceiling High ...

# Non-stake path — direct confirm
vb walk confirm <binary> <feat-id> \
  --description "..." --confidence high \
  --inspect-worker <agent-id>          # still required: who proposed this
```

Refusal modes: missing review file when stakes high → exit 1; verdict `!= ship` → exit 1; candidate_id mismatch → exit 1.

### Phase-level integration

New pipeline phase between `preparation` and `triage`. `pipeline.yml`:

```
preparation → walk → triage → deep → ...
```

Gates:
- `walk_state_started` (preparation → walk): `walk_state.stages["2a-inputs"].opened_at` set
- `walk_state_done` (walk → triage): all three stages `closed_at` set

## Section 4 — Render pipeline + visualization stack

### Tool selection per layer

| Layer | Primary | Fallback | Why |
|---|---|---|---|
| 1 — Attack-surface map | Graphviz `dot` server-side, SVG inlined | Hand-rolled SVG when ≤8 sources | Deterministic LR ranking; frozen ABI; no mermaid version drift |
| 2 — Trust boundary | Graphviz `dot` with `cluster_*` + `compound=true` | Existing CSS-grid in `binary.html.j2` | Cluster subgraphs are dot's superpower |
| 3 — Defense matrix | Markdown table + CSS-grid heatmap (Tailwind colors) | Pure markdown | 1–15 rows; no library needed |
| 4 — Cross-product topology | Cytoscape.js with `cose-bilkent`, positions cached | `dot` + `fdp` for static export | Only candidate that scales past 25 binaries with cluster collapse |
| 5 — Class coverage matrix (~62) | CSS-grid heatmap grouped by class prefix | Existing markdown table | 62 cells fits 8×8; pure Jinja, zero JS |
| 6 — Inputs × Features (NEW) | ECharts heatmap above 200-cell threshold | CSS-grid below | 25×30=750 cells past hand-roll comfort |

### Build pipeline

```
catalog/binaries/<name>.yml
        │
        ├─ scripts/catalog_render.py          → markdown
        │       └─ shells `dot -Tsvg` for L1/L2 → inlines SVG
        │       └─ markdown tables for L3/L5
        │       └─ ECharts JSON config for L6
        │
        ├─ scripts/catalog_site_render.py     → static HTML
        │       └─ same dot-SVG cache for L1/L2 → inline
        │       └─ Jinja heatmap macros for L3/L5
        │       └─ ECharts include for L6
        │       └─ Cytoscape.js include for L4 (product pages only)
        │
        └─ scripts/catalog_serve.py           → live FastAPI
                └─ LRU cache keyed by sha256(yaml_text) → catalog/site/static/diagrams/<sha>.svg
                └─ same Jinja templates as static
```

### Caching + reproducibility

- Cache key: `sha256(yaml_text)` per binary YAML
- Location: `catalog/site/static/diagrams/<sha>.svg` (committable to git)
- `dot` flags: `-Gstart=42 -Gepsilon=0.01 -Gfontnames=svg -Tsvg`
- YAML keys sorted before emitting `.dot` / ECharts JSON / Cytoscape JSON
- Cytoscape positions saved at `catalog/products/<slug>.layout.json`

### Print + disclosure quality

- `?print=1` query param on live server: strips dark-mode classes, forces SVG-only diagrams, expands collapsibles
- L6 ECharts: "Download PNG" button calls `chart.getDataURL({type:'png', pixelRatio:2})`
- All diagrams render to SVG-with-embedded-fonts; no OS-font substitution

### Theme / dark-mode

- Colors via CSS custom properties (`--vbn-source-F`, etc.) defined in Tailwind config
- `dot` SVG references variables via embedded `<style>` block
- Dark-mode toggle flips variables; no SVG re-render

### Accessibility

- Every diagram in a `<figure>` with `<figcaption>` carrying textual summary
- L3/L5/L6 markdown tables emit alongside heatmaps as screen-reader fallback
- Cytoscape graphs get `role="img"` + `aria-labelledby` pointing to figcaption

### New web-UI elements

- **Walk status header** (top of binary page): stage indicators, pending/deferred/stale counts
- **Features section**: per-FEAT cards with anchors table, signal sources, override buttons, confirmation_review collapsible
- **Three-tier rollup view**: Features → Capabilities → Sinks indented tree; orphan-CAP subsection
- **Coverage gaps panel** — six categories:
  1. Inputs with no chain (existing)
  2. Capabilities with no chain (existing)
  3. Sinks not grouped into any capability (existing)
  4. Capabilities not claimed by any feature (NEW)
  5. Features with no inputs[] AND no sources[] (NEW)
  6. Suspicious all-`?` rows or columns (NEW)

### Override endpoints

- `POST /api/walk/<binary>/override/<feat-id>` — flip confirmed/rejected, append to `walk_state.history` with `actor: human-override`
- `POST /api/walk/<binary>/claim-orphan/<cap-id>` — link orphan CAP under selected FEAT
- `POST /api/walk/<binary>/mark-stale-resolved/<feat-id>` — refresh signal_sources timestamps after researcher confirms still-valid

## Section 5 — Migration

### Three-tier policy

| Tier | Treatment |
|---|---|
| **Active** (recently engaged or in `vb status` "WORKED ON RECENTLY") | Auto-extract + walk in full; populate FEAT layer end-to-end |
| **Catalog-only** (seeded but no recent engagement) | Auto-extract runs; FEAT candidates land as `confirmed: false` backlog. No walk dispatched |
| **Frozen / mitigated** (`lifecycle: submitted/frozen/mitigated`) | Skip. YAML rendered with matrix-fallback (`inputs × capabilities`) |

`vb walk` refuses to start on a frozen binary unless `--force` is passed.

### Tier classifier

`scripts/catalog_migrate.py` (new). Output: `catalog/_migration_plan.yml` for hand-review. Override per-binary via `migration_tier_override:` in the binary YAML.

### Reverse-pointer backfill

Automatic. When `vb walk confirm` writes a FEAT with `capabilities: [CAP-001, CAP-007]`, the same write also appends `feature_ids: [FEAT-001]` to those CAP entries. Data converges as walks happen; no batch backfill script needed.

### Renderer fallback contract

```python
def render_matrix(binary_yaml):
    if binary_yaml.get("features"):
        return render_inputs_x_features(binary_yaml)
    return render_inputs_x_capabilities(binary_yaml)
```

Both renderers coexist forever. Catalog-only and frozen binaries never get the new matrix.

### Test plan

Smoke-test on `safeelevatedrun_dll` (canary) before running active-tier migration:
- Schema parses
- Renderer doesn't crash
- Web UI renders without JS errors
- Override buttons work
- `vb walk close-stage` advances correctly

### Rollback

`git restore catalog/binaries/<name>.yml`. Each migration commit is per-binary, scoped, reversible.

## Section 6 — Implementation sequencing

### Phase order

```
0. Smoke-test bench prep                                     (Day 0)
1. Schema additions to catalog/schema.yml                    (Day 1)
2. Renderer modernisation (mermaid → dot, SHA cache)         (Day 2-3)
3. Detector framework scaffolding                            (Day 4)
4. Detector implementations — Tier 1 + cheap Tier 5          (Day 5-6)
5. Detector implementations — Tier 2/3 (Windows-heavy)       (Day 7-9)
6. Detector implementations — Tier 4/4b/6                    (Day 10)
7. catalog_re_extract.py extension                           (Day 11)
8. vb-add subcommands                                        (Day 12)
9. vb walk CLI primitives                                    (Day 13-14)
10. Worker prompts                                           (Day 15)
11. Pipeline FSM updates                                     (Day 16)
12. Web UI render: features section + matrix L6              (Day 17-19)
13. Web UI live endpoints                                    (Day 20)
14. Cytoscape.js for product topology (Layer 4)              (Day 21-22)
15. CSS-grid heatmap for L5 + L3 cell-color                  (Day 23)
16. Migration                                                (Day 24-25)
17. Documentation + CLAUDE.md updates                        (Day 26)
18. End-to-end validation                                    (Day 27)
```

### Critical paths

- Schema → renderer modernisation → detector framework is the spine
- Tier 2/3 detectors are the biggest implementation chunk and the highest CVE-backed value
- Web UI parallelisable with detector implementation once schema is locked

### v1 scope

- Schema additions
- Detector framework + Tier 1 + Tier 2
- catalog_re_extract.py extension
- vb walk CLI primitives
- Worker prompts (inspect + skeptic)
- Web UI features section + L6 matrix + walk status header
- Override endpoints
- Migration on canary binary

Tiers 3/4/5/6 detectors, Cytoscape Layer 4, and full migration ship in v1.1+. The schema is forward-compatible.

### Estimate

~27 person-days focused. Realistically: 3–5 calendar weeks given parallel engagements.

## Open questions for implementation phase

None blocking. The following will be answered during implementation:

- Exact ECharts version + bundle size budget (Layer 6)
- Exact Cytoscape.js layout parameters (Layer 4)
- Skeptic prompt tuning after first 5–10 walks (calibration)
- Whether `walk_state.history[]` needs paging at high entry counts (defer until felt)

## References

- Memory: `~/.claude/projects/-home-splintersfury-vulnerabin/memory/project_re_pipeline_feat_layer.md`
- CVE-backed detector audit: agent run aba0d3890f611130f (2026-05-10)
- Visualization stack audit: agent run a0cbc0c265d66cfb1 (2026-05-10)
- Schema reference: `catalog/schema.yml`
- Defense library: `taxonomy/binary/defense_library.json`
