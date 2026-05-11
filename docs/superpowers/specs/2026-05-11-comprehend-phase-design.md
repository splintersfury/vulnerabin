# `comprehend` Phase Design — Product Mental Model Before Hunting

**Status:** Approved (pending implementation plan)
**Date:** 2026-05-11
**Author:** Ahmad Abdillah + Claude (Opus 4.7)
**Sibling:** `2026-05-11-reconstruct-phase-design.md`
**Driving motivation:** Reconstruction makes individual *code* readable. Comprehension makes the *system* readable. Before walking sources, building chains, or hunting vulns, the analyst (and the agent) needs a plain-language mental model: what this product is, how requests flow through it, what each binary does, where trust boundaries sit, what the attack surface is. The comprehend phase synthesizes that model from the reconstructed source + catalog state, and persists it as renderable narrative on product/binary pages.

---

## 1. Architecture

### 1.1 Pipeline placement

```
... → preparation → reconstruct → comprehend → walk → triage → deep → ...
                                    ↑ NEW
```

`pipeline.yml` declares:

```yaml
phases:
  comprehend:
    description: "Synthesize cross-binary product mental model from reconstructed source"
    entry_artifacts:
      - "catalog/binaries/{stem}.yml#reconstruction.status"   # at least the engagement's primary binary reconstructed
    exit_artifacts:
      - "catalog/products/{product}.yml#architecture_narrative"
      - "catalog/binaries/{stem}.yml#summary"
      - "catalog/binaries/{stem}.yml#full_picture"
    gates:
      pre:
        - primary_binary_reconstructed     # the engagement's primary binary has status: complete OR partial
      post:
        - narrative_present                # product YAML has architecture_narrative block populated
        - binary_summaries_present         # every reconstructed binary in the product has summary + full_picture
    transitions:
      from: [reconstruct]
      to: [walk]
    opt_out_flag: "--no-comprehend"        # walk can run without comprehension (worse mental model, faster)
```

### 1.2 Dependencies

- **Hard**: at least the engagement's primary binary must be reconstructed (status `complete` or `partial`). Walk needs *some* grounded narrative for the binary it's about to hunt against.
- **Soft**: other binaries in the same product may be partially reconstructed or `not_started`. Narrative degrades gracefully — non-reconstructed binaries get a placeholder ("Role inferred from catalog metadata; deep behavior unknown until reconstructed").

### 1.3 Trigger granularity

Per-engagement. When `/hunt <target>` runs:

1. Walk to the engagement's primary binary
2. Resolve product via `catalog/binaries/<stem>.yml#product`
3. Read all binaries listed in `catalog/products/<product>.yml#binaries`
4. For each binary with `reconstruction.status` ∈ {complete, partial}: include in comprehension
5. Generate per-binary summaries + product narrative, write back to catalog

This means **comprehension quality is a function of how much of the product has been reconstructed**. The first engagement on a product produces a narrative with one detailed binary and N placeholders. Later engagements progressively fill in the picture. The user's incremental backfill strategy (on-demand reconstruct on next touch) naturally compounds here.

### 1.4 Bindiff carryforward

Comprehension is expensive (multi-binary LLM synthesis). Re-running on a product where nothing changed should be a no-op. Re-running where one binary version bumped should only re-comprehend that binary + re-synthesize the product narrative.

**Fingerprint per binary** (recomputed at phase entry):

```python
binary_fingerprint = sha256(
    binary_stem +
    reconstruction.ref +
    reconstruction.version_tag +
    reconstruction.status +
    yaml_section_hash(catalog/binaries/<stem>.yml, ["sources", "sinks", "capabilities", "chains", "inputs", "features"]) +
    notes_dir_hash(<reconstruction.ref>/notes/)
)
```

**Fingerprint per product** (recomputed at phase entry):

```python
product_fingerprint = sha256(
    product_slug +
    sorted([binary_fingerprint(b) for b in product.binaries]) +
    yaml_section_hash(catalog/products/<product>.yml, ["trust_zones", "ipc_edges", "binaries"])
)
```

**Carryforward logic**:

- If `catalog/binaries/<stem>.yml#summary_fingerprint == binary_fingerprint(stem)`: skip per-binary comprehension for this stem (reuse existing `summary` + `full_picture`).
- If `catalog/products/<product>.yml#architecture_narrative.fingerprint == product_fingerprint`: skip product-level synthesis (reuse existing narrative).
- Otherwise: re-run the affected layer(s).

For a 30-binary product where one binary updated: 1 LLM call (re-comprehend that binary) + 1 LLM call (re-synthesize product narrative) instead of 31.

Cache stored inline in the YAML fields, not a separate file. One source of truth.

---

## 2. Workers

Three worker prompts under `prompts/workers/`:

### 2.1 `comprehend_binary.md`

**Input**: one binary's reconstructed `functions/*.c` (top N=50 by entrypoint-reachability + xref count) + `headers/types.h` + `headers/ioctls.h` + `headers/globals.h` + `notes/*.md` (all subsystem memory files) + the binary's existing YAML (sources, sinks, capabilities, chains, inputs, features).

**Output** (JSON):

```json
{
  "summary": "Single-sentence ELI5 of what this binary does",
  "full_picture": {
    "loaded_by": ["service manager", "BdNTwrk.dll via LoadLibrary"],
    "start_trigger": ["service start (auto)", "loaded on demand by parent service"],
    "ipc_peers": [
      {"name": "BdNTwrk.dll", "transport": "named pipe \\\\.\\pipe\\BdAg", "direction": "bidirectional"},
      {"name": "kernel BDDci4.sys", "transport": "DeviceIoControl", "direction": "out"}
    ],
    "accepted_inputs": [
      "IPC messages over \\\\.\\pipe\\BdAg (typed dispatch on field 0x10)",
      "Registry config under HKLM\\SOFTWARE\\Bitdefender\\..."
    ],
    "dangerous_operations_reachable": [
      "CreateProcessAsUserW with caller-supplied path",
      "RegSetValueExW under HKLM",
      "DeviceIoControl to kernel driver"
    ],
    "defense_gaps_observed": [
      "Caller authentication on pipe limited to DACL; DACL permits AU",
      "No path canonicalization before CreateProcessAsUserW"
    ]
  }
}
```

Worker is Opus 4.7, temperature 0, batched 1 (one binary per call — context is large, ~30-50k tokens).

### 2.2 `comprehend_dataflow.md`

**Input**: every binary's `summary` + `full_picture` from §2.1 + the product YAML's `process_model` block (trust zones, principals) + the existing cross-binary IPC edge list from `catalog/products/<product>.yml#ipc_edges`.

**Output** (JSON, fed into §2.3):

```json
{
  "data_flow": [
    {
      "step": 1,
      "actor": "Standard user attacker",
      "action": "Sends typed message over \\\\.\\pipe\\BdAg",
      "destination": "BdNTwrk.dll (running as LoggedInUser)"
    },
    {
      "step": 2,
      "actor": "BdNTwrk.dll",
      "action": "Forwards privileged request via named pipe \\\\.\\pipe\\BdServiceBus",
      "destination": "BdServiceHost.exe (SYSTEM)"
    },
    {
      "step": 3,
      "actor": "BdServiceHost.exe",
      "action": "Dispatches by message type to handler; some types spawn helper process",
      "destination": "Child process running as SYSTEM"
    }
  ],
  "trust_boundaries_crossed": [
    {"from": "Standard user", "to": "LoggedInUser", "via": "\\\\.\\pipe\\BdAg", "auth": "DACL allows AU"},
    {"from": "LoggedInUser", "to": "SYSTEM", "via": "\\\\.\\pipe\\BdServiceBus", "auth": "type tag, no caller token check"}
  ]
}
```

### 2.3 `comprehend_narrative.md`

**Input**: all per-binary `summary` + `full_picture` from §2.1 + the dataflow from §2.2 + product YAML metadata (name, vendor, version, binaries list, trust_zones, defenses).

**Output** (JSON), written to `catalog/products/<product>.yml#architecture_narrative`:

```json
{
  "summary": "Bitdefender Total Security is a Windows endpoint protection suite that runs detection in user mode (BdNTwrk) and enforcement in a SYSTEM service (BdServiceHost), with a kernel filter driver (BDDci4) for early-boot protection. Standard users interact with the agent through a named pipe; configuration writes traverse the agent → service → registry/filesystem chain.",
  "data_flow_prose": "User actions flow from the desktop UI through BdNTwrk (LoggedInUser context) over \\\\.\\pipe\\BdAg, are forwarded by BdNTwrk to BdServiceHost (SYSTEM) over \\\\.\\pipe\\BdServiceBus when privileged, and BdServiceHost dispatches by message type to subsystem handlers that touch the registry, filesystem, or kernel driver depending on the request.",
  "binary_roles": [
    {"stem": "bdservicehost", "role": "SYSTEM-context dispatcher; receives forwarded IPC, executes privileged ops"},
    {"stem": "bdntwrk", "role": "User-context broker; mediates UI to service; runs as LoggedInUser"},
    {"stem": "bddci4", "role": "Kernel filter driver; early-boot protection; receives DeviceIoControl from BdServiceHost"}
  ],
  "trust_boundaries": [
    "Standard-user → LoggedInUser via \\\\.\\pipe\\BdAg (DACL-gated)",
    "LoggedInUser → SYSTEM via \\\\.\\pipe\\BdServiceBus (type-tag-gated, no token check)",
    "SYSTEM → kernel via DeviceIoControl to \\Device\\BDDci4 (DACL-gated)"
  ],
  "attack_surface_primary": "The LoggedInUser → SYSTEM transition over \\\\.\\pipe\\BdServiceBus. Message-type dispatch in BdServiceHost is the highest-value target — successful injection of a privileged message type gives SYSTEM-context execution of vendor-provided code paths.",
  "fingerprint": "<product_fingerprint_at_synthesis_time>"
}
```

The `fingerprint` field lets §1.4 carryforward detect stale narrative.

---

## 3. Output schemas

### 3.1 Binary YAML additions

```yaml
# catalog/binaries/<stem>.yml

summary: "BdServiceHost is the SYSTEM-context message-dispatch service that executes privileged operations on behalf of user-mode components."

full_picture:
  loaded_by: [...]
  start_trigger: [...]
  ipc_peers: [...]
  accepted_inputs: [...]
  dangerous_operations_reachable: [...]
  defense_gaps_observed: [...]

summary_fingerprint: "<sha256 of binary_fingerprint inputs at last comprehension>"
last_comprehended: "2026-05-11T16:42:00Z"
```

### 3.2 Product YAML additions

```yaml
# catalog/products/<product>.yml

architecture_narrative:
  summary: "..."
  data_flow_prose: "..."
  binary_roles: [...]
  trust_boundaries: [...]
  attack_surface_primary: "..."
  fingerprint: "<product_fingerprint at last synthesis>"
  last_synthesized: "2026-05-11T16:43:00Z"
  binaries_comprehended: ["bdservicehost", "bdntwrk"]
  binaries_pending_reconstruction: ["bdtrackerscomm", "bdappservice", "..."]
```

The two `last_*` timestamps are mtime-style; the orchestrator overwrites them on every synthesis. The `binaries_comprehended` / `binaries_pending_reconstruction` arrays make narrative completeness self-documenting.

---

## 4. Visualization integration

### 4.1 Product page (Layer 4)

A new section **"How this product works"** rendered between the product description and Layer 4 topology:

```
# <Product Name>

<short product description from product YAML>

## How this product works                              ← NEW

**Summary**
<architecture_narrative.summary>

**Data flow**
<architecture_narrative.data_flow_prose>

**What each binary does**
- **<stem>** — <role>
- ...

**Trust boundaries**
- <boundary 1>
- ...

**Primary attack surface**
<architecture_narrative.attack_surface_primary>

> *Comprehension based on <N> of <M> binaries reconstructed. Pending: <list>.*

## Layer 4: Cross-binary topology
... existing ...
```

Same content in both `catalog_product_render.py` (markdown) and `catalog_site_render.py` (HTML via Jinja2 template `_templates/product.html.j2`).

### 4.2 Binary card on Layer 6

Each per-binary attack-flow card on the product page (Layer 6) gets:

```html
<div class="binary-card">
  <h3>BdServiceHost.exe</h3>
  <p class="eli5">BdServiceHost is the SYSTEM-context message-dispatch service that executes privileged operations on behalf of user-mode components.</p>

  <details>
    <summary>Full picture</summary>
    <ul>
      <li><strong>Loaded by:</strong> service manager (auto-start)</li>
      <li><strong>Start trigger:</strong> service start at boot</li>
      <li><strong>IPC peers:</strong> BdNTwrk.dll via \\.\pipe\BdServiceBus (in), BDDci4.sys via DeviceIoControl (out)</li>
      <li><strong>Accepted inputs:</strong> IPC messages over \\.\pipe\BdServiceBus (typed dispatch)</li>
      <li><strong>Dangerous ops reachable:</strong> CreateProcessAsUserW, RegSetValueExW, DeviceIoControl to kernel</li>
      <li><strong>Defense gaps:</strong> No caller token check on type-tag dispatch</li>
    </ul>
  </details>

  ... existing attack-flow content (sources, chains, etc.) ...
</div>
```

Markdown version uses standard headings + bullet list (no `<details>`).

### 4.3 Binary page (top-of-page banner)

The binary's own page (`catalog/site/binaries/<stem>.html`) gets a comprehension banner directly under the page title, ABOVE the reconstruction status banner:

```
# bdservicehost.exe — Bitdefender Total Security

> **TL;DR** — BdServiceHost is the SYSTEM-context message-dispatch service that executes privileged operations on behalf of user-mode components.

[reconstruction status banner from reconstruct spec §6.4]

## Attack-surface map (Layer 1)
...
```

### 4.4 Live FastAPI server

`catalog_serve.py` reads the YAML at request time (already its behavior), so narrative updates appear on next browser refresh. No new route needed.

### 4.5 vb status integration

- Engagement consuming a product where comprehend hasn't run → suggested next action: `→ run comprehend phase`
- Engagement consuming a product where `architecture_narrative.fingerprint` is stale (binaries reconstructed since last synthesis) → suggested next action: `→ re-comprehend (binary state changed)`
- `vb --eng <slug>` detail view shows comprehension state + how many binaries are factored in vs pending

---

## 5. Components

### 5.1 New scripts

| File | Purpose |
|---|---|
| `scripts/comprehend.py` | Phase orchestrator. Resolves engagement → product → binaries; computes fingerprints; dispatches workers; writes YAML; emits journal events |
| `scripts/comprehend_fingerprint.py` | Library: per-binary and per-product fingerprint computation |
| `scripts/catalog_narrative_render.py` | Helpers shared between `catalog_product_render.py` and `catalog_site_render.py` for the "How this product works" + binary card + binary banner blocks |

### 5.2 Modified scripts

| File | Change |
|---|---|
| `pipeline.yml` | Insert `comprehend` phase node, gates, transitions |
| `scripts/fsm.py` | Add `comprehend` to phase enum + gate validators |
| `scripts/journal.py` | Add `comprehend` to allowed phases |
| `scripts/catalog_product_render.py` | Emit "How this product works" + Layer 6 ELI5/Full Picture; consume `architecture_narrative` block |
| `scripts/catalog_site_render.py` | Same, for HTML; use new template helpers from `catalog_narrative_render.py` |
| `scripts/catalog_serve.py` | Binary page banner emission (live route reads YAML at request time, no schema change needed) |
| `scripts/status.py` (vb status) | Add comprehension state to suggested-next-action logic |
| `scripts/walk.py` (or whatever drives the walk phase) | Pre-gate check: refuse to start unless `architecture_narrative` present OR `--no-comprehend` set |
| `prompts/strategist.md` | Add `comprehend` phase awareness, journal event types, ability to call `/comprehend` slash command |
| `prompts/phases/walk_strategist.md` | Reads `architecture_narrative` at phase entry; uses it as grounding context for input/sink/feature candidate confirmation |

### 5.3 New prompts

| File | Purpose |
|---|---|
| `prompts/phases/comprehend.md` | Strategist-mode prompt for the phase |
| `prompts/workers/comprehend_binary.md` | One binary → summary + full_picture JSON |
| `prompts/workers/comprehend_dataflow.md` | Cross-binary data flow JSON |
| `prompts/workers/comprehend_narrative.md` | Final narrative synthesis JSON |

### 5.4 New Jinja2 templates / template fragments

| File | Purpose |
|---|---|
| `catalog/site/_templates/_how_this_works.html.j2` | "How this product works" block (rendered on product page) |
| `catalog/site/_templates/_binary_card_eli5.html.j2` | ELI5 + collapsible Full Picture for Layer 6 cards |
| `catalog/site/_templates/_binary_banner.html.j2` | TL;DR banner for binary page top |

### 5.5 vb-add additions

Single new subcommand, optional convenience:

```bash
vb-add narrative --product <slug> --field summary --text "..."
```

Sets a specific field of `architecture_narrative` by hand (escape hatch for when LLM output needs correction). All other fields generated by comprehend phase only.

(Excluded for YAGNI: per-binary `vb-add summary --text "..."`; `$EDITOR` on the YAML is fine.)

---

## 6. Error handling

| Failure | Recovery |
|---|---|
| `primary_binary_reconstructed` pre-gate fails | Halt phase, exit 2, suggest `→ run reconstruct phase` |
| Per-binary worker (comprehend_binary) returns malformed JSON | Retry once with same context; on second failure log unprocessed; binary marked "comprehension failed — narrative will use catalog metadata only" |
| Dataflow worker fails | Phase proceeds; synthesis worker gets "data flow unavailable" placeholder; final narrative degrades gracefully |
| Synthesis worker fails | Halt phase; write partial state with `architecture_narrative.error: "synthesis failed at <T>"`; binary summaries persisted regardless |
| Fingerprint mismatch loop (narrative re-generates every run) | Detected by orchestrator: if 3 consecutive runs produce different fingerprints from identical inputs, log warning and surface to user (likely a non-determinism bug) |

Idempotence: re-running comprehend when no fingerprints changed is a no-op (orchestrator exits 0 immediately).

---

## 7. Testing

### 7.1 Unit tests under `tests/comprehend/`

| Test | Asserts |
|---|---|
| `test_binary_fingerprint.py` | Same inputs produce same fingerprint; modifying any input changes the fingerprint |
| `test_product_fingerprint.py` | Product fingerprint is order-independent over binaries; changes when any binary fingerprint changes |
| `test_carryforward_noop.py` | Re-running on unchanged catalog skips all LLM calls |
| `test_partial_product.py` | Product with mixed reconstruction states produces narrative with pending placeholders |
| `test_narrative_schema.py` | All generated narratives validate against expected JSON schema |
| `test_walk_pre_gate.py` | Walk phase refuses entry when narrative missing AND `--no-comprehend` not set |

### 7.2 Integration test

Two-binary synthetic product fixture (`tests/fixtures/sample_product/`):
- `service.exe` (SYSTEM context, message dispatcher)
- `client.dll` (user context, sends messages)

End-to-end: reconstruct both → comprehend → assert narrative mentions the trust boundary + names both binaries correctly.

### 7.3 No-LLM mode

`comprehend.py --skip-llm` runs fingerprint computation + carryforward logic + writes empty narrative placeholders. Used in CI.

### 7.4 Acceptance test

Run against `bitdefender-total-security` (existing catalog product with multiple binaries) once at design-validation time. Manual eyeball check: does the generated narrative match what a human RE would write after reading the binary YAMLs and a handful of reconstructed functions?

---

## 8. Walk-phase integration

The walk phase (existing — input/sink/feature candidate confirmation) is the immediate downstream consumer. Three integration points:

1. **Strategist context**: `prompts/phases/walk_strategist.md` reads `catalog/products/<product>.yml#architecture_narrative` at phase entry and inlines it into the strategist's working context. This means input candidate confirmation is grounded in product-level understanding ("does this input claim square with the data flow we just synthesized?").
2. **Pre-gate**: walk refuses to start unless `architecture_narrative.fingerprint` is current with the catalog state, OR `--no-comprehend` was set on the engagement.
3. **Skeptic agent on walk_confirm_review** also receives the narrative — pushing back on confirms that contradict the mental model.

---

## 9. Out of scope (explicit cuts)

- **Per-binary `vb-add summary`** — `$EDITOR` is fine
- **Multi-product narrative synthesis** — narrative is per-product; cross-product comparison is not in scope
- **Diagram generation** (e.g., auto-mermaid from data flow) — narrative is prose + structured fields only. Mermaid diagrams stay in the existing Layer 1/2/4 renders.
- **History of past narratives** — only the current narrative is stored; prior narratives can be recovered from git history of the YAML
- **Localization** — narrative is English only

---

## 10. Acceptance criteria

Comprehend phase ships when:

1. `pipeline.yml` declares the phase with all gates; `fsm.py state <eng>` returns it in transitions.
2. End-to-end on `tests/fixtures/sample_product/` produces a complete narrative with both binaries factored in, in <2 LLM calls per binary + 1 synthesis call.
3. On `bitdefender-total-security` real product: narrative reads accurately (manual eyeball) for at least the reconstructed binaries; pending binaries show as placeholders.
4. Layer 4 "How this product works" section renders correctly in both `catalog_product_render.py` (markdown) and `catalog_site_render.py` (HTML).
5. Layer 6 binary cards show ELI5 + collapsible Full Picture.
6. Binary page top-of-page banner shows TL;DR.
7. Re-running comprehend with no changes is a sub-second no-op (fingerprint-only check).
8. Modifying one binary's reconstruction → next comprehend re-comprehends only that binary + re-synthesizes product narrative (verified by LLM call count).
9. Walk phase pre-gate refuses entry without narrative; `--no-comprehend` opt-out works.

---

## 11. Open items for implementation plan

These details left to the writing-plans phase:

1. Exact JSON schema validation library for worker outputs (consistent with reconstruct spec choice).
2. Concurrency in worker dispatch — per-binary workers can run in parallel; bound by LLM rate limits not Ghidra (since comprehend doesn't touch Ghidra projects).
3. Token-budget instrumentation per phase (cumulative; warning at `VULNERABIN_COMPREHEND_WARN_USD`, hard cap at `VULNERABIN_COMPREHEND_MAX_USD`).
4. Whether to surface the narrative in `vb status` output one-line view or only on `vb --eng <slug>` detail.
5. Exact Jinja2 template scope of `_how_this_works.html.j2` (does it own the H2 heading, or just the body block).

---

## 12. Sequencing relative to reconstruct spec

This spec assumes the reconstruct phase is implemented. Implementation order:

1. Reconstruct phase (per its spec)
2. Comprehend phase (this spec)
3. Walk-phase integration changes (pre-gate, strategist context inlining)

Reconstruct must ship first because comprehend has no useful input without reconstructed source.
