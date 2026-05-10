# Google Stitch prompt — Vulnerabin binary attack-surface catalog UI

## How to use

Copy everything below the `---` divider and paste into Google Stitch. Generate the design, then iterate on individual screens by referencing them by name (Index, Binary Detail, Product Detail). The prompt is structured for one comprehensive generation; you can also paste individual sections if Stitch hits length limits.

---

# Design brief

Design a desktop web application called **Vulnerabin Catalog** for vulnerability researchers who reverse-engineer Windows desktop and Electron applications to find security bugs. The app is a knowledge-management tool: it catalogs every binary the researcher has reverse-engineered, surfaces the attack surface visually, tracks which entry points have been investigated vs unexplored, and links findings to bug-bounty submissions.

The primary user is **a senior vulnerability researcher** with deep reverse-engineering experience. They are not a beginner. They want **information density, fast navigation, and accurate visualizations** more than they want polish or marketing-style flourishes. Think Sourcegraph, Linear, or Sentry rather than Vercel landing pages. Dark theme by default, monospace fonts for code/identifiers, generous use of color-coded badges and status pills.

The data model has three levels of granularity:

- **Index** — the global view across all binaries in the catalog
- **Binary detail** — one page per binary (e.g., `safeelevatedrun.dll`, `bdappsrv.exe`, `vhdmp.sys`) showing four visualization layers
- **Product detail** — one page per product suite (e.g., `Bitdefender Total Security`, which spans 14+ binaries) showing cross-binary topology

Every binary belongs to a product. Every binary has zero or more **sources** (entry points where attacker-controlled input enters), zero or more **sinks** (dangerous operations the binary performs), and zero or more **chains** (a source → ordered conditions → sink path that, if fired, exploits a vulnerability).

Every source is classified under a stable taxonomy with class IDs grouped by prefix:

- **F** — Filesystem trust-boundary (e.g., F-001 NTFS-junction-write-by-elevated-process). Color: red
- **I** — Local IPC (e.g., I-002 named-pipe-unauthenticated-write). Color: orange
- **N** — Network (e.g., N-001 DNS wire-format parser). Color: blue
- **K** — Kernel/Driver (e.g., K-001 IOCTL input buffer). Color: purple
- **U** — User-input / process surface. Color: green
- **T** — Trust assumption (e.g., T-005 path-traversal-in-trust-check). Color: gray
- **UP** — Update / install / package. Color: yellow
- **C** — Configuration / persistence. Color: brown
- **E** — Electron-specific. Color: teal
- **W** — Web (auth/session). Color: lavender
- **CR** — Cryptographic primitive misuse. Color: neutral

A chain has a **status**: `confirmed` (✅ green), `partial` (🟡 amber), `hypothesised` (❔ blue), `unexplored` (⏳ gray), `mitigated` (🛡 muted). These status badges appear throughout the UI.

A finding (a researcher's writeup of an actual vulnerability) has a **submission status**: `submitted_paid` (✅), `submitted` (🟢), `in_progress` (⏳), `submitted_dropped` (⚠), `not_submitted` (⏸).

## Screens to generate

### Screen 1 — Catalog Index

The landing page. A **sidebar on the left** lists every binary (filterable by product, by platform, by binary kind). The **main panel** shows a table of all binaries with columns: Binary name, Display name, Product, Versions count, Sources count, Sinks count, Chains count, Confirmed/Partial/Unexplored counts, last-updated date.

Above the table: a **search bar** and **filter chips** (product, platform: windows/linux/macos, binary_kind: exe/dll/sys/so, has-confirmed-chain, has-unexplored-chain).

To the right of the table: a **stats panel** showing total binaries, total chains, status distribution (a small donut chart of confirmed/partial/hypothesised/unexplored/mitigated counts), and the most-active source classes (a horizontal bar chart of class-ID → chain count, sorted descending).

At the top of the index page: a **"Recently submitted" rail** showing the latest 5-10 findings that were filed to bug-bounty platforms, each as a card with: vendor logo placeholder, finding title (truncated), platform badge (Bugcrowd/MSRC/HackerOne), submission status, and submission date.

### Screen 2 — Binary Detail (the heart of the app)

This is the most important screen. When the user clicks a binary in the index, they land here. The page has the following sections, in order:

**Header band** at the top:
- Binary name (large monospace, e.g., `safeelevatedrun.dll`)
- Display name (subtitle, e.g., "Bitdefender SafeElevatedRun")
- Breadcrumb: Catalog > Bitdefender Total Security > safeelevatedrun.dll
- A row of metadata pills: platform (windows), arch (x64), binary_kind (dll), trust_boundary (one-line summary), product link
- Action buttons: "Open YAML source", "Render as PDF", "Compare versions"

**At-a-glance section** (collapsible, expanded by default):
- Description (1-paragraph plain-English summary of what the binary does)
- Versions catalogued (small table: version, sha256, engagement-folder name, first-seen date)

**Layer 1 — Attack-surface map** (a graph visualization):
- A directed graph rendered in the SVG. The binary is a single dark node in the center labeled with its name and principal (e.g., "SYSTEM").
- To the left of the binary: every **source** as a colored node. The color reflects the source-class group (F=red, I=orange, N=blue, K=purple, U=green, T=gray, UP=yellow, C=brown, E=teal, W=lavender, CR=neutral). Each source node is labeled with: the source name (truncated), the class IDs (e.g., `I-002 + T-005 + T-006`), the attacker-control state (`ac=yes`, `ac=yes+caveat`, `ac=no`, `ac=unclear`), and the status badge (✅ confirmed / 🟡 partial / ❔ hypothesised / ⏳ unexplored / 🛡 mitigated).
- To the right of the binary: every **sink** as a darker red node. Labeled with sink name and CWE (e.g., "CreateProcessAsUserW (SYSTEM token) — CWE-269").
- Edges are simple arrows: source → binary, binary → sink. No labels on edges (keep it readable).
- The graph is interactive: hovering a source node opens a popover with the full source name, the via field (how the input arrives, e.g., "msgbus IPC pipe \\.\pipe\local\msgbus\bdappsrv"), the function (e.g., "FUN_18001c460"), and any caveat. Clicking a source scrolls to the source's row in the Sources table below.
- A small legend at the bottom right of the graph shows the class-color mapping.

**Layer 2 — Trust boundary & process model** (another graph, but shaped differently):
- A vertically-stacked layout with **trust-zone bands**. From top to bottom: SYSTEM (red-tinted background), Admin (amber-tinted), LoggedInUser (green-tinted), Standard user / attacker (dark/black band).
- Inside each band: nodes representing the binary (highlighted as `:::self` with a thick border) and any IPC peers / parent processes that live in that zone.
- Dashed edges across zone boundaries represent IPC connections, labeled with the channel (e.g., "msgbus IPC pipe", "COM IElevator", "named pipe \\.\pipe\foo").
- Dotted edges from the attacker zone up to user-context peers represent **speculative injection paths** (the attacker would need to inject code into a peer to reach the binary). Render these in a distinct dashed style with red color.
- Show "Impersonation seen: yes/no" and "PPL protected: yes/no" as small chips above the diagram.

**Layer 3 — Defense matrix** (a table):
- Columns: Class (badge with class-ID and color), Defense expected (text, what the canonical defense is), Observed in binary (text, what's actually in this binary), Gap (text, "YES / partial / none" with reasoning), Bypass attempts (text, what the researcher has tried).
- Cells with a "GAP: YES" should highlight in red; "GAP: partial" in amber; "GAP: none" in green.
- One row per source class touching this binary.

**Analysis coverage** (a sidebar-style component on the right of Layer 3, or below it):
- Decomp dirs scanned (list)
- Total function count, functions analyzed (X / Y, with a progress-bar indicator)
- Unanalyzed but high-priority (a bullet list)
- Recon gaps (a bullet list)

**Sources table** — every source as a row. Columns: ID (e.g., SRC-001), source-class-id badge, name, via, type, attacker-controlled (badge), function (monospace), first-seen version, last-confirmed version, notes (truncated, expandable).

**Sinks table** — every sink. Columns: ID, name, CWE, function, impact, first-seen version.

**Chains table** — every chain as a row. Columns: ID, title, source → sink (compact), status badge, severity, severity badge, finding link, submission link. Click a row to expand and see the chain detail.

**Chain detail (expandable)** — for each chain:
- A horizontal flowchart-style mini-graph: source node → condition 1 node → condition 2 node → ... → sink node. Each condition is labeled with the human-readable check that must hold. Source colored by class group; conditions in amber; sink in red.
- A summary card with: severity, CVSS vector (monospace), CWE list, status, confirmed-in-version, finding markdown link, submission reference link, list of "Bypasses required to fire this chain".
- Notes at the bottom (rich text).

### Screen 3 — Product Detail

When the user clicks a product (either from the breadcrumb on a binary page, or from a "Products" tab in the sidebar), they land on this page.

**Header band**:
- Product name (e.g., "Bitdefender Total Security")
- Vendor (e.g., "Bitdefender")
- Versions catalogued (a horizontal-scroll list of versions with engagement folder names)

**Topology view (Layer 4)** — the aerial graph:
- A larger version of the trust-zone-banded layout from Screen 2 (Layer 2), but with **all binaries in the product** placed in their respective zones.
- IPC edges across zones with labels.
- Each binary node is clickable and navigates to the binary detail page.
- Color the nodes by status: binaries with at least one `confirmed` chain are highlighted; binaries with `unexplored` chains are dimmer; binaries with no catalogued chains are gray.

**Source-class heatmap** — a table where rows are binaries and columns are source-class IDs (only those classes that appear in this product). Cells show the count of distinct sources per (binary, class). Cells with count > 0 are color-saturated by class group; cells with 0 show a `·`.

**Defense distribution** — for each defense component (e.g., `bdprivmon.sys`, `bddci4.sys`, `msgbus_application_rules`), a card showing the bullet list of defenses and known gaps. "GAP:" lines highlighted in red.

**Vulnerabilities ledger** — a table of findings across all binaries in the product. Columns: Binary, Finding (link), Classes (chips), Severity (badge), Status (badge), Submission (link).

**Open angles** — a list of researcher notes on what's flagged for vendor or future investigation. Plain bullet list.

**Binaries in this product** — a grid of cards, one per binary. Each card shows: binary name (monospace), principal, source count, chain count, last-updated date. Click a card to navigate to the binary detail.

## Visual style

- **Dark theme by default**. Background `#0a0a0c`, surface `#15161a`, secondary surface `#1d1f24`, primary text `#e4e4e7`, secondary text `#a1a1aa`.
- **Monospace** (JetBrains Mono, IBM Plex Mono, or similar) for: binary names, function names (`FUN_18000f5d0`), file paths, CVSS vectors, CWE IDs, hex values, IPC pipe paths.
- **Sans-serif** (Inter, system-ui) for prose and section headers.
- **Source-class color tokens** as defined above. Use **filled badges** for class IDs (e.g., a small pill with `I-002` in white text on an orange background).
- **Status badges** use the emoji + label pattern: `✅ confirmed`, `🟡 partial`, `❔ hypothesised`, `⏳ unexplored`, `🛡 mitigated`.
- **Severity** uses pill colors: P1 dark red, P2 red, P3 orange, P4 yellow, P5 gray. CVSS Critical = dark red, High = red, Medium = orange, Low = yellow, None = gray.
- **Density first**. Tables should fit lots of rows; sparing whitespace; small but legible (12–13px) text in tables. Section headers can be larger.
- **No marketing flourishes**. No hero illustrations, no testimonial sections, no pricing tiers. This is an internal tool.
- **Information cards** should have subtle 1px borders rather than heavy shadows.
- **Graphs** (Layers 1, 2, 4) should use clean SVG with the class-group color palette, anti-aliased edges, and readable labels at all zoom levels. Provide pan + zoom controls in the corner of each graph.
- **Tables** are sortable by clicking column headers. The column being sorted shows a small arrow icon. Sticky header on scroll.

## Interactions

- Clicking a source-class badge anywhere filters the index to binaries that exercise that class.
- Clicking a status badge filters to chains in that status.
- The breadcrumb is always navigable.
- Search is keyboard-accessible (Cmd/Ctrl-K opens a global fuzzy search across binaries, sources, sinks, chains, findings).
- Each section heading has a "copy link to this section" affordance (a `#` icon visible on hover).

## What NOT to design

- No login / auth flow. Single-user local tool.
- No marketing landing page. The index IS the homepage.
- No notification center, no chat, no comments. The artifacts are markdown files; collaboration happens in git.
- No mobile breakpoint. Desktop-only (≥1280px).
- No light theme variant for the first pass (can add later).

## Reference shapes (raw data structure for context)

Below are the actual YAML shapes the data comes from. Stitch should not generate fields not in this list, and should not invent fictional data. Examples are real and can be used in mockups.

**Binary YAML (catalog/binaries/<name>.yml):**
- binary, display_name, product, description, canonical_path, arch, platform, binary_kind, trust_boundary
- process_model: { loaded_by, principal, start_trigger, parent_processes[], ipc_peers[], impersonation_seen, ppl_protected }
- versions[]: { version, sha256, eng, seen, notes }
- sources[]: { id (SRC-NNN), source_class_id (taxonomy), co_class_ids[], name, via, type, attacker_controlled, caveat, function, first_seen_version, last_confirmed_version, notes }
- sinks[]: { id (SNK-NNN), name, cwe, function, impact, first_seen_version, notes }
- chains[]: { id (CHAIN-NNN), title, source_id, sink_id, conditions[], impact, cwe[], severity, cvss, status, confirmed_in_version, finding_ref, submission_ref, bypasses_required[], notes }
- defenses[]: { class_id, defense_expected, observed, gap, bypass_attempts }
- coverage: { decomp_dirs[], function_count, functions_analyzed[], unanalyzed_high_priority[], recon_gaps[] }

**Product YAML (catalog/products/<slug>.yml):**
- product, display_name, vendor, description
- versions_seen[]: { version, eng, seen }
- binaries[]: list of binary tokens
- topology: { trust_zones (principal -> [binary names]), ipc_edges[] (src/dst/via), defenses (per-component bullets) }
- vulnerabilities[]: { finding_ref, binary, classes[], severity, status, submission_ref }
- open_angles[]

**Real example data to use in mockups:**

- Binary: `safeelevatedrun.dll`, product: `bitdefender-total-security`, principal: SYSTEM, 2 sources (SRC-001 = `msgbus.run_elevated_async.executable_path` class I-002+T-005+T-006, SRC-002 = `msgbus.run_elevated_async.executable_args` class I-002), 1 sink (SNK-001 = `CreateProcessAsUserW(SYSTEM_token)`, CWE-269), 2 chains (CHAIN-001 partial P3 confirmed_in 27, finding `bitdefender-total-security-2026-04-11/findings/005-safeelevatedrun-path-traversal.md`, submission `bugcrowd:59aada4c-64d7-4215-851f-03ebde5d0629`; CHAIN-002 unexplored).

- Product: `Bitdefender Total Security`, vendor: Bitdefender, 13 binaries (`safeelevatedrun.dll`, `bdappservice.dll`, `bdprivmon.sys`, `bddci4.sys`, `trufos.sys`, `bdservicehost.exe`, `bdappsrv`, `bdagent.exe`, `seccenter.exe`, `bduserhost.exe`, `msgbus.dll`, `watchdog.exe`, `productagentservice.exe`), trust zones SYSTEM (9 binaries) / Admin / LoggedInUser / Standard-user-attacker, IPC edges include `bdagent.exe -[msgbus pipe]-> bdappsrv`, vulnerabilities ledger has the BDTS 005 (submitted ✅), trufos kernel infoleak (submitted_dropped ⚠), Bitdefender PAS junction ($1,000 paid ✅), and several in_progress entries.

- Source classes most-frequently appearing: K-001 IOCTL (16 findings), F-001 NTFS-junction-write (15), N-001 DNS wire-format parser (11), I-002 named-pipe-unauth-write (11), N-003 TLS protocol parser (8), W-001 authenticated-user-session (7).

## Output

Generate the three screens described (Index, Binary Detail, Product Detail). For each screen, produce:
- A high-fidelity mockup at desktop resolution (≥1440px wide)
- Interaction notes (hover states, click flows)
- Component breakdown (which reusable components — Badge, StatusPill, GraphCanvas, Table, Card — are used where)

If a section is too dense to fit comfortably, break it across two screens or use a tabbed layout within Binary Detail (tabs: "Overview", "Attack surface", "Trust model", "Defenses", "Chains", "Coverage").

Match the density and information-design quality of: Sourcegraph code search, Linear issue detail, Sentry issue detail, GitHub repo insights. Do not match: marketing landing pages, consumer SaaS dashboards, generic Tailwind UI templates.
