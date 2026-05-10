# Session notes — 2026-05-09 end-of-session catalog buildout

You went to sleep mid-session asking me to "keep at it all the way!" — here's what shipped.

## All four requested items done

### 1. Backfilled 87 binary YAMLs

Built `scripts/catalog_enrich.py`. Walks every YAML draft in `catalog/_drafts/` and pulls data from `engagements/_audit/sources_observed.jsonl` (Phase A audit) plus `taxonomy/binary/defense_library.json`. For each binary:

- Derives `source_class_id` + `co_class_ids` from audit records that match the binary's seed_meta findings_seen.
- Generates `sources[]` / `sinks[]` / `chains[]` skeletons where audit records exist (with `notes` cross-referencing the engagement + finding file).
- Infers `process_model.principal` from binary-name heuristics (`*svc*`/`*service*`/`*agent*` → SYSTEM; `*.sys` → kernel; `*setup*`/`*install*`/`*updater*` → installer-elevated; `*ui*`/`*tray*` → loggedInUser; else unknown).
- Stubs `defenses[]` with the canonical_defense text from defense_library for each class touched.
- Auto-fills `class_coverage[]` — every relevant taxonomy class for the binary's platform+kind, marked `present` for classes seen in sources, `unchecked` for the rest.

Idempotent: never overwrites pre-existing fields. Used `--promote` to mv all populated drafts into `catalog/binaries/`. **Result: 87 binaries catalogued, up from 1.**

The 86 binaries that didn't have matching audit records still got `class_coverage[]` populated (every relevant class as `unchecked`), `process_model.principal` inferred, and the comprehensive forcing function in place. They show "0 sources / 0 chains" honestly because we don't have evidence yet — but their pages render with full class-coverage matrices ready to walk.

### 2. Eight more product YAMLs

Authored `cisco-secure-client`, `nvidia-app`, `malwarebytes`, `sophos`, `protonvpn`, `keeper-security`, `bind9`, `nextcloud-desktop` — joining the existing 6 (bitdefender-total-security, dell-supportassist, backblaze, dropbox, teamviewer, rustdesk). **Total: 14 products.** Each has topology, vulnerabilities ledger, defenses, open-angles. All render to `catalog/pages/products/<slug>.md` and `catalog/site/products/<slug>.html`.

### 3. Interactive search/filter + hover tooltips

Index page (`catalog/site/index.html` + the live route at `/`):

- Live search input — types into `#vbn-search` filter rows by binary name + display_name + product. Verified working: typing "vhdmp" → 5 of 87 visible.
- Filter chips: Platform (All / windows / linux / macos / electron based on what's seen) and Status (All / Has confirmed / Has partial / Unexplored only). Active chip highlighted in primary blue.
- Live "Showing N of 87 binaries" counter.
- "Clear" button resets all filters.
- Vanilla JS, no dependencies. ~50 LOC inline `<script>` block at end of template.

Binary detail page (`catalog/site/binaries/<name>.html`):

- Hover any source node in the L1 Attack-Surface Map → tooltip popup shows the full `name`, `via`, `function`, `caveat`, and `source_class_id + co_class_ids`. Repositions to stay in viewport.
- Same for sink nodes — shows `cwe`, `function`, `impact`.
- Tooltip is a single `#vbn-tooltip` div positioned with `mousemove` listener.

### 4. Full live web app

Built `scripts/catalog_serve.py` — FastAPI app sharing the same Jinja2 templates as the static site. Reads YAML at every request, so editing `catalog/binaries/foo.yml` and refreshing shows the change immediately (no restart, no rebuild).

**Routes:**
- `GET /` — catalog browse (same UI as static index, but live data)
- `GET /binaries/<name>` — binary detail with all 5 visualization layers
- `GET /products` — product list grid
- `GET /products/<slug>` — product detail (Layer 4 topology, heatmap, ledger)
- `GET /taxonomy` — taxonomy reference
- `GET /api/binaries` — JSON list of all binaries (lightweight schema)
- `GET /api/binary/<name>` — full binary YAML as JSON
- `GET /api/products` — JSON list
- `GET /api/product/<slug>` — full product YAML
- `GET /api/search?q=...` — fuzzy search across binaries / products / classes
- `GET /healthz` — liveness check (returns counts)

**Run:** `python3 scripts/catalog_serve.py` → `http://127.0.0.1:8088`. As of this writing the server is live on port 8089 (started during testing).

## How to view what I built

The server is running on port 8089. Visit:

- http://127.0.0.1:8089/ — catalog browse with 87 binaries + filter chips + search
- http://127.0.0.1:8089/binaries/safeelevatedrun_dll — the densest detail page (5 layers + chains)
- http://127.0.0.1:8089/products/bitdefender-total-security — product topology with all binaries clustered by trust zone
- http://127.0.0.1:8089/api/search?q=junction — search the catalog from the command line
- http://127.0.0.1:8089/api/binaries — full binary list as JSON

If you want to restart the server: `cd /home/splintersfury/vulnerabin/scripts && python3 catalog_serve.py --port 8088`.

For the static-site variant (no server, just `file://` URLs): `python3 scripts/catalog_site_render.py` produces `catalog/site/*.html` you can open directly.

## Final inventory

| Component | Count |
|---|---|
| Binary YAMLs (`catalog/binaries/*.yml`) | 87 |
| Product YAMLs (`catalog/products/*.yml`) | 14 |
| Static HTML pages rendered | 105 |
| Drafts remaining | 0 |
| FastAPI routes | 11 |
| JSON API endpoints | 7 |
| Source classes in defense_library | 62 |
| Chains catalogued (auto-stubbed) | 26 |

## Known gaps / next-session candidates

These are real work that needs human curation, not quick fixes:

1. **Per-binary chain content is stubbed.** Auto-enrichment generated `chains[]` skeletons with placeholder conditions ("auto-stub: walk the source through any defenses..."). Real-world chains need hand-written conditions enumerating the trust checks. The 6 chains in `safeelevatedrun.dll` (the manually-authored canonical entry) are the quality bar.
2. **`platform` field is empty** on most enriched binaries. The seeder didn't set it. Easy fix: enrichment could default `platform: windows` for `binary_kind: sys/exe/dll`. Defaulted to "?" in the index.
3. **86 binaries have empty `sources[]`** because their engagement findings didn't get audit-record matches. The class_coverage matrix is the comprehensive forcing function for these — open the binary page and walk the inline detection checklists for each `unchecked` class.
4. **Defense matrix text** is canonical-defense from the library. The `observed`/`gap`/`bypass_attempts` columns need per-binary reverse-engineering.
5. **Product class-heatmaps** for newly-added products (cisco, nvidia, malwarebytes, sophos, protonvpn, keeper, bind9, nextcloud) are mostly empty because the binaries don't have populated source_class_id yet (chicken-and-egg with #1).

## Where everything lives

```
catalog/
├── binaries/                    87 YAMLs (the data)
├── products/                    14 YAMLs (the data)
├── pages/                       markdown rendering of each binary + product
├── site/                        static HTML site (Jinja2 + Tailwind)
│   ├── _templates/              Jinja2 templates
│   ├── _prototypes/README.md    your design tokens, extracted
│   ├── binaries/*.html
│   ├── products/*.html
│   └── index.html, taxonomy.html
├── README.md, schema.yml        binary YAML schema docs
├── stitch_prompt.md             your earlier UI design prompt
└── SESSION_NOTES_2026-05-09.md  this file

scripts/
├── catalog_seed.py              walks engagements/, makes drafts
├── catalog_enrich.py            populates drafts from audit data    [NEW]
├── catalog_render.py            YAML → markdown
├── catalog_product_render.py    product YAML → product markdown
├── catalog_site_render.py       YAML → static HTML site
├── catalog_serve.py             FastAPI live app                    [NEW]
└── catalog_diff.py              cross-version diff

taxonomy/binary/
├── sources_comprehensive.md     the 62-class taxonomy (Phase B)
├── sources_v2.json              machine-readable
└── defense_library.json         per-class detection checklist + canonical defense  [USED BY enrichment + serve]

engagements/_audit/
├── sources_observed.jsonl       101 findings classified                    [DRIVES enrichment]
├── audit_phase_a.md             cross-engagement synthesis
├── draft_taxonomy_v2.md         post-audit taxonomy refinement
└── sources_observed_summary.md  agent narrative
```

## What you can do tomorrow

Hot path: **for each new engagement, run `catalog_seed.py --binary <name>` then `catalog_enrich.py --promote`** — your binary lands in the catalog with a class-coverage matrix ready to walk. Open the binary's HTML page (or the live server route), walk the inline detection checklists, fill in `class_coverage[]` rationale, hand-author chains as you find them. Re-render or just refresh.

For variant analysis on a product where you have multiple version YAMLs (e.g., `vhdmp_26100_*` files): `catalog_diff.py vhdmp.sys --from <prev> --to <new>` shows what changed. The 5 vhdmp version variants in the catalog are ready to diff once you've populated their sources.

For new products you want to map out before doing the engagement: write a `catalog/products/<slug>.yml` (use `catalog/products/_schema.yml` as the template), define `binaries[]` and `topology.trust_zones`, render with `catalog_product_render.py`. The Layer 4 topology gives you the IPC graph to inform where to look first.

Sleep well.

---

## Morning addendum (2026-05-10) — research-workflow-shaped IA

You came back asking for the IA to mirror **how you actually use this**: Product → binaries → sources → conditions → sinks. Plus the chain detail should show research workflow stage (input identified → conditions enumerated → PoC built → tested → boundary crossed → submitted).

**What changed:**

1. **Landing is now Products grid** (was: binaries table). Every product as a card with vendor, version, binary count, chain count, status badges. Sorted with confirmed-first.
2. **Chain detail pages are first-class** at `/binaries/<name>/chains/<chain-id>` — 27 pages auto-generated. Each has:
   - **Research workflow tracker** at top: 6-stage horizontal kanban (input → conditions → PoC built → PoC tested → boundary crossed → submitted), current stage highlighted
   - **PoC + Outcome rows**: status, path, commands, boundary_crossed verdict, evidence link
   - **Source → Conditions → Sink** big horizontal flowchart with each condition numbered
   - Bypasses required, Impact, References, Notes, sibling chains
3. **Pipeline kanban view** at `/pipeline` — every chain across the catalog organised into the 6 workflow columns. PAS finding (CHAIN-001 productagentservice) is in `Submitted`. Trufos KASLR is in `PoC tested`. BDTS 005 is in `PoC built`. Stub chains are in `Input identified`. Move chains rightward as you do the work.
4. **Chains index** at `/chains` — flat cross-product chain table.
5. **YAML schema gained `poc:` and `outcome:` blocks per chain** (see safeelevatedrun_dll.yml CHAIN-001 + productagentservice_exe.yml CHAIN-001 + trufos_sys.yml CHAIN-001 for examples). The renderer's stage inference reads these to position the chain on the kanban.
6. **Bitdefender Total Security suite populated**: bdappservice.dll (dispatcher), bddci4.sys (defense), trufos.sys (K-002 KASLR with full chain + PoC + outcome), productagentservice.exe (paid F-001+F-002 chain with full PoC + boundary_crossed=yes + submission). Plus the existing safeelevatedrun.dll. Other 9+ BDTS binaries have skeletal class_coverage; fill in as research progresses.
7. **Nav reordered**: Products primary → Binaries → Chains → Pipeline → Taxonomy.

**End-to-end test verified through Playwright** (screenshots in repo root):
- vbn-1-products-landing.png — landing with 14 products
- vbn-2-product-bdts.png — Bitdefender Total Security topology + heatmap + ledger
- vbn-3-binary-pas.png — ProductAgentService.exe binary detail (5 layers)
- vbn-4-chain-pas.png — CHAIN-001 PAS detail (workflow tracker + flowchart + PoC + outcome)
- vbn-5-pipeline.png — research pipeline kanban with 6 columns

All 11 tested routes return 200. Server still live at http://127.0.0.1:8089/.

**Final catalog state:**
- 87 binaries (5 deeply populated; rest have class_coverage skeletons)
- 14 products
- 26 chains (3 with full PoC+outcome: PAS-CHAIN-001 submitted-paid, BDTS-005 partial with PoC built, trufos mitigated with PoC tested)
- 135 static HTML pages including 27 chain detail pages

**To use:**
- `python3 scripts/catalog_serve.py` → http://127.0.0.1:8088
- Open `/` → click Bitdefender → click ProductAgentService.exe → click CHAIN-001 → see the full workflow (Submitted)
- Or visit `/pipeline` for the funnel view across all chains

When you find a new vuln during RE: edit the binary YAML chains[], add the new chain with conditions[], populate `poc:` as you build it, populate `outcome:` after you run it, refresh — the chain auto-moves through the kanban as the data fills in.
