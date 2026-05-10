# Prototypes

Four reference HTML mockups from the user's Stitch session, 2026-05-09. These are the canonical visual reference for the static site generator (`scripts/catalog_site_render.py`).

## Files

- `binary_detail.html` — Binary Detail page (safeelevatedrun.dll). Shows: tabs, Layer 1 Attack-Surface Map (SVG + HTML overlay nodes), Defense Matrix table, Coverage Stats sidebar. Primary color `#adc6ff`.
- `product_detail.html` — Product Detail page (Bitdefender Total Security). Shows: L4 Topology (3-zone grid), Source-Class Heatmap, Defense Distribution cards, Vulnerabilities Ledger. Primary color `#adc6ff`.
- `catalog_index.html` — Catalog Index page. Shows: recently-submitted rail, filter chips, data table, stats sidebar (overview, donut chart, bar chart). Primary color `#ffffff`.
- `catalog_index_alt.html` — Same layout as index but with `accent: #3b82f6` blue accent and `on-surface` light-grey text instead of pure-white primary. More restrained.

## Design tokens (extracted)

- **Theme**: dark-only
- **Colors**: Material 3 surface tokens. Primary `#adc6ff` (blue) for binary/product pages; `#3b82f6` (accent blue) for index in v2.
  - `surface`: `#131315`
  - `background`: `#0c0c0e` (alt: `#131315`)
  - `on-surface`: `#e5e1e4`
  - `surface-container`: `#201f21`
  - `surface-container-low`: `#1b1b1d`
  - `surface-container-lowest`: `#0e0e10`
  - `surface-container-high`: `#2a2a2c`
  - `outline-variant`: `#424754`
  - `error`: `#ffb4ab`
  - `secondary`: `#4fdbc8`
  - `tertiary`: `#ffb786`
- **Fonts**: Inter for UI / prose; JetBrains Mono for code, identifiers, data
- **Type scale**:
  - `display-lg`: 32px / 40px / 700
  - `headline-md`: 24px / 32px / 600
  - `title-sm`: 16px / 24px / 600
  - `body-md`: 14px / 20px / 400
  - `body-sm`: 12px / 18px / 400
  - `code-md`: 13px / 20px (mono)
  - `code-sm`: 11px / 16px (mono)
  - `label-caps`: 10px / 12px / 700 / letter-spacing 0.1em
- **Spacing**: 4 / 8 / 12 (gutter) / 16 (margin) / 24 (lg) / 32 (xl)
- **Radius**: 0.125rem (default) / 0.25rem (lg) / 0.5rem (xl) / 9999px (full)
- **Icons**: Material Symbols Outlined (Google Fonts)

## What the generator borrows

- The Tailwind config block (verbatim) — `_templates/_base.html.j2`
- Top app bar layout
- Side nav (Catalog / Platforms / Binaries / Attack Surface / Analytics)
- Breadcrumbs at top of detail pages
- Tabs for binary detail (Overview / Attack surface / Trust model / Defenses / Chains / Coverage)
- Section headers with `font-label-caps` + Material icon
- Card/table component patterns
- The L1 attack-surface map: SVG paths + HTML node overlays (so labels stay sharp and clickable)
- The L4 topology grid: 3-zone CSS grid with dashed borders + colored zone labels
- Filter chips with rounded-full
- Donut chart SVG pattern
- Horizontal bar chart with `h-1.5` + width-percent fill
