# TeamViewer (Windows)

**Vendor**: TeamViewer

Cross-platform remote-desktop tool. Windows install includes a SYSTEM-context service (TeamViewer_Service.exe) plus a user-context UI (TeamViewer.exe) and multiple kernel drivers (TeamViewerVPN.sys, TVMonitor.sys). IPC backbone is a localhost TCP listener (port 5938 by default), not a named pipe — so I-009 classifies the IPC surface, NOT I-002. Engagement found multiple findings including an IPC auth bypass sent to psirt@teamviewer.com 2026-04-29.

## Versions catalogued

| Version | First seen | Engagement |
|---------|------------|------------|
| 2026.x | 2026-03-31 | `teamviewer-2026-03-31` |

## Topology (Layer 4)

Process and IPC topology of the product. Binaries clustered by trust zone; edges are observed IPC connections; dotted edges from the attacker zone are speculative injection paths.

```mermaid
flowchart TB
    subgraph ZSYSTEM["SYSTEM"]
        Nteamviewer_service_exe_port_5938["teamviewer_service.exe &#40;port 5938 listener&#41;"]:::sysz
        Nteamviewervpn_sys["teamviewervpn.sys"]:::sysz
        Ntvmonitor_sys["tvmonitor.sys"]:::sysz
    end
    subgraph ZAdmin_or_user["Admin_or_user"]
        Nteamviewer_exe_UI["teamviewer.exe &#40;UI&#41;"]:::admz
    end
    subgraph ZStandard_user_attacker["Standard_user_attacker"]
        Nany_standard_user_process["&#40;any standard-user process&#41;"]:::atkz
    end
    Nteamviewer_exe_UI -. localhost TCP 127.0.0.1:5938 .-> Nteamviewer_service_exe_port_5938
    classDef sysz fill:#fdd,stroke:#900
    classDef admz fill:#fed,stroke:#a60
    classDef usrz fill:#dfd,stroke:#080
    classDef atkz fill:#222,stroke:#000,color:#fff
    classDef neut fill:#eee,stroke:#666
    classDef ext fill:#ffd,stroke:#aa0
```


## Source-class coverage across binaries

Heatmap: which v2 source classes are catalogued per binary. Counts are the number of distinct sources tagged with that class.

| Binary | F-003 | F-006 | I-002 | K-001 |
|---|---|---|---|---|
| `teamviewer_service.exe` | 1 | 1 | 2 | · |
| `teamviewer_host_setup_x64_2026.exe` | · | · | · | · |
| `teamviewer_virtualdevicedriver.dll` | · | · | · | · |
| `teamviewer_xpsdriverfilter.dll` | · | · | · | · |
| `teamviewervpn.sys` | · | · | · | 2 |
| `tvmonitor.sys` | · | · | · | · |
| `tvvirtualmonitordriver.dll` | · | · | · | · |


## Defense distribution across the product

Defenses observed by component. `GAP:` lines flag known weaknesses still open.

### `teamviewer_service`

- binds to 127.0.0.1 (localhost-only)
- GAP: I-009 — no peer authentication; any local process connects (submitted to psirt@teamviewer.com)
- Application-layer auth via passwords; bypassable in some flows (T-005 path traversal in install validation)

### `drivers`

- kernel drivers serving virtual-monitor and VPN functionality
- K-001 IOCTL surface present; not yet deeply audited for memory corruption


## Vulnerabilities surfaced

Cross-binary findings catalog. Status badges: ✅ submitted_paid · 🟢 submitted · ⏳ in_progress · ⚠ submitted_dropped · ⏸ not_submitted.

| Binary | Finding | Classes | Severity | Status | Submission |
|--------|---------|---------|----------|--------|------------|
| `teamviewer_service.exe` | [`teamviewer-2026-03-31/findings/001-localhost-tcp-ipc-auth-bypass.md`](../../engagements/teamviewer-2026-03-31/findings/001-localhost-tcp-ipc-auth-bypass.md) | I-009 | TBD | 🟢 submitted | psirt@teamviewer.com |
| `teamviewer_service.exe` | [`teamviewer-2026-03-31/findings/002-ipc-command-handler.md`](../../engagements/teamviewer-2026-03-31/findings/002-ipc-command-handler.md) | I-009 | TBD | 🟢 submitted | psirt@teamviewer.com |
| `teamviewer_service.exe` | [`teamviewer-2026-03-31/findings/003-driver-install-validation-analysis.md`](../../engagements/teamviewer-2026-03-31/findings/003-driver-install-validation-analysis.md) | I-009, T-005 | TBD | ⏸ not_submitted | — |
| `teamviewer_service.exe` | [`teamviewer-2026-03-31/findings/004-log-readable-low-priv.md`](../../engagements/teamviewer-2026-03-31/findings/004-log-readable-low-priv.md) | F-006 | TBD | ⏸ not_submitted | — |
| `teamviewer_service.exe` | [`teamviewer-2026-03-31/findings/005-hardlink-class.md`](../../engagements/teamviewer-2026-03-31/findings/005-hardlink-class.md) | F-003 | TBD | ⏸ not_submitted | — |
| `teamviewer_service.exe` | [`teamviewer-2026-03-31/findings/008-ipc-additional.md`](../../engagements/teamviewer-2026-03-31/findings/008-ipc-additional.md) | I-009 | TBD | 🟢 submitted | psirt@teamviewer.com |


## Open angles flagged for vendor / future investigation

- tvmonitor.sys / teamviewervpn.sys IOCTL surface — K-001 not deeply audited
- TLS-pinning on outbound TeamViewer cloud connections not verified
- auto-updater UP-003 not investigated


## Binaries in this product

- [`teamviewer_service.exe`](../teamviewer_service_exe.md) — SYSTEM, 4 sources, 4 chains
- [`teamviewer_host_setup_x64_2026.exe`](../teamviewer_host_setup_x64_2026_exe.md) — SYSTEM, 0 sources, 0 chains
- [`teamviewer_virtualdevicedriver.dll`](../teamviewer_virtualdevicedriver_dll.md) — loggedInUser, 0 sources, 0 chains
- [`teamviewer_xpsdriverfilter.dll`](../teamviewer_xpsdriverfilter_dll.md) — loggedInUser, 0 sources, 0 chains
- [`teamviewervpn.sys`](../teamviewervpn_sys.md) — kernel, 2 sources, 2 chains
- [`tvmonitor.sys`](../tvmonitor_sys.md) — kernel, 0 sources, 0 chains
- [`tvvirtualmonitordriver.dll`](../tvvirtualmonitordriver_dll.md) — unknown, 0 sources, 0 chains

---
_Auto-generated by `scripts/catalog_product_render.py` at 2026-05-09 15:32 UTC._
