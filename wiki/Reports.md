# Reports & Audit

Starting with **2.1.0**, SPSTrust can produce a read-only **trust matrix**: a snapshot of
the current cross-farm trust state, written both as a machine-readable JSON file and as a
self-contained HTML report.

## What is reported

For every publishing-farm / consuming-farm / service relationship declared in your
configuration, SPSTrust resolves the state of each trust dimension:

| Dimension              | Source                                   | Notes |
| ---------------------- | ---------------------------------------- | ----- |
| `RootTrust`            | `Get-SPSTrustedRootAuthority`            | ROOT certificate trust on the publishing farm |
| `StsTrust`             | `Get-SPSTrustedServiceTokenIssuer`       | STS trust (N/A for a `Content` service) |
| `Published`            | `Get-SPSPublishedServiceApplication`     | Service application published (N/A for `Content`) |
| `TopologyPermission`   | `Get-SPSTopologyServiceAppPermission`    | Application Discovery & Load Balancing permission |
| `ServiceAppPermission` | `Get-SPSPublishedServiceAppPermission`   | Per-service permission (N/A for `Content`) |
| `Proxy`                | `Get-SPSPublishedServiceAppProxy`        | Service application proxy on the consuming farm (N/A for `Content`) |

Each cell is reported as **Present**, **Absent**, **N/A** (not applicable) or **Error**
(the underlying check failed — the message is captured in the row's *Notes*). A single
failing farm never aborts the whole audit.

> [!NOTE]
> Collection is strictly **read-only**. It calls only the `Get-SPS*` functions and never
> publishes, grants, revokes, connects or removes anything.

## When the report is generated

The report is produced in **two** situations:

1. **At the end of every normal run** (`Configure` or `-CleanServices`) — a post-run
   snapshot of the resulting state.
2. **In `-ReportOnly` mode** — an audit that skips all four configuration stages and only
   collects state and writes the report. Use this to document or verify an existing
   topology without changing anything.

```powershell
# Read-only audit only (no changes)
.\SPSTrust.ps1 -ConfigFile '.\Config\CONTOSO-PROD.psd1' -FarmAccount (Get-Credential) -ReportOnly
```

## Output layout

Relative to `SPSTrust.ps1`:

```
Results\
  CONTOSO-PROD.json              # latest results snapshot (overwritten each run)
  history\
    CONTOSO-PROD-20260710-1200.json   # timestamped archives of previous snapshots
Reports\
  CONTOSO-PROD.html              # latest HTML trust matrix (overwritten each run)
```

- The results file is named `<Application>-<Environment>.json`.
- Before each run the current results file is archived into `Results\history\` with a
  timestamp, then snapshots older than `-HistoryRetentionDays` (default **30**) are pruned.
- The HTML report is self-contained (embedded CSS/JS, no CDN) so it opens offline on a
  SharePoint server. It includes summary cards and an interactive matrix (search box and
  click-to-sort headers), with a colored status pill per cell.

## Regenerating a report from a saved snapshot

The HTML report can be rebuilt from any results JSON without touching the farm:

```powershell
Import-Module .\Modules\SPSTrust.Common\SPSTrust.Common.psd1
Export-SPSTrustReport -InputFile '.\Results\history\CONTOSO-PROD-20260710-1200.json' `
                      -OutputPath '.\Reports\CONTOSO-PROD-20260710-1200.html'
```

## Related parameters

| Parameter               | Default | Description |
| ----------------------- | ------- | ----------- |
| `-ReportOnly`           | off     | Read-only audit: skip all configuration stages, only collect state and write the report. |
| `-HistoryRetentionDays` | `30`    | Days of archived result snapshots to keep in `Results\history\`. `0` disables pruning. |

## See also

- [Usage](./Usage)
- [Configuration](./Configuration)
