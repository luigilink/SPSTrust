# Usage

## Parameters

| Parameter               | Required | Description                                                                 |
| ----------------------- | -------- | --------------------------------------------------------------------------- |
| `-ConfigFile`           | Yes      | Path to the `.psd1` configuration file.                                     |
| `-FarmAccount`          | Yes      | Credential of the service account that runs the script (same on all farms). |
| `-CleanServices`        | No       | Switch. Removes published services and trust on each trusted farm.          |
| `-ReportOnly`           | No       | Switch. Read-only audit: skips all configuration stages and only writes the JSON + HTML trust matrix. |
| `-LogRetentionDays`     | No       | Days of transcript logs to keep in `Logs\`. Defaults to `180`. `0` disables pruning. |
| `-HistoryRetentionDays` | No       | Days of archived result snapshots to keep in `Results\history\`. Defaults to `30`. `0` disables pruning. |

### Basic usage example

Establish trust with a specified configuration and farm account:

```powershell
.\SPSTrust.ps1 -ConfigFile '.\Config\CONTOSO-PROD.psd1' -FarmAccount (Get-Credential)
```

### Clean services usage example

Remove published services and trust on each trusted farm (note that `-FarmAccount`
is still required):

```powershell
.\SPSTrust.ps1 -ConfigFile '.\Config\CONTOSO-PROD.psd1' -FarmAccount (Get-Credential) -CleanServices
```

### Read-only audit example

Produce a trust matrix (JSON + HTML) without changing anything:

```powershell
.\SPSTrust.ps1 -ConfigFile '.\Config\CONTOSO-PROD.psd1' -FarmAccount (Get-Credential) -ReportOnly
```

### Custom log retention

Keep 30 days of transcript logs instead of the default 180:

```powershell
.\SPSTrust.ps1 -ConfigFile '.\Config\CONTOSO-PROD.psd1' -FarmAccount (Get-Credential) -LogRetentionDays 30
```

## Output

- **Transcript logs** are written to a `Logs\` folder next to `SPSTrust.ps1`, named
  `<Application>-<Environment>-<date>.log`. Logs older than `-LogRetentionDays` are
  pruned at the end of each run.
- **Results & report** — every run (including `-ReportOnly`) writes a JSON snapshot to
  `Results\<Application>-<Environment>.json` and an HTML trust matrix to
  `Reports\<Application>-<Environment>.html`. See the [Reports & Audit](./Reports) page.
- Progress and per-farm results are streamed to the console (and captured in the transcript).

## Next Step

See the [Reports & Audit](./Reports) page for the trust matrix, or the
[Release Process](./Release-Process) page for how new versions are shipped.
