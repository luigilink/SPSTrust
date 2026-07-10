# Usage

## Parameters

| Parameter           | Required | Description                                                                 |
| ------------------- | -------- | --------------------------------------------------------------------------- |
| `-ConfigFile`       | Yes      | Path to the `.psd1` configuration file.                                     |
| `-FarmAccount`      | Yes      | Credential of the service account that runs the script (same on all farms). |
| `-CleanServices`    | No       | Switch. Removes published services and trust on each trusted farm.          |
| `-LogRetentionDays` | No       | Days of transcript logs to keep in `Logs\`. Defaults to `180`. `0` disables pruning. |

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

### Custom log retention

Keep 30 days of transcript logs instead of the default 180:

```powershell
.\SPSTrust.ps1 -ConfigFile '.\Config\CONTOSO-PROD.psd1' -FarmAccount (Get-Credential) -LogRetentionDays 30
```

## Output

- **Transcript logs** are written to a `Logs\` folder next to `SPSTrust.ps1`, named
  `<Application>-<Environment>-<date>.log`. Logs older than `-LogRetentionDays` are
  pruned at the end of each run.
- Progress and per-farm results are streamed to the console (and captured in the transcript).

## Next Step

See the [Release Process](./Release-Process) page for how new versions are shipped.
