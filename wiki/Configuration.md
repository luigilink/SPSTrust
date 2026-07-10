# Configuration

SPSTrust is configured with a **PowerShell data file** (`.psd1`). Copy the bundled
`Config/CONTOSO-PROD.example.psd1` to `Config/<Application>-<Environment>.psd1` and adjust
the values for your environment. Below is the sample structure:

```powershell
@{
    ConfigurationName = 'PROD'
    ApplicationName   = 'contoso'
    Domain            = 'contoso.com'
    CertFileShared    = '\\srvfileshared.contoso.com\certsfolder'

    Trusts = @(
        @{
            LocalFarm   = 'SEARCH'
            RemoteFarms = @('CONTENT', 'SERVICES')
            Services    = @('CONTOSOPRODSCH')
        }
        @{
            LocalFarm   = 'SERVICES'
            RemoteFarms = @('CONTENT', 'SEARCH')
            Services    = @('CONTOSOPRODUPS', 'CONTOSOPRODMMS', 'CONTOSOPRODSSA')
        }
        @{
            LocalFarm   = 'CONTENT'
            RemoteFarms = @('SEARCH', 'SERVICES')
            Services    = @('Content')
        }
    )

    Farms = @(
        @{ Name = 'SEARCH';   Server = 'srvcontososearch'   }
        @{ Name = 'SERVICES'; Server = 'srvcontososervices' }
        @{ Name = 'CONTENT';  Server = 'srvcontosocontent'  }
    )
}
```

> [!NOTE]
> Earlier releases (1.x) used a JSON configuration file. Starting with 2.0.0 the
> configuration is a PowerShell data file (`.psd1`) loaded with `Import-PowerShellDataFile`.
> Convert your JSON to the equivalent `.psd1` hashtable shown above.

## Configuration and Application

- `ConfigurationName` populates the `Environment` variable (e.g. `PROD`, `PPRD`, `DEV`).
- `ApplicationName` populates the `Application` variable (e.g. `contoso`).

Together they name the transcript log file (`<Application>-<Environment>-<date>.log`).

## Domain

`Domain` is the DNS suffix appended to each farm's `Server` value to build the fully
qualified server name targeted by the remote sessions (e.g. `srvcontososearch` +
`contoso.com` → `srvcontososearch.contoso.com`).

## Certificate Configuration

`CertFileShared` is the UNC path of the shared folder used to exchange STS/ROOT
certificates between farms (e.g. `\\srvfileshared.contoso.com\certsfolder`). It must be
reachable by all relevant servers.

> [!IMPORTANT]
> The credential passed to `-FarmAccount` needs **write** permission on this file share.

## Trust Relationships

Each entry in `Trusts` defines one **local (publishing) farm**, the **remote (consuming)
farms** that trust it, and the **services** it exposes.

### Trust Definitions

1. **SEARCH Farm**
   - **Trusted Remote Farms**: `CONTENT`, `SERVICES`
   - **Exposed Services**: `CONTOSOPRODSCH`
2. **SERVICES Farm**
   - **Trusted Remote Farms**: `CONTENT`, `SEARCH`
   - **Exposed Services**:
     - `CONTOSOPRODUPS` (User Profile Service)
     - `CONTOSOPRODMMS` (Managed Metadata Service)
     - `CONTOSOPRODSSA` (Search Service Application)
3. **CONTENT Farm**
   - **Trusted Remote Farms**: `SEARCH`, `SERVICES`
   - **Exposed Service**: `Content`

> [!NOTE]
> The special service name `Content` marks a content farm that only exchanges ROOT
> trust — no STS trust, no published service application, and no proxy are created for it.

> [!IMPORTANT]
> You must use the **same service account** to configure trust between all farms.

## Farm Server Details

Each farm is associated with a dedicated server:

| Farm Name | Server Name        |
| --------- | ------------------ |
| SEARCH    | srvcontososearch   |
| SERVICES  | srvcontososervices |
| CONTENT   | srvcontosocontent  |

## Notes

- **UNC syntax**: in a `.psd1` single-quoted string, backslashes are literal — use the
  path as-is (`\\server\share`), with no JSON-style escaping.
- **Farm names**: `LocalFarm` and `RemoteFarms` values must match the `Farms[].Name`
  values exactly to resolve the trust relationships.
- **Service availability**: each farm exposes its services only to the trusted farms you
  list, keeping the setup segmented.

## Next Step

Continue to the [Usage](./Usage) page.
