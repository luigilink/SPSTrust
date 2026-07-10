# SPSTrust - SharePoint Trust Farm Tool

SPSTrust is a PowerShell script tool to configure trust relationships between SharePoint Server farms — exchanging STS/ROOT certificates, publishing service applications, granting Topology and published service-application permissions, and connecting service application proxies across farms.

It follows the Microsoft guidance [Share service applications across farms in SharePoint Server](https://learn.microsoft.com/en-us/sharepoint/administration/share-service-applications-across-farms) and is compatible with all supported on-premises versions (SharePoint Server 2016 to Subscription Edition).

## Key Features

- Declarative, JSON-free configuration via a PowerShell data file (`.psd1`)
- Idempotent: safe to re-run — it only creates what is missing
- `-CleanServices` switch to tear down published services and trust
- `-ReportOnly` read-only audit mode producing a JSON + HTML trust matrix
- Shared logic packaged in the reusable `SPSTrust.Common` module
- Transcript logging with automatic retention/rotation

## Documentation

- [🚀 Getting Started](./Getting-Started)
- [⚙️ Configuration](./Configuration)
- [📖 Usage](./Usage)
- [📊 Reports & Audit](./Reports)
- [📦 Release Process](./Release-Process)

## Requirements

- PowerShell 5.1 or later
- CredSSP configured between the servers
- Administrative privileges on the SharePoint servers
- The same farm service account used across all farms being trusted
