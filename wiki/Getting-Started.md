# Getting Started

## Prerequisites

- PowerShell 5.1 or later
- CredSSP configured between the servers
- Administrative privileges on the SharePoint Server
- The **same** farm service account across every farm you want to trust

## How it works

SPSTrust is an idempotent orchestration script. Given your farm topology and the
trust relationships you declare in a configuration file, it performs four stages:

1. **Exchange certificates** — export each farm's STS and ROOT certificates to a
   shared folder, then import them on the publishing farms.
2. **Publish service applications** — publish each declared service application on
   its local (publishing) farm.
3. **Grant permissions** — grant the consuming farms access to the Application
   Discovery and Load Balancing (Topology) service and to each published service
   application.
4. **Connect proxies** — create the service application proxy on each consuming farm.

The `-CleanServices` switch reverses every stage (remove proxies, revoke
permissions, unpublish, and remove trust).

Shared logic lives in the `SPSTrust.Common` PowerShell module (`Modules/SPSTrust.Common`),
which the entry script imports at runtime. Remote actions are executed on the target
servers through `New-PSSession` with **CredSSP** authentication.

## Configure CredSSP

### Option 1: Manually configure CredSSP

You can manually configure CredSSP through a few PowerShell cmdlets (and potentially
group policy to configure the allowed delegate computers). Some basic instructions can
be found at [Understanding CredSSP](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider).

### Option 2: Configure CredSSP through a DSC resource

It is possible to use a DSC resource to configure your CredSSP settings on a server and
include this in all of your SharePoint server configurations. This is done through the
[xCredSSP](https://github.com/dsccommunity/xCredSSP) resource. The example below shows
how this can be used.

```powershell
xCredSSP CredSSPServer { Ensure = "Present"; Role = "Server" }
xCredSSP CredSSPClient { Ensure = "Present"; Role = "Client"; DelegateComputers = $CredSSPDelegates }
```

In the above example, `$CredSSPDelegates` can be a wildcard name (such as `*.contoso.com`
to allow all servers in the contoso.com domain), or a list of specific servers (such as
`server1`, `server2` to allow only specific servers).

## Installation

1. [Download the latest release](https://github.com/luigilink/SPSTrust/releases/latest)
   and unzip it to a directory on one of your SharePoint Servers. The archive extracts to
   `SPSTrust.ps1` and a `Modules/` folder.
2. Prepare your configuration file. Copy `Config/CONTOSO-PROD.example.psd1` to
   `Config/<Application>-<Environment>.psd1` and edit it — see the
   [Configuration](./Configuration) page for details.
3. Run the script:

```powershell
.\SPSTrust.ps1 -ConfigFile '.\Config\CONTOSO-PROD.psd1' -FarmAccount (Get-Credential)
```

## Next Step

Continue to the [Configuration](./Configuration) page.

## Change log

A full list of changes in each version can be found in the [change log](https://github.com/luigilink/SPSTrust/blob/main/CHANGELOG.md).
