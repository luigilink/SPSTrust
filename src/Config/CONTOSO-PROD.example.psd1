@{
    # SPSTrust configuration file (PowerShell data file).
    # Copy this example to '<Application>-<Environment>.psd1' (e.g. CONTOSO-PROD.psd1)
    # and adjust the values to match your environment, then run:
    #   .\SPSTrust.ps1 -ConfigFile '.\Config\CONTOSO-PROD.psd1' -FarmAccount (Get-Credential)

    # Logical environment name (e.g. PROD, PPRD, DEV). Used in log file names.
    ConfigurationName = 'PROD'

    # Application / customer short name. Used in log file names.
    ApplicationName   = 'contoso'

    # DNS domain suffix appended to each farm 'Server' value to build the FQDN.
    Domain            = 'contoso.com'

    # UNC path to the shared folder used to exchange STS/ROOT certificates between farms.
    CertFileShared    = '\\srvfileshared.contoso.com\certsfolder'

    # Trust relationships. For each local (publishing) farm, list the remote
    # (consuming) farms and the service applications to publish/consume.
    # Use the service name 'Content' for a content farm that only exchanges
    # ROOT trust (no STS, no published service application).
    Trusts            = @(
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

    # Farm inventory. 'Name' is the logical farm name referenced by Trusts;
    # 'Server' is the short host name of a server in that farm (Domain is appended).
    Farms             = @(
        @{
            Name   = 'SEARCH'
            Server = 'srvcontososearch'
        }
        @{
            Name   = 'SERVICES'
            Server = 'srvcontososervices'
        }
        @{
            Name   = 'CONTENT'
            Server = 'srvcontosocontent'
        }
    )
}
