function Get-SPSTrustStatus {
    <#
        .SYNOPSIS
        Collects the current cross-farm trust state as a read-only status object.

        .DESCRIPTION
        Get-SPSTrustStatus walks the declared topology (Farms x Trusts x Services x
        RemoteFarms) and resolves, for every publishing-farm / consuming-farm / service
        combination, the current state of each trust dimension by calling only the
        read-only Get-SPS* functions of the module:

        - RootTrust            (Get-SPSTrustedRootAuthority)
        - StsTrust             (Get-SPSTrustedServiceTokenIssuer)
        - Published            (Get-SPSPublishedServiceApplication)
        - TopologyPermission   (Get-SPSTopologyServiceAppPermission)
        - ServiceAppPermission (Get-SPSPublishedServiceAppPermission)
        - Proxy                (Get-SPSPublishedServiceAppProxy)

        The function performs **no** changes: it never publishes, grants, revokes,
        connects or removes anything. It is safe to run at any time to audit or document
        a topology, and is also used by SPSTrust.ps1 to produce the post-run report.

        Each dimension is reported as 'Present', 'Absent', 'N/A' (not applicable, e.g.
        STS/publish/proxy for a 'Content' service) or 'Error' (the underlying getter
        threw - the message is captured in the row's Notes field). One failing farm does
        not abort the whole audit.

        Returns an ordered hashtable suitable for ConvertTo-Json and for
        Export-SPSTrustReport.

        .PARAMETER Farms
        The farm inventory: an array of objects/hashtables each exposing Name and Server.

        .PARAMETER Trusts
        The trust definitions: an array of objects/hashtables each exposing LocalFarm,
        RemoteFarms and Services.

        .PARAMETER Domain
        DNS suffix appended to each farm Server value to build the target FQDN.

        .PARAMETER InstallAccount
        Credential used for the CredSSP remote sessions (the farm service account).

        .PARAMETER Application
        Application short name, stored in the status metadata.

        .PARAMETER Environment
        Environment name (e.g. PROD), stored in the status metadata.

        .PARAMETER Version
        Tool version string, stored in the status metadata.

        .EXAMPLE
        $status = Get-SPSTrustStatus -Farms $cfg.Farms -Trusts $cfg.Trusts -Domain $cfg.Domain -InstallAccount $cred
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Object[]]
        $Farms,

        [Parameter(Mandatory = $true)]
        [System.Object[]]
        $Trusts,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Domain,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $InstallAccount,

        [Parameter()]
        [System.String]
        $Application = '',

        [Parameter()]
        [System.String]
        $Environment = '',

        [Parameter()]
        [System.String]
        $Version = ''
    )

    # Build a farm-name -> target FQDN lookup from the inventory.
    $fqdnByFarm = @{}
    foreach ($farm in $Farms) {
        $fqdnByFarm[$farm.Name] = "$($farm.Server).$Domain"
    }

    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($trust in $Trusts) {
        $publishingFarm = $trust.LocalFarm
        $publishingServer = $fqdnByFarm[$publishingFarm]
        $services = @($trust.Services)

        foreach ($consumingFarm in $trust.RemoteFarms) {
            $consumingServer = $fqdnByFarm[$consumingFarm]

            # Per (publishing, consuming) dimensions: ROOT trust, Topology permission, Farm Id.
            $rootTrust = 'Error'
            $topologyPermission = 'Error'
            $notes = [System.Collections.Generic.List[string]]::new()

            try {
                $rootResult = Get-SPSTrustedRootAuthority -Name "$($consumingFarm)_ROOT" `
                    -Server $publishingServer -InstallAccount $InstallAccount
                $rootTrust = if ($rootResult.Ensure -eq 'Present') { 'Present' } else { 'Absent' }
            }
            catch {
                $notes.Add("ROOT: $($_.Exception.Message)")
            }

            $farmId = $null
            try {
                $farmId = Get-SPSFarmId -Server $consumingServer -InstallAccount $InstallAccount
            }
            catch {
                $notes.Add("FarmId: $($_.Exception.Message)")
            }

            if ($null -ne $farmId) {
                try {
                    $topoResult = Get-SPSTopologyServiceAppPermission -FarmId "$farmId" `
                        -Server $publishingServer -InstallAccount $InstallAccount
                    $topologyPermission = if ($topoResult.Ensure -eq 'Present') { 'Present' } else { 'Absent' }
                }
                catch {
                    $notes.Add("Topology: $($_.Exception.Message)")
                }
            }
            else {
                $topologyPermission = 'Error'
            }

            foreach ($service in $services) {
                $isContent = ($service -eq 'Content')
                $stsTrust = 'N/A'
                $published = 'N/A'
                $serviceAppPermission = 'N/A'
                $proxy = 'N/A'

                if (-not $isContent) {
                    try {
                        $stsResult = Get-SPSTrustedServiceTokenIssuer -Name "$($consumingFarm)_STS" `
                            -Server $publishingServer -InstallAccount $InstallAccount
                        $stsTrust = if ($stsResult.Ensure -eq 'Present') { 'Present' } else { 'Absent' }
                    }
                    catch {
                        $stsTrust = 'Error'
                        $notes.Add("STS: $($_.Exception.Message)")
                    }

                    try {
                        $pubResult = Get-SPSPublishedServiceApplication -Name $service `
                            -Server $publishingServer -InstallAccount $InstallAccount
                        $published = if ($pubResult.Ensure -eq 'Present') { 'Present' } else { 'Absent' }
                    }
                    catch {
                        $published = 'Error'
                        $notes.Add("Published: $($_.Exception.Message)")
                    }

                    if ($null -ne $farmId) {
                        try {
                            $saResult = Get-SPSPublishedServiceAppPermission -FarmId "$farmId" -Name $service `
                                -Server $publishingServer -InstallAccount $InstallAccount
                            $serviceAppPermission = if ($saResult.Ensure -eq 'Present') { 'Present' } else { 'Absent' }
                        }
                        catch {
                            $serviceAppPermission = 'Error'
                            $notes.Add("SAPermission: $($_.Exception.Message)")
                        }
                    }
                    else {
                        $serviceAppPermission = 'Error'
                    }

                    try {
                        $proxyResult = Get-SPSPublishedServiceAppProxy -Name $service `
                            -Server $publishingServer -InstallAccount $InstallAccount
                        $proxy = if ($proxyResult.Ensure -eq 'Present') { 'Present' } else { 'Absent' }
                    }
                    catch {
                        $proxy = 'Error'
                        $notes.Add("Proxy: $($_.Exception.Message)")
                    }
                }

                $rows.Add([ordered]@{
                        PublishingFarm       = $publishingFarm
                        PublishingServer     = $publishingServer
                        ConsumingFarm        = $consumingFarm
                        ConsumingServer      = $consumingServer
                        Service              = $service
                        RootTrust            = $rootTrust
                        StsTrust             = $stsTrust
                        Published            = $published
                        TopologyPermission   = $topologyPermission
                        ServiceAppPermission = $serviceAppPermission
                        Proxy                = $proxy
                        Notes                = ($notes -join '; ')
                    })
            }
        }
    }

    $status = [ordered]@{
        Application    = $Application
        Environment    = $Environment
        Domain         = $Domain
        Version        = $Version
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        RowCount       = $rows.Count
        Rows           = $rows.ToArray()
    }

    return $status
}
