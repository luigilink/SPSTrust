@{
    RootModule        = 'SPSTrust.Common.psm1'
    ModuleVersion     = '2.1.0'
    GUID              = 'e1cce4f2-12de-4923-8e67-f37a081944aa'
    Author            = 'Jean-Cyril DROUHIN'
    CompanyName       = 'luigilink'
    Copyright         = '(c) Jean-Cyril DROUHIN. All rights reserved.'
    Description       = 'Shared functions for the SPSTrust toolkit (configure trust relationships between SharePoint Server farms: exchange STS/ROOT certificates, publish service applications, grant Topology and published service-application permissions, and connect service application proxies across farms).'

    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Backup-SPSJsonFile'
        'Clear-SPSLogFolder'
        'Export-SPSSecurityTokenCertificate'
        'Export-SPSTrustedRootAuthority'
        'Export-SPSTrustReport'
        'Get-SPSFarmId'
        'Get-SPSPublishedServiceAppPermission'
        'Get-SPSPublishedServiceAppProxy'
        'Get-SPSPublishedServiceApplication'
        'Get-SPSServer'
        'Get-SPSTopologyServiceAppPermission'
        'Get-SPSTrustedRootAuthority'
        'Get-SPSTrustedServiceTokenIssuer'
        'Get-SPSTrustStatus'
        'New-SPSPublishedServiceAppProxy'
        'Publish-SPSServiceApplication'
        'Remove-SPSPublishedServiceAppProxy'
        'Set-SPSPublishedServiceAppPermission'
        'Set-SPSTopologyServiceAppPermission'
        'Set-SPSTrustedRootAuthority'
        'Set-SPSTrustedServiceTokenIssuer'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('SharePoint', 'SharePointServer', 'Trust', 'ServiceApplication', 'CredSSP')
            LicenseUri   = 'https://github.com/luigilink/SPSTrust/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/luigilink/SPSTrust'
            ReleaseNotes = 'https://github.com/luigilink/SPSTrust/blob/main/RELEASE-NOTES.md'
        }
    }
}
