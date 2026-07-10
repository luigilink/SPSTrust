function New-SPSPublishedServiceAppProxy {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $ServiceUri,

    [Parameter(Mandatory = $true)]
    [System.String]
    $ServiceType,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Adding service application proxy '$Name' on '$Server'"
  Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    Receive-SPServiceApplicationConnectionInfo -FarmUrl $params.ServiceUri | Out-Null

    switch ($params.ServiceType) {
      { $_.contains('SearchServiceApplication') } {
        New-SPEnterpriseSearchServiceApplicationProxy -Name $params.Name `
          -Uri $params.ServiceUri `
          -Verbose
      }
      { $_.contains('UserProfileApplication') } {
        New-SPProfileServiceApplicationProxy -Name $params.Name `
          -Uri $params.ServiceUri `
          -DefaultProxyGroup `
          -Verbose
      }
      { $_.contains('MetadataWebServiceApplication') } {
        New-SPMetadataServiceApplicationProxy -Name $params.Name `
          -Uri $params.ServiceUri `
          -DefaultProxyGroup `
          -Verbose
        $mmsProxy = Get-SPMetadataServiceApplicationProxy $params.Name
        $mmsProxy.Properties.IsDefaultSiteCollectionTaxonomy = $true
        $mmsProxy.Properties.IsContentTypePushdownEnabled = $true
        $mmsProxy.Properties.IsDefaultKeywordTaxonomy = $true
        $mmsProxy.Update()
      }
      { $_.contains('SPSecurityTokenServiceApplication') } {
        New-SPSecureStoreServiceApplicationProxy -Name $params.Name `
          -Uri $params.ServiceUri `
          -DefaultProxyGroup `
          -Verbose
      }
      { $_.contains('TranslationServiceApplication') } {
        New-SPTranslationServiceApplicationProxy -Name $params.Name `
          -Uri $params.ServiceUri `
          -DefaultProxyGroup `
          -Verbose
      }
    }
  }
}
