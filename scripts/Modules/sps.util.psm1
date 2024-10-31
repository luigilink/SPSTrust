function Get-SPSFarmId {
  [CmdletBinding()]
  [OutputType([System.Collections.Hashtable])]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose "Getting Farm ID of Farm '$Server'"
  $result = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
            (Get-SPFarm).ID.Guid
  }
  return $result
}
function Get-SPSTrustedRootAuthority {
  [CmdletBinding()]
  [OutputType([System.Collections.Hashtable])]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.String]
    $CertificateThumbprint,

    [Parameter()]
    [System.String]
    $CertificateFilePath,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose "Getting Trusted Root Authority with name '$Name'"

  if (-not ($PSBoundParameters.ContainsKey("CertificateThumbprint")) -and `
      -not($PSBoundParameters.ContainsKey("CertificateFilePath"))) {
    Write-Verbose -Message ("At least one of the following parameters must be specified: " + `
        "CertificateThumbprint, CertificateFilePath.")
  }
  $result = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    $rootCert = Get-SPTrustedRootAuthority -Identity $params.Name -ErrorAction SilentlyContinue
    $ensure = 'Absent'

    if ($null -eq $rootCert) {
      return @{
        Name                  = $params.Name
        CertificateThumbprint = [string]::Empty
        CertificateFilePath   = ''
        Ensure                = $ensure
      }
    }
    else {
      $ensure = 'Present'
      return @{
        Name                  = $params.Name
        CertificateThumbprint = $rootCert.Certificate.Thumbprint
        CertificateFilePath   = ''
        Ensure                = $ensure
      }
    }
  }
  return $result
}
function Set-SPSTrustedRootAuthority {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.String]
    $CertificateThumbprint,

    [Parameter()]
    [String]
    $CertificateFilePath,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $InstallAccount,

    [Parameter()]
    [ValidateSet('Present', 'Absent')]
    [System.String]
    $Ensure = 'Present'
  )

  Write-Verbose -Message "Setting SPTrustedRootAuthority '$Name'"
  if ($Ensure -eq 'Present') {
    if (-not ($PSBoundParameters.ContainsKey("CertificateThumbprint")) -and `
        -not($PSBoundParameters.ContainsKey("CertificateFilePath"))) {
      $message = ("At least one of the following parameters must be specified: " + `
          "CertificateThumbprint, CertificateFilePath.")
      throw $message
    }

    if ($PSBoundParameters.ContainsKey("CertificateFilePath") -and `
        -not ($PSBoundParameters.ContainsKey("CertificateThumbprint"))) {
      if (-not (Test-Path -Path $CertificateFilePath)) {
        $message = ("Specified CertificateFilePath does not exist: $CertificateFilePath")
        throw $message
      }
    }
  }

  $null = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments @($PSBoundParameters, $MyInvocation.MyCommand.Source) `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    if ($params.Ensure -eq 'Absent') {
      Write-Verbose -Message "Removing SPTrustedRootAuthority '$params.Name'"
      Remove-SPTrustedRootAuthority -Identity $params.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
    else {
      if ($params.ContainsKey("CertificateFilePath")) {
        Write-Verbose -Message "Importing certificate from CertificateFilePath"
        try {
          $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
          $cert.Import($params.CertificateFilePath)
        }
        catch {
          $message = "An error occured: $($_.Exception.Message)"
          throw $message
        }

        if ($null -eq $cert) {
          $message = "Import of certificate failed."
          throw $message
        }

        if ($params.ContainsKey("CertificateThumbprint")) {
          if (-not $params.CertificateThumbprint.Equals($cert.Thumbprint)) {
            $message = "Imported certificate thumbprint ($($cert.Thumbprint)) does not match expected thumbprint ($($params.CertificateThumbprint))."
            throw $message
          }
        }
      }
      else {
        Write-Verbose -Message "Importing certificate from CertificateThumbprint"
        $cert = Get-Item -Path "CERT:\LocalMachine\My\$($params.CertificateThumbprint)" `
          -ErrorAction SilentlyContinue

        if ($null -eq $cert) {
          $message = "Certificate not found in the local Certificate Store"
          throw $message
        }
      }

      if ($cert.HasPrivateKey) {
        Write-Verbose -Message "Certificate has private key. Removing private key."
        $pubKeyBytes = $cert.Export("cert")
        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert2.Import($pubKeyBytes)
        $cert = $cert2
      }

      Write-Verbose -Message "Updating Root Authority"
      New-SPTrustedRootAuthority -Name $params.Name -Certificate $cert
    }
  }
}
function Get-SPSTrustedServiceTokenIssuer {
  [CmdletBinding()]
  [OutputType([System.Collections.Hashtable])]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.String]
    $CertificateThumbprint,

    [Parameter()]
    [System.String]
    $CertificateFilePath,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose "Getting Trusted Service Token Issuer with name '$Name'"

  if (-not ($PSBoundParameters.ContainsKey("CertificateThumbprint")) -and `
      -not($PSBoundParameters.ContainsKey("CertificateFilePath"))) {
    Write-Verbose -Message ("At least one of the following parameters must be specified: " + `
        "CertificateThumbprint, CertificateFilePath.")
  }
  $result = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    $rootCert = Get-SPTrustedServiceTokenIssuer -Identity $params.Name -ErrorAction SilentlyContinue
    $ensure = 'Absent'

    if ($null -eq $rootCert) {
      return @{
        Name                  = $params.Name
        CertificateThumbprint = [string]::Empty
        CertificateFilePath   = ''
        Ensure                = $ensure
      }
    }
    else {
      $ensure = 'Present'
      return @{
        Name                  = $params.Name
        CertificateThumbprint = $rootCert.Certificate.Thumbprint
        CertificateFilePath   = ''
        Ensure                = $ensure
      }
    }
  }
  return $result
}
function Set-SPSTrustedServiceTokenIssuer {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.String]
    $CertificateThumbprint,

    [Parameter()]
    [String]
    $CertificateFilePath,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $InstallAccount,

    [Parameter()]
    [ValidateSet('Present', 'Absent')]
    [System.String]
    $Ensure = 'Present'
  )

  Write-Verbose -Message "Setting SPTrustedServiceTokenIssuer '$Name'"
  if ($Ensure -eq 'Present') {
    if (-not ($PSBoundParameters.ContainsKey("CertificateThumbprint")) -and `
        -not($PSBoundParameters.ContainsKey("CertificateFilePath"))) {
      $message = ("At least one of the following parameters must be specified: " + `
          "CertificateThumbprint, CertificateFilePath.")
      throw $message
    }

    if ($PSBoundParameters.ContainsKey("CertificateFilePath") -and `
        -not ($PSBoundParameters.ContainsKey("CertificateThumbprint"))) {
      if (-not (Test-Path -Path $CertificateFilePath)) {
        $message = ("Specified CertificateFilePath does not exist: $CertificateFilePath")
        throw $message
      }
    }
  }

  $null = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments @($PSBoundParameters, $MyInvocation.MyCommand.Source) `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    if ($params.Ensure -eq 'Absent') {
      Write-Verbose -Message "Removing SPTrustedIdentityTokenIssuer '$params.Name'"
      Remove-SPTrustedIdentityTokenIssuer -Identity $params.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
    else {
      if ($params.ContainsKey("CertificateFilePath")) {
        Write-Verbose -Message "Importing certificate from CertificateFilePath"
        try {
          $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
          $cert.Import($params.CertificateFilePath)
        }
        catch {
          $message = "An error occured: $($_.Exception.Message)"
          throw $message
        }

        if ($null -eq $cert) {
          $message = "Import of certificate failed."
          throw $message
        }

        if ($params.ContainsKey("CertificateThumbprint")) {
          if (-not $params.CertificateThumbprint.Equals($cert.Thumbprint)) {
            $message = "Imported certificate thumbprint ($($cert.Thumbprint)) does not match expected thumbprint ($($params.CertificateThumbprint))."
            throw $message
          }
        }
      }
      else {
        Write-Verbose -Message "Importing certificate from CertificateThumbprint"
        $cert = Get-Item -Path "CERT:\LocalMachine\My\$($params.CertificateThumbprint)" `
          -ErrorAction SilentlyContinue

        if ($null -eq $cert) {
          $message = "Certificate not found in the local Certificate Store"
          throw $message
        }
      }

      if ($cert.HasPrivateKey) {
        Write-Verbose -Message "Certificate has private key. Removing private key."
        $pubKeyBytes = $cert.Export("cert")
        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert2.Import($pubKeyBytes)
        $cert = $cert2
      }

      Write-Verbose -Message "Adding STS SPTrustedServiceTokenIssuer"
      New-SPTrustedServiceTokenIssuer -Name $params.Name -Certificate $cert
    }
  }
}
function Export-SPSTrustedRootAuthority {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [String]
    $CertificateFilePath,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Exporting SPTrustedRootAuthority '$Name'"

  $null = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments @($PSBoundParameters, $MyInvocation.MyCommand.Source) `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]
    $trustType = 'ROOT'
    $certPath = "$($params.CertificateFilePath)\$($params.Name)_$($trustType).cer"
    $certRoot = Get-SPCertificateAuthority -ErrorAction SilentlyContinue

    if ($null -eq $certRoot) {
      $message = "ROOT Certificate not found in Farm $params.Name"
      throw $message
    }
    else {
      $spRootCertificate = $certRoot.RootCertificate
      [byte[]]$rawcert = $spRootCertificate.RawData

      Write-Verbose -Message "Saving SPTrustedRootAuthority to '$certPath'"
      $rawcert | Set-Content -Path $certPath -Encoding Byte;
    }
  }
}
function Get-SPSPublishedServiceApplication {
  [CmdletBinding()]
  [OutputType([System.Collections.Hashtable])]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Getting service application publish status '$Name'"

  $result = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    $serviceApp = Get-SPServiceApplication -Name $params.Name -ErrorAction SilentlyContinue
    if ($null -eq $serviceApp) {
      Write-Verbose -Message "The service application $Name does not exist"
      $sharedEnsure = "Absent"
    }
    if ($null -eq $serviceApp.Uri) {
      Write-Verbose -Message ("Only Business Data Connectivity, Machine Translation, Managed Metadata, " + `
          "User Profile, Search, Secure Store are supported to be published via DSC.")
      $sharedEnsure = "Absent"
    }
    else {
      if ($serviceApp.Shared -eq $true) {
        $sharedEnsure = "Present"
      }
      elseif ($serviceApp.Shared -eq $false) {
        $sharedEnsure = "Absent"
      }
    }
    return @{
      Name   = $params.Name
      Ensure = $sharedEnsure
      Uri    = $serviceApp.Uri.tostring()
    }
  }
  return $result
}
function Get-SPSPublishedServiceAppProxy {
  [CmdletBinding()]
  [OutputType([System.Collections.Hashtable])]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Getting service application proxy '$Name'"

  $result = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    $serviceAppProxies = Get-SPServiceApplicationProxy -ErrorAction SilentlyContinue
    if ($null -ne $serviceAppProxies) {
      $serviceAppProxy = $serviceAppProxies | Where-Object -FilterScript {
        $_.Name -eq $params.Name
      }
      if ($null -ne $serviceAppProxy) {
        $currentEnsure = 'Present'
      }
      else {
        Write-Verbose -Message "The service application proxy $Name does not exist"
        $currentEnsure = 'Absent'
      }
    }
    return @{
      Name   = $params.Name
      Ensure = $currentEnsure
    }
  }
  return $result
}
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
    $Server,

    [Parameter()]
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

    switch ($params.Name) {
      { $_.contains('SCH') } {
        New-SPEnterpriseSearchServiceApplicationProxy -Name $params.Name `
          -Uri $params.ServiceUri `
          -Verbose
      }
      { $_.contains('UPS') } {
        New-SPProfileServiceApplicationProxy -Name $params.Name `
          -Uri $params.ServiceUri `
          -DefaultProxyGroup `
          -Verbose
      }
      { $_.contains('DAT') } {
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
      { $_.contains('SSA') } {
        New-SPSecureStoreServiceApplicationProxy -Name $params.Name `
          -Uri $params.ServiceUri `
          -DefaultProxyGroup `
          -Verbose
      }
    }
  }
}
function Remove-SPSPublishedServiceAppProxy {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Removing service application proxy '$Name' on '$Server'"
  Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    $serviceAppProxies = Get-SPServiceApplicationProxy -ErrorAction SilentlyContinue
    if ($null -ne $serviceAppProxies) {
      $serviceAppProxy = $serviceAppProxies | Where-Object -FilterScript {
        $_.Name -eq $params.Name
      }
      if ($null -ne $serviceAppProxy) {
        Remove-SPServiceApplicationProxy $serviceAppProxy -RemoveData -Confirm:$false -Verbose
        Write-Verbose -Message "The service application proxy $($params.Name) was successfully removed"
      }
      else {
        Write-Verbose -Message "The service application proxy $($params.Name) does not exist"
      }
    }
  }
}
function Publish-SPSServiceApplication {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $InstallAccount,

    [Parameter()]
    [ValidateSet('Present', 'Absent')]
    [System.String]
    $Ensure = 'Present'
  )

  Write-Verbose -Message "Setting service application publish status '$Name'"
  Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    $serviceApp = Get-SPServiceApplication -Name $params.Name -ErrorAction SilentlyContinue
    if ($null -eq $serviceApp) {
      $message = ("The service application $($params.Name) does not exist")
      throw $message
    }

    if ($null -eq $serviceApp.Uri) {
      $message = ("Only Business Data Connectivity, Machine Translation, Managed Metadata, " + `
          "User Profile, Search, Secure Store are supported to be published via DSC.")
      throw $message
    }

    if ($params.Ensure -eq 'Present') {
      Write-Verbose -Message "Publishing Service Application $($params.Name)"
      if ($serviceApp.DefaultEndpoint.DisplayName -eq 'http') {
        $httpsEndpoint = $serviceApp.Endpoints | Where-Object -FilterScript { $_.DisplayName -eq 'https' }
        Set-SPServiceApplication $serviceApp -DefaultEndpoint $httpsEndpoint -Confirm:$false -Verbose
      }
      Publish-SPServiceApplication -Identity $serviceApp -Verbose
    }

    if ($params.Ensure -eq 'Absent') {
      Write-Verbose -Message "Unpublishing Service Application $($params.Name)"
      Unpublish-SPServiceApplication  -Identity $serviceApp -Verbose
    }
  }
}
function Get-SPSTopologyServiceAppPermission {
  [CmdletBinding()]
  [OutputType([System.Collections.Hashtable])]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $FarmId,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Getting Topology Service permissions for FarmID '$FarmId'"
  $result = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]
    $ensure = 'Absent'

    $security = Get-SPTopologyServiceApplication | Get-SPServiceApplicationSecurity
    $getAccessRule = $security.AccessRules | Where-Object -FilterScript { $_.Name -eq "c:0%.c|system|$($params.FarmId)" }

    if ($null -eq $getAccessRule) {
      return @{
        Server = $params.Server
        Ensure = $ensure
      }
    }
    else {
      $ensure = 'Present'
      return @{
        Server = $params.Server
        Ensure = $ensure
      }
    }
  }
  return $result
}
function Set-SPSTopologyServiceAppPermission {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $FarmId,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Setting Topology Service permissions for FarmID '$FarmId'"
  Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    $security = Get-SPTopologyServiceApplication | Get-SPServiceApplicationSecurity
    $claimProvider = (Get-SPClaimProvider System).ClaimProvider
    $claimType = 'http://schemas.microsoft.com/sharepoint/2009/08/claims/farmid'
    $principal = New-SPClaimsPrincipal -ClaimType $claimType `
      -ClaimProvider $claimProvider `
      -ClaimValue $($params.FarmId)

    Grant-SPObjectSecurity -Identity $security `
      -Principal $principal `
      -Rights 'Full Control' `
      -Verbose

    Get-SPTopologyServiceApplication | Set-SPServiceApplicationSecurity -ObjectSecurity $security -Verbose
  }
}
function Get-SPSPublishedServiceAppPermission {
  [CmdletBinding()]
  [OutputType([System.Collections.Hashtable])]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $FarmId,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Getting Topology Service permissions for FarmID '$FarmId'"
  $result = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]
    $ensure = 'Absent'

    $serviceApp = Get-SPServiceApplication -Name $params.Name -ErrorAction SilentlyContinue
    if ($null -eq $serviceApp) {
      $message = ("The service application $($params.Name) does not exist")
      throw $message
    }

    if ($null -eq $serviceApp.Uri) {
      $message = ("Only Business Data Connectivity, Machine Translation, Managed Metadata, " + `
          "User Profile, Search, Secure Store are supported to be published via DSC.")
      throw $message
    }

    $security = Get-SPServiceApplication $serviceApp | Get-SPServiceApplicationSecurity
    $getAccessRule = $security.AccessRules | Where-Object -FilterScript { $_.Name -eq "c:0%.c|system|$($params.FarmId)" }

    if ($null -eq $getAccessRule) {
      return @{
        Server = $params.Server
        Name   = $params.Name
        Ensure = $ensure
      }
    }
    else {
      $ensure = 'Present'
      return @{
        Server = $params.Server
        Name   = $params.Name
        Ensure = $ensure
      }
    }
  }
  return $result
}
function Set-SPSPublishedServiceAppPermission {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $FarmId,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Setting Topology Service permissions for FarmID '$FarmId'"
  Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    $serviceApp = Get-SPServiceApplication -Name $params.Name -ErrorAction SilentlyContinue
    if ($null -eq $serviceApp) {
      $message = ("The service application $($params.Name) does not exist")
      throw $message
    }

    if ($null -eq $serviceApp.Uri) {
      $message = ("Only Business Data Connectivity, Machine Translation, Managed Metadata, " + `
          "User Profile, Search, Secure Store are supported to be published via DSC.")
      throw $message
    }

    if ($serviceApp.GetType().ToString() -eq 'Microsoft.Office.Server.Administration.UserProfileApplication') {
      Write-Verbose -Message 'The User Profile Application requires domain credentials for connection access'
      Write-Verbose -Message 'Check that web app pool account exists in the connect permissions'
    }
    else {
      $security = Get-SPServiceApplication $serviceApp | Get-SPServiceApplicationSecurity
      $claimProvider = (Get-SPClaimProvider System).ClaimProvider
      $claimType = 'http://schemas.microsoft.com/sharepoint/2009/08/claims/farmid'
      $spoRights = $security.NamedAccessRights.Name
      $principal = New-SPClaimsPrincipal -ClaimType $claimType `
        -ClaimProvider $claimProvider `
        -ClaimValue $($params.FarmId)


      Grant-SPObjectSecurity -Identity $security `
        -Principal $principal `
        -Rights $spoRights `
        -Verbose

      Set-SPServiceApplicationSecurity $serviceApp -ObjectSecurity $security -Verbose
    }
  }
}
function Export-SPSSecurityTokenCertificate {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [System.String]
    $Name,

    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    [Parameter()]
    [String]
    $CertificateFilePath,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $InstallAccount
  )

  Write-Verbose -Message "Exporting SPSecurityTokenCertificate '$Name'"

  $null = Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments @($PSBoundParameters, $MyInvocation.MyCommand.Source) `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]
    $trustType = 'STS'
    $certPath = "$($params.CertificateFilePath)\$($params.Name)_$($trustType).cer"
    $certSTS = Get-SPSecurityTokenServiceConfig -ErrorAction SilentlyContinue

    if ($null -eq $certSTS) {
      $message = "STS Certificate not found in Farm $params.Name"
      throw $message
    }
    else {
      $spSTSCertificate = $certSTS.LocalLoginProvider.SigningCertificate
      [byte[]]$rawcert = $spSTSCertificate.RawData

      Write-Verbose -Message "Saving SPSecurityTokenCertificate to '$certPath'"
      $rawcert | Set-Content -Path $certPath -Encoding Byte;
    }
  }
}
