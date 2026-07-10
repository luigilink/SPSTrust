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

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $InstallAccount,

    # Ensure parameter to specify whether to add (Present) or remove (Absent) permissions
    [Parameter()]
    [ValidateSet('Present', 'Absent')]
    [System.String]
    $Ensure = 'Present'
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

      # Grant or revoke permissions based on the Ensure parameter
      if ($params.Ensure -eq 'Present') {
        Grant-SPObjectSecurity -Identity $security `
          -Principal $principal `
          -Rights $spoRights `
          -Verbose
      }
      elseif ($params.Ensure -eq 'Absent') {
        Revoke-SPObjectSecurity -Identity $security `
          -Principal $principal `
          -Verbose
      }

      # Apply the updated security settings to the Targeted Service Application
      Set-SPServiceApplicationSecurity $serviceApp -ObjectSecurity $security -Verbose
    }
  }
}
