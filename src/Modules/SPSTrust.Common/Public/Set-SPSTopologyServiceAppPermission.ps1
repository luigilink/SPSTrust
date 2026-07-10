function Set-SPSTopologyServiceAppPermission {
  [CmdletBinding()]
  param
  (
    # Farm ID for which the permissions are being set
    [Parameter(Mandatory = $true)]
    [System.String]
    $FarmId,

    # Server where the command will be executed
    [Parameter(Mandatory = $true)]
    [System.String]
    $Server,

    # Credentials to use for executing the command
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

  # Invoke the command on the specified server with the provided credentials
  Invoke-SPSCommand -Credential $InstallAccount `
    -Arguments $PSBoundParameters `
    -Server $Server `
    -ScriptBlock {
    $params = $args[0]

    # Get the security settings for the Topology Service Application
    $security = Get-SPTopologyServiceApplication | Get-SPServiceApplicationSecurity

    # Get the claim provider and define the claim type for the Farm ID
    $claimProvider = (Get-SPClaimProvider System).ClaimProvider
    $claimType = 'http://schemas.microsoft.com/sharepoint/2009/08/claims/farmid'

    # Create a new claims principal for the Farm ID
    $principal = New-SPClaimsPrincipal -ClaimType $claimType `
      -ClaimProvider $claimProvider `
      -ClaimValue $($params.FarmId)

    # Grant or revoke permissions based on the Ensure parameter
    if ($params.Ensure -eq 'Present') {
      Grant-SPObjectSecurity -Identity $security `
        -Principal $principal `
        -Rights 'Full Control' `
        -Verbose
    }
    elseif ($params.Ensure -eq 'Absent') {
      Revoke-SPObjectSecurity -Identity $security `
        -Principal $principal `
        -Verbose
    }

    # Apply the updated security settings to the Topology Service Application
    Get-SPTopologyServiceApplication | Set-SPServiceApplicationSecurity -ObjectSecurity $security -Verbose
  }
}

