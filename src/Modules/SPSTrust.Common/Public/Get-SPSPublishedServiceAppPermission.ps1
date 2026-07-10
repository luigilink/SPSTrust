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

    [Parameter(Mandatory = $true)]
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
