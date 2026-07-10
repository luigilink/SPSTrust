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
