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

    [Parameter(Mandatory = $true)]
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
