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

    [Parameter(Mandatory = $true)]
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
