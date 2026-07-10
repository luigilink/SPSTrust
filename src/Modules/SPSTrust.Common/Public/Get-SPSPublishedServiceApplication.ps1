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

    [Parameter(Mandatory = $true)]
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
      Type   = $serviceApp.GetType().FullName
    }
  }
  return $result
}
