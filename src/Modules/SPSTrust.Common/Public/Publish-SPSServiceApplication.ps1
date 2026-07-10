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
