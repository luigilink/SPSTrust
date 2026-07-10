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

    [Parameter(Mandatory = $true)]
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
