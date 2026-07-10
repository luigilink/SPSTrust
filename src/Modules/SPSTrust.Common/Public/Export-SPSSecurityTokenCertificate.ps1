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

    [Parameter(Mandatory = $true)]
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
